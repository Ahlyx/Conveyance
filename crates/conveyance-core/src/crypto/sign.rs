//! Ed25519 identity signatures (`ed25519-dalek`).
//!
//! The long-term PC and phone identity keys are Ed25519. Everything here
//! is tested against RFC 8032 §7.1 vectors rather than round-trip tests,
//! because round-tripping proves nothing about interoperability: a
//! self-consistent wrong implementation would pass them forever.
//!
//! The secret key type deliberately exposes `to_bytes`: phase 2 storage
//! must serialize identity material, so pretending the bytes are not
//! reachable would just force an escape hatch later. Reachability is
//! fine; accidental *visibility* is what `Debug` redaction prevents.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use super::{CryptoError, EntropySource};

/// An Ed25519 signing key: someone's long-term identity.
#[derive(Clone)]
pub struct IdentitySecretKey(SigningKey);

impl IdentitySecretKey {
    /// Build from exactly 32 bytes of already-uniformly-random material.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(SigningKey::from_bytes(&bytes))
    }

    /// Generate a fresh key from the given entropy source.
    pub fn generate<E: EntropySource>(entropy: &E) -> Result<Self, CryptoError> {
        let mut bytes = [0u8; 32];
        entropy.fill(&mut bytes)?;
        Ok(Self::from_bytes(bytes))
    }

    /// Raw scalar bytes, e.g. for encrypted-at-rest persistence.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn public_key(&self) -> IdentityPublicKey {
        IdentityPublicKey(self.0.verifying_key())
    }

    /// Sign a message; returns the 64-byte compact signature.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.0.sign(message).to_bytes()
    }
}

impl std::fmt::Debug for IdentitySecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IdentitySecretKey(<redacted>)")
    }
}

/// An Ed25519 verification key: the public half of an identity.
#[derive(Clone, Debug)]
pub struct IdentityPublicKey(VerifyingKey);

impl IdentityPublicKey {
    /// Decode from 32 bytes. Fallible by nature: not every 32 bytes are
    /// a valid curve point, which is why pairing inputs get rejected at
    /// this boundary rather than deeper in the protocol.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        VerifyingKey::from_bytes(bytes)
            .map(IdentityPublicKey)
            .map_err(|_| CryptoError::BadKeyBytes)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Verify a 64-byte compact signature over a message.
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<(), CryptoError> {
        let sig = Signature::from_bytes(signature);
        self.0
            .verify(message, &sig)
            .map_err(|_| CryptoError::SignatureInvalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::test_support::{CounterEntropy, FailingEntropy};

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 8032 §7.1 TEST 1: empty message.
    #[test]
    fn rfc8032_test1() {
        let sk = IdentitySecretKey::from_bytes(
            hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")[..]
                .try_into()
                .unwrap(),
        );
        let expected_pk = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        assert_eq!(sk.public_key().to_bytes(), expected_pk[..]);

        let sig = sk.sign(b"");
        assert_eq!(
            sig.to_vec(),
            hex(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
            )
        );
        sk.public_key()
            .verify(b"", &sig)
            .expect("RFC vector must verify");
    }

    /// RFC 8032 §7.1 TEST 2: single byte message.
    #[test]
    fn rfc8032_test2() {
        let sk = IdentitySecretKey::from_bytes(
            hex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")[..]
                .try_into()
                .unwrap(),
        );
        let pk = sk.public_key();
        assert_eq!(
            pk.to_bytes()[..],
            hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")[..]
        );

        let msg = [0x72u8];
        let sig = sk.sign(&msg);
        assert_eq!(
            sig.to_vec(),
            hex(
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
            )
        );
        pk.verify(&msg, &sig).expect("RFC vector must verify");
    }

    /// RFC 8032 §7.1 SHA(abc): long message crossing block boundaries.
    #[test]
    fn rfc8032_sha_abc() {
        let sk = IdentitySecretKey::from_bytes(
            hex("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42")[..]
                .try_into()
                .unwrap(),
        );
        let msg = hex(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        );
        let sig = sk.sign(&msg);
        assert_eq!(
            sig.to_vec(),
            hex(
                "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"
            )
        );
        sk.public_key()
            .verify(&msg, &sig)
            .expect("RFC vector must verify");
    }

    /// Tampered messages/signatures/wrong keys all fail, and fail as
    /// `SignatureInvalid` -- never as a panic.
    #[test]
    fn tampering_is_rejected_not_fatal() {
        let sk = IdentitySecretKey::generate(&CounterEntropy).unwrap();
        let pk = sk.public_key();
        let mut sig = sk.sign(b"approve this");

        pk.verify(b"approve this", &sig)
            .expect("fresh signature verifies");
        sig[0] ^= 0x01;
        assert!(matches!(
            pk.verify(b"approve this", &sig),
            Err(CryptoError::SignatureInvalid)
        ));

        let good_sig = sk.sign(b"approve this");
        assert!(matches!(
            pk.verify(b"approve THAT", &good_sig),
            Err(CryptoError::SignatureInvalid)
        ));

        let other = IdentitySecretKey::generate(&CounterEntropy).unwrap();
        assert!(matches!(
            other.public_key().verify(b"approve this", &good_sig),
            Err(CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn invalid_public_key_bytes_are_rejected() {
        // Empirically verified against ed25519-dalek 3.x: this encoding
        // is not a decompressible curve point. Note the all-zeros
        // encoding (the identity element) IS accepted by the crate --
        // small-order/identity rejection is a protocol-layer concern
        // here, handled by the peer-identity-mismatch check against the
        // stored pairing, not by key decoding.
        assert!(matches!(
            IdentityPublicKey::from_bytes(&{
                let mut b = [0xffu8; 32];
                b[31] = 0xfe;
                b
            }),
            Err(CryptoError::BadKeyBytes)
        ));
    }

    #[test]
    fn generate_propagates_entropy_failure_and_matches_from_bytes() {
        assert!(matches!(
            IdentitySecretKey::generate(&FailingEntropy),
            Err(CryptoError::EntropyFailure)
        ));
        let sk = IdentitySecretKey::generate(&CounterEntropy).unwrap();
        let rebuilt = IdentitySecretKey::from_bytes(sk.to_bytes());
        assert_eq!(sk.sign(b"x").to_vec(), rebuilt.sign(b"x").to_vec());
    }

    #[test]
    fn secret_debug_is_redacted() {
        let sk = IdentitySecretKey::generate(&CounterEntropy).unwrap();
        let rendered = format!("{sk:?}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        // The raw scalar must not appear anywhere in the rendering.
        let raw = hex_encode_lower(&sk.to_bytes());
        assert!(!rendered.contains(&raw[..16]));
    }

    fn hex_encode_lower(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
