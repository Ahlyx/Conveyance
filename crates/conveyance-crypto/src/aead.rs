//! ChaCha20-Poly1305 AEAD for data at rest (`chacha20poly1305`).
//!
//! Scope note: this module is for *stored blobs* (identity.enc, phase 2).
//! Session traffic encryption is NOT hand-rolled here -- it happens
//! inside the Noise transport (phase 3), per the spec's MUST NOT rule
//! against encrypting payloads outside Noise.
//!
//! Failure policy: `open` returns a single opaque error whether the key
//! was wrong, the nonce was wrong, or a byte flipped. Callers get no
//! oracle for telling those apart, and neither should anything built on
//! top of this module.
//!
//! Nonces are caller-supplied, keeping these functions pure: the storage
//! layer owns the nonce discipline (random per blob is the intended
//! pattern; a 12-byte random nonce repeats with negligible probability
//! at the blob counts Conveyance will ever see).

use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload},
};

use super::{CryptoError, EntropySource};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A 256-bit AEAD key (e.g. an Argon2id-derived DEK).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AeadKey([u8; 32]);

impl AeadKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn generate<E: EntropySource>(entropy: &E) -> Result<Self, CryptoError> {
        let mut bytes = [0u8; 32];
        entropy.fill(&mut bytes)?;
        Ok(Self::from_bytes(bytes))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl std::fmt::Debug for AeadKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AeadKey(<redacted>)")
    }
}

/// A 96-bit AEAD nonce. Public value type; uniqueness is the caller's
/// contract, secrecy is nobody's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nonce(pub [u8; 12]);

/// Encrypt plaintext with associated data. Output is ciphertext || tag
/// (the tag is the standard trailing 16 bytes).
pub fn seal(key: &AeadKey, nonce: &Nonce, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let key_arr: chacha20poly1305::Key = key.0.into();
    let cipher = ChaCha20Poly1305::new(&key_arr);
    cipher
        .encrypt(
            (&nonce.0).into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        // Unreachable in practice: encryption only fails on allocator
        // exhaustion for in-memory buffers of this size class.
        .expect("ChaCha20-Poly1305 encryption cannot fail for in-memory inputs")
}

/// Decrypt ciphertext produced by [`seal`]. Any failure -- wrong key,
/// wrong nonce, wrong AAD, corrupted byte -- collapses into one error.
pub fn open(
    key: &AeadKey,
    nonce: &Nonce,
    ciphertext_and_tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let key_arr: chacha20poly1305::Key = key.0.into();
    let cipher = ChaCha20Poly1305::new(&key_arr);
    cipher
        .decrypt(
            (&nonce.0).into(),
            Payload {
                msg: ciphertext_and_tag,
                aad,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{CounterEntropy, FailingEntropy};

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn key32(hexstr: &str) -> [u8; 32] {
        hex(hexstr).try_into().unwrap()
    }

    fn nonce12(hexstr: &str) -> Nonce {
        Nonce(hex(hexstr).try_into().unwrap())
    }

    /// RFC 8439 §2.8.2, the full AEAD_CHACHA20_POLY1305 worked example:
    /// the sunscreen text. Verifies both directions -- our seal must
    /// reproduce the RFC's ciphertext||tag byte-for-byte, and open must
    /// recover the plaintext from the RFC's own bytes.
    #[test]
    fn rfc8439_aead_vector() {
        let key = AeadKey::from_bytes(key32(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        ));
        let nonce = nonce12("070000004041424344454647");
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you \
              only one tip for the future, sunscreen would be it.";

        // NOTE: the RFC plaintext has no line-break whitespace; rebuild it
        // exactly (the b-string above contains none because we used a
        // single-line continuation).
        assert_eq!(plaintext.len(), 114);

        let expected_ct = hex("d31a8d34648e60db7b86afbc53ef7ec2\
             a4aded51296e08fea9e2b5a736ee62d6\
             3dbea45e8ca9671282fafb69da92728b\
             1a71de0a9e060b2905d6a5b67ecd3b36\
             92ddbd7f2d778b8c9803aee328091b58\
             fab324e4fad675945585808b4831d7bc\
             3ff4def08e4b7a9de576d26586cec64b\
             6116");
        let expected_tag = hex("1ae10b594f09e26a7e902ecbd0600691");

        let sealed = seal(&key, &nonce, plaintext, &aad);
        let (ct, tag) = sealed.split_at(sealed.len() - 16);
        assert_eq!(ct, &expected_ct[..], "ciphertext diverges from RFC 8439");
        assert_eq!(tag, &expected_tag[..], "tag diverges from RFC 8439");

        let opened = open(&key, &nonce, &sealed, &aad).expect("RFC vector must decrypt");
        assert_eq!(opened, plaintext.to_vec());
    }

    #[test]
    fn round_trip_with_empty_inputs() {
        let key = AeadKey::generate(&CounterEntropy).unwrap();
        let nonce = Nonce([0u8; 12]);
        let sealed = seal(&key, &nonce, b"", b"");
        assert_eq!(sealed.len(), 16, "empty plaintext still carries a tag");
        assert_eq!(open(&key, &nonce, &sealed, b"").unwrap(), b"");
    }

    /// Every corruption path lands in the same opaque error: bit flip,
    /// truncated tag, wrong AAD, wrong key, wrong nonce. No distinction,
    /// no panic.
    #[test]
    fn all_failures_are_indistinguishable() {
        let key = AeadKey::generate(&CounterEntropy).unwrap();
        let nonce = Nonce([7u8; 12]);
        let sealed = seal(&key, &nonce, b"secret payload", b"header");

        let mut flipped = sealed.clone();
        flipped[0] ^= 0x01;
        assert!(matches!(
            open(&key, &nonce, &flipped, b"header"),
            Err(CryptoError::DecryptionFailed)
        ));

        let mut truncated = sealed.clone();
        truncated.truncate(truncated.len() - 1);
        assert!(matches!(
            open(&key, &nonce, &truncated, b"header"),
            Err(CryptoError::DecryptionFailed)
        ));

        assert!(matches!(
            open(&key, &nonce, &sealed, b"wrong aad"),
            Err(CryptoError::DecryptionFailed)
        ));

        let other_key = AeadKey::from_bytes([9u8; 32]);
        assert!(matches!(
            open(&other_key, &nonce, &sealed, b"header"),
            Err(CryptoError::DecryptionFailed)
        ));

        let other_nonce = Nonce([8u8; 12]);
        assert!(matches!(
            open(&key, &other_nonce, &sealed, b"header"),
            Err(CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn generate_propagates_entropy_failure_and_debug_redacts() {
        assert!(matches!(
            AeadKey::generate(&FailingEntropy),
            Err(CryptoError::EntropyFailure)
        ));
        let key = AeadKey::generate(&CounterEntropy).unwrap();
        let rendered = format!("{key:?}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(!rendered.contains(&hex_encode_test(&key.to_bytes())[..12]));
    }

    fn hex_encode_test(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
