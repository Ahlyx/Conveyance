//! Ed25519 identity signatures.
//!
//! Raw-bytes surface: the secret key is a 32-byte scalar, the public key
//! 32 bytes, the signature 64. `conveyance_crypto::sign` is tested against
//! RFC 8032 §7.1 vectors; this bridge only marshals.
//!
//! `ed25519_verify` returns `Result<(), _>` — [`CryptoFfiError::SignatureInvalid`]
//! is an expected, branchable outcome on the phone side (an attack or a
//! peer bug), not an exception. The Kotlin adapter surfaces it as a
//! `Result`.

use crate::{CryptoFfiError, fixed, map_core_err};
use conveyance_crypto::sign::{IdentityPublicKey, IdentitySecretKey};

/// Derive the 32-byte Ed25519 public key from a 32-byte secret scalar.
#[uniffi::export]
pub fn ed25519_public_from_secret(secret: Vec<u8>) -> Result<Vec<u8>, CryptoFfiError> {
    let sk: [u8; 32] = fixed(secret)?;
    Ok(IdentitySecretKey::from_bytes(sk)
        .public_key()
        .to_bytes()
        .to_vec())
}

/// Sign `message` with a 32-byte Ed25519 secret scalar; returns the
/// 64-byte compact signature.
#[uniffi::export]
pub fn ed25519_sign(secret: Vec<u8>, message: Vec<u8>) -> Result<Vec<u8>, CryptoFfiError> {
    let sk: [u8; 32] = fixed(secret)?;
    Ok(IdentitySecretKey::from_bytes(sk).sign(&message).to_vec())
}

/// Verify a 64-byte compact signature over `message` against a 32-byte
/// public key. `BadKeyBytes` if the key is not a valid curve point;
/// `SignatureInvalid` if verification fails.
#[uniffi::export]
pub fn ed25519_verify(
    public: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
) -> Result<(), CryptoFfiError> {
    let pk: [u8; 32] = fixed(public)?;
    let sig: [u8; 64] = fixed(signature)?;
    let pk = IdentityPublicKey::from_bytes(&pk).map_err(map_core_err)?;
    pk.verify(&message, &sig).map_err(map_core_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 8032 §7.1 TEST 1 (empty message), the same vector
    /// `conveyance_crypto::sign` pins. Frozen here so a regression in the
    /// bridge or the crate fails `cargo test` loudly; the JSON fixture and
    /// the Kotlin test assert the identical bytes.
    const SK_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const PK_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const SIG_HEX: &str = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    #[test]
    fn rfc8032_test1_public_sign_verify() {
        let pk = ed25519_public_from_secret(unhex(SK_HEX)).unwrap();
        assert_eq!(pk, unhex(PK_HEX));

        let sig = ed25519_sign(unhex(SK_HEX), vec![]).unwrap();
        assert_eq!(sig, unhex(SIG_HEX));

        ed25519_verify(unhex(PK_HEX), vec![], unhex(SIG_HEX)).unwrap();
    }

    #[test]
    fn tampering_and_bad_lengths_are_typed_errors() {
        let mut bad_sig = unhex(SIG_HEX);
        bad_sig[0] ^= 0x01;
        assert!(matches!(
            ed25519_verify(unhex(PK_HEX), vec![], bad_sig),
            Err(CryptoFfiError::SignatureInvalid)
        ));

        assert!(matches!(
            ed25519_verify(unhex(PK_HEX), b"other".to_vec(), unhex(SIG_HEX)),
            Err(CryptoFfiError::SignatureInvalid)
        ));

        assert!(matches!(
            ed25519_sign(vec![0u8; 31], vec![]),
            Err(CryptoFfiError::BadLength)
        ));
        assert!(matches!(
            ed25519_verify(vec![0u8; 32], vec![], vec![0u8; 63]),
            Err(CryptoFfiError::BadLength)
        ));

        // Not a decompressible curve point (matches
        // `conveyance_crypto::sign`'s own rejection vector).
        let mut bad_pk = vec![0xffu8; 32];
        bad_pk[31] = 0xfe;
        assert!(matches!(
            ed25519_verify(bad_pk, vec![], unhex(SIG_HEX)),
            Err(CryptoFfiError::BadKeyBytes)
        ));
    }
}
