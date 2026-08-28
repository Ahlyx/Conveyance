//! ChaCha20-Poly1305 AEAD for data at rest (`identity.enc`, Phase 10.2).
//!
//! Session traffic is NOT encrypted through here — that goes through the
//! Noise transport (Phase 10.4). `conveyance_crypto::aead` is tested
//! against the RFC 8439 §2.8.2 worked example; this bridge marshals a
//! 32-byte key, a 12-byte nonce, and returns / consumes `ciphertext || tag`
//! (the trailing 16 bytes are the Poly1305 tag).
//!
//! `open` returns `Result<_, DecryptionFailed>` — one opaque error for
//! every failure (wrong key, wrong nonce, wrong AAD, flipped byte). No
//! oracle.

use crate::{CryptoFfiError, fixed, map_core_err};
use conveyance_crypto::aead::{AeadKey, Nonce};

/// Encrypt `plaintext` with associated data `aad`. Output is
/// `ciphertext || tag`.
#[uniffi::export]
pub fn chacha20poly1305_seal(
    key: Vec<u8>,
    nonce: Vec<u8>,
    plaintext: Vec<u8>,
    aad: Vec<u8>,
) -> Result<Vec<u8>, CryptoFfiError> {
    let key: [u8; 32] = fixed(key)?;
    let nonce: [u8; 12] = fixed(nonce)?;
    Ok(conveyance_crypto::aead::seal(
        &AeadKey::from_bytes(key),
        &Nonce(nonce),
        &plaintext,
        &aad,
    ))
}

/// Decrypt `ciphertext_and_tag` produced by [`chacha20poly1305_seal`].
/// Any failure collapses into [`CryptoFfiError::DecryptionFailed`].
#[uniffi::export]
pub fn chacha20poly1305_open(
    key: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext_and_tag: Vec<u8>,
    aad: Vec<u8>,
) -> Result<Vec<u8>, CryptoFfiError> {
    let key: [u8; 32] = fixed(key)?;
    let nonce: [u8; 12] = fixed(nonce)?;
    conveyance_crypto::aead::open(
        &AeadKey::from_bytes(key),
        &Nonce(nonce),
        &ciphertext_and_tag,
        &aad,
    )
    .map_err(map_core_err)
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

    /// RFC 8439 §2.8.2 — the same worked example `conveyance_crypto::aead`
    /// pins. Frozen here; emitted as a fixture; asserted from Kotlin.
    const KEY_HEX: &str = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
    const NONCE_HEX: &str = "070000004041424344454647";
    const AAD_HEX: &str = "50515253c0c1c2c3c4c5c6c7";
    const PLAINTEXT: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const SEALED_HEX: &str = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691";

    #[test]
    fn rfc8439_round_trip() {
        let sealed = chacha20poly1305_seal(
            unhex(KEY_HEX),
            unhex(NONCE_HEX),
            PLAINTEXT.to_vec(),
            unhex(AAD_HEX),
        )
        .unwrap();
        assert_eq!(sealed, unhex(SEALED_HEX), "AEAD ciphertext||tag drift");

        let opened = chacha20poly1305_open(
            unhex(KEY_HEX),
            unhex(NONCE_HEX),
            unhex(SEALED_HEX),
            unhex(AAD_HEX),
        )
        .unwrap();
        assert_eq!(opened, PLAINTEXT);
    }

    #[test]
    fn tamper_and_bad_lengths_are_typed_errors() {
        let mut flipped = unhex(SEALED_HEX);
        flipped[0] ^= 0x01;
        assert!(matches!(
            chacha20poly1305_open(unhex(KEY_HEX), unhex(NONCE_HEX), flipped, unhex(AAD_HEX)),
            Err(CryptoFfiError::DecryptionFailed)
        ));
        assert!(matches!(
            chacha20poly1305_open(
                unhex(KEY_HEX),
                unhex(NONCE_HEX),
                unhex(SEALED_HEX),
                b"x".to_vec()
            ),
            Err(CryptoFfiError::DecryptionFailed)
        ));
        assert!(matches!(
            chacha20poly1305_seal(vec![0u8; 31], unhex(NONCE_HEX), vec![], vec![]),
            Err(CryptoFfiError::BadLength)
        ));
        assert!(matches!(
            chacha20poly1305_seal(unhex(KEY_HEX), vec![0u8; 11], vec![], vec![]),
            Err(CryptoFfiError::BadLength)
        ));
    }

    #[test]
    fn empty_plaintext_still_carries_a_tag() {
        let sealed =
            chacha20poly1305_seal(unhex(KEY_HEX), unhex(NONCE_HEX), vec![], vec![]).unwrap();
        assert_eq!(sealed.len(), 16);
        let opened =
            chacha20poly1305_open(unhex(KEY_HEX), unhex(NONCE_HEX), sealed, vec![]).unwrap();
        assert!(opened.is_empty());
    }
}
