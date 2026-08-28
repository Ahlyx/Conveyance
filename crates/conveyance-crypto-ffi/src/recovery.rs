//! Recovery-phrase generation and identity derivation.
//!
//! This is the entropy entry point for the phone's identity: a 24-word
//! BIP-39 phrase is the *only* source of the long-term Ed25519 and X25519
//! keys (`CONVEYANCE_SPEC.md` "Recovery"). There is deliberately no bridge
//! for generating a raw Ed25519/X25519 scalar directly — the phone never
//! has identity keys that did not come from a phrase.
//!
//! [`recovery_phrase_to_identity`] is the security-critical spine: it must
//! produce byte-identical keys to any other implementation of the same
//! phrase. Every step is pinned in `conveyance_crypto::recovery` (BIP-39
//! PBKDF2-HMAC-SHA512 with an **empty** passphrase per spec, then
//! HKDF-BLAKE2s with zero salt and the two exact info strings); this
//! bridge only marshals bytes.

use crate::{CryptoFfiError, map_core_err};
use conveyance_crypto::dh::DhSecret;
use conveyance_crypto::recovery::RecoveryPhrase;
use conveyance_crypto::sign::IdentitySecretKey;

/// Both long-term identity keypairs derived from one recovery phrase, as
/// raw 32-byte scalars and public keys. The BIP-39 seed itself is not
/// returned: nothing on the phone consumes it, and it is one more piece
/// of secret material with no reason to cross the boundary.
#[derive(uniffi::Record)]
pub struct IdentityKeys {
    pub ed25519_secret: Vec<u8>,
    pub ed25519_public: Vec<u8>,
    pub x25519_secret: Vec<u8>,
    pub x25519_public: Vec<u8>,
}

/// Generate a fresh 24-word English BIP-39 phrase from 256 bits of OS
/// entropy. Returned as the canonical space-separated string.
#[uniffi::export]
pub fn generate_recovery_phrase() -> Result<String, CryptoFfiError> {
    let phrase = RecoveryPhrase::generate(&conveyance_crypto::OsEntropy).map_err(map_core_err)?;
    Ok(phrase.as_words().collect::<Vec<_>>().join(" "))
}

/// Validate a recovery phrase (BIP-39 checksum) and derive both identity
/// keypairs. Wrong word count, unknown words, and bad checksum all collapse
/// into [`CryptoFfiError::BadRecoveryPhrase`] — no parsing oracle.
#[uniffi::export]
pub fn recovery_phrase_to_identity(phrase: String) -> Result<IdentityKeys, CryptoFfiError> {
    let phrase = RecoveryPhrase::from_words(&phrase).map_err(map_core_err)?;
    // Spec: BIP-39-to-seed with an EMPTY passphrase.
    let keyset = phrase.to_seed("").derive_identity_keys();

    let ed_secret = *keyset.ed25519_secret.expose();
    let x_secret = *keyset.x25519_secret.expose();
    let ed_public = IdentitySecretKey::from_bytes(ed_secret)
        .public_key()
        .to_bytes();
    let x_public = DhSecret::from_bytes(x_secret).public_key().to_bytes();

    Ok(IdentityKeys {
        ed25519_secret: ed_secret.to_vec(),
        ed25519_public: ed_public.to_vec(),
        x25519_secret: x_secret.to_vec(),
        x25519_public: x_public.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The all-zeros 256-bit entropy phrase, BIP-39's most widely quoted
    /// vector. Conveyance derives with an EMPTY passphrase (not "TREZOR"),
    /// so the derived-key hex below has no third-party publication: it is
    /// frozen against `conveyance_crypto`'s implementation and is the same
    /// value the JSON fixture and the Kotlin instrumented test assert.
    const ZEROS_24WORD: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn zeros_phrase_derives_frozen_identity_keys() {
        let keys = recovery_phrase_to_identity(ZEROS_24WORD.to_string()).unwrap();
        assert_eq!(
            hex(&keys.ed25519_secret),
            "d1e044dad39a9278124157c7f8f3dae0e7515c18fce7d09d69ad8c88acefd91f",
            "ed25519 secret drift"
        );
        assert_eq!(
            hex(&keys.ed25519_public),
            "95dbfb758f5764904c5dee525766c2161100b46991e223c6b44399a2284895f1",
            "ed25519 public drift"
        );
        assert_eq!(
            hex(&keys.x25519_secret),
            "17f78459a26f287e26b7a0b60ab126e997809bbb1c2a6ea01ab50da54b62cff5",
            "x25519 secret drift"
        );
        assert_eq!(
            hex(&keys.x25519_public),
            "82d6a4f53fadbb062089d3312c0bc9ab21e43b00a6055cb9b720ed30c4221c1c",
            "x25519 public drift"
        );
    }

    #[test]
    fn public_keys_are_consistent_with_secrets() {
        let keys = recovery_phrase_to_identity(ZEROS_24WORD.to_string()).unwrap();
        let ed_pk =
            IdentitySecretKey::from_bytes(crate::fixed(keys.ed25519_secret.clone()).unwrap())
                .public_key()
                .to_bytes();
        let x_pk = DhSecret::from_bytes(crate::fixed(keys.x25519_secret.clone()).unwrap())
            .public_key()
            .to_bytes();
        assert_eq!(ed_pk.to_vec(), keys.ed25519_public);
        assert_eq!(x_pk.to_vec(), keys.x25519_public);
        assert_ne!(keys.ed25519_secret, keys.x25519_secret);
    }

    #[test]
    fn bad_phrase_is_rejected() {
        assert!(matches!(
            recovery_phrase_to_identity("not a real phrase".to_string()),
            Err(CryptoFfiError::BadRecoveryPhrase)
        ));
        let tampered = ZEROS_24WORD.replace(" art", " zoo");
        assert!(matches!(
            recovery_phrase_to_identity(tampered),
            Err(CryptoFfiError::BadRecoveryPhrase)
        ));
    }

    #[test]
    fn generation_produces_24_distinct_words_each_call() {
        let a = generate_recovery_phrase().unwrap();
        let b = generate_recovery_phrase().unwrap();
        assert_eq!(a.split_whitespace().count(), 24);
        assert_ne!(a, b, "two CSPRNG draws colliding means the RNG is broken");
        // A freshly generated phrase must derive without error.
        recovery_phrase_to_identity(a).unwrap();
    }
}
