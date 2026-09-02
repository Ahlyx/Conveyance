//! Sealed-at-rest storage primitives for the phone: `identity.enc` and
//! `credentials.enc` rows.
//!
//! The Phase 10.2 security goal is that the phone's identity secret
//! scalars never cross this FFI boundary as plaintext. So this module
//! exposes no function that returns them: [`create_sealed_identity`]
//! derives and seals in one call (only the blob and the public keys come
//! back), and [`open_sealed_identity`] returns an opaque
//! [`UnlockedIdentity`] handle whose secrets live in a `Zeroizing` buffer
//! in native memory. Kotlin signs *through* the handle; it never holds
//! the scalar.
//!
//! The seal/open logic and the `bip39 -> HKDF` derivation are
//! `conveyance_crypto::sealed` — this is the usual thin bridge.

use std::sync::Arc;

use crate::{CryptoFfiError, fixed, map_core_err};
use conveyance_crypto::dh::DhSecret;
use conveyance_crypto::recovery::RecoveryPhrase;
use conveyance_crypto::sealed;
use conveyance_crypto::sign::IdentitySecretKey;

/// Output of [`create_sealed_identity`]: the versioned `identity.enc`
/// bytes plus the two public keys (safe to hold in the clear).
#[derive(uniffi::Record)]
pub struct SealedIdentity {
    pub blob: Vec<u8>,
    pub ed25519_public: Vec<u8>,
    pub x25519_public: Vec<u8>,
}

/// Derive both identity keypairs from `phrase` and seal the secret
/// scalars into an `identity.enc` blob under `content_key` (32 bytes,
/// caller-generated). The scalars never leave Rust.
#[uniffi::export]
pub fn create_sealed_identity(
    phrase: String,
    content_key: Vec<u8>,
) -> Result<SealedIdentity, CryptoFfiError> {
    let content_key: [u8; 32] = fixed(content_key)?;
    let phrase = RecoveryPhrase::from_words(&phrase).map_err(map_core_err)?;
    let s = sealed::seal_identity(&conveyance_crypto::OsEntropy, &content_key, &phrase)
        .map_err(map_core_err)?;
    Ok(SealedIdentity {
        blob: s.blob,
        ed25519_public: s.ed25519_public.to_vec(),
        x25519_public: s.x25519_public.to_vec(),
    })
}

/// Open an `identity.enc` blob into an [`UnlockedIdentity`] handle. Wrong
/// key or a tampered/truncated blob → [`CryptoFfiError::DecryptionFailed`].
#[uniffi::export]
pub fn open_sealed_identity(
    blob: Vec<u8>,
    content_key: Vec<u8>,
) -> Result<Arc<UnlockedIdentity>, CryptoFfiError> {
    let content_key: [u8; 32] = fixed(content_key)?;
    let secrets = sealed::open_identity(&content_key, &blob).map_err(map_core_err)?;
    Ok(Arc::new(UnlockedIdentity { secrets }))
}

/// An unlocked phone identity. The Ed25519 and X25519 secret scalars are
/// held in a `Zeroizing` buffer in native memory and are wiped when the
/// last reference drops — on the Kotlin side, when the generated
/// `destroy()` runs (or `use { }` ends). There is no accessor for the
/// scalars; only operations over them.
#[derive(uniffi::Object)]
pub struct UnlockedIdentity {
    secrets: sealed::IdentitySecrets,
}

impl UnlockedIdentity {
    /// The long-term X25519 static secret, for building the Noise KK
    /// handshake in the [`crate::noise`] module. `pub(crate)` — it stays
    /// in native memory and never reaches the FFI surface.
    pub(crate) fn x25519_static(&self) -> [u8; 32] {
        self.secrets.x25519()
    }
}

#[uniffi::export]
impl UnlockedIdentity {
    /// The long-term Ed25519 identity public key (32 bytes).
    pub fn ed25519_public(&self) -> Vec<u8> {
        IdentitySecretKey::from_bytes(self.secrets.ed25519())
            .public_key()
            .to_bytes()
            .to_vec()
    }

    /// The long-term X25519 static public key (32 bytes).
    pub fn x25519_public(&self) -> Vec<u8> {
        DhSecret::from_bytes(self.secrets.x25519())
            .public_key()
            .to_bytes()
            .to_vec()
    }

    /// Sign `message` with the Ed25519 identity key; 64-byte signature.
    /// The caller builds the message (e.g. an approval-log row's
    /// signing payload); this only signs.
    pub fn sign(&self, message: Vec<u8>) -> Vec<u8> {
        IdentitySecretKey::from_bytes(self.secrets.ed25519())
            .sign(&message)
            .to_vec()
    }
    // dh(peer_x_pub) for the Noise KK handshake is added in Phase 10.4,
    // where snow consumes the static X25519 secret through this handle.
}

/// Seal one credential secret under a per-service DEK (32 bytes).
#[uniffi::export]
pub fn seal_credential(secret: Vec<u8>, dek: Vec<u8>) -> Result<Vec<u8>, CryptoFfiError> {
    let dek: [u8; 32] = fixed(dek)?;
    sealed::seal_credential(&conveyance_crypto::OsEntropy, &dek, &secret).map_err(map_core_err)
}

/// Open one credential blob. The plaintext returns to the caller (Phase
/// 10.7's request executor needs it for the outbound request); rows are
/// opened one at a time, never in bulk.
#[uniffi::export]
pub fn open_credential(blob: Vec<u8>, dek: Vec<u8>) -> Result<Vec<u8>, CryptoFfiError> {
    let dek: [u8; 32] = fixed(dek)?;
    sealed::open_credential(&dek, &blob).map_err(map_core_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZEROS_24WORD: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn create_open_sign_round_trip() {
        let ck = vec![0x42u8; 32];
        let sealed = create_sealed_identity(ZEROS_24WORD.to_string(), ck.clone()).unwrap();

        // Public keys match the frozen recovery vector.
        assert_eq!(
            hex(&sealed.ed25519_public),
            "95dbfb758f5764904c5dee525766c2161100b46991e223c6b44399a2284895f1"
        );

        let id = open_sealed_identity(sealed.blob.clone(), ck).unwrap();
        assert_eq!(id.ed25519_public(), sealed.ed25519_public);
        assert_eq!(id.x25519_public(), sealed.x25519_public);

        // Ed25519 is deterministic: a fixed message signs to a fixed value
        // that verifies against the handle's public key.
        let sig = id.sign(b"conveyance approval row 1".to_vec());
        crate::sign::ed25519_verify(
            id.ed25519_public(),
            b"conveyance approval row 1".to_vec(),
            sig,
        )
        .unwrap();
    }

    #[test]
    fn wrong_content_key_is_decryption_failed() {
        let sealed = create_sealed_identity(ZEROS_24WORD.to_string(), vec![1u8; 32]).unwrap();
        assert!(matches!(
            open_sealed_identity(sealed.blob, vec![2u8; 32]),
            Err(CryptoFfiError::DecryptionFailed)
        ));
    }

    #[test]
    fn bad_lengths_and_phrases_are_typed_errors() {
        assert!(matches!(
            create_sealed_identity(ZEROS_24WORD.to_string(), vec![0u8; 31]),
            Err(CryptoFfiError::BadLength)
        ));
        assert!(matches!(
            create_sealed_identity("not a phrase".to_string(), vec![0u8; 32]),
            Err(CryptoFfiError::BadRecoveryPhrase)
        ));
        assert!(matches!(
            open_sealed_identity(vec![1u8; 8], vec![0u8; 32]),
            Err(CryptoFfiError::DecryptionFailed)
        ));
    }

    #[test]
    fn credential_seal_open_round_trip() {
        let dek = vec![9u8; 32];
        let blob = seal_credential(b"AKIA-super-secret".to_vec(), dek.clone()).unwrap();
        assert_eq!(
            open_credential(blob.clone(), dek).unwrap(),
            b"AKIA-super-secret"
        );
        assert!(matches!(
            open_credential(blob, vec![10u8; 32]),
            Err(CryptoFfiError::DecryptionFailed)
        ));
    }
}
