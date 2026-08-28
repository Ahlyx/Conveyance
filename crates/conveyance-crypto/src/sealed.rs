//! Versioned AEAD-sealed blobs for encrypted-at-rest storage on the
//! phone: `identity.enc` and each `credentials.enc` row.
//!
//! Layout: `version(1) || nonce(12) || ChaCha20-Poly1305(key, plaintext,
//! aad = [version])`. The version byte is both a format tag and the AEAD
//! associated data, so a blob sealed under one format version fails to
//! open as another rather than silently mis-parsing.
//!
//! Why this lives in `conveyance-crypto` and not in the FFI bridge: the
//! phone's identity secret scalars must be derived, sealed, opened, and
//! used without ever crossing the UniFFI boundary as plaintext (Phase
//! 10.2 security goal). The bridge exposes an opaque handle; the actual
//! seal/open — and the `bip39 -> HKDF` derivation feeding it — happen
//! here, in Rust, over `Zeroizing` buffers. Keeping it here also lets the
//! cross-implementation fixtures exercise it without a bridge build.
//!
//! Failure policy mirrors `aead`: [`open`] returns one opaque
//! [`CryptoError::DecryptionFailed`] for every failure mode — wrong key,
//! wrong version, truncation, a flipped byte. No oracle.

use zeroize::{Zeroize, Zeroizing};

use crate::aead::{self, AeadKey, Nonce};
use crate::recovery::RecoveryPhrase;
use crate::{CryptoError, EntropySource, Secret};

/// `identity.enc` format version. Bump only alongside a migration path.
pub const IDENTITY_V1: u8 = 1;
/// `credentials.enc` per-row format version.
pub const CREDENTIAL_V1: u8 = 1;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 1 + NONCE_LEN;

/// Seal `plaintext` under `key` (32 bytes) with format tag `version`.
pub fn seal<E: EntropySource>(
    entropy: &E,
    version: u8,
    key: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut nonce = [0u8; NONCE_LEN];
    entropy.fill(&mut nonce)?;
    let key = AeadKey::from_bytes(*key);
    let ct = aead::seal(&key, &Nonce(nonce), plaintext, &[version]);

    let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
    out.push(version);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a blob produced by [`seal`] with the same `version` and `key`.
pub fn open(version: u8, key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if blob.len() < HEADER_LEN + TAG_LEN || blob[0] != version {
        return Err(CryptoError::DecryptionFailed);
    }
    let nonce: [u8; NONCE_LEN] = blob[1..HEADER_LEN].try_into().expect("len checked above");
    let key = AeadKey::from_bytes(*key);
    aead::open(&key, &Nonce(nonce), &blob[HEADER_LEN..], &[version])
}

/// The 64-byte identity plaintext held out of reach: the Ed25519 secret
/// scalar followed by the X25519 secret scalar. Zeroizes on drop.
#[derive(Clone)]
pub struct IdentitySecrets(Secret<64>);

impl IdentitySecrets {
    /// The Ed25519 signing scalar.
    pub fn ed25519(&self) -> [u8; 32] {
        self.0.expose()[..32].try_into().expect("64-byte buffer")
    }

    /// The X25519 static scalar.
    pub fn x25519(&self) -> [u8; 32] {
        self.0.expose()[32..].try_into().expect("64-byte buffer")
    }
}

impl std::fmt::Debug for IdentitySecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IdentitySecrets(<redacted>)")
    }
}

/// Output of [`seal_identity`]: the on-disk blob plus the two public keys
/// (which the caller needs for pairing display and peer lookup, and which
/// are safe to hold in the clear).
pub struct SealedIdentity {
    pub blob: Vec<u8>,
    pub ed25519_public: [u8; 32],
    pub x25519_public: [u8; 32],
}

/// Derive both identity keypairs from `phrase` (BIP-39 seed with an empty
/// passphrase, then HKDF-BLAKE2s, per spec) and seal the two secret
/// scalars into an `identity.enc` blob under `content_key`. The secret
/// scalars exist only in `Zeroizing` buffers inside this function.
pub fn seal_identity<E: EntropySource>(
    entropy: &E,
    content_key: &[u8; 32],
    phrase: &RecoveryPhrase,
) -> Result<SealedIdentity, CryptoError> {
    let keyset = phrase.to_seed("").derive_identity_keys();
    let ed = keyset.ed25519_secret.expose();
    let x = keyset.x25519_secret.expose();

    let mut plaintext = Zeroizing::new([0u8; 64]);
    plaintext[..32].copy_from_slice(ed);
    plaintext[32..].copy_from_slice(x);
    let blob = seal(entropy, IDENTITY_V1, content_key, &plaintext[..])?;

    let ed25519_public = crate::sign::IdentitySecretKey::from_bytes(*ed)
        .public_key()
        .to_bytes();
    let x25519_public = crate::dh::DhSecret::from_bytes(*x).public_key().to_bytes();

    Ok(SealedIdentity {
        blob,
        ed25519_public,
        x25519_public,
    })
}

/// Open an `identity.enc` blob. Wrong key or a tampered/truncated blob →
/// [`CryptoError::DecryptionFailed`].
pub fn open_identity(content_key: &[u8; 32], blob: &[u8]) -> Result<IdentitySecrets, CryptoError> {
    let mut plaintext = open(IDENTITY_V1, content_key, blob)?;
    if plaintext.len() != 64 {
        plaintext.zeroize();
        return Err(CryptoError::DecryptionFailed);
    }
    let mut buf = [0u8; 64];
    buf.copy_from_slice(&plaintext);
    plaintext.zeroize();
    let secrets = IdentitySecrets(Secret::from_bytes(buf));
    buf.zeroize();
    Ok(secrets)
}

/// Seal one credential secret under a per-service DEK.
pub fn seal_credential<E: EntropySource>(
    entropy: &E,
    dek: &[u8; 32],
    secret: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    seal(entropy, CREDENTIAL_V1, dek, secret)
}

/// Open one credential blob. The caller (Phase 10.7's request executor)
/// receives the plaintext; it is never decrypted in bulk.
pub fn open_credential(dek: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, CryptoError> {
    open(CREDENTIAL_V1, dek, blob)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::CounterEntropy;

    const ZEROS_24WORD: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn key(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn seal_open_round_trips() {
        let blob = seal(&CounterEntropy, 7, &key(1), b"hello world").unwrap();
        assert_eq!(blob[0], 7);
        assert_eq!(open(7, &key(1), &blob).unwrap(), b"hello world");
    }

    #[test]
    fn every_mismatch_is_one_opaque_error() {
        let blob = seal(&CounterEntropy, IDENTITY_V1, &key(1), b"secret").unwrap();

        assert!(matches!(
            open(IDENTITY_V1, &key(2), &blob),
            Err(CryptoError::DecryptionFailed)
        ));
        assert!(matches!(
            open(2, &key(1), &blob),
            Err(CryptoError::DecryptionFailed)
        ));
        let mut flipped = blob.clone();
        flipped[HEADER_LEN] ^= 1;
        assert!(matches!(
            open(IDENTITY_V1, &key(1), &flipped),
            Err(CryptoError::DecryptionFailed)
        ));
        assert!(matches!(
            open(IDENTITY_V1, &key(1), &blob[..blob.len() - 1]),
            Err(CryptoError::DecryptionFailed)
        ));
        assert!(matches!(
            open(IDENTITY_V1, &key(1), &[]),
            Err(CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn identity_round_trip_matches_direct_derivation() {
        let phrase = RecoveryPhrase::from_words(ZEROS_24WORD).unwrap();
        let ck = key(0x42);

        let sealed = seal_identity(&CounterEntropy, &ck, &phrase).unwrap();
        let opened = open_identity(&ck, &sealed.blob).unwrap();

        let direct = phrase.to_seed("").derive_identity_keys();
        assert_eq!(opened.ed25519(), *direct.ed25519_secret.expose());
        assert_eq!(opened.x25519(), *direct.x25519_secret.expose());

        // Public keys returned by seal_identity match those derived from
        // the opened secrets.
        assert_eq!(
            sealed.ed25519_public,
            crate::sign::IdentitySecretKey::from_bytes(opened.ed25519())
                .public_key()
                .to_bytes()
        );
        assert_eq!(
            sealed.x25519_public,
            crate::dh::DhSecret::from_bytes(opened.x25519())
                .public_key()
                .to_bytes()
        );
    }

    #[test]
    fn identity_blob_is_versioned_and_nonce_randomised() {
        let phrase = RecoveryPhrase::from_words(ZEROS_24WORD).unwrap();
        let a = seal_identity(&CounterEntropy, &key(1), &phrase).unwrap();
        let b = seal_identity(&CounterEntropy, &key(1), &phrase).unwrap();
        assert_eq!(a.blob[0], IDENTITY_V1);
        assert_ne!(a.blob[1..HEADER_LEN], b.blob[1..HEADER_LEN], "nonce reuse");
        assert_ne!(a.blob, b.blob);
    }

    #[test]
    fn wrong_content_key_fails_to_open_identity() {
        let phrase = RecoveryPhrase::from_words(ZEROS_24WORD).unwrap();
        let sealed = seal_identity(&CounterEntropy, &key(1), &phrase).unwrap();
        assert!(matches!(
            open_identity(&key(2), &sealed.blob),
            Err(CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn credential_round_trips_and_is_version_tagged() {
        let dek = key(9);
        let blob = seal_credential(&CounterEntropy, &dek, b"AKIA...topsecret").unwrap();
        assert_eq!(blob[0], CREDENTIAL_V1);
        assert_eq!(open_credential(&dek, &blob).unwrap(), b"AKIA...topsecret");
        assert!(matches!(
            open_credential(&key(10), &blob),
            Err(CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn identity_secrets_debug_is_redacted() {
        let phrase = RecoveryPhrase::from_words(ZEROS_24WORD).unwrap();
        let sealed = seal_identity(&CounterEntropy, &key(1), &phrase).unwrap();
        let opened = open_identity(&key(1), &sealed.blob).unwrap();
        let rendered = format!("{opened:?}");
        assert!(rendered.contains("<redacted>"));
    }
}
