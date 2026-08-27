//! `identity.enc`: the PC's long-term identity keys, encrypted at rest.
//!
//! Layering (per spec "Storage layout" + phase-2 decisions):
//!
//! 1. A random 32-byte KEK lives in the OS keychain
//!    (service `conveyance`, account `pc-identity-kek-v1`). It is created
//!    on first save and never leaves the machine.
//! 2. The DEK is HKDF-BLAKE2s(KEK, info=`conveyance-v1-pc-storage-dek`) --
//!    domain-separated so the same stored KEK can derive other keys later
//!    without cross-use.
//! 3. The serialized keyset is sealed with ChaCha20-Poly1305 under that
//!    DEK and a fresh random nonce; file layout is
//!    `b"CVY" || version(1) || nonce(12) || ciphertext||tag`.
//!
//! Failure policy is spec-mandated: if the OS keychain cannot be reached,
//! that is a typed error (`keychain_unavailable`) the daemon turns into
//! refuse-to-start. There is deliberately NO passphrase fallback -- a
//! silent fallback would quietly downgrade the at-rest guarantee on the
//! one platform where the user cannot see it happen.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::crypto::{
    EntropySource, Secret, aead, hex_decode, hex_decode_array, hex_encode, hkdf_blake2s,
    sign::IdentitySecretKey,
};

use super::{KEYCHAIN_SERVICE, StorageError};

pub const KEK_ACCOUNT: &str = "pc-identity-kek-v1";
const DEK_INFO: &[u8] = b"conveyance-v1-pc-storage-dek";
const MAGIC: [u8; 3] = *b"CVY";
const FORMAT_VERSION: u8 = 1;

/// Where the KEK lives. Abstracted so tests can run without touching any
/// real OS credential store, and so a future backend swap does not touch
/// this module's logic.
pub trait KeyProvider {
    /// Returns Ok(None) when the entry simply does not exist yet. An Err
    /// means the provider itself failed (service down, no session) --
    /// callers must not treat that as "absent".
    fn get(&self, account: &str) -> Result<Option<Vec<u8>>, StorageError>;
    fn set(&self, account: &str, value: &[u8]) -> Result<(), StorageError>;
}

/// Production provider backed by the OS keychain via the `keyring` crate.
///
/// The KEK is stored as its lowercase-hex string rather than raw bytes:
/// every keyring backend exposes string passwords, while byte-secret APIs
/// are unevenly supported across platforms. Hex is trivially reversible;
/// the entropy of the underlying 32 bytes is what matters.
pub struct OsKeyring;

impl KeyProvider for OsKeyring {
    fn get(&self, account: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, account)
            .map_err(|e| StorageError::KeychainUnavailable(e.to_string()))?;
        match entry.get_password() {
            Ok(hex_str) => hex_decode(&hex_str)
                .ok_or_else(|| {
                    StorageError::KeychainUnavailable(format!(
                        "entry '{account}' holds non-hex data"
                    ))
                })
                .map(Some),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(StorageError::KeychainUnavailable(e.to_string())),
        }
    }

    fn set(&self, account: &str, value: &[u8]) -> Result<(), StorageError> {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, account)
            .map_err(|e| StorageError::KeychainUnavailable(e.to_string()))?;
        entry
            .set_password(&hex_encode(value))
            .map_err(|e| StorageError::KeychainUnavailable(e.to_string()))
    }
}

/// Both halves of the PC's long-term identity.
#[derive(Clone)]
pub struct StoredIdentity {
    pub ed25519_secret: Secret<32>,
    pub x25519_secret: Secret<32>,
}

impl StoredIdentity {
    /// Generate a fresh PC identity. Unlike the phone side, the PC has NO
    /// recovery phrase: these bytes exist exactly once, here and in the
    /// encrypted file. Losing both means generating a new identity and
    /// re-pairing -- which is precisely the recovery model the spec wants
    /// (the phrase restores phones, never PCs).
    pub fn generate<E: EntropySource>(entropy: &E) -> Result<Self, StorageError> {
        let mut ed = [0u8; 32];
        let mut x = [0u8; 32];
        entropy.fill(&mut ed)?;
        entropy.fill(&mut x)?;
        Ok(Self {
            ed25519_secret: Secret::from_bytes(ed),
            x25519_secret: Secret::from_bytes(x),
        })
    }

    pub fn save<P: KeyProvider, E: EntropySource>(
        &self,
        path: &Path,
        keys: &P,
        entropy: &E,
    ) -> Result<(), StorageError> {
        // Get or create the KEK. Two savers racing would generate two
        // KEKs; single-process daemon makes that unreachable today, and
        // set() is idempotent-overwrite anyway, so each writer's file is
        // sealed under whichever KEK it read -- self-consistent either way.
        let kek: [u8; 32] = match keys.get(KEK_ACCOUNT)? {
            Some(k) => <[u8; 32]>::try_from(k).map_err(|_| {
                StorageError::KeychainUnavailable(format!(
                    "entry '{KEK_ACCOUNT}' exists but has wrong length"
                ))
            })?,
            None => {
                let mut k = [0u8; 32];
                entropy.fill(&mut k)?;
                keys.set(KEK_ACCOUNT, &k)?;
                k
            }
        };

        let mut dek_bytes = [0u8; 32];
        hkdf_blake2s(&kek, DEK_INFO, &mut dek_bytes);
        let dek = aead::AeadKey::from_bytes(dek_bytes); // zeroizes on drop

        let plaintext = SerializedIdentity::from(self);
        let json = serde_json::to_vec(&plaintext).expect("serializing our own struct cannot fail");

        let mut nonce_bytes = [0u8; 12];
        entropy.fill(&mut nonce_bytes)?;
        let nonce = aead::Nonce(nonce_bytes);

        let sealed = aead::seal(&dek, &nonce, &json, b"");

        let mut blob = Vec::with_capacity(MAGIC.len() + 1 + 12 + sealed.len());
        blob.extend_from_slice(&MAGIC);
        blob.push(FORMAT_VERSION);
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&sealed);

        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(|source| StorageError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }

        std::fs::write(path, blob).map_err(|source| StorageError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(())
    }

    pub fn load<P: KeyProvider>(path: &Path, keys: &P) -> Result<Self, StorageError> {
        let blob = std::fs::read(path).map_err(|source| match source.kind() {
            std::io::ErrorKind::NotFound => StorageError::IdentityFileNotFound(path.to_path_buf()),
            _ => StorageError::Io {
                path: path.to_path_buf(),
                source,
            },
        })?;

        if blob.len() < MAGIC.len() + 1 + 12 + 16 || blob[..3] != MAGIC {
            return Err(StorageError::IdentityFileCorrupt(path.to_path_buf()));
        }
        let version = blob[3];
        if version != FORMAT_VERSION {
            return Err(StorageError::IdentityVersionUnsupported { found: version });
        }
        let nonce = aead::Nonce(blob[4..16].try_into().expect("length checked above"));
        let ciphertext = &blob[16..];

        let kek = keys
            .get(KEK_ACCOUNT)?
            .ok_or_else(|| StorageError::KeyMaterialMissing {
                account: KEK_ACCOUNT.to_string(),
            })?;

        let mut dek_bytes = [0u8; 32];
        hkdf_blake2s(&kek, DEK_INFO, &mut dek_bytes);
        let dek = aead::AeadKey::from_bytes(dek_bytes);

        let json = aead::open(&dek, &nonce, ciphertext, b"")
            .map_err(|_| StorageError::IdentityDecryptFailed)?;

        let parsed: SerializedIdentity = serde_json::from_slice(&json)
            .map_err(|_| StorageError::IdentityFileCorrupt(path.to_path_buf()))?;
        parsed.into_identity(path)
    }
}

impl std::fmt::Debug for StoredIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StoredIdentity(<redacted>)")
    }
}

/// On-disk JSON shape. Versioned so format evolution is a new variant of
/// the envelope version byte plus migration code, never an ambiguity.
#[derive(Serialize, Deserialize)]
struct SerializedIdentity {
    version: u8,
    ed25519_secret: String,
    x25519_secret: String,
}

impl From<&StoredIdentity> for SerializedIdentity {
    fn from(id: &StoredIdentity) -> Self {
        Self {
            version: 1,
            ed25519_secret: hex_encode(id.ed25519_secret.expose()),
            x25519_secret: hex_encode(id.x25519_secret.expose()),
        }
    }
}

impl SerializedIdentity {
    fn into_identity(self, path: &Path) -> Result<StoredIdentity, StorageError> {
        if self.version != 1 {
            return Err(StorageError::IdentityVersionUnsupported {
                found: self.version,
            });
        }
        let parse32 = |hex: &str| -> Result<[u8; 32], StorageError> {
            hex_decode_array::<32>(hex)
                .ok_or_else(|| StorageError::IdentityFileCorrupt(path.to_path_buf()))
        };
        Ok(StoredIdentity {
            ed25519_secret: Secret::from_bytes(parse32(&self.ed25519_secret)?),
            x25519_secret: Secret::from_bytes(parse32(&self.x25519_secret)?),
        })
    }
}

// Convenience so callers can go from stored bytes to a usable signing
// key without importing crypto modules directly.
impl StoredIdentity {
    pub fn identity_key(&self) -> IdentitySecretKey {
        IdentitySecretKey::from_bytes(*self.ed25519_secret.expose())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::OsEntropy;
    use crate::crypto::test_support::{CounterEntropy, FailingEntropy};
    use crate::test_support::MockKeyProvider;

    fn fresh(dir: &tempfile::TempDir) -> (PathBuf, MockKeyProvider, StoredIdentity) {
        let keys = MockKeyProvider::new();
        let identity = StoredIdentity::generate(&OsEntropy).unwrap();
        let path = dir.path().join("identity.enc");
        (path, keys, identity)
    }

    use std::path::PathBuf;

    #[test]
    fn save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let (path, keys, identity) = fresh(&dir);

        identity.save(&path, &keys, &CounterEntropy).unwrap();
        assert!(path.exists(), "identity.enc must be written");

        let loaded = StoredIdentity::load(&path, &keys).unwrap();
        assert_eq!(
            loaded.ed25519_secret.expose(),
            identity.ed25519_secret.expose()
        );
        assert_eq!(
            loaded.x25519_secret.expose(),
            identity.x25519_secret.expose()
        );
    }

    #[test]
    fn second_save_reuses_stored_kek_so_older_file_still_loads() {
        let dir = tempfile::tempdir().unwrap();
        let (path_a, keys, identity) = fresh(&dir);

        identity.save(&path_a, &keys, &CounterEntropy).unwrap();

        // Save again to a second path: same KEK must be reused, so BOTH
        // files remain loadable. If each save minted a new KEK, rotating
        // the file would silently brick the old one.
        let path_b = dir.path().join("identity-b.enc");
        identity.save(&path_b, &keys, &CounterEntropy).unwrap();

        StoredIdentity::load(&path_a, &keys).unwrap();
        StoredIdentity::load(&path_b, &keys).unwrap();
    }

    #[test]
    fn missing_kek_on_load_is_key_material_missing_not_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let (path, keys, identity) = fresh(&dir);
        identity.save(&path, &keys, &CounterEntropy).unwrap();

        keys.remove(KEK_ACCOUNT);

        match StoredIdentity::load(&path, &keys) {
            Err(StorageError::KeyMaterialMissing { account }) => {
                assert_eq!(account, KEK_ACCOUNT)
            }
            other => panic!("expected KeyMaterialMissing, got {other:?}"),
        }
    }

    #[test]
    fn dead_provider_is_reported_as_unavailable_with_spec_code() {
        // Dead at save time: nothing is written, error carries the spec code.
        let dir = tempfile::tempdir().unwrap();
        let (path, mut keys, identity) = fresh(&dir);
        keys.fail = true;

        match identity.save(&path, &keys, &CounterEntropy) {
            Err(e @ StorageError::KeychainUnavailable(_)) => {
                assert_eq!(e.spec_code(), Some("conveyance/keychain_unavailable"))
            }
            other => panic!("expected KeychainUnavailable on save, got {other:?}"),
        }
        assert!(!path.exists(), "failed save must not leave a partial file");

        // Dead only at load time: file exists, keychain check fails first.
        keys.fail = false;
        identity.save(&path, &keys, &CounterEntropy).unwrap();
        keys.fail = true;

        match StoredIdentity::load(&path, &keys) {
            Err(StorageError::KeychainUnavailable(_)) => {}
            other => panic!("expected KeychainUnavailable on load, got {other:?}"),
        }
    }

    #[test]
    fn corrupted_ciphertext_is_decrypt_failed_not_panic() {
        let dir = tempfile::tempdir().unwrap();
        let (path, keys, identity) = fresh(&dir);
        identity.save(&path, &keys, &CounterEntropy).unwrap();

        let mut blob = std::fs::read(&path).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01; // flip a tag byte
        std::fs::write(&path, blob).unwrap();

        assert!(matches!(
            StoredIdentity::load(&path, &keys),
            Err(StorageError::IdentityDecryptFailed)
        ));
    }

    #[test]
    fn truncated_and_garbled_files_are_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let (path, keys, identity) = fresh(&dir);
        identity.save(&path, &keys, &CounterEntropy).unwrap();

        let full = std::fs::read(&path).unwrap();

        std::fs::write(&path, &full[..10]).unwrap(); // shorter than header
        assert!(matches!(
            StoredIdentity::load(&path, &keys),
            Err(StorageError::IdentityFileCorrupt(_))
        ));

        let mut bad_magic = full.clone();
        bad_magic[0] = b'X';
        std::fs::write(&path, bad_magic).unwrap();
        assert!(matches!(
            StoredIdentity::load(&path, &keys),
            Err(StorageError::IdentityFileCorrupt(_))
        ));

        let mut bad_version = full;
        bad_version[3] = 9;
        std::fs::write(&path, bad_version).unwrap();
        assert!(matches!(
            StoredIdentity::load(&path, &keys),
            Err(StorageError::IdentityVersionUnsupported { found: 9 })
        ));
    }

    #[test]
    fn missing_file_is_distinct_from_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let keys = MockKeyProvider::new();
        match StoredIdentity::load(&dir.path().join("nope.enc"), &keys) {
            Err(StorageError::IdentityFileNotFound(_)) => {}
            other => panic!("expected IdentityFileNotFound, got {other:?}"),
        }
    }

    #[test]
    fn debug_never_leaks_secrets() {
        let identity = StoredIdentity::generate(&OsEntropy).unwrap();
        let rendered = format!("{identity:?}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        let prefix: String = identity
            .ed25519_secret
            .expose()
            .iter()
            .take(4)
            .map(|b| format!("{b:02x}"))
            .collect();
        assert!(!rendered.contains(&prefix), "secret bytes leaked via Debug");
    }

    #[test]
    fn generated_identities_are_usable_signing_keys() {
        let identity = StoredIdentity::generate(&OsEntropy).unwrap();
        let sk = identity.identity_key();
        let sig = sk.sign(b"phase 2");
        sk.public_key().verify(b"phase 2", &sig).unwrap();
    }

    #[test]
    fn entropy_failure_propagates_as_crypto_error() {
        let identity = StoredIdentity::generate(&FailingEntropy);
        assert!(matches!(
            identity,
            Err(StorageError::Crypto(
                crate::crypto::CryptoError::EntropyFailure
            ))
        ));
    }
}
