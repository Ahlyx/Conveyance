//! Argon2id passphrase → 32-byte DEK, the spec's Tier-1 session-unlock
//! derivation.
//!
//! Parameters are fixed by `conveyance_crypto::kdf` (m=64 MiB, t=3, p=1,
//! 16-byte salt, 32-byte output) and not exposed here — the phone does not
//! get to pick them. The 64 MiB cost is real on an emulator; the fixture
//! suite keeps its Argon2id vector count to a minimum for that reason, and
//! the Kotlin side logs derivation time (spec: tune upward only if a full
//! derivation runs under 500 ms on target hardware, which an emulator is
//! not).

use crate::{CryptoFfiError, fixed, map_core_err};

/// Derive a 32-byte DEK from `passphrase` and a 16-byte `salt` using the
/// spec's fixed Argon2id parameters.
#[uniffi::export]
pub fn argon2id_derive_dek(passphrase: Vec<u8>, salt: Vec<u8>) -> Result<Vec<u8>, CryptoFfiError> {
    let salt: [u8; conveyance_crypto::kdf::KDF_SALT_LEN] = fixed(salt)?;
    conveyance_crypto::kdf::derive_dek(&passphrase, &salt)
        .map(|dek| dek.to_vec())
        .map_err(map_core_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // No third-party KAT exists for these exact parameters (see
    // `conveyance_crypto::kdf` docs). Frozen against the implementation;
    // the same value is emitted as a fixture and asserted from Kotlin.
    const PASSPHRASE: &[u8] = b"correct horse battery staple";
    const SALT: [u8; 16] = [0x5a; 16];
    const DEK_HEX: &str = "b5d354876f658cde1a5d125c43b4a60465890d322a2394066a3428b0d1fa231a";

    #[test]
    fn derives_frozen_dek() {
        let dek = argon2id_derive_dek(PASSPHRASE.to_vec(), SALT.to_vec()).unwrap();
        assert_eq!(dek.len(), 32);
        assert_eq!(hex(&dek), DEK_HEX, "Argon2id DEK drift");
    }

    #[test]
    fn wrong_salt_length_is_typed_error() {
        assert!(matches!(
            argon2id_derive_dek(PASSPHRASE.to_vec(), vec![0u8; 15]),
            Err(CryptoFfiError::BadLength)
        ));
    }
}
