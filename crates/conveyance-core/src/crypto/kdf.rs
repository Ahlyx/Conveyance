//! Argon2id passphrase KDF (`argon2`), the spec's Tier-1 session-unlock
//! derivation.
//!
//! Parameters are fixed by CONVEYANCE_SPEC.md: m=65536 KiB (64 MiB),
//! t=3, p=1, output 32 bytes, 16-byte caller-supplied salt. The output
//! length is not negotiable from this side: it feeds a ChaCha20-Poly1305
//! key directly.
//!
//! The generic `derive_dek_with_params` exists for one reason: the spec
//! says to *tune upward* if target hardware is faster than 500 ms. When
//! that day comes, tuning happens through an explicit parameter struct
//! and a benchmark (`cargo run --example kdf_timing`), never by editing
//! constants inside a call chain.
//!
//! No official KAT exists for these exact parameters (the argon2 crate
//! ships reference vectors for other parameter sets; the RFC 9106
//! vectors use different memory sizes). What is tested instead:
//! determinism, sensitivity to every input, and rejection of invalid
//! parameter combinations. The primitive itself is the maintained RustCrypto
//! implementation -- the risk being managed here is wiring, not math.

use argon2::{Algorithm, Argon2, Params, Version};

use super::CryptoError;

/// Spec parameters. Public so callers can display/verify what was used.
pub const KDF_M_KIB: u32 = 65536;
pub const KDF_T_COST: u32 = 3;
pub const KDF_P_COST: u32 = 1;
/// Feeds ChaCha20-Poly1305 directly; see spec amendment.
pub const KDF_OUTPUT_LEN: usize = 32;
pub const KDF_SALT_LEN: usize = 16;

/// Explicit, validated KDF parameters. Constructed via `TryFrom`-style
/// validation so an impossible combination is a typed error at the
/// boundary rather than a panic three layers down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    /// The spec's fixed parameters.
    pub fn spec() -> Self {
        Self {
            m_kib: KDF_M_KIB,
            t_cost: KDF_T_COST,
            p_cost: KDF_P_COST,
        }
    }

    fn validate(&self) -> Result<Params, CryptoError> {
        Params::new(self.m_kib, self.t_cost, self.p_cost, Some(KDF_OUTPUT_LEN))
            .map_err(|_| CryptoError::KdfFailure)
    }
}

/// Derive a DEK from a passphrase using the spec's fixed parameters.
pub fn derive_dek(
    passphrase: &[u8],
    salt: &[u8; KDF_SALT_LEN],
) -> Result<[u8; KDF_OUTPUT_LEN], CryptoError> {
    derive_dek_with_params(passphrase, salt, KdfParams::spec())
}

/// Derive with explicit parameters. `KdfFailure` covers both "parameters
/// are impossible" (e.g. p=0) and "the library rejected the derivation";
/// distinguishing them would tell an attacker nothing useful anyway --
/// both are caller bugs, never data-dependent states.
pub fn derive_dek_with_params(
    passphrase: &[u8],
    salt: &[u8; KDF_SALT_LEN],
    params: KdfParams,
) -> Result<[u8; KDF_OUTPUT_LEN], CryptoError> {
    let validated = params.validate()?;
    let ctx = Argon2::new(Algorithm::Argon2id, Version::V0x13, validated);

    let mut out = [0u8; KDF_OUTPUT_LEN];
    // After successful param validation, hash_password_into cannot fail:
    // its error cases are exactly the malformed-parameter and oversize-
    // output conditions we have already excluded by construction.
    ctx.hash_password_into(passphrase, salt, &mut out)
        .expect("validated params + fixed sizes make this infallible");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn salt() -> [u8; 16] {
        [0x5au8; 16]
    }

    #[test]
    fn deterministic_and_correct_length() {
        let a = derive_dek(b"correct horse battery staple", &salt()).unwrap();
        let b = derive_dek(b"correct horse battery staple", &salt()).unwrap();
        assert_eq!(a.len(), 32);
        assert_eq!(a, b);
    }

    #[test]
    fn sensitive_to_every_input() {
        let base = derive_dek(b"passphrase", &salt()).unwrap();

        assert_ne!(base, derive_dek(b"passphrasE", &salt()).unwrap());
        let mut other_salt = salt();
        other_salt[0] ^= 1;
        assert_ne!(base, derive_dek(b"passphrase", &other_salt).unwrap());
    }

    #[test]
    fn empty_passphrase_is_allowed_not_an_error() {
        // Deliberate: emptiness is a policy question for the caller
        // (first-run UX enforces minimums), not the KDF's business.
        let _ = derive_dek(b"", &salt()).unwrap();
    }

    #[test]
    fn invalid_params_are_typed_errors() {
        let bad_p = KdfParams {
            m_kib: 65536,
            t_cost: 3,
            p_cost: 0,
        };
        assert!(matches!(
            derive_dek_with_params(b"x", &salt(), bad_p),
            Err(CryptoError::KdfFailure)
        ));

        let bad_m = KdfParams {
            m_kib: 0,
            t_cost: 3,
            p_cost: 1,
        };
        assert!(matches!(
            derive_dek_with_params(b"x", &salt(), bad_m),
            Err(CryptoError::KdfFailure)
        ));
    }
}
