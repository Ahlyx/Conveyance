//! Cryptographic primitives for Conveyance, isolated behind small typed
//! wrappers.
//!
//! Design rules for this module, in priority order:
//!
//! 1. **Fixed primitives.** Everything here implements a choice already
//!    recorded in CONVEYANCE_SPEC.md ("Cryptographic primitives"). The
//!    interesting decisions were made at spec time; this code's job is to
//!    be boring, correct, and hard to misuse.
//! 2. **Test vectors before wrappers.** Every primitive that has official
//!    published vectors is tested against them (RFC 8032, RFC 7748,
//!    RFC 8439, RFC 8785, BIP-39/TREZOR). Where no official vectors exist
//!    -- HKDF-BLAKE2s specifically -- the test recomputes the result
//!    through an independent construction of the same primitive and says
//!    so in comments. Absence of third-party vectors is a fact worth
//!    recording, not hiding.
//! 3. **Secret material is never accidentally visible.** Types holding
//!    key bytes implement `Debug` manually and print `<redacted>` --
//!    deriving `Debug` on a key type survives code review looking
//!    innocent and then leaks into logs on the first `{:?}` mistake.
//! 4. **Panics versus Results.** Fallibility is exposed exactly where a
//!    caller can meaningfully react: OS entropy failure, decryption
//!    failure, bad mnemonic checksum, non-canonicalizable input, invalid
//!    curve points. Internally, operations whose failure is provably
//!    impossible *after* validation use `expect` with a comment naming
//!    the invariant -- a phantom `Err` arm nobody can trigger is dead
//!    code pretending to be robustness, and it would also make the 100%
//!    branch coverage requirement meaningless.
//!
//! Entropy: callers who need fresh key material go through
//! [`EntropySource`]. Production code uses [`OsEntropy`]; tests inject
//! deterministic or failing sources. There is deliberately no hidden
//! global RNG.

pub mod aead;
pub mod canonical_json;
pub mod dh;
pub mod hashchain;
pub(crate) mod hkdf;
pub mod kdf;
pub mod recovery;
pub mod sign;

use thiserror::Error;
use zeroize::Zeroizing;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Errors from the cryptographic layer. Variants are deliberately coarse:
/// like the spec's error model, they must not leak *which* internal check
/// failed -- a decryption error does not say whether the key was wrong or
/// the ciphertext was corrupted, because that distinction helps attackers
/// and nobody else.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("signature verification failed")]
    SignatureInvalid,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("entropy source failed")]
    EntropyFailure,
    #[error("invalid recovery phrase")]
    BadRecoveryPhrase,
    #[error("invalid key encoding")]
    BadKeyBytes,
    #[error("key derivation failed")]
    KdfFailure,
    #[error("value outside the canonical-JSON domain")]
    OutsideCanonicalDomain,
}

/// Where random bytes come from. A trait rather than a bare function so
/// that every generator's failure path is testable: production passes
/// [`OsEntropy`], tests pass sources that return short reads or errors.
///
/// This is intentionally NOT an async or object-safe abstraction -- there
/// is exactly one production implementation and it is five lines.
pub trait EntropySource {
    fn fill(&self, dest: &mut [u8]) -> Result<(), CryptoError>;
}

/// The OS CSPRNG (`getrandom`). The only entropy source production code
/// should ever construct.
pub struct OsEntropy;

impl EntropySource for OsEntropy {
    fn fill(&self, dest: &mut [u8]) -> Result<(), CryptoError> {
        getrandom::fill(dest).map_err(|_| CryptoError::EntropyFailure)
    }
}

/// Lowercase hex. Used for embedding binary identifiers (`req_id`) into
/// canonical JSON, which has no byte-array type. Matches auditmcp's
/// convention so log tooling reads the same.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

/// A fixed-size secret byte array that zeroizes on drop and refuses to
/// print itself. All raw key storage inside this module goes through
/// this (or a crate type that already zeroizes) so a dropped key does
/// not linger in freed memory waiting for a heap-scanning attacker.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Secret<const N: usize>(pub(super) Zeroizing<[u8; N]>);

impl<const N: usize> Secret<N> {
    pub fn from_bytes(bytes: [u8; N]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn expose(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> std::fmt::Debug for Secret<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret<{N}>(<redacted>)")
    }
}

/// Shared test-only entropy sources, so every module's failure paths and
/// determinism checks draw from the same seams.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// Deterministic source for tests that need reproducible key
    /// material; cycles a counter so successive fills differ.
    pub(crate) struct CounterEntropy;

    impl EntropySource for CounterEntropy {
        fn fill(&self, dest: &mut [u8]) -> Result<(), CryptoError> {
            static CALL: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
            let call = CALL.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            for (i, b) in dest.iter_mut().enumerate() {
                *b = ((i + call as usize) % 251) as u8;
            }
            Ok(())
        }
    }

    /// Always fails; exists so every `EntropyFailure` branch in the
    /// module has a reachable test.
    pub(crate) struct FailingEntropy;

    impl EntropySource for FailingEntropy {
        fn fill(&self, _dest: &mut [u8]) -> Result<(), CryptoError> {
            Err(CryptoError::EntropyFailure)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_support::{CounterEntropy, FailingEntropy};

    #[test]
    fn os_entropy_produces_distinct_buffers() {
        let src = OsEntropy;
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        src.fill(&mut a).expect("OS entropy must work in tests");
        src.fill(&mut b).expect("OS entropy must work in tests");
        assert_ne!(a, b, "two 256-bit draws colliding means the RNG is broken");
    }

    #[test]
    fn counter_entropy_advances_between_calls() {
        let mut a = [0u8; 8];
        let mut b = [0u8; 8];
        CounterEntropy.fill(&mut a).unwrap();
        CounterEntropy.fill(&mut b).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn failing_entropy_fails() {
        assert!(matches!(
            FailingEntropy.fill(&mut [0u8; 4]),
            Err(CryptoError::EntropyFailure)
        ));
    }

    #[test]
    fn hex_encode_is_lowercase_and_padded() {
        assert_eq!(hex_encode(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn secret_debug_never_shows_bytes() {
        let s = Secret::from_bytes([0xab; 32]);
        let rendered = format!("{s:?}");
        assert!(!rendered.contains("ab"), "{rendered} leaked key material");
        assert!(rendered.contains("<redacted>"));
    }
}
