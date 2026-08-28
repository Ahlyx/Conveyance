//! Cryptographic primitives for Conveyance, isolated behind small typed
//! wrappers.
//!
//! This crate was extracted from `conveyance-core` for phase 10.1: it is
//! the pure, I/O-free subset (no rusqlite, keyring, tokio, or BLE) so it
//! can cross-compile to Android and be shared with the phone side via
//! UniFFI. `conveyance-core` re-exports it as `conveyance_core::crypto`,
//! so every pre-phase-10 call site is unchanged.
//!
//! Design rules for this crate, in priority order:
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
pub mod fixtures;
pub mod hashchain;
pub(crate) mod hkdf;
pub mod kdf;
pub mod recovery;
pub mod sealed;
pub mod sign;
pub mod signing;

/// HKDF-BLAKE2s (RFC 5869), the one entry point the rest of the workspace
/// needs — `conveyance-core`'s storage layer derives its DEK with it. The
/// `hkdf` module stays crate-private so the hand-rolled HMAC internals are
/// not part of the public surface; only this function is.
pub use hkdf::hkdf_blake2s;

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

/// Lowercase hex. Used for embedding binary identifiers (`req_id`,
/// signatures, hashes) into canonical JSON, which has no byte-array
/// type. Public since phase 9: the daemon's log enrichment embeds
/// response signatures in payloads using the same encoding as the
/// hash chain -- one hex convention everywhere.
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

/// Inverse of [`hex_encode`]. Rejects odd length and any character
/// outside `[0-9a-f]` -- uppercase included, unlike `u8::from_str_radix`.
/// Conveyance's hashed and signed content is lowercase-hex by spec, so
/// tolerating mixed case here would let two renders of one value compare
/// unequal downstream (in the log diff especially).
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    // `as_chunks` (not `chunks_exact`) so the [u8; 2] shape is known to
    // the compiler and the trailing remainder -- empty, given the length
    // check above -- is explicit.
    let (pairs, rest) = s.as_bytes().as_chunks::<2>();
    debug_assert!(rest.is_empty());
    let mut out = Vec::with_capacity(pairs.len());
    for &[hi, lo] in pairs {
        out.push((from_lower_hex_digit(hi)? << 4) | from_lower_hex_digit(lo)?);
    }
    Some(out)
}

/// Fixed-width [`hex_decode`]: additionally rejects any string whose
/// length is not exactly `2 * N`.
pub fn hex_decode_array<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    hex_decode(s)?.try_into().ok()
}

fn from_lower_hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// A fixed-size secret byte array that zeroizes on drop and refuses to
/// print itself. All raw key storage inside this module goes through
/// this (or a crate type that already zeroizes) so a dropped key does
/// not linger in freed memory waiting for a heap-scanning attacker.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Secret<const N: usize>(pub(crate) Zeroizing<[u8; N]>);

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
/// determinism checks draw from the same seams. Gated behind the
/// `test-support` feature (not just `#[cfg(test)]`) because
/// `conveyance-core`'s pairing/session/wire/storage tests consume these
/// across the crate boundary.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use super::*;

    /// Deterministic source for tests that need reproducible key
    /// material; cycles a counter so successive fills differ.
    pub struct CounterEntropy;

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
    pub struct FailingEntropy;

    impl EntropySource for FailingEntropy {
        fn fill(&self, _dest: &mut [u8]) -> Result<(), CryptoError> {
            Err(CryptoError::EntropyFailure)
        }
    }

    /// Fills every request with the same bytes, cycled to the
    /// destination length. For tests that must pin the exact value a
    /// generator returns (e.g. forcing a known pairing nonce).
    pub struct FixedEntropy(pub Vec<u8>);

    impl EntropySource for FixedEntropy {
        fn fill(&self, dest: &mut [u8]) -> Result<(), CryptoError> {
            assert!(!self.0.is_empty(), "FixedEntropy needs at least one byte");
            for (i, b) in dest.iter_mut().enumerate() {
                *b = self.0[i % self.0.len()];
            }
            Ok(())
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
    fn hex_decode_round_trips_and_rejects_malformed() {
        for bytes in [
            &b""[..],
            &[0x00][..],
            &[0x0f, 0xa0, 0xff][..],
            &[0x5a; 64][..],
        ] {
            assert_eq!(hex_decode(&hex_encode(bytes)).as_deref(), Some(bytes));
        }
        // Odd length, non-hex characters, and uppercase are all refused.
        assert_eq!(hex_decode("abc"), None);
        assert_eq!(hex_decode("zz"), None);
        assert_eq!(hex_decode("00FF"), None);
        assert_eq!(hex_decode("00 ff"), None);
    }

    #[test]
    fn hex_decode_array_enforces_exact_width() {
        assert_eq!(hex_decode_array::<2>("00ff"), Some([0x00, 0xff]));
        assert_eq!(hex_decode_array::<2>("00"), None);
        assert_eq!(hex_decode_array::<2>("00ff00"), None);
        assert_eq!(
            hex_decode_array::<32>(&hex_encode(&[7u8; 32])),
            Some([7u8; 32])
        );
    }

    #[test]
    fn secret_debug_never_shows_bytes() {
        let s = Secret::from_bytes([0xab; 32]);
        let rendered = format!("{s:?}");
        assert!(!rendered.contains("ab"), "{rendered} leaked key material");
        assert!(rendered.contains("<redacted>"));
    }
}
