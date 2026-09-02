//! UniFFI bridge over `conveyance-crypto` for the Android phone side.
//!
//! **The Android Rust bridge.** Phase 10.1's spike (one function,
//! `hkdf_blake2s`) proved the toolchain end to end: `conveyance-crypto`
//! cross-compiles to Android, UniFFI generates Kotlin bindings, and a
//! value round-trips through them byte-identically to the Rust reference
//! on a real emulator. This crate now bridges every primitive the app
//! needs — recovery-phrase derivation, Ed25519, canonical JSON, the
//! signing-payload construction, Argon2id, ChaCha20-Poly1305, HKDF-BLAKE2s,
//! the SHA-256 hash chain — plus (phase 10.4) the `Noise_KK` session
//! over `conveyance-noise` ([`noise`]). Same `.so`, same binding module.
//!
//! Design rules, unchanged from the spike and load-bearing as this grows:
//!
//! * **The bridge is thin.** Each exported function converts owned FFI
//!   types to slices/arrays, calls straight into `conveyance-crypto`, and
//!   converts back. No cryptographic logic lives here — a second
//!   implementation is the exact thing the UniFFI decision exists to
//!   avoid. Every function is a pure function of its inputs, which is what
//!   lets the JSON fixture cross-check (emitted by `conveyance-crypto`,
//!   asserted from Kotlin) be a straight table comparison.
//!
//! * **Stateless.** Key material crosses the boundary as `Vec<u8>`; this
//!   crate holds no state and owns no handles. That means secret bytes
//!   (Ed25519 scalar, Argon2id DEK, derived identity keys) enter the JVM
//!   heap as `ByteArray`, where they are GC-managed and not zeroized — a
//!   real limitation for Phase 10.1, documented on the Kotlin adapter and
//!   in the phase report. The Kotlin API is an interface so Phase 10.2 can
//!   move secret handling to Rust-owned, Keystore-backed handles without
//!   touching call sites.
//!
//! * **No panic crosses the ABI.** A panic unwinding into the generated C
//!   ABI aborts the process on the phone. Every fallible-at-the-boundary
//!   case — wrong byte-string length, an over-long HKDF request that
//!   `conveyance_crypto::hkdf_blake2s` would panic on, a non-canonical
//!   value — is a typed [`CryptoFfiError`] instead.

uniffi::setup_scaffolding!();

pub mod aead;
pub mod canonical;
pub mod hashchain;
pub mod hkdf;
pub mod kdf;
pub mod noise;
pub mod recovery;
pub mod sealed;
pub mod sign;
pub mod signing;

/// Failures any bridged primitive can report to Kotlin.
///
/// Deliberately coarse, and for the same reason `conveyance_crypto`'s own
/// `CryptoError` is coarse: a security product must not hand callers an
/// oracle for *which* internal check failed. `SignatureInvalid` and
/// `DecryptionFailed` do not say whether the key, the nonce, or a single
/// byte was wrong. The length/JSON variants are caller misuse, not
/// cryptographic outcomes, and are safe to name precisely.
///
/// `ZeroLength` and `OutputTooLong` predate this expansion (the spike's
/// HKDF guard) and keep their names and meaning so the existing Kotlin
/// spike test is unaffected.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CryptoFfiError {
    #[error("requested HKDF output length is zero")]
    ZeroLength,
    #[error("requested HKDF output length exceeds the RFC 5869 maximum of 255*HashLen bytes")]
    OutputTooLong,
    #[error("a byte string argument has the wrong length for its field")]
    BadLength,
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
    #[error("input is not valid JSON")]
    InvalidJson,
    #[error("value outside the canonical-JSON domain")]
    OutsideCanonicalDomain,
}

/// Map `conveyance-crypto`'s error onto the FFI error. One-to-one; every
/// arm is spelled out so a new `CryptoError` variant fails to compile here
/// rather than silently collapsing to a wrong code.
pub(crate) fn map_core_err(e: conveyance_crypto::CryptoError) -> CryptoFfiError {
    use conveyance_crypto::CryptoError as E;
    match e {
        E::SignatureInvalid => CryptoFfiError::SignatureInvalid,
        E::DecryptionFailed => CryptoFfiError::DecryptionFailed,
        E::EntropyFailure => CryptoFfiError::EntropyFailure,
        E::BadRecoveryPhrase => CryptoFfiError::BadRecoveryPhrase,
        E::BadKeyBytes => CryptoFfiError::BadKeyBytes,
        E::KdfFailure => CryptoFfiError::KdfFailure,
        E::OutsideCanonicalDomain => CryptoFfiError::OutsideCanonicalDomain,
    }
}

/// Convert an owned `Vec<u8>` to a fixed-size array, or [`CryptoFfiError::BadLength`].
pub(crate) fn fixed<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], CryptoFfiError> {
    bytes.try_into().map_err(|_| CryptoFfiError::BadLength)
}
