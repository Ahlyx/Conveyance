//! UniFFI bridge over `conveyance-crypto` for the Android phone side.
//!
//! **Phase 10.1 viability spike.** The point of this crate right now is
//! not its API surface — it is to prove the toolchain end to end:
//! `conveyance-crypto` cross-compiles to Android, UniFFI generates Kotlin
//! bindings from the compiled `.so`, and a value round-trips through
//! those bindings byte-identically to the Rust reference on a real
//! emulator. Exactly one primitive is bridged, `hkdf_blake2s`; the full
//! crypto surface follows only if the spike succeeds.
//!
//! Design notes that will still hold when this grows:
//!
//! * The bridge is *thin*. It converts owned FFI types to slices, calls
//!   straight into `conveyance-crypto`, and converts back. No crypto
//!   logic lives here — a second implementation is the thing the whole
//!   UniFFI decision exists to avoid.
//! * Every fallible-at-the-boundary case is a typed `Result`, never a
//!   panic. A panic unwinding into the generated C ABI is an abort on
//!   the phone; `conveyance_crypto::hkdf_blake2s` panics on an
//!   over-long output request, so that case is checked here first.

uniffi::setup_scaffolding!();

/// RFC 5869 caps HKDF-Expand output at 255 * HashLen; BLAKE2s HashLen is
/// 32. `conveyance_crypto::hkdf_blake2s` panics past this, so the bridge
/// rejects it as a typed error instead.
const HKDF_MAX_OUTPUT: usize = 255 * 32;

/// Failures the HKDF bridge can report to Kotlin. Coarse on purpose:
/// these are caller misuse (a bad length), not cryptographic outcomes.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CryptoFfiError {
    #[error("requested HKDF output length is zero")]
    ZeroLength,
    #[error("requested HKDF output length exceeds the RFC 5869 maximum of 255*HashLen bytes")]
    OutputTooLong,
}

/// HKDF-BLAKE2s (RFC 5869) with the salt omitted — i.e. 32 zero bytes
/// per RFC 5869 §2.2, matching `CONVEYANCE_SPEC.md`. Delegates verbatim
/// to [`conveyance_crypto::hkdf_blake2s`]; the output is byte-identical
/// to the PC side for the same inputs.
#[uniffi::export]
pub fn hkdf_blake2s(ikm: Vec<u8>, info: Vec<u8>, length: u32) -> Result<Vec<u8>, CryptoFfiError> {
    let len = length as usize;
    if len == 0 {
        return Err(CryptoFfiError::ZeroLength);
    }
    if len > HKDF_MAX_OUTPUT {
        return Err(CryptoFfiError::OutputTooLong);
    }

    let mut okm = vec![0u8; len];
    conveyance_crypto::hkdf_blake2s(&ikm, &info, &mut okm);
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-answer vector for the spike, shared verbatim with the
    /// Kotlin instrumented test (`HkdfBlake2sSpikeTest`). BLAKE2s has no
    /// official HKDF vectors (see `conveyance-crypto`'s hkdf module
    /// docs), so this value is anchored to the Rust implementation: if
    /// the Kotlin binding reproduces it, the FFI path is faithful.
    const SPIKE_IKM: &[u8] = b"conveyance hkdf-blake2s spike";
    const SPIKE_INFO: &[u8] = b"spike-vector-v1";
    const SPIKE_OKM_32_HEX: &str =
        "3b0d11d95126c099d16717960a07423b60ac5705b7d0615aa9d7ab7065badcca";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn hkdf_blake2s_matches_known_answer() {
        let okm = hkdf_blake2s(SPIKE_IKM.to_vec(), SPIKE_INFO.to_vec(), 32).unwrap();
        assert_eq!(hex(&okm), SPIKE_OKM_32_HEX);
    }

    #[test]
    fn rejects_zero_and_overlong_lengths() {
        assert!(matches!(
            hkdf_blake2s(vec![1], vec![], 0),
            Err(CryptoFfiError::ZeroLength)
        ));
        assert!(matches!(
            hkdf_blake2s(vec![1], vec![], (HKDF_MAX_OUTPUT + 1) as u32),
            Err(CryptoFfiError::OutputTooLong)
        ));
    }

    #[test]
    fn output_is_length_prefix_stable() {
        let short = hkdf_blake2s(SPIKE_IKM.to_vec(), SPIKE_INFO.to_vec(), 32).unwrap();
        let long = hkdf_blake2s(SPIKE_IKM.to_vec(), SPIKE_INFO.to_vec(), 40).unwrap();
        assert_eq!(short.as_slice(), &long[..32]);
    }
}
