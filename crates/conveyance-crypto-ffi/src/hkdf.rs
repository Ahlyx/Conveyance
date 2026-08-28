//! HKDF-BLAKE2s bridge — the original spike primitive, unchanged in
//! signature and error contract so the existing Kotlin instrumented test
//! keeps compiling.

use crate::CryptoFfiError;

/// RFC 5869 caps HKDF-Expand output at 255 * HashLen; BLAKE2s HashLen is
/// 32. `conveyance_crypto::hkdf_blake2s` panics past this, so the bridge
/// rejects it as a typed error instead.
const HKDF_MAX_OUTPUT: usize = 255 * 32;

/// HKDF-BLAKE2s (RFC 5869) with the salt omitted — i.e. 32 zero bytes per
/// RFC 5869 §2.2, matching `CONVEYANCE_SPEC.md`. Delegates verbatim to
/// [`conveyance_crypto::hkdf_blake2s`]; output is byte-identical to the PC
/// side for the same inputs.
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

    // The anchor also pinned by
    // `conveyance_crypto::hkdf::tests::blake2s_known_answer` and by the
    // Kotlin instrumented test. BLAKE2s has no official HKDF vectors, so
    // the value is fixed to the Rust implementation: reproducing it byte
    // for byte is what "faithful bridge" means.
    const SPIKE_IKM: &[u8] = &[0x5a; 64];
    const SPIKE_INFO: &[u8] = b"conveyance-v1-identity-ed25519";
    const SPIKE_OKM_32_HEX: &str =
        "076cd99ded0d8b7bd6a6d87fd944e1ac7f52f81fa20489b68bc70ed07febfe3a";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn matches_known_answer() {
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
