//! The pinned Conveyance BLE identifiers.
//!
//! Kept OUTSIDE the feature-gated `ble` module on purpose: the pairing
//! ceremony embeds the service UUID into every QR payload whether or not
//! this build can speak Bluetooth. Also kept free of the `uuid` crate so
//! gateless builds don't pull it just for constants -- the raw bytes are
//! what both the QR payload and GATT APIs ultimately need.
//!
//! Pinned in CONVEYANCE_SPEC.md ("Wire protocol" / BLE topology) and
//! permanent for v1: changing any of these breaks pairings in the wild.
//! The anti-typo tests assert the spec strings verbatim and that the
//! values are random-V4-shaped.

pub const SERVICE_UUID: &str = "709031fe-abea-437f-801e-dc6872723b1f";
pub const PC_TO_PHONE_TX_UUID: &str = "56d373b8-1dcf-4107-894b-b4888ff0db3f";
pub const PHONE_TO_PC_TX_UUID: &str = "b4b10ea8-450c-47bd-93d9-065bb67e1bc9";

/// Raw 16-byte form of [`SERVICE_UUID`] -- exactly what the QR payload's
/// `ble_service_uuid` field carries (a UUID *is* 16 bytes).
pub const SERVICE_UUID_BYTES: [u8; 16] = [
    0x70, 0x90, 0x31, 0xfe, 0xab, 0xea, 0x43, 0x7f, 0x80, 0x1e, 0xdc, 0x68, 0x72, 0x72, 0x3b, 0x1f,
];

/// Convenience accessor matching the constant above.
pub fn service_uuid_bytes() -> [u8; 16] {
    SERVICE_UUID_BYTES
}
#[cfg(test)]
mod tests {
    use super::*;

    fn parse_hex_uuid(s: &str) -> Option<[u8; 16]> {
        if s.len() != 36 {
            return None;
        }
        let hex: Vec<u8> = s
            .chars()
            .filter(|c| *c != '-')
            .map(|c| c.to_digit(16).map(|d| d as u8))
            .collect::<Option<Vec<_>>>()?;
        if hex.len() != 32 {
            return None;
        }
        Some({
            let mut out = [0u8; 16];
            for (i, chunk) in hex.chunks(2).enumerate() {
                out[i] = (chunk[0] << 4) | chunk[1];
            }
            out
        })
    }

    #[test]
    fn pinned_uuids_match_the_spec_strings() {
        assert_eq!(SERVICE_UUID, "709031fe-abea-437f-801e-dc6872723b1f");
        assert_eq!(PC_TO_PHONE_TX_UUID, "56d373b8-1dcf-4107-894b-b4888ff0db3f");
        assert_eq!(PHONE_TO_PC_TX_UUID, "b4b10ea8-450c-47bd-93d9-065bb67e1bc9");

        for s in [SERVICE_UUID, PC_TO_PHONE_TX_UUID, PHONE_TO_PC_TX_UUID] {
            assert!(parse_hex_uuid(s).is_some(), "{s} must parse");
        }

        // Distinctness: three different objects, not copy-paste slips.
        assert_ne!(SERVICE_UUID, PC_TO_PHONE_TX_UUID);
        assert_ne!(SERVICE_UUID, PHONE_TO_PC_TX_UUID);
        assert_ne!(PC_TO_PHONE_TX_UUID, PHONE_TO_PC_TX_UUID);
    }

    #[test]
    fn version_nibbles_are_v4_shaped() {
        // Random V4 UUIDs carry version 4 in the high nibble of byte 6
        // and the RFC 4122 variant in the top bits of byte 8. Guards
        // against someone replacing these with derived/zeroed values.
        for s in [SERVICE_UUID, PC_TO_PHONE_TX_UUID, PHONE_TO_PC_TX_UUID] {
            let b = parse_hex_uuid(s).unwrap();
            assert_eq!(b[6] >> 4, 0b0100, "{s} version nibble must be 4");
            assert_eq!(b[8] >> 6, 0b10, "{s} variant must be RFC 4122");
        }
    }

    #[test]
    fn service_bytes_constant_matches_its_string() {
        let parsed = parse_hex_uuid(SERVICE_UUID).unwrap();
        assert_eq!(SERVICE_UUID_BYTES, parsed);
    }
}
