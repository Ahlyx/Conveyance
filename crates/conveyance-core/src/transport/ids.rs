//! The pinned Conveyance BLE identifiers.
//!
//! Kept OUTSIDE the feature-gated `ble` module on purpose: the pairing
//! ceremony embeds the service UUID into every QR payload whether or not
//! this build can speak Bluetooth.
//!
//! Pinned in CONVEYANCE_SPEC.md ("Wire protocol" / BLE topology) and
//! permanent for v1: changing any of these breaks pairings in the wild.
//! The anti-typo tests assert the spec strings verbatim and that the
//! values are random-V4-shaped.

use uuid::Uuid;

pub const SERVICE_UUID: &str = "709031fe-abea-437f-801e-dc6872723b1f";
pub const PC_TO_PHONE_TX_UUID: &str = "56d373b8-1dcf-4107-894b-b4888ff0db3f";
pub const PHONE_TO_PC_TX_UUID: &str = "b4b10ea8-450c-47bd-93d9-065bb67e1bc9";

pub fn service_uuid() -> Uuid {
    Uuid::parse_str(SERVICE_UUID).expect("pinned constant must parse")
}

/// Raw 16-byte form, exactly what the QR payload's `ble_service_uuid`
/// field carries (a UUID *is* 16 bytes).
pub fn service_uuid_bytes() -> [u8; 16] {
    *service_uuid().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_uuids_match_the_spec_strings() {
        assert_eq!(SERVICE_UUID, "709031fe-abea-437f-801e-dc6872723b1f");
        assert_eq!(PC_TO_PHONE_TX_UUID, "56d373b8-1dcf-4107-894b-b4888ff0db3f");
        assert_eq!(PHONE_TO_PC_TX_UUID, "b4b10ea8-450c-47bd-93d9-065bb67e1bc9");

        for s in [SERVICE_UUID, PC_TO_PHONE_TX_UUID, PHONE_TO_PC_TX_UUID] {
            Uuid::parse_str(s).expect("pinned UUIDs must parse");
        }

        // Distinctness: three different objects, not copy-paste slips.
        assert_ne!(SERVICE_UUID, PC_TO_PHONE_TX_UUID);
        assert_ne!(SERVICE_UUID, PHONE_TO_PC_TX_UUID);
        assert_ne!(PC_TO_PHONE_TX_UUID, PHONE_TO_PC_TX_UUID);
    }

    #[test]
    fn version_nibbles_are_v4_shaped() {
        for s in [SERVICE_UUID, PC_TO_PHONE_TX_UUID, PHONE_TO_PC_TX_UUID] {
            let u = Uuid::parse_str(s).unwrap();
            let bytes = u.as_bytes();
            assert_eq!(bytes[6] >> 4, 0b0100, "{s} version nibble must be 4");
            assert_eq!(bytes[8] >> 6, 0b10, "{s} variant must be RFC 4122");
        }
    }
}
