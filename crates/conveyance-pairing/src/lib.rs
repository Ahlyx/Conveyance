//! Pure pairing protocol shared by the PC implementation and Android's FFI.
//!
//! QR parsing, CBOR wire messages, and the signature preimage live here so
//! both ends use the same protocol implementation. This crate has no BLE,
//! database, or platform dependencies and can be built for Android.

mod messages;
mod qr;

pub use messages::{
    PAIR_CONTEXT, PairingAck, PairingConfirm, decode_ack_message, decode_confirm_message,
    encode_ack_message, encode_confirm_message, pairing_payload,
};
pub use qr::{
    PC_NAME_MAX_BYTES, PROTOCOL_VERSION, PairingError, PairingQr, QR_TTL, SERVICE_UUID_BYTES,
};
