//! Pairing signatures and message records are shared with Android's FFI.
pub use conveyance_pairing::{
    PAIR_CONTEXT, PairingAck, PairingConfirm, decode_ack_message, decode_confirm_message,
    encode_ack_message, encode_confirm_message, pairing_payload,
};
