//! The application wire protocol: CBOR message types, framing, and the
//! approval-execute binding.
//!
//! Everything here is pure -- no I/O, no session state. The session layer
//! (phase 3) moves these bytes; BLE (phase 5) carries frames; the daemon
//! (phase 7) composes them. Keeping this module pure is what lets its
//! parser be fuzzed without a runtime.
//!
//! Layout:
//!
//! * [`message`] — `ReqId` and all ten message types from the spec's
//!   "Wire protocol" section, plus signature payload construction.
//! * [`framing`] — 6-byte length-prefixed frames with START/END/ACK
//!   flags and a 128 KiB reassembly cap.
//! * [`binding`] — consume-on-use tracking of approved req_ids.

pub mod binding;
pub mod framing;
pub mod message;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("CBOR encoding/decoding failed: {0}")]
    Cbor(String),

    /// A `params` or `body` value sits outside the canonical-JSON domain
    /// (floats, raw bytes). Deliberately distinct from generic decode
    /// errors: when phase 8's shim surfaces this to an LLM client, "your
    /// params contain a float; retry with an integer or string" is a
    /// recoverable instruction, and it deserves its own variant.
    #[error("value in '{field}' is outside the canonical-JSON domain (no floats or binary values)")]
    UnsupportedValueType { field: &'static str },

    // ---- framing ----------------------------------------------------
    #[error("frame shorter than the 6-byte header")]
    FrameTruncated,
    #[error("frame declares {declared} payload bytes but {actual} follow")]
    FrameLengthMismatch { declared: usize, actual: usize },
    #[error("frame has reserved byte set to nonzero")]
    NonZeroReserved,
    #[error("illegal flag combination: {bits:#010b}")]
    IllegalFlags { bits: u8 },
    #[error("middle frame received while not reassembling a message")]
    StrayMiddleFrame,
    #[error("second START frame while a message is mid-reassembly")]
    NestedMessage,
    #[error("sequence gap: expected {expected}, got {got}")]
    SequenceGap { expected: u16, got: u16 },
    #[error("reassembly buffer limit exceeded ({size} > {cap} bytes)")]
    MessageTooLarge { size: usize, cap: usize },
    #[error("split requested with zero-byte per-frame payload")]
    InvalidSplitSize,

    // ---- signatures & binding ---------------------------------------
    #[error("signature verification failed")]
    SignatureInvalid,
    #[error("approval/execute mismatch: {cause}")]
    ApprovalMismatch { cause: MismatchCause },
    #[error(transparent)]
    Crypto(#[from] crate::crypto::CryptoError),

    #[error("message decode referenced an unknown op_type/status/decision value")]
    UnknownEnumValue,
}

/// Why an ExecuteRequest failed binding validation. All causes surface to
/// clients as `conveyance/approval_mismatch` (an attack signal per the
/// spec); the distinction exists for LOCAL logging so phase 7 can tell a
/// TOCTOU substitution apart from a replay apart from a stale approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MismatchCause {
    /// Executed fields differ from what was approved.
    PayloadDiffers,
    /// No approval recorded for this req_id at all.
    UnknownReqId,
    /// Approval existed but lapsed past the 5-minute window.
    ExpiredReqId,
    /// The approval was already consumed by a prior execution.
    ReplayedReqId,
}

impl std::fmt::Display for MismatchCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PayloadDiffers => write!(f, "payload differs from approved"),
            Self::UnknownReqId => write!(f, "unknown req_id"),
            Self::ExpiredReqId => write!(f, "approval expired"),
            Self::ReplayedReqId => write!(f, "replay of consumed req_id"),
        }
    }
}

impl ProtocolError {
    /// Spec error-model code, where one exists. Framing errors are
    /// internal: they end the session (`protocol_violation`) but have no
    /// client-facing code in v1.
    pub fn spec_code(&self) -> Option<&'static str> {
        match self {
            ProtocolError::MessageTooLarge { .. } => Some("conveyance/message_too_large"),
            ProtocolError::ApprovalMismatch { .. } => Some("conveyance/approval_mismatch"),
            _ => None,
        }
    }
}
