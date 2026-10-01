//! Shared typed application protocol for the PC and Android phone.
//!
//! This leaf crate owns CBOR decoding, semantic validation, signature
//! preimages, and approval/execute binding. It deliberately has no
//! database, session, platform, or UI dependencies.

pub mod binding;
pub mod message;
pub mod policy;

#[cfg(test)]
mod strict_tests;

pub use conveyance_crypto as crypto;
pub use conveyance_wire::framing;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("CBOR encoding/decoding failed: {0}")]
    Cbor(String),
    #[error("wire message exceeds the protocol size limit")]
    MessageTooLarge,
    #[error("wire message contains trailing CBOR data")]
    TrailingData,
    #[error("wire message contains duplicate or non-text map keys")]
    InvalidMap,
    #[error("wire message nesting exceeds the protocol safety limit")]
    NestingTooDeep,
    #[error("wire message has an unexpected type")]
    UnexpectedMessageType,
    #[error("ApprovalRequest op_type is not authenticated_request")]
    UnsupportedApprovalOperation,
    #[error("value in '{field}' is outside the canonical-JSON domain")]
    UnsupportedValueType { field: &'static str },
    #[error("signature verification failed")]
    SignatureInvalid,
    #[error("approval/execute mismatch: {cause}")]
    ApprovalMismatch { cause: MismatchCause },
    #[error("duplicate req_id cannot replace an existing approval")]
    DuplicateRequestId,
    #[error("only an approved authenticated request can be bound")]
    NotApproved,
    #[error(transparent)]
    Frame(#[from] conveyance_wire::FrameError),
    #[error(transparent)]
    Crypto(#[from] conveyance_crypto::CryptoError),
    #[error("message decode referenced an unknown op_type/status/decision value")]
    UnknownEnumValue,
}

/// Why an ExecuteRequest failed exact approval binding. The distinctions
/// are for local audit and regression tests; remote callers receive the
/// single protocol approval-mismatch code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MismatchCause {
    PayloadDiffers,
    UnknownReqId,
    ExpiredReqId,
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
    pub fn spec_code(&self) -> Option<&'static str> {
        match self {
            Self::Frame(error) => error.spec_code(),
            Self::ApprovalMismatch { .. } => Some("conveyance/approval_mismatch"),
            _ => None,
        }
    }
}
