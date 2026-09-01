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
pub mod message;

/// BLE framing. Extracted to the standalone `conveyance-wire` crate
/// (phase 10.3) so the Android port drift-gates against one source of
/// truth; re-exported here so `conveyance_core::wire::framing::*` paths
/// are unchanged.
pub use conveyance_wire::framing;

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

    // ---- framing --------------------------------------------------------
    /// A frame or reassembly-step rejection from `conveyance-wire`. Kept
    /// as a nested variant (rather than flattened) so the framing crate
    /// owns its own taxonomy and the Android port has one enum to mirror.
    #[error(transparent)]
    Frame(#[from] conveyance_wire::FrameError),

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
            ProtocolError::Frame(e) => e.spec_code(),
            ProtocolError::ApprovalMismatch { .. } => Some("conveyance/approval_mismatch"),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::framing::Framer;
    use super::message::{Pong, ReqId, WireMessage, decode, encode};

    /// Cross-layer soak: mutated valid CBOR-message bytes fed through
    /// BOTH the framer and the message decoder. Neither may panic; typed
    /// errors pass. The pure-framing soak lives in `conveyance-wire`;
    /// this one is what would catch a panic that only shows up when the
    /// two parsers see the same adversarial bytes. Seeded, deterministic.
    #[test]
    fn mutation_soak_across_framing_and_message_decode() {
        struct Lcg(u64);
        impl Lcg {
            fn next(&mut self) -> u64 {
                self.0 = self
                    .0
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                self.0 >> 16
            }
        }
        let mut rng = Lcg(0xC0FFEE);

        let base_messages: Vec<Vec<u8>> = (0..8)
            .map(|n| {
                encode(&WireMessage::Pong(Pong {
                    req_id: ReqId([(n * 17) as u8; 16]),
                    timestamp: n as i64,
                }))
                .unwrap()
            })
            .collect();

        for _ in 0..50_000u32 {
            let src = &base_messages[(rng.next() % base_messages.len() as u64) as usize];
            let mut bytes = src.clone();
            let flips = 1 + (rng.next() % 8) as usize;
            for _ in 0..flips {
                let idx = (rng.next() as usize) % bytes.len().max(1);
                if idx < bytes.len() {
                    bytes[idx] ^= (rng.next() & 0xFF) as u8;
                }
            }
            if rng.next() & 1 == 1 && !bytes.is_empty() {
                bytes.truncate((rng.next() as usize) % bytes.len());
            }

            let _ = Framer::new().ingest(&bytes); // must not panic
            let _ = decode(&bytes); // must not panic
        }
    }
}
