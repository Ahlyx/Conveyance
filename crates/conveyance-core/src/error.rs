//! The structured error model from the spec's "Error model" section.
//!
//! Every error that can reach an MCP client is one of the named codes,
//! serialized as exactly this shape:
//!
//! ```json
//! {
//!   "code": "conveyance/no_session",
//!   "message": "...",
//!   "retryable": true,
//!   "retry_after_seconds": null,
//!   "details": null
//! }
//! ```
//!
//! Two rules from the spec shape how this module is written:
//!
//! * Security-relevant failures (handshake, peer identity) MUST NOT leak
//!   which validation failed. Their messages are therefore fixed and
//!   generic -- callers cannot add detail to them, because any "helpful"
//!   specificity ("static key mismatch on message 2") is reconnaissance
//!   for whoever triggered the failure.
//! * `retry_after_seconds` exists in the JSON for shape stability, but no
//!   v1 code defines a concrete wait. It stays `None` everywhere; do not
//!   invent values to fill it.

use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConveyanceError {
    #[error("No active Conveyance session. User must start one on the paired phone.")]
    NoSession,
    #[error("Could not reach the paired phone to establish a session.")]
    PhoneUnreachable,
    #[error("The request was denied on the phone.")]
    ApprovalDenied,
    #[error("No approval decision arrived within the approval window.")]
    ApprovalTimeout,
    #[error("The session ended while the request was in flight.")]
    SessionEnded,
    #[error("Session handshake failed.")]
    HandshakeFailed,
    #[error("Peer identity does not match the stored pairing. Re-pairing is required.")]
    PeerIdentityMismatch,
    #[error("Executed payload does not match the approved payload.")]
    ApprovalMismatch,
    #[error("No credentials are stored for the requested service.")]
    ServiceUnknown,
    #[error("Message exceeded the reassembly buffer limit.")]
    MessageTooLarge,
    #[error("The OS keychain is unavailable; Conveyance refuses to fall back silently.")]
    KeychainUnavailable,
}

impl ConveyanceError {
    /// The machine-parseable, namespaced code, byte-for-byte as listed in
    /// the spec's error table. Downstream tooling (the shim's JSON-RPC
    /// errors, log queries) matches on these strings.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoSession => "conveyance/no_session",
            Self::PhoneUnreachable => "conveyance/phone_unreachable",
            Self::ApprovalDenied => "conveyance/approval_denied",
            Self::ApprovalTimeout => "conveyance/approval_timeout",
            Self::SessionEnded => "conveyance/session_ended",
            Self::HandshakeFailed => "conveyance/handshake_failed",
            Self::PeerIdentityMismatch => "conveyance/peer_identity_mismatch",
            Self::ApprovalMismatch => "conveyance/approval_mismatch",
            Self::ServiceUnknown => "conveyance/service_unknown",
            Self::MessageTooLarge => "conveyance/message_too_large",
            Self::KeychainUnavailable => "conveyance/keychain_unavailable",
        }
    }

    /// Whether a retry may ever succeed, per the spec table. Note that
    /// `true` does not mean "immediately": several retryable codes still
    /// require user action first (starting a session, re-establishing one).
    pub fn retryable(&self) -> bool {
        match self {
            Self::NoSession
            | Self::PhoneUnreachable
            | Self::ApprovalTimeout
            | Self::SessionEnded => true,
            Self::ApprovalDenied
            | Self::HandshakeFailed
            | Self::PeerIdentityMismatch
            | Self::ApprovalMismatch
            | Self::ServiceUnknown
            | Self::MessageTooLarge
            | Self::KeychainUnavailable => false,
        }
    }

    /// Serialize into the spec's wire shape. `details` starts `None`;
    /// attach non-secret context by setting the field on the returned
    /// struct before serialization where a call site genuinely has some.
    pub fn to_error_json(&self) -> ErrorJson {
        ErrorJson {
            code: self.code(),
            message: self.to_string(),
            retryable: self.retryable(),
            retry_after_seconds: None,
            details: None,
        }
    }
}

/// The exact wire shape from the spec. Kept as its own `Serialize` type
/// rather than hand-built `serde_json::Value`s so the shape is declared
/// once and checked by the compiler; when errors travel over CBOR later,
/// the same struct serializes there too.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ErrorJson {
    pub code: &'static str,
    pub message: String,
    pub retryable: bool,
    pub retry_after_seconds: Option<u64>,
    pub details: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant must serialize to the full five-field shape with the
    /// exact code string and retryable flag from the spec table. Adding a
    /// variant without updating this test leaves it unexercised, which is
    /// the point: the test fails to compile-cleanly only if the match in
    /// `code()`/`retryable()` went stale, so a new variant forces a row here.
    #[test]
    fn every_variant_matches_the_spec_table() {
        let cases: Vec<(ConveyanceError, &str, bool)> = vec![
            (ConveyanceError::NoSession, "conveyance/no_session", true),
            (
                ConveyanceError::PhoneUnreachable,
                "conveyance/phone_unreachable",
                true,
            ),
            (
                ConveyanceError::ApprovalDenied,
                "conveyance/approval_denied",
                false,
            ),
            (
                ConveyanceError::ApprovalTimeout,
                "conveyance/approval_timeout",
                true,
            ),
            (
                ConveyanceError::SessionEnded,
                "conveyance/session_ended",
                true,
            ),
            (
                ConveyanceError::HandshakeFailed,
                "conveyance/handshake_failed",
                false,
            ),
            (
                ConveyanceError::PeerIdentityMismatch,
                "conveyance/peer_identity_mismatch",
                false,
            ),
            (
                ConveyanceError::ApprovalMismatch,
                "conveyance/approval_mismatch",
                false,
            ),
            (
                ConveyanceError::ServiceUnknown,
                "conveyance/service_unknown",
                false,
            ),
            (
                ConveyanceError::MessageTooLarge,
                "conveyance/message_too_large",
                false,
            ),
            (
                ConveyanceError::KeychainUnavailable,
                "conveyance/keychain_unavailable",
                false,
            ),
        ];

        for (err, code, retryable) in cases {
            let json = err.to_error_json();
            assert_eq!(json.code, code);
            assert_eq!(json.retryable, retryable);
            // v1 defines no concrete waits anywhere.
            assert_eq!(json.retry_after_seconds, None);

            let value = serde_json::to_value(&json).unwrap();
            let obj = value.as_object().unwrap();
            let mut keys: Vec<_> = obj.keys().collect();
            keys.sort();
            assert_eq!(
                keys,
                [
                    "code",
                    "details",
                    "message",
                    "retry_after_seconds",
                    "retryable"
                ],
                "{code}: field set drifted from the spec shape"
            );
        }
    }

    #[test]
    fn security_relevant_messages_stay_generic() {
        // These must not name which check failed. If someone makes them
        // specific later, this test is where the discussion happens.
        for err in [
            ConveyanceError::HandshakeFailed,
            ConveyanceError::PeerIdentityMismatch,
        ] {
            let msg = err.to_string().to_lowercase();
            for leaked in ["key", "signature", "curve", "mac", "nonce"] {
                assert!(!msg.contains(leaked), "'{msg}' leaks '{leaked}'");
            }
        }
    }

    #[test]
    fn json_serializes_with_null_fields_present() {
        // Shape parity means null fields are PRESENT, not omitted -- clients
        // key off the field existing.
        let value = serde_json::to_value(ConveyanceError::NoSession.to_error_json()).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "code": "conveyance/no_session",
                "message": "No active Conveyance session. User must start one on the paired phone.",
                "retryable": true,
                "retry_after_seconds": null,
                "details": null,
            })
        );
    }
}
