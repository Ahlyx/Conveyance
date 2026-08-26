//! The PC-side pairing ceremony: QR payload, confirm/ack signatures,
//! replay gate, state machine, and the async driver.
//!
//! Composes phases 1 (signatures), 2 (PairingsDb), 4 (WireMessage), and
//! 5 (Transport). The phone side lives in phase 10; tests here use a
//! mock-phone harness over in-memory links.

pub mod ceremony;
pub mod machine;
pub mod messages;
pub mod nonce;
pub mod qr;

use std::time::Duration;

use thiserror::Error;

/// Spec: signature-invalid failures MUST NOT indicate which validation
/// failed. This is the generic face of every rejection except the two
/// the spec explicitly allows to be specific (version mismatch, and
/// locally-logged replay/timeouts that never reach an attacker's eyes).
#[derive(Debug, Error)]
pub enum PairingError {
    #[error("pairing failed")]
    GenericFailed,
    #[error("incompatible protocol versions (found v{found}, expected v{expected})")]
    VersionMismatch { found: u16, expected: u16 },
    #[error("QR code expired -- generate a new one")]
    QrExpired,
    #[error("no approval arrived within the confirm window")]
    ConfirmTimedOut,
    #[error("replayed pairing nonce")]
    ReplayedNonce,
    #[error("PC name exceeds 64 bytes ({0})")]
    PcNameTooLong(usize),
    #[error("QR encoding failed: {0}")]
    QrEncode(String),
    #[error("QR data corrupt")]
    QrCorrupt,
    #[error(transparent)]
    Protocol(#[from] crate::wire::ProtocolError),
    #[error(transparent)]
    Crypto(#[from] crate::crypto::CryptoError),
    #[error(transparent)]
    Storage(#[from] crate::storage::StorageError),
    #[error("transport error during pairing: {0}")]
    Transport(String),
}

impl PairingError {
    /// The spec error-model mapping, where one applies. v1 has no
    /// pairing-specific client codes: the CLI prints these errors
    /// directly instead.
    pub fn spec_code(&self) -> Option<&'static str> {
        None
    }
}

pub use ceremony::{CeremonyContext, CeremonyLimits, PairedPeer, run_pairing};
pub use machine::{Event, PairingState, TransitionError};
pub use nonce::NonceGuard;
pub use qr::PairingQr;

/// Convenience: seconds helper for callers building limits from config.
pub const fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}
