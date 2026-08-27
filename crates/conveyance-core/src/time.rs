//! Wall-clock helpers.
//!
//! Every log row, wire message, and QR payload timestamps in Unix
//! seconds. This is the one place that conversion lives -- the daemon,
//! the pairing ceremony, the mock phone, and the CLI all call
//! [`unix_now`] rather than re-deriving it, so a change to clock handling
//! (monotonic guards, leap-second policy, a test seam) moves in one file.

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch, saturating to 0 if the system clock is
/// set before 1970 (a misconfigured machine, never a real one). A
/// pre-epoch clock is not worth a panic on a path this hot.
pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
