//! Crash-recovery sweep: reconcile the execution log at startup.
//!
//! A request that died mid-flight leaves a log trail with no terminal
//! row. The spec (via the phases doc) requires two things of recovery:
//!
//! * every orphaned req_id becomes visible as `request_timeout`, and
//! * a crash before a terminal state is distinguishable from a live
//!   timeout. Both ride `payload_json.reason`:
//!   `crashed_before_terminal` here, `timeout` for deadlines that
//!   expire while the daemon is running (see session.rs).
//!
//! Terminal event types: `execute_result` (the happy end),
//! `approval_denied` (a decision IS terminal even though nothing
//! executed), and `request_timeout` itself (idempotence across
//! repeated sweeps). Anything else trailing a req_id --
//! `approval_request`, `approval_granted`, `execute_sent` -- means the
//! process died between those steps.
//!
//! Sweep rows are appended, never in-place edits: the log is append-
//! only by construction and the hash chain must stay verifiable.

use std::collections::HashMap;

use conveyance_core::crypto::hashchain::LogEvent;
use conveyance_core::storage::logdb::LogDb;
use conveyance_core::time::unix_now;

/// Payload reason for requests orphaned by a crash/restart.
pub const CRASHED_BEFORE_TERMINAL: &str = "crashed_before_terminal";

/// Payload reason for deadlines that expired live.
pub const TIMEOUT_REASON: &str = "timeout";

use crate::session::{LIFECYCLE_REQ_ID, TERMINAL_EVENT_TYPES};

/// Append `request_timeout` rows for every orphaned req_id. Returns
/// the number swept. Deterministic: orphans are processed in the order
/// their first row appears, so two sweeps over identical logs produce
/// identical chains.
pub fn sweep_orphaned_requests(
    log: &LogDb,
) -> Result<usize, conveyance_core::storage::StorageError> {
    let events = log.events()?;

    // Newest row per req_id decides state; first-appearance index
    // decides sweep order.
    let mut newest: HashMap<[u8; 16], (usize, &str)> = HashMap::new();
    for (idx, ev) in events.iter().enumerate() {
        newest
            .entry(ev.req_id)
            .or_insert((idx, ev.event_type.as_str()));
        // or_insert keeps the FIRST index; overwrite keeps the LAST type.
        let entry = newest.get_mut(&ev.req_id).expect("just inserted");
        entry.1 = ev.event_type.as_str();
    }

    let mut orphans: Vec<(usize, [u8; 16], &str)> = newest
        .into_iter()
        .filter(|(req_id, _)| *req_id != LIFECYCLE_REQ_ID)
        .map(|(req_id, (idx, last_type))| (idx, req_id, last_type))
        .collect();
    orphans.sort_by_key(|(idx, _, _)| *idx);
    orphans.retain(|(_, _, last_type)| !TERMINAL_EVENT_TYPES.contains(last_type));

    let now = unix_now();
    let mut swept = 0;
    for (_, req_id, last_type) in orphans {
        let payload = serde_json::json!({
            "reason": CRASHED_BEFORE_TERMINAL,
            "orphaned_after": last_type,
        });
        let payload_json = conveyance_core::crypto::canonical_json::to_canonical_string(&payload)
            .unwrap_or_else(|_| payload.to_string());
        log.append(&LogEvent {
            req_id,
            event_type: "request_timeout".into(),
            payload_json,
            timestamp: now,
        })?;
        swept += 1;
    }
    Ok(swept)
}

#[cfg(test)]
mod tests {
    use super::*;
    use conveyance_core::crypto::hashchain::LogEvent;

    fn ev(req_id: [u8; 16], event_type: &str) -> LogEvent {
        LogEvent {
            req_id,
            event_type: event_type.into(),
            payload_json: "{}".into(),
            timestamp: 1_700_000_000,
        }
    }

    #[test]
    fn orphans_get_crashed_reason_terminal_rows_are_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let db = LogDb::open(&dir.path().join("e.db")).unwrap();

        let full_cycle = [7u8; 16];
        let denied_only = [8u8; 16];
        let approved_never_executed = [9u8; 16];
        let sent_never_resulted = [10u8; 16];

        db.append(&ev(full_cycle, "approval_request")).unwrap();
        db.append(&ev(full_cycle, "approval_granted")).unwrap();
        db.append(&ev(full_cycle, "execute_sent")).unwrap();
        db.append(&ev(full_cycle, "execute_result")).unwrap();
        db.append(&ev(denied_only, "approval_request")).unwrap();
        db.append(&ev(denied_only, "approval_denied")).unwrap();
        db.append(&ev(approved_never_executed, "approval_request"))
            .unwrap();
        db.append(&ev(approved_never_executed, "approval_granted"))
            .unwrap();
        db.append(&ev(sent_never_resulted, "approval_request"))
            .unwrap();
        db.append(&ev(sent_never_resulted, "execute_sent")).unwrap();

        let swept = sweep_orphaned_requests(&db).unwrap();
        assert_eq!(swept, 2, "two partial trails need reconciliation");

        let types: Vec<_> = db
            .events()
            .unwrap()
            .iter()
            .map(|e| e.event_type.clone())
            .collect();
        assert_eq!(types.iter().filter(|t| *t == "request_timeout").count(), 2);

        // Both sweep rows name the crash reason AND where they stopped.
        let timeouts: Vec<_> = db
            .events()
            .unwrap()
            .into_iter()
            .filter(|e| e.event_type == "request_timeout")
            .collect();
        for row in &timeouts {
            assert!(
                row.payload_json.contains(CRASHED_BEFORE_TERMINAL),
                "{}",
                row.payload_json
            );
            assert!(
                row.payload_json.contains("orphaned_after"),
                "{}",
                row.payload_json
            );
        }
        assert!(
            timeouts
                .iter()
                .any(|e| e.payload_json.contains("execute_sent")),
            "sent-but-unresulted orphan should record its stage"
        );

        // Sweeps are idempotent AND chain-verifiable afterwards.
        assert_eq!(sweep_orphaned_requests(&db).unwrap(), 0);
        assert_eq!(db.verify().unwrap(), Ok(types.len()));
    }

    #[test]
    fn lifecycle_rows_are_ignored_by_the_sweep() {
        let dir = tempfile::tempdir().unwrap();
        let db = LogDb::open(&dir.path().join("e.db")).unwrap();
        db.append(&LogEvent {
            req_id: LIFECYCLE_REQ_ID,
            event_type: "session_start".into(),
            payload_json: "{}".into(),
            timestamp: 1,
        })
        .unwrap();
        assert_eq!(sweep_orphaned_requests(&db).unwrap(), 0);
    }
}
