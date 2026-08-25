//! The tamper-evident hash chain shared by both logs.
//!
//! Formula (spec "Logging", amended): each row's hash is
//! `SHA256(prev_hash || canonical_json({req_id, event_type,
//! payload_json, timestamp}))`, with genesis `prev_hash` = 32 zero
//! bytes. Hashed content is *event data only*: the DB-assigned `id` is
//! excluded so that two independent logs of the same events -- phone and
//! PC -- produce identical chains row-for-row. That property is what the
//! log diff tool (phase 9) stands on.
//!
//! Known limitation, inherited from the construction itself and stated
//! in the spec: interior rows cannot be altered, removed, or reordered
//! without detection, but truncating the newest rows is undetectable.
//! Nothing here claims otherwise.
//!
//! This module is pure: it computes hashes over value types. The SQLite
//! writer (phase 2) persists these values; it must not re-derive hashing
//! logic of its own.

use sha2::{Digest, Sha256};

use super::hex_encode;

/// `prev_hash` for the first entry in any chain.
pub const GENESIS_PREV_HASH: [u8; 32] = [0u8; 32];

/// One loggable event: exactly the fields that participate in the chain.
#[derive(Clone, Debug, PartialEq)]
pub struct LogEvent {
    /// 128-bit request correlation id.
    pub req_id: [u8; 16],
    /// e.g. "approval_request", "execute_result" -- spec's event_type set.
    pub event_type: String,
    /// Canonical JSON text of the event details (stored as a string per
    /// the schema; embedded as a JSON string value when hashed).
    pub payload_json: String,
    /// Unix seconds.
    pub timestamp: i64,
}

/// A row as stored: its event content plus the chaining columns.
#[derive(Clone, Debug, PartialEq)]
pub struct ChainRow {
    pub event: LogEvent,
    pub prev_hash: [u8; 32],
    pub hash: [u8; 32],
}

/// How a chain walk failed. Distinct variants on purpose: "someone edited
/// a row" and "a row vanished between two intact neighbors" are different
/// incidents requiring different responses.
#[derive(Debug, Clone, PartialEq)]
pub enum ChainIssue {
    /// Row content no longer matches its own stored hash.
    ContentTampered {
        index: usize,
        expected_hash: String,
        stored_hash: String,
    },
    /// The row's stored `prev_hash` does not equal the running head --
    /// catches removals (the successor now points at a hash we never
    /// reached) and reordering.
    LinkBroken {
        index: usize,
        expected_prev: String,
        stored_prev: String,
    },
}

impl std::fmt::Display for ChainIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainIssue::ContentTampered {
                index,
                expected_hash,
                stored_hash,
            } => write!(
                f,
                "row {index} altered: recomputed hash {expected_hash}, stored {stored_hash}"
            ),
            ChainIssue::LinkBroken {
                index,
                expected_prev,
                stored_prev,
            } => write!(
                f,
                "chain broken at row {index}: expected prev {expected_prev}, found {stored_prev}"
            ),
        }
    }
}

/// The canonical JSON bytes for one event's chained content. Public so
/// the storage layer can persist exactly what was hashed and nothing
/// else.
///
/// Infallible by construction: every field is either a string, an
/// integer, or lowercase hex -- nothing that can leave the canonical-JSON
/// domain, whatever callers put inside `payload_json`.
pub fn event_content_json(event: &LogEvent) -> Vec<u8> {
    let value = serde_json::json!({
        "event_type": event.event_type,
        "payload_json": event.payload_json,
        // Hex, not base64: canonical JSON has no byte-array type, and
        // auditmcp's tooling expects lowercase hex identifiers.
        "req_id": hex_encode(&event.req_id),
        "timestamp": event.timestamp,
    });
    canonicalize(value)
}

fn canonicalize(value: serde_json::Value) -> Vec<u8> {
    // Our own constant-shaped values are always inside the domain;
    // failure would mean the canonicalizer rejects our own field set,
    // which is a programming error worth crashing on loudly rather than
    // hashing divergent bytes silently.
    super::canonical_json::canonicalize(&value)
        .expect("own constant-shaped values are canonicalizable")
        .into()
}

/// Compute one row's hash given the previous hash and its event.
pub fn compute_entry_hash(prev_hash: &[u8; 32], event: &LogEvent) -> [u8; 32] {
    let content = event_content_json(event);
    let mut hasher = Sha256::new();
    Digest::update(&mut hasher, prev_hash);
    Digest::update(&mut hasher, &content);
    hasher.finalize().into()
}

/// Chain a sequence of events into full rows, linking each to the last.
pub fn build_chain(events: &[LogEvent]) -> Vec<ChainRow> {
    let mut rows = Vec::with_capacity(events.len());
    let mut prev = GENESIS_PREV_HASH;
    for event in events {
        let hash = compute_entry_hash(&prev, event);
        rows.push(ChainRow {
            event: event.clone(),
            prev_hash: prev,
            hash,
        });
        prev = hash;
    }
    rows
}

/// Walk rows in storage order and verify every link and every content
/// hash. Returns the verified row count, or the first issue found
/// (mirrors auditmcp's first-failure reporting).
pub fn verify_chain(rows: &[ChainRow]) -> Result<usize, ChainIssue> {
    let mut head = GENESIS_PREV_HASH;

    for (index, row) in rows.iter().enumerate() {
        if row.prev_hash != head {
            return Err(ChainIssue::LinkBroken {
                index,
                expected_prev: hex_encode(&head),
                stored_prev: hex_encode(&row.prev_hash),
            });
        }

        let recomputed = compute_entry_hash(&row.prev_hash, &row.event);

        if recomputed != row.hash {
            return Err(ChainIssue::ContentTampered {
                index,
                expected_hash: hex_encode(&recomputed),
                stored_hash: hex_encode(&row.hash),
            });
        }

        head = row.hash;
    }

    Ok(rows.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(n: u8) -> LogEvent {
        LogEvent {
            req_id: [n; 16],
            event_type: "approval_granted".into(),
            payload_json: format!(r#"{{"decision":"approved","n":{n}}}"#),
            timestamp: 1_700_000_000 + n as i64,
        }
    }

    #[test]
    fn genesis_link_is_32_zero_bytes() {
        let chain = build_chain(&[event(1)]);
        assert_eq!(chain[0].prev_hash, GENESIS_PREV_HASH);
        assert_ne!(chain[0].hash, [0u8; 32]);
    }

    /// Independent recomputation of row 2's hash straight from the
    /// formula, not via build_chain's internals: guards against the
    /// builder and verifier sharing a bug.
    #[test]
    fn formula_recomputed_independently() {
        let events = vec![event(1), event(2)];
        let chain = build_chain(&events);

        let mut hasher = Sha256::new();
        hasher.update(GENESIS_PREV_HASH);
        hasher.update(event_content_json(&events[0]));
        let h0: [u8; 32] = hasher.finalize().into();

        let mut hasher = Sha256::new();
        hasher.update(h0);
        hasher.update(event_content_json(&events[1]));
        let h1: [u8; 32] = hasher.finalize().into();

        assert_eq!(chain[0].hash, h0);
        assert_eq!(chain[1].hash, h1);
    }

    #[test]
    fn empty_chain_verifies() {
        assert_eq!(verify_chain(&[]).unwrap(), 0);
    }

    #[test]
    fn intact_chain_verifies() {
        let events: Vec<_> = (1..=5).map(event).collect();
        let chain = build_chain(&events);
        assert_eq!(verify_chain(&chain).unwrap(), 5);
    }

    #[test]
    fn altered_content_is_detected() {
        let events: Vec<_> = (1..=4).map(event).collect();
        let mut chain = build_chain(&events);

        chain[2].event.payload_json = r#"{"decision":"approved","n":99}"#.into();

        match verify_chain(&chain) {
            Err(ChainIssue::ContentTampered { index, .. }) => assert_eq!(index, 2),
            other => panic!("expected ContentTampered at 2, got {other:?}"),
        }
    }

    #[test]
    fn removed_interior_row_breaks_the_link_at_its_successor() {
        let events: Vec<_> = (1..=4).map(event).collect();
        let mut chain = build_chain(&events);

        // Remove row 1; row 2 still carries the original prev_hash.
        chain.remove(1);

        match verify_chain(&chain) {
            Err(ChainIssue::LinkBroken { index, .. }) => assert_eq!(index, 1),
            other => panic!("expected LinkBroken at successor, got {other:?}"),
        }
    }

    #[test]
    fn reordered_rows_break_links() {
        let events: Vec<_> = (1..=4).map(event).collect();
        let mut chain = build_chain(&events);

        chain.swap(1, 2);

        match verify_chain(&chain) {
            Err(ChainIssue::LinkBroken { .. }) => {}
            other => panic!("expected LinkBroken after reorder, got {other:?}"),
        }
    }

    #[test]
    fn tampered_prev_hash_column_is_a_broken_link_not_tampered_content() {
        let events: Vec<_> = (1..=3).map(event).collect();
        let mut chain = build_chain(&events);

        chain[1].prev_hash[0] ^= 0xff;

        match verify_chain(&chain) {
            Err(ChainIssue::LinkBroken { index, .. }) => assert_eq!(index, 1),
            other => panic!("expected LinkBroken, got {other:?}"),
        }
    }

    /// Display strings for both issue variants -- phase 9's `log verify`
    /// prints these verbatim, so their shape is worth pinning.
    #[test]
    fn issue_display_is_stable() {
        let events: Vec<_> = (1..=2).map(event).collect();
        let mut chain = build_chain(&events);

        chain[0].event.payload_json = "changed".into();
        match verify_chain(&chain) {
            Err(issue) => {
                let text = issue.to_string();
                assert!(text.starts_with("row 0 altered:"), "{text}");
                assert!(text.contains("recomputed"), "{text}");
                assert!(text.contains("stored"), "{text}");
            }
            Ok(_) => panic!("tampered chain verified clean"),
        }

        chain = build_chain(&events);
        chain[1].prev_hash[31] ^= 0x01;
        match verify_chain(&chain) {
            Err(issue) => {
                let text = issue.to_string();
                assert!(text.starts_with("chain broken at row 1:"), "{text}");
                assert!(text.contains("expected prev"), "{text}");
            }
            Ok(_) => panic!("broken chain verified clean"),
        }
    }
}
