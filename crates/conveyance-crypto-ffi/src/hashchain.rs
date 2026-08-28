//! The tamper-evident SHA-256 hash chain shared by both logs.
//!
//! Phase 10.1 exposes the pure computation the phone's `approvals.db`
//! needs in 10.2: the per-row hash, the exact bytes it is taken over
//! (`event_content_json`, useful for debugging and fixtures), and a full
//! chain walk. `conveyance_crypto::hashchain` is the reference — hashed
//! content is `{req_id, event_type, payload_json, timestamp}` only, the
//! DB-assigned `id` deliberately excluded so two independent logs of the
//! same events (phone and PC) produce identical chains row for row.
//!
//! [`hash_chain_verify`] preserves the *specific* break reason
//! ([`ChainBreakKind`]) rather than collapsing to a boolean: 10.2 wants to
//! tell "a row was edited" from "a row vanished between intact neighbours",
//! and the diff tool (Phase 9, PC side) already does.

use crate::{CryptoFfiError, fixed};
use conveyance_crypto::hashchain::{self, ChainIssue, ChainRow as CoreRow, LogEvent as CoreEvent};

/// One loggable event — exactly the fields that participate in the chain.
#[derive(uniffi::Record, Clone)]
pub struct LogEvent {
    /// 16-byte request correlation id.
    pub req_id: Vec<u8>,
    pub event_type: String,
    /// Canonical JSON text of the event details.
    pub payload_json: String,
    /// Unix seconds.
    pub timestamp: i64,
}

/// A stored row: event content plus the two chaining columns.
#[derive(uniffi::Record, Clone)]
pub struct ChainRow {
    pub event: LogEvent,
    /// 32-byte SHA-256 of the previous row (32 zero bytes for the first).
    pub prev_hash: Vec<u8>,
    /// 32-byte SHA-256 of this row.
    pub hash: Vec<u8>,
}

/// Why a chain walk failed, carrying the same detail
/// `conveyance_crypto::hashchain::ChainIssue` does.
#[derive(uniffi::Enum)]
pub enum ChainBreakKind {
    /// Row content no longer matches its stored hash.
    ContentTampered {
        expected_hash: String,
        stored_hash: String,
    },
    /// The row's `prev_hash` does not equal the running head — a removal
    /// or a reorder.
    LinkBroken {
        expected_prev: String,
        stored_prev: String,
    },
}

/// Result of [`hash_chain_verify`].
#[derive(uniffi::Enum)]
pub enum ChainVerification {
    Intact {
        verified_rows: u64,
    },
    Broken {
        /// Storage-order index of the offending row.
        index: u64,
        kind: ChainBreakKind,
    },
}

fn to_core_event(e: LogEvent) -> Result<CoreEvent, CryptoFfiError> {
    Ok(CoreEvent {
        req_id: fixed(e.req_id)?,
        event_type: e.event_type,
        payload_json: e.payload_json,
        timestamp: e.timestamp,
    })
}

fn to_core_row(r: ChainRow) -> Result<CoreRow, CryptoFfiError> {
    Ok(CoreRow {
        prev_hash: fixed(r.prev_hash)?,
        hash: fixed(r.hash)?,
        event: to_core_event(r.event)?,
    })
}

/// `prev_hash` for the first entry in any chain: 32 zero bytes.
#[uniffi::export]
pub fn hash_chain_genesis_prev_hash() -> Vec<u8> {
    hashchain::GENESIS_PREV_HASH.to_vec()
}

/// The canonical JSON bytes an event's row hash is taken over, as a
/// string. Exposed for debugging and for the fixture cross-check; the
/// row hash itself is [`hash_chain_row_hash`].
#[uniffi::export]
pub fn hash_chain_event_content_json(event: LogEvent) -> Result<String, CryptoFfiError> {
    let ev = to_core_event(event)?;
    // `event_content_json` is canonical JSON, always valid UTF-8.
    Ok(String::from_utf8(hashchain::event_content_json(&ev))
        .expect("canonical JSON is valid UTF-8"))
}

/// Compute one row's hash: `SHA256(prev_hash || event_content_json(event))`.
#[uniffi::export]
pub fn hash_chain_row_hash(prev_hash: Vec<u8>, event: LogEvent) -> Result<Vec<u8>, CryptoFfiError> {
    let prev: [u8; 32] = fixed(prev_hash)?;
    let ev = to_core_event(event)?;
    Ok(hashchain::compute_entry_hash(&prev, &ev).to_vec())
}

/// Walk `rows` in storage order, verifying every link and every content
/// hash. Reports the verified count or the first break, with its reason.
#[uniffi::export]
pub fn hash_chain_verify(rows: Vec<ChainRow>) -> Result<ChainVerification, CryptoFfiError> {
    let core: Vec<CoreRow> = rows
        .into_iter()
        .map(to_core_row)
        .collect::<Result<_, _>>()?;

    Ok(match hashchain::verify_chain(&core) {
        Ok(n) => ChainVerification::Intact {
            verified_rows: n as u64,
        },
        Err(ChainIssue::ContentTampered {
            index,
            expected_hash,
            stored_hash,
        }) => ChainVerification::Broken {
            index: index as u64,
            kind: ChainBreakKind::ContentTampered {
                expected_hash,
                stored_hash,
            },
        },
        Err(ChainIssue::LinkBroken {
            index,
            expected_prev,
            stored_prev,
        }) => ChainVerification::Broken {
            index: index as u64,
            kind: ChainBreakKind::LinkBroken {
                expected_prev,
                stored_prev,
            },
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn event(n: u8) -> LogEvent {
        LogEvent {
            req_id: vec![n; 16],
            event_type: "approval_granted".to_string(),
            payload_json: format!(r#"{{"decision":"approved","n":{n}}}"#),
            timestamp: 1_700_000_000 + n as i64,
        }
    }

    // Frozen against `conveyance_crypto::hashchain`; emitted as a fixture
    // and asserted from Kotlin.
    const ROW1_CONTENT_JSON: &str = concat!(
        r#"{"event_type":"approval_granted","#,
        r#""payload_json":"{\"decision\":\"approved\",\"n\":1}","#,
        r#""req_id":"01010101010101010101010101010101","#,
        r#""timestamp":1700000001}"#
    );
    const ROW1_HASH_HEX: &str = "5ceb3f981e02dce4f1429c1fba3a1ec8e59941ea440c36bc2a52a73f45ef776a";

    #[test]
    fn genesis_is_32_zero_bytes() {
        assert_eq!(hash_chain_genesis_prev_hash(), vec![0u8; 32]);
    }

    #[test]
    fn row1_content_and_hash_are_frozen() {
        let genesis = hash_chain_genesis_prev_hash();
        assert_eq!(
            hash_chain_event_content_json(event(1)).unwrap(),
            ROW1_CONTENT_JSON
        );
        let h = hash_chain_row_hash(genesis, event(1)).unwrap();
        assert_eq!(hex(&h), ROW1_HASH_HEX);
    }

    #[test]
    fn intact_chain_verifies() {
        let mut prev = hash_chain_genesis_prev_hash();
        let mut rows = Vec::new();
        for n in 1..=4 {
            let e = event(n);
            let h = hash_chain_row_hash(prev.clone(), e.clone()).unwrap();
            rows.push(ChainRow {
                event: e,
                prev_hash: prev.clone(),
                hash: h.clone(),
            });
            prev = h;
        }
        match hash_chain_verify(rows).unwrap() {
            ChainVerification::Intact { verified_rows } => assert_eq!(verified_rows, 4),
            other => panic!("expected Intact, got {:?}", DebugV(&other)),
        }
    }

    #[test]
    fn tampered_content_is_reported_with_reason_and_index() {
        let mut prev = hash_chain_genesis_prev_hash();
        let mut rows = Vec::new();
        for n in 1..=3 {
            let e = event(n);
            let h = hash_chain_row_hash(prev.clone(), e.clone()).unwrap();
            rows.push(ChainRow {
                event: e,
                prev_hash: prev.clone(),
                hash: h.clone(),
            });
            prev = h;
        }
        rows[1].event.payload_json = r#"{"decision":"approved","n":99}"#.to_string();

        match hash_chain_verify(rows).unwrap() {
            ChainVerification::Broken {
                index,
                kind: ChainBreakKind::ContentTampered { .. },
            } => assert_eq!(index, 1),
            other => panic!(
                "expected Broken/ContentTampered@1, got {:?}",
                DebugV(&other)
            ),
        }
    }

    #[test]
    fn removed_interior_row_is_a_link_break() {
        let mut prev = hash_chain_genesis_prev_hash();
        let mut rows = Vec::new();
        for n in 1..=3 {
            let e = event(n);
            let h = hash_chain_row_hash(prev.clone(), e.clone()).unwrap();
            rows.push(ChainRow {
                event: e,
                prev_hash: prev.clone(),
                hash: h.clone(),
            });
            prev = h;
        }
        rows.remove(1);

        match hash_chain_verify(rows).unwrap() {
            ChainVerification::Broken {
                index,
                kind: ChainBreakKind::LinkBroken { .. },
            } => assert_eq!(index, 1),
            other => panic!("expected Broken/LinkBroken@1, got {:?}", DebugV(&other)),
        }
    }

    #[test]
    fn bad_req_id_length_is_typed_error() {
        let mut e = event(1);
        e.req_id = vec![0u8; 15];
        assert!(matches!(
            hash_chain_row_hash(hash_chain_genesis_prev_hash(), e),
            Err(CryptoFfiError::BadLength)
        ));
    }

    // `ChainVerification` is a UniFFI enum without a Debug derive; this
    // wrapper gives the panic messages above something to print.
    struct DebugV<'a>(&'a ChainVerification);
    impl std::fmt::Debug for DebugV<'_> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self.0 {
                ChainVerification::Intact { verified_rows } => {
                    write!(f, "Intact({verified_rows})")
                }
                ChainVerification::Broken { index, kind } => {
                    let k = match kind {
                        ChainBreakKind::ContentTampered { .. } => "ContentTampered",
                        ChainBreakKind::LinkBroken { .. } => "LinkBroken",
                    };
                    write!(f, "Broken({index}, {k})")
                }
            }
        }
    }
}
