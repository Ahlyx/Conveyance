//! `executions.db`: the PC-side hash-chained execution log.
//!
//! Append is synchronous and serialized. Two invariants make concurrent
//! appends chain-safe (both from auditmcp's documented experience):
//!
//! 1. Every append runs `BEGIN IMMEDIATE` -- the write lock is taken at
//!    BEGIN, so a second writer *blocks before reading anything*. With
//!    SQLite's default deferred BEGIN, two writers could each read the
//!    same head, compute hashes against it, and commit two rows claiming
//!    the same prev_hash: a silent fork WAL mode does nothing to prevent.
//! 2. The head is read inside that transaction -- never cached on the
//!    struct, never accepted from a caller. A head read before the lock
//!    can be stale the moment another process commits.
//!
//! The hash computation itself is delegated to
//! [`crate::crypto::hashchain`]; this file must never grow its own
//! hashing logic.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::params;

use crate::crypto::hashchain::{self, ChainIssue, ChainRow, GENESIS_PREV_HASH, LogEvent};

use super::{DbKind, StorageError, migrate::run_migrations, open_connection, recover_mutex};

pub struct LogDb {
    conn: Mutex<rusqlite::Connection>,
    path: PathBuf,
}

impl LogDb {
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        let mut conn = open_connection(path)?;
        run_migrations(&mut conn, DbKind::Executions)?;
        Ok(Self {
            conn: Mutex::new(conn),
            path: path.to_path_buf(),
        })
    }

    /// Append one event, chaining onto whatever the current head is at
    /// the moment the write lock is ours. Returns the row as stored.
    pub fn append(&self, event: &LogEvent) -> Result<ChainRow, StorageError> {
        let mut conn = recover_mutex(self.conn.lock());
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|source| StorageError::Db {
                path: self.path.clone(),
                source,
            })?;

        // Safe to read NOW and only now: IMMEDIATE BEGIN holds the write
        // lock, so no other process can move the head between this read
        // and our COMMIT.
        let prev_hash = read_head(&tx, &self.path)?;
        let hash = hashchain::compute_entry_hash(&prev_hash, event);

        tx.execute(
            "INSERT INTO entries (req_id, event_type, payload_json, timestamp, prev_hash, hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                event.req_id.as_slice(),
                event.event_type,
                event.payload_json,
                event.timestamp,
                prev_hash.as_slice(),
                hash.as_slice()
            ],
        )
        .map_err(|source| StorageError::Db {
            path: self.path.clone(),
            source,
        })?;

        tx.commit().map_err(|source| StorageError::Db {
            path: self.path.clone(),
            source,
        })?;

        Ok(ChainRow {
            event: event.clone(),
            prev_hash,
            hash,
        })
    }

    /// Walk the stored chain in id order and verify it. `Ok(Ok(n))`
    /// means n rows verified intact; `Ok(Err(issue))` reports the first
    /// broken link or altered row found; the outer error is for
    /// operational failures (DB unreadable, malformed columns).
    pub fn verify(&self) -> Result<Result<usize, ChainIssue>, StorageError> {
        let rows = self.read_rows()?;
        Ok(hashchain::verify_chain(&rows))
    }

    /// Row count. Test/inspection surface for now; `conveyance status`
    /// (phase 7) is the expected consumer.
    #[cfg(test)]
    pub(crate) fn count(&self) -> Result<i64, StorageError> {
        let conn = recover_mutex(self.conn.lock());
        conn.query_row("SELECT count(*) FROM entries", [], |r| r.get(0))
            .map_err(|source| StorageError::Db {
                path: self.path.clone(),
                source,
            })
    }

    fn read_rows(&self) -> Result<Vec<ChainRow>, StorageError> {
        let conn = recover_mutex(self.conn.lock());
        let mut stmt = conn
            .prepare(
                "SELECT id, req_id, event_type, payload_json, timestamp, prev_hash, hash
                 FROM entries ORDER BY id",
            )
            .map_err(|source| StorageError::Db {
                path: self.path.clone(),
                source,
            })?;

        let mut out = Vec::new();
        let mut rows = stmt.query([]).map_err(|source| StorageError::Db {
            path: self.path.clone(),
            source,
        })?;
        while let Some(row) = rows.next().map_err(|source| StorageError::Db {
            path: self.path.clone(),
            source,
        })? {
            let id: i64 = row.get(0).map_err(|source| StorageError::Db {
                path: self.path.clone(),
                source,
            })?;
            let req_id: Vec<u8> = row.get(1).map_err(|source| StorageError::Db {
                path: self.path.clone(),
                source,
            })?;
            let event_type: String = row.get(2).map_err(|source| StorageError::Db {
                path: self.path.clone(),
                source,
            })?;
            let payload_json: String = row.get(3).map_err(|source| StorageError::Db {
                path: self.path.clone(),
                source,
            })?;
            let timestamp: i64 = row.get(4).map_err(|source| StorageError::Db {
                path: self.path.clone(),
                source,
            })?;
            let prev_hash: Vec<u8> = row.get(5).map_err(|source| StorageError::Db {
                path: self.path.clone(),
                source,
            })?;
            let hash: Vec<u8> = row.get(6).map_err(|source| StorageError::Db {
                path: self.path.clone(),
                source,
            })?;

            // Column widths are enforced by nothing but this code; a
            // hand-edited DB with a 31-byte hash must fail loudly here,
            // not produce a subtly wrong verification verdict.
            let malformed = |_| StorageError::MalformedRow {
                path: self.path.clone(),
                row_id: id,
            };
            out.push(ChainRow {
                event: LogEvent {
                    req_id: <[u8; 16]>::try_from(req_id).map_err(malformed)?,
                    event_type,
                    payload_json,
                    timestamp,
                },
                prev_hash: <[u8; 32]>::try_from(prev_hash).map_err(malformed)?,
                hash: <[u8; 32]>::try_from(hash).map_err(malformed)?,
            });
        }
        Ok(out)
    }
}

fn read_head(tx: &rusqlite::Transaction, path: &Path) -> Result<[u8; 32], StorageError> {
    let head: Option<Vec<u8>> = tx
        .query_row(
            "SELECT hash FROM entries ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other),
        })
        .map_err(|source| StorageError::Db {
            path: path.to_path_buf(),
            source,
        })?;

    match head {
        None => Ok(GENESIS_PREV_HASH),
        Some(bytes) => <[u8; 32]>::try_from(bytes).map_err(|_| StorageError::MalformedRow {
            path: path.to_path_buf(),
            row_id: -1,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(n: u8) -> LogEvent {
        LogEvent {
            req_id: [n; 16],
            event_type: "execute_result".into(),
            payload_json: format!(r#"{{"status":"ok","n":{n}}}"#),
            timestamp: 1_700_000_000 + n as i64,
        }
    }

    #[test]
    fn append_then_verify_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let db = LogDb::open(&dir.path().join("e.db")).unwrap();

        assert_eq!(db.verify().unwrap(), Ok(0), "empty log verifies");

        let first = db.append(&event(1)).unwrap();
        assert_eq!(first.prev_hash, GENESIS_PREV_HASH);
        let second = db.append(&event(2)).unwrap();
        assert_eq!(second.prev_hash, first.hash, "rows chain onto each other");

        assert_eq!(db.count().unwrap(), 2);
        assert_eq!(db.verify().unwrap(), Ok(2));
    }

    /// The stored head must equal what crypto::hashchain would compute --
    /// proving the storage layer feeds the same module rather than
    /// growing parallel logic.
    #[test]
    fn stored_hashes_match_crypto_module() {
        let dir = tempfile::tempdir().unwrap();
        let db = LogDb::open(&dir.path().join("e.db")).unwrap();

        let events: Vec<_> = (1..=4).map(event).collect();
        let expected = hashchain::build_chain(&events);
        for e in &events {
            db.append(e).unwrap();
        }

        let stored = db.read_rows().unwrap();
        assert_eq!(stored, expected);
    }

    #[test]
    fn tampered_row_is_detected_at_the_right_index() {
        let dir = tempfile::tempdir().unwrap();
        let db = LogDb::open(&dir.path().join("e.db")).unwrap();
        for n in 1..=3u8 {
            db.append(&event(n)).unwrap();
        }
        drop(db);

        // Tamper directly through SQL, as an attacker with file access would.
        let raw = rusqlite::Connection::open(dir.path().join("e.db")).unwrap();
        raw.execute(
            "UPDATE entries SET payload_json = '{\"evil\":true}' WHERE id = 2",
            [],
        )
        .unwrap();

        let db = LogDb::open(&dir.path().join("e.db")).unwrap();
        match db.verify().unwrap() {
            Err(ChainIssue::ContentTampered { index, .. }) => assert_eq!(index, 1),
            other => panic!("expected ContentTampered at index 1, got {other:?}"),
        }
    }

    #[test]
    fn removed_interior_row_breaks_verification() {
        let dir = tempfile::tempdir().unwrap();
        let db = LogDb::open(&dir.path().join("e.db")).unwrap();
        for n in 1..=4u8 {
            db.append(&event(n)).unwrap();
        }
        drop(db);

        let raw = rusqlite::Connection::open(dir.path().join("e.db")).unwrap();
        raw.execute("DELETE FROM entries WHERE id = 2", []).unwrap();

        let db = LogDb::open(&dir.path().join("e.db")).unwrap();
        match db.verify().unwrap() {
            Err(ChainIssue::LinkBroken { index, .. }) => assert_eq!(index, 1),
            other => panic!("expected LinkBroken after removal, got {other:?}"),
        }
    }

    /// THE contention test: eight separate connections on one file, all
    /// appending simultaneously. If BEGIN IMMEDIATE + in-transaction head
    /// reads were wrong in any way, some pair of threads would fork the
    /// chain (two rows sharing one prev_hash) and final verification would
    /// report a broken link -- or worse, silently succeed short.
    #[test]
    fn concurrent_writers_never_fork_the_chain() {
        const WRITERS: usize = 8;
        const PER_WRITER: usize = 6;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("contended.db");

        // One opener creates schema before the race.
        {
            LogDb::open(&path).unwrap();
        }

        let path_str = path.to_string_lossy().to_string();
        let handles: Vec<_> = (0..WRITERS)
            .map(|w| {
                let p = path_str.clone();
                std::thread::spawn(move || {
                    let db = LogDb::open(Path::new(&p)).expect("open under contention");
                    for i in 0..PER_WRITER {
                        let ev = LogEvent {
                            req_id: [w as u8, i as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                            event_type: "approval_granted".into(),
                            payload_json: format!(r#"{{"writer":{w},"i":{i}}}"#),
                            timestamp: 1_700_000_000,
                        };
                        db.append(&ev).expect("append under contention");
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("writer thread panicked");
        }

        let db = LogDb::open(&path).unwrap();
        assert_eq!(
            db.count().unwrap() as usize,
            WRITERS * PER_WRITER,
            "every append must land exactly once"
        );
        assert_eq!(
            db.verify().unwrap(),
            Ok(WRITERS * PER_WRITER),
            "chain must be intact after contention"
        );
    }

    #[test]
    fn malformed_chain_column_is_reported_not_misverified() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("short.db");
        let db = LogDb::open(&path).unwrap();
        db.append(&event(9)).unwrap();
        drop(db);

        let raw = rusqlite::Connection::open(&path).unwrap();
        raw.execute("UPDATE entries SET hash = X'00112233' WHERE id = 1", [])
            .unwrap();

        let db = LogDb::open(&path).unwrap();
        match db.verify() {
            Err(StorageError::MalformedRow { row_id, .. }) => assert_eq!(row_id, 1),
            other => panic!("expected MalformedRow, got {other:?}"),
        }
    }
}
