//! `pairings.db`: the paired-phone registry.
//!
//! Rows are created by the pairing ceremony (phase 6) and consumed by
//! session start, `conveyance status`, and `conveyance unpair` (phase 7+).
//! Phase 2 delivers schema + CRUD so later phases never touch raw SQL.
//!
//! The handle a user types into `conveyance unpair <phone-id>` is derived
//! from the phone's public key (see [`phone_id_for`]), not stored as its
//! own column of invented state -- though here it IS also the primary key,
//! because deriving it is deterministic and free.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::params;
use sha2::{Digest, Sha256};

use crate::crypto::hex_encode;

use super::{DbKind, StorageError, migrate::run_migrations, open_connection, recover_mutex};

/// Derive the user-facing phone handle from the phone's Ed25519 public
/// key: first 16 lowercase hex chars of SHA-256(pubkey), per the spec's
/// Revocation section.
///
/// // SECURITY NOTE: this is a stable pseudonymous identifier. It is fine
/// in local output (`conveyance status`, `unpair`) because anyone with the
/// pubkey can recompute it. It must NOT be pasted into externally shared
/// contexts (support logs, telemetry, screenshots) without thought: it is
/// an identity-correlation handle. If a future feature needs a shareable
/// label, generate a random one at pairing time instead of reaching for
/// this value.
pub fn phone_id_for(id_pub: &[u8; 32]) -> String {
    // First 8 bytes of the digest -> 16 lowercase hex chars.
    hex_encode(&Sha256::digest(id_pub)[..8])
}

/// One paired-phone record.
#[derive(Clone, Debug, PartialEq)]
pub struct PairingRecord {
    pub phone_id: String,
    pub id_pub: [u8; 32],
    pub dh_pub: [u8; 32],
    /// Unix seconds at pairing.
    pub paired_at: i64,
    /// Unix seconds of last session end; null until phase 7 starts
    /// writing sessions.
    pub last_session_at: Option<i64>,
}

pub struct PairingsDb {
    conn: Mutex<rusqlite::Connection>,
    path: PathBuf,
}

impl PairingsDb {
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        let mut conn = open_connection(path)?;
        run_migrations(&mut conn, DbKind::Pairings)?;
        Ok(Self {
            conn: Mutex::new(conn),
            path: path.to_path_buf(),
        })
    }

    /// Insert or refresh a pairing. Re-pairing the same phone (same
    /// id_pub) updates the row rather than duplicating it, per the spec's
    /// re-pairing flow. Returns the record as stored.
    pub fn record(
        &self,
        id_pub: [u8; 32],
        dh_pub: [u8; 32],
        paired_at: i64,
    ) -> Result<PairingRecord, StorageError> {
        let phone_id = phone_id_for(&id_pub);
        let conn = recover_mutex(self.conn.lock());
        conn.execute(
            r#"
            INSERT INTO pairings (phone_id, id_pub, dh_pub, paired_at, last_session_at)
            VALUES (?1, ?2, ?3, ?4, NULL)
            ON CONFLICT(id_pub) DO UPDATE SET
              phone_id = excluded.phone_id,
              dh_pub = excluded.dh_pub,
              paired_at = excluded.paired_at
            "#,
            params![phone_id, id_pub.to_vec(), dh_pub.to_vec(), paired_at],
        )
        .map_err(|source| StorageError::Db {
            path: self.path.clone(),
            source,
        })?;

        Ok(PairingRecord {
            phone_id,
            id_pub,
            dh_pub,
            paired_at,
            last_session_at: None,
        })
    }

    pub fn list(&self) -> Result<Vec<PairingRecord>, StorageError> {
        let conn = recover_mutex(self.conn.lock());
        let mut stmt = conn.prepare(
            "SELECT phone_id, id_pub, dh_pub, paired_at, last_session_at FROM pairings ORDER BY paired_at",
        ).map_err(|source| StorageError::Db { path: self.path.clone(), source })?;

        let rows = stmt
            .query_map([], |row| {
                Ok(RawRow {
                    phone_id: row.get(0)?,
                    id_pub: row.get(1)?,
                    dh_pub: row.get(2)?,
                    paired_at: row.get(3)?,
                    last_session_at: row.get(4)?,
                })
            })
            .map_err(|source| StorageError::Db {
                path: self.path.clone(),
                source,
            })?;

        let mut out = Vec::new();
        for row in rows {
            let raw = row.map_err(|source| StorageError::Db {
                path: self.path.clone(),
                source,
            })?;
            out.push(PairingRecord {
                phone_id: raw.phone_id,
                id_pub: blob32(raw.id_pub).map_err(|_| StorageError::MalformedRow {
                    path: self.path.clone(),
                    row_id: -1,
                })?,
                dh_pub: blob32(raw.dh_pub).map_err(|_| StorageError::MalformedRow {
                    path: self.path.clone(),
                    row_id: -1,
                })?,
                paired_at: raw.paired_at,
                last_session_at: raw.last_session_at,
            });
        }
        Ok(out)
    }

    /// Remove by phone_id. Returns false if no such pairing existed --
    /// `unpair` on a stale id is a no-op, not an error.
    pub fn remove(&self, phone_id: &str) -> Result<bool, StorageError> {
        let conn = recover_mutex(self.conn.lock());
        let changed = conn
            .execute(
                "DELETE FROM pairings WHERE phone_id = ?1",
                params![phone_id],
            )
            .map_err(|source| StorageError::Db {
                path: self.path.clone(),
                source,
            })?;
        Ok(changed > 0)
    }

    /// Fold the write-ahead log back into the main database file. See
    /// `LogDb::checkpoint` for why this exists (clean-shutdown step).
    pub fn checkpoint(&self) -> Result<(), StorageError> {
        let conn = recover_mutex(self.conn.lock());
        let _: (i64, i64, i64) = conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(|source| StorageError::Db {
                path: self.path.clone(),
                source,
            })?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn count(&self) -> Result<i64, StorageError> {
        let conn = recover_mutex(self.conn.lock());
        conn.query_row("SELECT count(*) FROM pairings", [], |r| r.get(0))
            .map_err(|source| StorageError::Db {
                path: self.path.clone(),
                source,
            })
    }
}

struct RawRow {
    phone_id: String,
    id_pub: Vec<u8>,
    dh_pub: Vec<u8>,
    paired_at: i64,
    last_session_at: Option<i64>,
}

fn blob32(v: Vec<u8>) -> Result<[u8; 32], Vec<u8>> {
    <[u8; 32]>::try_from(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn phone_id_is_deterministic_16_lowercase_hex() {
        let a = phone_id_for(&key(1));
        let b = phone_id_for(&key(1));
        assert_eq!(a, b);
        assert_eq!(a.len(), 16);
        assert!(
            a.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_ne!(phone_id_for(&key(2)), a);
    }

    #[test]
    fn record_list_remove_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let db = PairingsDb::open(&dir.path().join("p.db")).unwrap();

        let rec = db.record(key(1), key(2), 1_700_000_000).unwrap();
        assert_eq!(rec.phone_id, phone_id_for(&key(1)));
        assert_eq!(db.count().unwrap(), 1);

        let listed = db.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id_pub, key(1));
        assert_eq!(listed[0].dh_pub, key(2));
        assert_eq!(listed[0].paired_at, 1_700_000_000);
        assert_eq!(listed[0].last_session_at, None);

        assert!(db.remove(&rec.phone_id).unwrap());
        assert!(
            !db.remove(&rec.phone_id).unwrap(),
            "second removal is a no-op"
        );
        assert_eq!(db.count().unwrap(), 0);
    }

    #[test]
    fn re_pairing_same_phone_updates_not_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        let db = PairingsDb::open(&dir.path().join("p.db")).unwrap();

        db.record(key(7), key(8), 1000).unwrap();
        let again = db.record(key(7), key(9), 2000).unwrap();

        assert_eq!(db.count().unwrap(), 1);
        let listed = db.list().unwrap();
        assert_eq!(listed[0].dh_pub, key(9));
        assert_eq!(listed[0].paired_at, 2000);
        assert_eq!(again.phone_id, listed[0].phone_id);
    }

    #[test]
    fn records_survive_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.db");

        {
            let db = PairingsDb::open(&path).unwrap();
            db.record(key(3), key(4), 1234).unwrap();
        } // dropped

        let db = PairingsDb::open(&path).unwrap();
        assert_eq!(db.count().unwrap(), 1);
        assert_eq!(db.list().unwrap()[0].id_pub, key(3));
    }
}
