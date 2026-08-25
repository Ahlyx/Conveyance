//! Schema creation for both databases, via ordered migrations.
//!
//! Each migration is a named SQL script applied in its own transaction
//! together with the `PRAGMA user_version` bump. SQLite DDL is
//! transactional, so a crash mid-migration leaves either the old schema
//! with the old version or the new schema with the new version -- never
//! a half-migrated database claiming to be current.
//!
//! Migrations are append-only by discipline: editing an already-shipped
//! entry would leave real databases on a schema that no longer matches
//! what the code expects, with no error anywhere.

use rusqlite::Connection;
use std::path::PathBuf;

use super::StorageError;

/// Which logical database a connection holds. Each has an independent
/// migration list; schemas are not shared (the spec keeps the two logs'
/// concerns deliberately separate).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DbKind {
    Executions,
    Pairings,
}

fn migrations(kind: DbKind) -> &'static [(&'static str, &'static str)] {
    match kind {
        DbKind::Executions => &[(
            "entries table + indexes",
            // Verbatim from the spec's "Logging" section. prev_hash is
            // NOT NULL here because our genesis is 32 zero bytes --
            // always representable, unlike auditmcp's nullable-text
            // sentinel scheme.
            r#"
                CREATE TABLE entries (
                  id            INTEGER PRIMARY KEY AUTOINCREMENT,
                  req_id        BLOB NOT NULL,
                  event_type    TEXT NOT NULL,
                  payload_json  TEXT NOT NULL,
                  timestamp     INTEGER NOT NULL,
                  prev_hash     BLOB NOT NULL,
                  hash          BLOB NOT NULL UNIQUE
                );
                CREATE INDEX idx_req_id ON entries(req_id);
                CREATE INDEX idx_timestamp ON entries(timestamp);
                "#,
        )],
        DbKind::Pairings => &[(
            "pairings table",
            r#"
            CREATE TABLE pairings (
              phone_id        TEXT PRIMARY KEY,
              id_pub          BLOB NOT NULL UNIQUE,
              dh_pub          BLOB NOT NULL UNIQUE,
              paired_at       INTEGER NOT NULL,
              last_session_at INTEGER
            );
            "#,
        )],
    }
}

/// Bring `conn` up to the latest schema for `kind`. Idempotent: opens on
/// an already-current database apply nothing.
pub(crate) fn run_migrations(conn: &mut Connection, kind: DbKind) -> Result<(), StorageError> {
    let db_path = PathBuf::from(conn.path().unwrap_or_default());
    let current: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|e| StorageError::Db {
            path: db_path.clone(),
            source: e,
        })?;

    for (index, (name, sql)) in migrations(kind).iter().enumerate() {
        let version = index as i64 + 1;
        if current >= version {
            continue;
        }

        let fail = |source: rusqlite::Error| StorageError::MigrationFailed {
            name,
            path: db_path.clone(),
            source,
        };

        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(fail)?;
        // execute_batch runs the whole script; a failure aborts before any
        // DDL lands (SQLite DDL is transactional).
        tx.execute_batch(sql).map_err(fail)?;
        tx.pragma_update(None, "user_version", version)
            .map_err(fail)?;
        tx.commit().map_err(fail)?;
    }

    Ok(())
}

#[cfg(test)]
pub(crate) fn user_version(conn: &Connection) -> Result<i64, rusqlite::Error> {
    conn.query_row("PRAGMA user_version", [], |row| row.get(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db(name: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(name);
        (dir, path)
    }

    #[test]
    fn migrations_apply_and_are_idempotent() {
        let (_dir, path) = temp_db("exec.db");

        let mut conn = super::super::open_connection(&path).unwrap();
        run_migrations(&mut conn, DbKind::Executions).unwrap();
        assert_eq!(user_version(&conn).unwrap(), 1);

        // Objects exist exactly once.
        let tables: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='entries'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(tables, 1);
        let indexes: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(indexes, 2);

        // Re-running must change nothing and error nowhere.
        run_migrations(&mut conn, DbKind::Executions).unwrap();
        assert_eq!(user_version(&conn).unwrap(), 1);
    }

    #[test]
    fn pairings_schema_applies_independently() {
        let (_dir, path) = temp_db("pair.db");
        let mut conn = super::super::open_connection(&path).unwrap();

        run_migrations(&mut conn, DbKind::Pairings).unwrap();
        assert_eq!(user_version(&conn).unwrap(), 1);
        // Executions migrations were NOT applied to this DB.
        let entries: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE name='entries'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(entries, 0);

        run_migrations(&mut conn, DbKind::Pairings).unwrap();
        assert_eq!(user_version(&conn).unwrap(), 1);
    }

    /// A fresh DB at user_version 0 gets exactly the shipped migrations;
    /// this pins that nobody accidentally bumps LATEST without adding a
    /// migration entry (which would silently skip schema).
    #[test]
    fn fresh_database_reaches_version_matching_migration_count() {
        let (_dir, path) = temp_db("fresh.db");
        let mut conn = super::super::open_connection(&path).unwrap();
        run_migrations(&mut conn, DbKind::Executions).unwrap();
        assert_eq!(
            user_version(&conn).unwrap(),
            migrations(DbKind::Executions).len() as i64
        );
    }
}
