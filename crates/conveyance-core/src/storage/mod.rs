//! Persistent storage for the PC side: SQLite databases and the
//! encrypted identity file, per the spec's "Storage layout" section.
//!
//! Layout of this module:
//!
//! * [`migrate`] — schema creation via ordered migrations tracked by
//!   `PRAGMA user_version`, so a future schema change is a new entry in
//!   a list rather than an edit to old SQL.
//! * [`logdb`] — `executions.db`: append-only hash-chained log. The
//!   chain math lives in [`crate::crypto::hashchain`]; this layer only
//!   persists what that module computes and feeds stored rows back to
//!   it for verification. Re-implementing hashing here would let the
//!   two drift apart silently.
//! * [`pairings`] — `pairings.db`: paired-phone records.
//! * [`identity`] — `identity.enc`: long-term PC keys encrypted under a
//!   key derived from one stored in the OS keychain.
//!
//! Concurrency posture differs from auditmcp's on purpose. auditmcp's
//! logging is fail-open — dropping an audit row beats blocking a proxied
//! tool call — so it buffers writes behind a background thread. Our log
//! is authoritative and fail-closed: an execution that cannot be logged
//! must not happen. Appends are therefore synchronous, made safe under
//! contention by the same two properties auditmcp documents:
//! `BEGIN IMMEDIATE` (write lock taken at BEGIN, so two writers cannot
//! both chain off one head) and reading the head *inside* that
//! transaction (a cached or caller-supplied head can be stale the
//! instant another process commits).

pub mod identity;
pub mod logdb;
pub mod logdiff;
pub mod migrate;
pub mod pairings;

pub(crate) use migrate::DbKind;

use std::path::{Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("database error at {path}: {source}")]
    Db {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },
    #[error("row {row_id} in {path} has a malformed chain column (expected 32 bytes)")]
    MalformedRow { path: PathBuf, row_id: i64 },
    #[error("migration '{name}' failed on {path}: {source}")]
    MigrationFailed {
        name: &'static str,
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },
    #[error("io error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("identity file not found at {0}")]
    IdentityFileNotFound(PathBuf),
    #[error(transparent)]
    Crypto(#[from] crate::crypto::CryptoError),
    #[error("identity file at {0} is not readable as a Conveyance identity file")]
    IdentityFileCorrupt(PathBuf),
    #[error("identity file format version {found} is not supported by this build")]
    IdentityVersionUnsupported { found: u8 },
    #[error("identity decryption failed -- wrong key or corrupted file")]
    IdentityDecryptFailed,
    #[error("OS keychain unavailable: {0}")]
    KeychainUnavailable(String),
    #[error(
        "no key material named '{account}' in the OS keychain; \
         an identity must be generated before it can be loaded"
    )]
    KeyMaterialMissing { account: String },
}

/// Keychain service name. Deliberately short -- this string shows up in
/// Keychain Access.app and equivalent UIs, where users can actually read
/// it. The account name (`pc-identity-kek-v1`) carries the version suffix
/// so a future KEK scheme rotates alongside, never colliding.
pub const KEYCHAIN_SERVICE: &str = "conveyance";

impl StorageError {
    /// The spec error-model code this maps to, where one exists. Only
    /// keychain unavailability has a named code in v1; everything else
    /// here is internal to the daemon and surfaces through it.
    pub fn spec_code(&self) -> Option<&'static str> {
        match self {
            StorageError::KeychainUnavailable(_) => Some("conveyance/keychain_unavailable"),
            _ => None,
        }
    }
}

/// Open (creating if needed) a database file with the pragmas every
/// Conveyance DB expects. Mirrors auditmcp's connection setup:
///
/// * WAL mode — concurrent readers during a write, crash-safe;
/// * synchronous=NORMAL — WAL's recommended pairing, no durability loss
///   worth worrying about at our scale;
/// * foreign_keys=ON — declared constraints are enforced, not decorative;
/// * busy_timeout(5s) — a second writer's BEGIN IMMEDIATE waits its turn
///   instead of failing instantly with SQLITE_BUSY. 5s is far beyond any
///   realistic single insert; hitting it means something is genuinely wedged.
pub(crate) fn open_connection(path: &Path) -> Result<rusqlite::Connection, StorageError> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|e| StorageError::Db {
            path: path.to_path_buf(),
            source: rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CANTOPEN),
                Some(e.to_string()),
            ),
        })?;
    }

    let conn = rusqlite::Connection::open(path).map_err(|source| StorageError::Db {
        path: path.to_path_buf(),
        source,
    })?;

    conn.busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|source| StorageError::Db {
            path: path.to_path_buf(),
            source,
        })?;
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(|source| StorageError::Db {
            path: path.to_path_buf(),
            source,
        })?;
    conn.pragma_update(None, "synchronous", "NORMAL")
        .map_err(|source| StorageError::Db {
            path: path.to_path_buf(),
            source,
        })?;
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(|source| StorageError::Db {
            path: path.to_path_buf(),
            source,
        })?;

    Ok(conn)
}

/// Lock-acquisition for the shared connections. A panic in one thread
/// while holding the mutex poisons it, but SQLite guarantees the
/// transaction rolled back, so the data is consistent -- recovering the
/// inner connection is correct and better than cascading poisoning into
/// unrelated requests.
pub(crate) fn recover_mutex<'a, T>(
    guard: Result<
        std::sync::MutexGuard<'a, T>,
        std::sync::PoisonError<std::sync::MutexGuard<'a, T>>,
    >,
) -> std::sync::MutexGuard<'a, T> {
    guard.unwrap_or_else(std::sync::PoisonError::into_inner)
}
