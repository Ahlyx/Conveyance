//! Platform-appropriate config and data directories, per the spec's
//! "Storage layout" section:
//!
//! | Platform | Config                                    | Data                     |
//! |----------|-------------------------------------------|--------------------------|
//! | Linux    | `$XDG_CONFIG_HOME/conveyance`             | `$XDG_DATA_HOME/conveyance` |
//! | macOS    | `~/Library/Application Support/conveyance`| same as config           |
//! | Windows  | `%APPDATA%\conveyance`                    | `%LOCALAPPDATA%\conveyance` |
//!
//! Resolution is delegated to the `dirs` crate rather than hand-rolled:
//! the XDG fallback rules and Windows folder-ID lookups have edge cases
//! that are easy to get subtly wrong and invisible until someone's home
//! directory is not where you assumed.

use std::path::{Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PathError {
    #[error(
        "could not locate a config directory on this platform (XDG_CONFIG_HOME/HOME or APPDATA unset?)"
    )]
    ConfigDirUnavailable,
    #[error(
        "could not locate a data directory on this platform (XDG_DATA_HOME/HOME or LOCALAPPDATA unset?)"
    )]
    DataDirUnavailable,
}

/// Directory holding `config.toml`.
pub fn config_dir() -> Result<PathBuf, PathError> {
    dirs::config_dir()
        .map(|base| base.join("conveyance"))
        .ok_or(PathError::ConfigDirUnavailable)
}

/// Directory holding state that must not silently travel between machines
/// with the user: databases, logs, sockets.
///
/// On Windows this is deliberately `%LOCALAPPDATA%`, *not* the roaming
/// profile that `dirs::data_dir()` would return there. A hash-chained
/// execution log and an identity blob are machine-bound state; letting
/// roaming sync duplicate them across machines would produce divergent
/// chains and confusing forensic questions. Linux and macOS have no such
/// split, so `dirs::data_dir()` is correct there.
pub fn data_dir() -> Result<PathBuf, PathError> {
    #[cfg(windows)]
    let base = dirs::data_local_dir().ok_or(PathError::DataDirUnavailable);
    #[cfg(not(windows))]
    let base = dirs::data_dir().ok_or(PathError::DataDirUnavailable);

    base.map(|dir| dir.join("conveyance"))
}

/// The three on-disk artifacts the daemon and the CLI both address, under
/// one data directory. Filenames are fixed by the spec's "Storage
/// layout" section; this is the single place they are spelled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataPaths {
    /// `identity.enc` -- the encrypted long-term PC identity.
    pub identity: PathBuf,
    /// `pairings.db` -- paired-phone registry.
    pub pairings: PathBuf,
    /// `executions.db` -- hash-chained execution log.
    pub executions: PathBuf,
}

impl DataPaths {
    /// The three paths under an explicit directory (a `--data-dir`
    /// override, or a test's temp dir).
    pub fn under(dir: &Path) -> Self {
        Self {
            identity: dir.join("identity.enc"),
            pairings: dir.join("pairings.db"),
            executions: dir.join("executions.db"),
        }
    }

    /// Resolve under `base` when given, otherwise under the platform
    /// [`data_dir`].
    pub fn resolve(base: Option<PathBuf>) -> Result<Self, PathError> {
        let dir = match base {
            Some(d) => d,
            None => data_dir()?,
        };
        Ok(Self::under(&dir))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// These assertions are intentionally weak: they hold on all three
    /// supported platforms without assuming anything about usernames,
    /// drive letters, or which env vars are set. The per-platform mapping
    /// itself is the `dirs` crate's tested contract; what we own here is
    /// the choice of dirs API and the "conveyance" suffix.
    #[test]
    fn config_dir_is_absolute_and_scoped() {
        let dir = config_dir().expect("config dir should resolve on every supported platform");
        assert!(dir.is_absolute(), "not absolute: {dir:?}");
        assert_eq!(dir.file_name().and_then(|n| n.to_str()), Some("conveyance"));
    }

    #[test]
    fn data_dir_is_absolute_and_scoped() {
        let dir = data_dir().expect("data dir should resolve on every supported platform");
        assert!(dir.is_absolute(), "not absolute: {dir:?}");
        assert_eq!(dir.file_name().and_then(|n| n.to_str()), Some("conveyance"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_data_dir_is_local_not_roaming() {
        // The whole point of using LOCALAPPDATA: see doc comment above.
        let dir = data_dir().unwrap();
        let local = std::env::var("LOCALAPPDATA").expect("LOCALAPPDATA set on Windows");
        assert!(dir.starts_with(local), "{dir:?} not under LOCALAPPDATA");
    }

    #[test]
    fn data_paths_use_the_spec_filenames() {
        let dp = DataPaths::under(std::path::Path::new("/base"));
        assert_eq!(dp.identity.file_name().unwrap(), "identity.enc");
        assert_eq!(dp.pairings.file_name().unwrap(), "pairings.db");
        assert_eq!(dp.executions.file_name().unwrap(), "executions.db");

        // resolve(Some(..)) is just under() with the override.
        assert_eq!(
            DataPaths::resolve(Some("/base".into())).unwrap(),
            DataPaths::under(std::path::Path::new("/base"))
        );
        // resolve(None) lands under the platform data dir.
        assert_eq!(
            DataPaths::resolve(None).unwrap().pairings,
            data_dir().unwrap().join("pairings.db")
        );
    }
}
