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

use std::path::PathBuf;

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
}
