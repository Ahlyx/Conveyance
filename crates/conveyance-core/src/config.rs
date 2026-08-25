//! Config parsing, matching the spec's "Config format" section.
//!
//! Scope in phase 0 is deliberately narrow: parse and expose. Validation
//! (timer minimums/maximums, unknown fields, malformed high-risk rules)
//! is a phase 9 deliverable and is intentionally absent here -- a half
//! done validator is worse than none, because it looks like enforcement
//! while guaranteeing nothing. Until then, garbage config parses into
//! garbage values; the daemon must not treat a successful load as a
//! safety statement.
//!
//! Loading never creates files. A missing config is an error, not an
//! invitation to write defaults to disk: a "why did this file appear
//! here" surprise is exactly the kind of side effect a tool holding
//! credentials must not have.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;

use crate::paths;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("config file not found at {path}")]
    NotFound { path: PathBuf },
    #[error("failed to read config file at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid config: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("cannot determine a config location on this platform: {0}")]
    NoConfigDir(#[from] paths::PathError),
}

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub daemon: DaemonConfig,
    #[serde(default)]
    pub session: SessionConfig,
    /// The spec's `[ble]` section exists but is intentionally empty: the
    /// service UUID is baked in, not configurable. The section is parsed
    /// (and ignored) so its presence in a user's file is not an error.
    #[serde(default)]
    pub ble: BleConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub high_risk: Vec<HighRiskRule>,
}

#[derive(Debug, Default, Deserialize)]
pub struct DaemonConfig {
    /// Unix socket path (Linux/macOS), per the spec's example.
    pub socket_path: Option<String>,
    /// Windows named pipe path, e.g. `\\.\pipe\conveyance-daemon`.
    pub named_pipe: Option<String>,
}

/// Session timer values as written by the user. The spec documents both
/// defaults and hard bounds; only the defaults are applied here. Bounds
/// are enforced by the daemon at session time (phase 3) and validated on
/// load (phase 9) -- see the module doc comment.
#[derive(Debug, Deserialize)]
pub struct SessionConfig {
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_seconds: u64,
    #[serde(default = "default_hard_cap")]
    pub hard_cap_seconds: u64,
    #[serde(default = "default_warn_before")]
    pub warn_before_seconds: u64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            idle_timeout_seconds: default_idle_timeout(),
            hard_cap_seconds: default_hard_cap(),
            warn_before_seconds: default_warn_before(),
        }
    }
}

fn default_idle_timeout() -> u64 {
    1800
}

fn default_hard_cap() -> u64 {
    14400
}

fn default_warn_before() -> u64 {
    120
}

#[derive(Debug, Default, Deserialize)]
pub struct BleConfig {}

#[derive(Debug, Default, Deserialize)]
pub struct LoggingConfig {
    /// Path template for `executions.db`. May contain `~`; expansion is
    /// the consumer's job, not the parser's.
    pub executions_db: Option<String>,
}

/// One Tier-3 escalation rule. All matchers are optional and combine as
/// AND when present; semantics are defined by the phone-side evaluator,
/// not here -- this struct only carries what was written.
#[derive(Debug, Deserialize)]
pub struct HighRiskRule {
    pub match_service: Option<String>,
    pub match_method: Option<String>,
    pub match_endpoint: Option<String>,
    pub required_tier: u8,
}

impl Config {
    /// Parse config from TOML text.
    pub fn from_toml_str(text: &str) -> Result<Self, ConfigError> {
        toml::from_str(text).map_err(ConfigError::Parse)
    }

    /// Load from an explicit path. Used by tests and, later, by CLI flags
    /// that override the platform location.
    pub fn load_from_path(path: &Path) -> Result<Self, ConfigError> {
        let text = fs::read_to_string(path).map_err(|source| match source.kind() {
            std::io::ErrorKind::NotFound => ConfigError::NotFound { path: path.into() },
            _ => ConfigError::Io {
                path: path.into(),
                source,
            },
        })?;
        Self::from_toml_str(&text)
    }

    /// Load from `<platform config dir>/config.toml`. Missing file is an
    /// error -- see the module doc comment for why loading does not
    /// auto-create one.
    pub fn load() -> Result<Self, ConfigError> {
        let dir = paths::config_dir()?;
        Self::load_from_path(&dir.join("config.toml"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The full example from the spec's "Config format" section, verbatim
    /// where possible. If this stops parsing, the parser has drifted from
    /// the spec's published shape.
    const SPEC_EXAMPLE: &str = r#"
[daemon]
socket_path = "~/.local/share/conveyance/daemon.sock"

[session]
idle_timeout_seconds  = 1800
hard_cap_seconds      = 14400
warn_before_seconds   = 120

[ble]

[logging]
executions_db = "~/.local/share/conveyance/executions.db"

[[high_risk]]
match_service    = "aws"
match_endpoint   = "*prod*"
required_tier    = 3

[[high_risk]]
match_method     = "DELETE"
required_tier    = 3
"#;

    #[test]
    fn parses_the_spec_example() {
        let cfg = Config::from_toml_str(SPEC_EXAMPLE).expect("spec example must parse");

        assert_eq!(
            cfg.daemon.socket_path.as_deref(),
            Some("~/.local/share/conveyance/daemon.sock")
        );
        assert_eq!(cfg.session.idle_timeout_seconds, 1800);
        assert_eq!(cfg.session.hard_cap_seconds, 14400);
        assert_eq!(cfg.session.warn_before_seconds, 120);
        assert_eq!(
            cfg.logging.executions_db.as_deref(),
            Some("~/.local/share/conveyance/executions.db")
        );
        assert_eq!(cfg.high_risk.len(), 2);
        assert_eq!(cfg.high_risk[0].match_service.as_deref(), Some("aws"));
        assert_eq!(cfg.high_risk[0].match_endpoint.as_deref(), Some("*prod*"));
        assert_eq!(cfg.high_risk[1].match_method.as_deref(), Some("DELETE"));
        assert!(cfg.high_risk.iter().all(|r| r.required_tier == 3));
    }

    #[test]
    fn empty_config_gets_spec_defaults() {
        let cfg = Config::from_toml_str("").expect("empty config must parse via defaults");
        assert_eq!(cfg.session.idle_timeout_seconds, 1800);
        assert_eq!(cfg.session.hard_cap_seconds, 14400);
        assert_eq!(cfg.session.warn_before_seconds, 120);
        assert!(cfg.high_risk.is_empty());
        assert!(cfg.daemon.socket_path.is_none());
        assert!(cfg.logging.executions_db.is_none());
    }

    #[test]
    fn windows_named_pipe_field_parses() {
        let cfg = Config::from_toml_str(
            "[daemon]\nnamed_pipe = \"\\\\\\\\.\\\\pipe\\\\conveyance-daemon\"\n",
        )
        .expect("named pipe form must parse");
        assert_eq!(
            cfg.daemon.named_pipe.as_deref(),
            Some("\\\\.\\pipe\\conveyance-daemon")
        );
    }

    #[test]
    fn invalid_syntax_is_a_parse_error_not_a_panic() {
        let err = Config::from_toml_str("[session\nidle=oops").unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)));
    }

    #[test]
    fn missing_required_high_risk_field_is_rejected() {
        let err = Config::from_toml_str("[[high_risk]]\nmatch_service = \"aws\"").unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)));
    }

    #[test]
    fn loads_from_explicit_path_and_reports_missing_cleanly() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.toml");

        let err = Config::load_from_path(&path).unwrap_err();
        assert!(matches!(err, ConfigError::NotFound { .. }));

        std::fs::write(&path, SPEC_EXAMPLE).unwrap();
        let cfg = Config::load_from_path(&path).unwrap();
        assert_eq!(cfg.session.idle_timeout_seconds, 1800);
    }
}
