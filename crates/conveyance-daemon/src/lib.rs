//! Long-running daemon: refuse-to-start chain, IPC server, clean shutdown.
//!
//! Phase 7.0 scope: skeleton + IPC + session lifecycle plumbing.
//! Request routing arrives in 7.1.

pub mod ipc;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use std::time::Duration;

use crate::ipc::IpcError;
use conveyance_core::storage::StorageError;
use conveyance_core::storage::identity::StoredIdentity;
use conveyance_core::storage::logdb::LogDb;
use conveyance_core::storage::pairings::PairingsDb;
use interprocess::local_socket::GenericNamespaced;
use tokio::sync::Mutex;

use crate::ipc::{IpcRequest, IpcResponse};
use conveyance_core::session::Session as CoreSession;
use conveyance_core::storage::identity::OsKeyring;

// ---- config -------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct DaemonConfig {
    pub socket: String,
    pub pairings_db: PathBuf,
    pub executions_db: PathBuf,
    pub identity_file: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error("data directory unavailable: {0}")]
    DataDir(String),
    #[error(
        "OS keychain unavailable: {source}\n\
         Conveyance refuses to fall back to a passphrase.\n\
         Linux: check `systemctl --user status gnome-keyring`.\n\
         macOS: open Keychain Access.\n\
         Windows: check Credential Manager."
    )]
    KeychainUnavailable {
        #[source]
        source: StorageError,
    },
    #[error("cannot open {what}: {message}")]
    Open { what: String, message: String },
    #[error(
        "socket {socket} is already in use -- \
         is another daemon running? Check with: conveyance status"
    )]
    SocketInUse { socket: String },
    #[error("socket bind failed at {socket}: {source}")]
    SocketBind {
        socket: String,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid configuration: {0}")]
    Config(String),
}

/// Resolve raw TOML config into concrete daemon settings.
pub fn resolve_config(raw: &conveyance_core::config::Config) -> Result<DaemonConfig, StartupError> {
    let data =
        conveyance_core::paths::data_dir().map_err(|e| StartupError::DataDir(e.to_string()))?;
    let _ = conveyance_core::session::SessionParams::validated(
        Duration::from_secs(raw.session.idle_timeout_seconds),
        Duration::from_secs(raw.session.warn_before_seconds),
        Duration::from_secs(raw.session.hard_cap_seconds),
    )
    .map_err(|_| StartupError::Config("session timers violate spec bounds".into()))?;

    Ok(DaemonConfig {
        socket: raw
            .daemon
            .socket_path
            .clone()
            .unwrap_or_else(default_socket_name),
        pairings_db: data.join("pairings.db"),
        executions_db: match &raw.logging.executions_db {
            Some(p) => expand_tilde(p),
            None => data.join("executions.db"),
        },
        identity_file: data.join("identity.enc"),
    })
}

fn default_socket_name() -> String {
    #[cfg(unix)]
    {
        format!(
            "{}/conveyance-daemon.sock",
            std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".into())
        )
    }
    #[cfg(windows)]
    "\\\\.\\pipe\\conveyance-daemon".to_string()
}

fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        let home = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/"));
        home.join(rest)
    } else {
        PathBuf::from(path)
    }
}

// ---- shared state -------------------------------------------------------------

/// Shared daemon state accessed by IPC handlers.
///
/// All mutable state sits behind this struct; each handler operates on
/// individual fields through separate mutexes so concurrent shims never
/// block each other unnecessarily.
pub struct DaemonState {
    pub started_at: Instant,
    pub session: Mutex<Option<CoreSession>>,
    pub store_pairings: PairingsDb,
    pub pc_id_secret: conveyance_core::crypto::sign::IdentitySecretKey,
    pub pc_dh_secret: conveyance_core::crypto::Secret<32>,
    pub session_params: conveyance_core::session::SessionParams,
}

impl DaemonState {
    async fn status_response(&self) -> IpcResponse {
        let paired = self
            .store_pairings
            .list()
            .unwrap_or_default()
            .into_iter()
            .map(|p| p.phone_id)
            .collect();
        let session_active = self.session.lock().await.is_some();
        IpcResponse::Status {
            version: env!("CARGO_PKG_VERSION").into(),
            uptime_seconds: self.started_at.elapsed().as_secs(),
            session_active,
            paired_phones: paired,
        }
    }

    async fn dispatch(&self, req: IpcRequest) -> IpcResponse {
        match req {
            IpcRequest::Status => self.status_response().await,
            IpcRequest::CheckSession => {
                if self.session.lock().await.is_some() {
                    IpcResponse::SessionStarted
                } else {
                    no_session_error()
                }
            }
            IpcRequest::SessionEnd => {
                if self.session.lock().await.take().is_some() {
                    IpcResponse::SessionEnded
                } else {
                    IpcResponse::Ok
                }
            }
            IpcRequest::SessionStart
            | IpcRequest::AuthenticatedRequest { .. }
            | IpcRequest::ListServices => {
                if self.session.lock().await.is_none() {
                    no_session_error()
                } else {
                    spec_error("conveyance/internal", "arrives in later sub-phase", false)
                }
            }
        }
    }
}

// ---- refuse-to-start ----------------------------------------------------------

pub struct OpenStores {
    pub identity: StoredIdentity,
    pub store: PairingsDb,
    pub log: LogDb,
}

pub fn refuse_to_start(config: &DaemonConfig) -> Result<OpenStores, StartupError> {
    let parent = config.pairings_db.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)
        .map_err(|e| StartupError::DataDir(format!("{}: {e}", parent.display())))?;

    let identity =
        StoredIdentity::load(&config.identity_file, &OsKeyring).map_err(|e| match e {
            StorageError::KeychainUnavailable(_) | StorageError::KeyMaterialMissing { .. } => {
                StartupError::KeychainUnavailable { source: e }
            }
            other => StartupError::Open {
                what: format!("identity file {}", config.identity_file.display()),
                message: other.to_string(),
            },
        })?;

    let store = PairingsDb::open(&config.pairings_db).map_err(|e| StartupError::Open {
        what: format!("pairings database {}", config.pairings_db.display()),
        message: e.to_string(),
    })?;
    let log = LogDb::open(&config.executions_db).map_err(|e| StartupError::Open {
        what: format!("executions database {}", config.executions_db.display()),
        message: e.to_string(),
    })?;

    Ok(OpenStores {
        identity,
        store,
        log,
    })
}

// ---- IPC server ------------------------------------------------------------------

/// Start the IPC accept loop. Returns a shutdown sender.
/// Must be called inside a tokio runtime.
pub fn start_ipc_server(
    config: &DaemonConfig,
    state: Arc<DaemonState>,
) -> Result<tokio::sync::watch::Sender<bool>, StartupError> {
    remove_stale_socket(&config.socket);

    use interprocess::local_socket::tokio::prelude::*;
    let name = config
        .socket
        .clone()
        .to_ns_name::<GenericNamespaced>()
        .map_err(|e| StartupError::SocketBind {
            socket: config.socket.clone(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()),
        })?;
    let listener = interprocess::local_socket::ListenerOptions::new()
        .name(name)
        .create_tokio()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AddrInUse {
                StartupError::SocketInUse {
                    socket: config.socket.clone(),
                }
            } else {
                StartupError::SocketBind {
                    socket: config.socket.clone(),
                    source: e,
                }
            }
        })?;

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => return,
                conn = listener.accept() => {
                    match conn {
                        Ok(stream) => {
                            let st = state.clone();
                            let sd = shutdown_rx.clone();
                            tokio::spawn(async move {
                                let mut sd = sd;
                                tokio::select! {
                                    _ = sd.changed() => {}
                                    _ = handle_conn(stream, st) => {}
                                }
                            });
                        }
                        Err(_) => continue,
                    }
                }
            }
        }
    });

    Ok(shutdown_tx)
}

async fn handle_conn(
    mut stream: interprocess::local_socket::tokio::Stream,
    state: Arc<DaemonState>,
) {
    loop {
        let req = match read_request(&mut stream).await {
            Ok(r) => r,
            Err(_) => return,
        };
        let resp = state.dispatch(req).await;
        if write_response(&mut stream, &resp).await.is_err() {
            return;
        }
    }
}

// ---- framing -----------------------------------------------------------------------

const MAX_IPC_MESSAGE: usize = 16 * 1024 * 1024;

async fn read_request(
    stream: &mut interprocess::local_socket::tokio::Stream,
) -> Result<IpcRequest, IpcError> {
    use tokio::io::AsyncReadExt;
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.map_err(io_err)?;
    let declared = u32::from_be_bytes(len_buf) as usize;
    if declared > MAX_IPC_MESSAGE {
        return Err(IpcError::TooLarge {
            size: declared,
            cap: MAX_IPC_MESSAGE,
        });
    }
    let mut payload = vec![0u8; declared];
    stream.read_exact(&mut payload).await.map_err(io_err)?;
    ciborium::de::from_reader(&mut &payload[..])
        .map_err(|e| IpcError::Codec(format!("decode failed: {e}")))
}

async fn write_response(
    stream: &mut interprocess::local_socket::tokio::Stream,
    resp: &IpcResponse,
) -> Result<(), IpcError> {
    use tokio::io::AsyncWriteExt;
    let mut payload = Vec::new();
    ciborium::ser::into_writer(resp, &mut payload).map_err(|e| IpcError::Codec(e.to_string()))?;
    let len = (payload.len() as u32).to_be_bytes();
    stream.write_all(&len).await.map_err(io_err)?;
    stream.write_all(&payload).await.map_err(io_err)?;
    stream.flush().await.map_err(io_err)?;
    Ok(())
}

fn io_err(e: std::io::Error) -> IpcError {
    IpcError::Io(e.to_string())
}

fn spec_error(code: &str, message: &str, retryable: bool) -> IpcResponse {
    IpcResponse::Error {
        code: code.into(),
        message: message.into(),
        retryable,
    }
}

fn no_session_error() -> IpcResponse {
    IpcResponse::Error {
        code: "conveyance/no_session".into(),
        message: "No active Conveyance session. User must start one on the paired phone.".into(),
        retryable: true,
    }
}

#[cfg(unix)]
fn remove_stale_socket(socket: &str) {
    let _ = std::fs::remove_file(socket);
}
#[cfg(not(unix))]
fn remove_stale_socket(_socket: &str) {}

#[cfg(unix)]
#[allow(dead_code)]
fn cleanup_socket_file(socket: &str) {
    let _ = std::fs::remove_file(socket);
}
#[cfg(not(unix))]
#[allow(dead_code)]
fn cleanup_socket_file(_socket: &str) {}

pub use crate::ipc::single_request;
