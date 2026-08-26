//! Daemon-shim IPC: framed CBOR request/response over a local socket.
//!
//! Internal protocol (not spec'd externally): 4-byte big-endian length
//! prefix, then CBOR-encoded [`IpcRequest`] / [`IpcResponse`].
//!
//! The 4-byte prefix allows up to 4 GiB on paper; [`MAX_IPC_MESSAGE`]
//! is what the reader actually enforces. Same posture as phase 4's
//! reassembly cap: the format allows more than we intend to accept.
//!
//! Client helpers here are used by the CLI (`status`, `session start`,
//! `session end`) so both sides share one codec and one framing.

use interprocess::local_socket::tokio::Stream;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Reader-enforced ceiling on a single IPC message. 16 MiB is generous
/// for anything the shim legitimately sends (request params are JSON),
/// small enough that a runaway or hostile client cannot OOM the daemon.
pub const MAX_IPC_MESSAGE: usize = 16 * 1024 * 1024;
const LEN_PREFIX: usize = 4;

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("daemon socket not found at {path} -- is the daemon running?")]
    NotRunning { path: String },
    #[error("IPC message exceeds limit ({size} > {cap})")]
    TooLarge { size: usize, cap: usize },
    #[error("connection closed by peer")]
    Disconnected,
    #[error("IPC codec error: {0}")]
    Codec(String),
    #[error("IPC io error: {0}")]
    Io(String),
}

impl From<std::io::Error> for IpcError {
    fn from(e: std::io::Error) -> Self {
        // Deliberately no NotFound => NotRunning mapping here: only the
        // CONNECT site knows which endpoint failed (and can name it in
        // the error). Mid-connection ENOENT means something else
        // entirely and must not masquerade as "daemon not running".
        IpcError::Io(e.to_string())
    }
}

// ---- protocol ----------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum IpcRequest {
    /// Begin scanning for the paired phone and establish the Noise
    /// session. Errors with `phone_unreachable` on timeout.
    SessionStart,
    /// End any active session. Idempotent.
    SessionEnd,
    AuthenticatedRequest {
        service: String,
        method: String,
        endpoint: String,
        params: serde_json::Value,
        requested_by: Option<String>,
    },
    ListServices,
    /// Current session state only (timers, active flag).
    CheckSession,
    /// Broader daemon view: version, uptime, paired phones, session.
    Status,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum IpcResponse {
    Ok,
    SessionStarted,
    SessionEnded,
    SessionActive {
        idle_seconds_remaining: u64,
        hard_cap_seconds_remaining: u64,
    },
    Services(Vec<String>),
    Status {
        version: String,
        uptime_seconds: u64,
        session_active: bool,
        paired_phones: Vec<String>,
    },
    Body(serde_json::Value),
    /// Structured error carrying exactly the spec's five-field shape.
    Error {
        code: String,
        message: String,
        retryable: bool,
    },
}

pub async fn write_message(stream: &mut Stream, req: &IpcRequest) -> Result<(), IpcError> {
    let mut payload = Vec::new();
    ciborium_encode(req, &mut payload)?;
    if payload.len() > MAX_IPC_MESSAGE {
        return Err(IpcError::TooLarge {
            size: payload.len(),
            cap: MAX_IPC_MESSAGE,
        });
    }
    let len = (payload.len() as u32).to_be_bytes();
    use tokio::io::AsyncWriteExt;
    stream.write_all(&len).await?;
    stream.write_all(&payload).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn read_response(stream: &mut Stream) -> Result<IpcResponse, IpcError> {
    use tokio::io::AsyncReadExt;
    let mut len_buf = [0u8; LEN_PREFIX];
    match stream.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(IpcError::Disconnected);
        }
        Err(e) => return Err(e.into()),
    }
    let declared = u32::from_be_bytes(len_buf) as usize;
    if declared > MAX_IPC_MESSAGE {
        return Err(IpcError::TooLarge {
            size: declared,
            cap: MAX_IPC_MESSAGE,
        });
    }
    let mut payload = vec![0u8; declared];
    stream.read_exact(&mut payload).await?;
    ciborium_decode(&payload)
}

fn ciborium_encode<T: Serialize>(v: &T, out: &mut Vec<u8>) -> Result<(), IpcError> {
    ciborium::ser::into_writer(v, out).map_err(|e| IpcError::Codec(e.to_string()))
}

fn ciborium_decode<T>(bytes: &[u8]) -> Result<T, IpcError>
where
    T: serde::de::DeserializeOwned,
{
    ciborium::de::from_reader(&mut &bytes[..])
        .map_err(|e| IpcError::Codec(format!("decode failed: {e}")))
}

// ---- client --------------------------------------------------------------

/// Platform interpretation of a configured socket identity, shared by
/// the daemon listener and every client so both sides always land on
/// the same endpoint.
///
/// * A Unix absolute path is a filesystem socket path (the spec's
///   `socket_path` knob).
/// * Anything else is a NAMESPACED name: abstract namespace on Linux,
///   `/tmp/<name>` on other Unices, `\\.\pipe\<name>` on Windows.
///   Namespaced names are what tests use -- unique per test, no
///   filesystem cleanup, identical semantics across platforms.
pub fn local_name(socket: &str) -> Result<interprocess::local_socket::Name<'_>, IpcError> {
    #[cfg(unix)]
    use interprocess::local_socket::{GenericFilePath, ToFsName};
    use interprocess::local_socket::{GenericNamespaced, ToNsName};

    #[cfg(unix)]
    {
        if socket.starts_with('/') {
            return socket
                .to_fs_name::<GenericFilePath>()
                .map_err(|e| IpcError::Io(format!("invalid socket path {socket}: {e}")));
        }
    }
    socket
        .to_ns_name::<GenericNamespaced>()
        .map_err(|e| IpcError::Io(format!("invalid socket name {socket}: {e}")))
}

/// Connect to the daemon at `socket` and perform one request/response
/// exchange. Used by CLI subcommands; the daemon-side listener lives in
/// the server loop instead.
pub async fn single_request(socket: &str, req: IpcRequest) -> Result<IpcResponse, IpcError> {
    use interprocess::local_socket::tokio::prelude::*;

    let name = local_name(socket)?;
    let mut stream = Stream::connect(name).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            IpcError::NotRunning {
                path: socket.to_string(),
            }
        } else if e.kind() == std::io::ErrorKind::TimedOut {
            // Windows pipe connect can surface as timeout when the name
            // simply does not exist; from the caller's seat that reads
            // identically to "no daemon".
            IpcError::NotRunning {
                path: socket.to_string(),
            }
        } else {
            IpcError::Io(e.to_string())
        }
    })?;
    write_message(&mut stream, &req).await?;
    read_response(&mut stream).await
}
