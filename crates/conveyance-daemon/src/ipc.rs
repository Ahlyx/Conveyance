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

/// Which io::ErrorKind values from a failed IPC connect mean "nothing
/// is listening at this address" -- i.e. the daemon is not running and
/// starting one may help (retryable). Enumerated explicitly, with the
/// platform flavor each kind covers, rather than a catch-all: an
/// unmapped kind must surface as a loud unknown error, never silently
/// masquerade as "daemon not running".
///
/// * [`ErrorKind::NotFound`] -- the ADDRESS ITSELF does not exist.
///   Windows: named pipe absent (`ERROR_FILE_NOT_FOUND` from
///   CreateFile). macOS/other Unices using filesystem sockets: path
///   absent (ENOENT).
/// * [`ErrorKind::ConnectionRefused`] -- the address exists but no
///   listener accepted: Linux abstract-namespace connect to an
///   unbound name (ECONNREFUSED), and Unix-domain connects to a bound
///   but listener-less socket on Linux/macOS alike. This is the
///   flavor Linux CI actually produces for our namespaced names.
/// * [`ErrorKind::TimedOut`] -- Windows named-pipe opens can surface
///   as timeout when the pipe name does not exist; from the caller's
///   seat it reads identically to "no daemon". Kept deliberately,
///   documented quirk of the Windows pipe namespace.
///
/// Deliberately NOT mapped: PermissionDenied (a daemon IS there --
/// access is the problem, "not running" would be a lie),
/// ConnectionReset/NotConnected (mid-transport conditions, not
/// connect-phase absence), AddrInUse (server-side bind only).
fn is_daemon_unreachable(kind: std::io::ErrorKind) -> bool {
    matches!(
        kind,
        std::io::ErrorKind::NotFound
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::TimedOut
    )
}

/// Apply the daemon-unreachable classification to a failed connect.
pub(crate) fn map_connect_error(e: std::io::Error, socket: &str) -> IpcError {
    if is_daemon_unreachable(e.kind()) {
        IpcError::NotRunning {
            path: socket.to_string(),
        }
    } else {
        IpcError::Io(e.to_string())
    }
}

/// Connect to the daemon at `socket` and perform one request/response
/// exchange. Used by CLI subcommands; the daemon-side listener lives in
/// the server loop instead.
pub async fn single_request(socket: &str, req: IpcRequest) -> Result<IpcResponse, IpcError> {
    use interprocess::local_socket::tokio::prelude::*;

    let name = local_name(socket)?;
    let mut stream = Stream::connect(name)
        .await
        .map_err(|e| map_connect_error(e, socket))?;
    write_message(&mut stream, &req).await?;
    read_response(&mut stream).await
}

#[cfg(test)]
mod connect_error_tests {
    use super::*;
    use std::io::ErrorKind;

    /// Regression matrix for the phase-9 Ubuntu CI failure: Linux's
    /// abstract-namespace connect to an unbound name yields
    /// ConnectionRefused, which previously fell through the mapping and
    /// reached clients as non-retryable. Each row pins ONE kind, the
    /// platform flavor that produces it, and the required verdict -- a
    /// future refactor cannot silently drop a flavor.
    #[test]
    fn unreachable_flavors_map_to_not_running_per_platform() {
        let cases: &[(ErrorKind, &str, bool)] = &[
            // Windows: CreateFile on an absent pipe name.
            (ErrorKind::NotFound, "windows: pipe name absent", true),
            // macOS / filesystem-socket platforms: ENOENT on path.
            (
                ErrorKind::NotFound,
                "unix: socket path absent (ENOENT)",
                true,
            ),
            // Linux abstract namespace + any listener-less UDS:
            // ECONNREFUSED.
            (
                ErrorKind::ConnectionRefused,
                "linux: abstract ns unbound (ECONNREFUSED)",
                true,
            ),
            // Windows quirk: absent pipe can surface as timeout.
            (ErrorKind::TimedOut, "windows: pipe open timeout", true),
            // A daemon IS listening; access is the problem. Must stay
            // unmapped -- "not running" would misdirect the user.
            (
                ErrorKind::PermissionDenied,
                "any: socket exists, access denied",
                false,
            ),
            // Mid-transport conditions, not connect-phase absence.
            (
                ErrorKind::ConnectionReset,
                "any: reset during exchange",
                false,
            ),
            (ErrorKind::NotConnected, "any: transport torn down", false),
        ];

        for (kind, flavor, expect_unreachable) in cases {
            let err = std::io::Error::new(*kind, *flavor);
            let mapped = map_connect_error(err, "test-socket");
            match (*expect_unreachable, mapped) {
                (true, IpcError::NotRunning { path }) => {
                    assert_eq!(path, "test-socket");
                }
                (false, IpcError::Io(_)) => {}
                (expected, actual) => panic!(
                    "flavor '{flavor}' ({kind:?}): expected unreachable={expected}, got {actual:?}"
                ),
            }
        }
    }

    /// The kind-based mapping relies on std's OS-error normalization;
    /// pin the two errnos Linux/macOS actually produce for absence and
    /// refusal so an OS/toolchain change cannot shift them unnoticed.
    #[cfg(unix)]
    #[test]
    fn os_errnos_normalize_to_the_kinds_we_enumerate() {
        // ENOENT (POSIX-fixed value 2).
        assert_eq!(
            std::io::Error::from_raw_os_error(2).kind(),
            ErrorKind::NotFound
        );
        // ECONNREFUSED (Linux 111; macOS 61 normalizes to the same kind).
        assert_eq!(
            std::io::Error::from_raw_os_error(111).kind(),
            ErrorKind::ConnectionRefused
        );
        #[cfg(target_os = "macos")]
        assert_eq!(
            std::io::Error::from_raw_os_error(61).kind(),
            ErrorKind::ConnectionRefused
        );
    }

    /// End-to-end flavor proof: a REAL local-socket connect against a
    /// name nobody serves must classify as NotRunning on EVERY
    /// platform, whatever OS error it surfaces as underneath. This is
    /// the exact path the shim's
    /// `daemon_unreachable_maps_to_structured_internal_error` test
    /// exercises; it failed on Ubuntu before ConnectionRefused was
    /// enumerated.
    #[tokio::test]
    async fn real_connect_to_absent_daemon_is_not_running() {
        use interprocess::local_socket::tokio::prelude::*;

        let unique = format!(
            "conveyance-absent-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let name = local_name(&unique).unwrap();
        let connect = Stream::connect(name).await;
        let err = match connect {
            Err(e) => e,
            Ok(_) => panic!("nothing serves this name; connect must fail"),
        };

        assert!(
            is_daemon_unreachable(err.kind()),
            "platform produced kind {:?} ({err}) which we do not recognize as \
             daemon-unreachable -- add this kind to the enumeration if it is \
             genuinely an absence flavor",
            err.kind()
        );
        match map_connect_error(err, &unique) {
            IpcError::NotRunning { path } => assert_eq!(path, unique),
            other => panic!("expected NotRunning, got {other:?}"),
        }
    }
}
