//! Socket lifecycle: bind, accept loop, clean shutdown.
//!
//! Two properties the phases doc demands live here:
//!
//! * *Refuse to start when another daemon owns the name* -- decided by
//!   PROBING (dialing) the endpoint, not by trusting create errors. On
//!   Windows a named pipe can exist in several listener instances, so
//!   "create succeeded" alone would lie; a successful probe-connect is
//!   the honest signal that someone is serving.
//! * *Restartable after unclean death* -- interprocess reclaims the
//!   socket file when a listener drops normally, but a hard-killed
//!   daemon leaves it behind. A leftover that nothing answers is removed
//!   once and the bind retried; anything else stays refused.
//!
//! Shutdown: one watch flag fans out to the accept loop and every live
//! connection handler. Dropping a handler future closes its socket, so
//! connection drain is bounded by construction; the 10 s ceiling covers
//! the session-end + database checkpoint steps that follow.
//!
//! Note what shutdown does NOT do: unlink the socket path manually.
//! Interprocess already unlinks exactly once, when the owning listener
//! drops. A manual removal here would race a successor daemon that bound
//! in the meantime and delete ITS socket file out from under it.

use std::sync::Arc;
use std::time::Duration;

use interprocess::local_socket::ListenerOptions;
use tokio::sync::watch;

use conveyance_core::session::EndReason;

use crate::ipc::{self, IpcError, IpcRequest, IpcResponse};
use crate::{DaemonConfig, DaemonState, StartupError};

/// Ceiling for the whole drain (session ended + logged, databases
/// checkpointed). The spec allows up to 10 s; normal shutdown completes
/// in milliseconds, so hitting this means something is genuinely wrong,
/// and exiting anyway still beats hanging the service manager.
const DRAIN_BUDGET: Duration = Duration::from_secs(10);

/// Probe window for "is anyone serving this name". Short on purpose: a
/// local connect either succeeds near-instantly or there is nothing to
/// talk to.
const PROBE_TIMEOUT: Duration = Duration::from_millis(500);

// ---- serving ------------------------------------------------------------------

/// Bind the configured socket and spawn the accept loop. Returns the
/// shutdown sender; sending `true` stops accepting and tears down all
/// live connections.
pub async fn start_ipc_server(
    config: &DaemonConfig,
    state: Arc<DaemonState>,
) -> Result<watch::Sender<bool>, StartupError> {
    if probe_is_served(&config.socket).await {
        return Err(StartupError::SocketInUse {
            socket: config.socket.clone(),
        });
    }

    let listener = bind_with_stale_retry(config)?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let socket_name = config.socket.clone();
    tokio::spawn(accept_loop(listener, state, shutdown_rx, socket_name));
    Ok(shutdown_tx)
}

/// Dial the configured name; success means a live daemon already owns
/// it and we must refuse. Any probe failure counts as absence --
/// conflicts that appear between probe and bind surface as AddrInUse at
/// create time.
async fn probe_is_served(socket: &str) -> bool {
    use interprocess::local_socket::tokio::prelude::*;

    let Ok(name) = ipc::local_name(socket) else {
        return false;
    };
    matches!(
        tokio::time::timeout(PROBE_TIMEOUT, LocalSocketStream::connect(name)).await,
        Ok(Ok(_)),
    )
}

fn bind_with_stale_retry(
    config: &DaemonConfig,
) -> Result<interprocess::local_socket::tokio::Listener, StartupError> {
    let attempt = || {
        let name = to_name_or_err(&config.socket)?;
        ListenerOptions::new()
            .name(name)
            .create_tokio()
            .map_err(|e| classify_bind_error(&config.socket, e))
    };

    match attempt() {
        Ok(l) => Ok(l),
        // A hard-killed previous daemon can leave a filesystem socket
        // behind (Unix). The probe established nothing is answering, so
        // removing it is reclamation, not vandalism. One retry only: a
        // second AddrInUse is a real conflict that appeared meanwhile.
        Err(StartupError::SocketInUse { .. }) => {
            remove_stale_socket(&config.socket);
            attempt()
        }
        Err(other) => Err(other),
    }
}

fn to_name_or_err(socket: &str) -> Result<interprocess::local_socket::Name<'_>, StartupError> {
    ipc::local_name(socket).map_err(|e| StartupError::SocketBind {
        socket: socket.to_string(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()),
    })
}

fn classify_bind_error(socket: &str, e: std::io::Error) -> StartupError {
    if e.kind() == std::io::ErrorKind::AddrInUse {
        StartupError::SocketInUse {
            socket: socket.to_string(),
        }
    } else {
        StartupError::SocketBind {
            socket: socket.to_string(),
            source: e,
        }
    }
}

#[allow(unused_variables)]
fn remove_stale_socket(socket: &str) {
    // Only meaningful for Unix FILESYSTEM paths; namespaced names
    // (abstract namespace on Linux, named pipes on Windows) leave
    // nothing on disk to remove.
    #[cfg(unix)]
    if socket.starts_with('/') {
        let _ = std::fs::remove_file(socket);
    }
    #[cfg(not(unix))]
    let _ = socket;
}

async fn accept_loop(
    listener: interprocess::local_socket::tokio::Listener,
    state: Arc<DaemonState>,
    mut shutdown: watch::Receiver<bool>,
    socket: String,
) {
    use interprocess::local_socket::tokio::prelude::*;

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            conn = listener.accept() => {
                match conn {
                    Ok(stream) => {
                        let st = state.clone();
                        let sd = shutdown.clone();
                        tokio::spawn(async move {
                            let mut sd = sd;
                            tokio::select! {
                                _ = sd.changed() => {}
                                _ = handle_conn(stream, st) => {}
                            }
                        });
                    }
                    // Transient accept failure: keep serving rather than
                    // dying on one bad wakeup.
                    Err(_) => continue,
                }
            }
        }
    }
    // Dropping the listener here performs interprocess name reclamation
    // (Unix unlink). `socket` is retained in scope deliberately: it
    // documents ownership of the name for readers even though cleanup
    // is automatic.
    let _owned_name_for_clarity = socket;
}

/// One shim connection: sequential framed request/response until EOF or
/// shutdown. Errors terminate THIS connection only.
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

// ---- framing ------------------------------------------------------------------
//
// Server-side twin of the client codec in ipc.rs. Kept separate rather
// than genericized: two small concrete functions over one shared cap
// constant are easier to audit than parameterized plumbing.

use ipc::MAX_IPC_MESSAGE;

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

// ---- lifecycle ----------------------------------------------------------------

/// Serve until SIGTERM/SIGINT/Ctrl-C, then drain within bounds.
pub async fn serve_until_signal(
    config: DaemonConfig,
    state: Arc<DaemonState>,
) -> Result<(), StartupError> {
    let shutdown_tx = start_ipc_server(&config, state.clone()).await?;

    eprintln!(
        "conveyance daemon {} listening on '{}'",
        env!("CARGO_PKG_VERSION"),
        config.socket
    );

    wait_for_shutdown_signal().await;
    eprintln!("conveyance daemon: shutting down");

    // Fan-out close: accept loop exits, live handler futures are
    // dropped (which closes their sockets).
    let _ = shutdown_tx.send(true);
    drop(shutdown_tx);

    // Ordered drain: session end writes its log row BEFORE databases
    // checkpoint, so a restart never sees a checkpointed log missing
    // its final event.
    let drain = async {
        if state.sessions.is_active() {
            // Idempotent; replies after keys are zeroized and the end
            // row is durable.
            let _ = state.sessions.end(EndReason::UserEnded).await;
        }
        let _ = state.log.checkpoint();
        let _ = state.store_pairings.checkpoint();
    };
    if tokio::time::timeout(DRAIN_BUDGET, drain).await.is_err() {
        eprintln!("conveyance daemon: drain budget exceeded; exiting anyway");
    }

    Ok(())
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("conveyance daemon: cannot install SIGTERM handler: {e}");
                return;
            }
        };
        let mut int = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("conveyance daemon: cannot install SIGINT handler: {e}");
                return;
            }
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        if tokio::signal::ctrl_c().await.is_err() {
            eprintln!("conveyance daemon: cannot install Ctrl-C handler");
        }
    }
}
