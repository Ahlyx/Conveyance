//! The Conveyance command line.
//!
//! Subcommands appear here as phases implement them. `pair` is first
//! (phase 6); daemon/shim/log subcommands follow in phases 7-9 and will
//! call into their crates' library surfaces rather than duplicating
//! logic here.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "conveyance",
    version,
    about = "Phone-approved capability broker for MCP tool calls"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start pairing: render a QR for the phone to scan, wait for the
    /// ceremony to complete.
    Pair {
        /// Hostname shown on the phone. Defaults to this machine's name.
        #[arg(long)]
        name: Option<String>,
    },
    /// Run the daemon: refuse-to-start checks, IPC listener, session
    /// lifecycle. Blocks until SIGTERM/SIGINT/Ctrl-C.
    Daemon {
        /// Explicit config file instead of the platform location.
        #[arg(long)]
        config: Option<std::path::PathBuf>,
        /// Override the local-socket identity (same form on client
        /// commands via --socket).
        #[arg(long)]
        socket: Option<String>,
    },
    /// Ask a running daemon for its status view.
    Status {
        /// Socket identity of the daemon (see `conveyance daemon`).
        #[arg(long)]
        socket: Option<String>,
    },
    /// Session control over the daemon's IPC socket.
    Session {
        #[command(subcommand)]
        cmd: SessionCommand,
    },
}

#[derive(Subcommand)]
enum SessionCommand {
    /// Scan for the paired phone and establish the Noise session.
    Start {
        #[arg(long)]
        socket: Option<String>,
    },
    /// End any active session. Idempotent.
    End {
        #[arg(long)]
        socket: Option<String>,
    },
}

#[cfg(feature = "ble")]
fn data_dir() -> Result<std::path::PathBuf, String> {
    conveyance_core::paths::data_dir().map_err(|e| e.to_string())
}

#[cfg(feature = "ble")]
fn hostname_fallback() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "this-pc".to_string())
}

/// Load the long-term identity, generating + persisting it on first run.
/// Generation happens ONLY inside this explicit user-invoked command --
/// never as a side effect of some other command loading storage.
#[cfg(feature = "ble")]
fn load_or_create_identity(
    path: &std::path::Path,
) -> Result<conveyance_core::storage::identity::StoredIdentity, String> {
    use conveyance_core::storage::identity::{OsKeyring, StoredIdentity};

    match StoredIdentity::load(path, &OsKeyring) {
        Ok(id) => Ok(id),
        Err(conveyance_core::storage::StorageError::IdentityFileNotFound(_)) => {
            println!("no identity found -- generating one");
            let id = StoredIdentity::generate(&conveyance_core::crypto::OsEntropy)
                .map_err(|e| format!("entropy failure during identity generation: {e}"))?;
            id.save(path, &OsKeyring, &conveyance_core::crypto::OsEntropy)
                .map_err(|e| format!("failed to persist new identity: {e}"))?;
            println!("identity written to {}", path.display());
            Ok(id)
        }
        Err(e) => Err(format!(
            "cannot load identity: {e}\n\
             If the OS keychain is locked or unavailable, unlock it and retry."
        )),
    }
}

impl Command {
    async fn run(self) -> Result<(), String> {
        match self {
            Command::Pair { name } => pair(name).await,
            Command::Daemon { config, socket } => daemon(config, socket).await,
            Command::Status { socket } => status(client_socket(socket)?).await,
            Command::Session { cmd } => match cmd {
                SessionCommand::Start { socket } => {
                    session_cmd(
                        conveyance_daemon::ipc::IpcRequest::SessionStart,
                        socket,
                        "session started",
                    )
                    .await
                }
                SessionCommand::End { socket } => {
                    session_cmd(
                        conveyance_daemon::ipc::IpcRequest::SessionEnd,
                        socket,
                        "session ended",
                    )
                    .await
                }
            },
        }
    }
}

/// Resolve the socket a client command should dial: the flag wins,
/// otherwise the configured/default identity from the daemon lib.
fn client_socket(flag: Option<String>) -> Result<String, String> {
    if let Some(s) = flag {
        return Ok(s);
    }
    let raw = conveyance_daemon::load_config_or_defaults()?;
    Ok(conveyance_daemon::effective_socket(&raw))
}

fn load_daemon_config(
    config_path: Option<std::path::PathBuf>,
) -> Result<conveyance_daemon::DaemonConfig, String> {
    let raw = match config_path {
        Some(path) => conveyance_core::config::Config::load_from_path(&path)
            .map_err(|e| format!("cannot load {}: {e}", path.display()))?,
        None => conveyance_daemon::load_config_or_defaults()?,
    };
    conveyance_daemon::resolve_config(&raw).map_err(|e| e.to_string())
}

async fn daemon(
    config_path: Option<std::path::PathBuf>,
    socket: Option<String>,
) -> Result<(), String> {
    let mut config = load_daemon_config(config_path)?;
    if let Some(s) = socket {
        config.socket = s;
    }
    conveyance_daemon::run(config)
        .await
        .map_err(|e| e.to_string())
}

async fn status(socket: String) -> Result<(), String> {
    use conveyance_daemon::ipc::{IpcRequest, IpcResponse, single_request};

    match single_request(&socket, IpcRequest::Status).await {
        Ok(IpcResponse::Status {
            version,
            uptime_seconds,
            session_active,
            paired_phones,
        }) => {
            println!("conveyance daemon v{version} | uptime {uptime_seconds}s");
            let phones = if paired_phones.is_empty() {
                "(none)".to_string()
            } else {
                paired_phones.join(", ")
            };
            if session_active {
                // Timer detail rides CheckSession; Status stays cheap.
                println!("session: ACTIVE | paired phones: {phones}");
            } else {
                println!("session: inactive | paired phones: {phones}");
            }
            Ok(())
        }
        Ok(_) => Err("daemon returned an unexpected response to status".to_string()),
        Err(e) => Err(e.to_string()),
    }
}

async fn session_cmd(
    req: conveyance_daemon::ipc::IpcRequest,
    socket: Option<String>,
    success_text: &str,
) -> Result<(), String> {
    use conveyance_daemon::ipc::{IpcResponse, single_request};

    let socket = client_socket(socket)?;
    match single_request(&socket, req).await {
        Ok(IpcResponse::Error { code, message, .. }) => {
            // Spec error shape reaches CLI users verbatim: code first,
            // message after -- scripts parse the code, humans read on.
            Err(format!("{code}: {message}"))
        }
        Ok(_) => {
            println!("{success_text}");
            Ok(())
        }
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(feature = "ble")]
async fn pair(name: Option<String>) -> Result<(), String> {
    use conveyance_core::pairing::{CeremonyContext, CeremonyLimits, NonceGuard, run_pairing};
    use conveyance_core::transport::ble::BleTransport;

    let data = data_dir()?;
    let mut transport = BleTransport::new()
        .await
        .map_err(|e| format!("Bluetooth unavailable on this machine: {e}"))?;

    let identity = load_or_create_identity(&data.join("identity.enc"))?;
    let signer = identity.identity_key();
    let store = conveyance_core::storage::pairings::PairingsDb::open(&data.join("pairings.db"))
        .map_err(|e| e.to_string())?;
    let mut nonces = NonceGuard::open(&data.join("pairing-nonce-bloom.bin"));

    let mut ctx = CeremonyContext {
        pc_id_secret: &signer,
        pc_dh_pub: *identity.x25519_secret.expose(),
        pc_name: name.unwrap_or_else(hostname_fallback),
        service_uuid_bytes: conveyance_core::transport::ids::service_uuid_bytes(),
        store: &store,
        nonces: &mut nonces,
    };

    println!("Pairing: scan this QR with Conveyance on your phone.");
    println!("The code expires in 60 seconds.\n");

    let peer = run_pairing(&mut transport, &mut ctx, CeremonyLimits::spec(), |qr| {
        println!("{}", qr.render_ascii());
        println!("Waiting for phone to advertise and confirm...\n");
    })
    .await
    .map_err(|e| e.to_string())?;

    println!(
        "PAIRED. Phone handle: {}",
        conveyance_core::storage::pairings::phone_id_for(&peer.phone_id_pub)
    );
    Ok(())
}

#[cfg(not(feature = "ble"))]
async fn pair(_name: Option<String>) -> Result<(), String> {
    Err(
        "this build lacks BLE support; rebuild with:\n  cargo build --release --features ble"
            .to_string(),
    )
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(msg) = cli.command.run().await {
        // Exit codes: 1 = operation failed; the stub binaries' 2 for
        // unimplemented remains reserved to them.
        eprintln!("{msg}");
        std::process::exit(1);
    }
}
