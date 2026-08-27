//! The Conveyance command line.
//!
//! Every subcommand (`init`, `pair`, `daemon`, `mcp-shim`, `status`,
//! `session`, `unpair`, `log`) is a thin dispatcher: argument parsing
//! lives here, all behaviour lives in the `conveyance-core`,
//! `conveyance-daemon`, and `conveyance-shim` library surfaces.

mod logcmd;

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
    /// Generate the long-term identity if none exists (first-run step).
    Init {
        #[command(subcommand)]
        cmd: Init,
    },
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
        /// Redirect all daemon storage (identity, databases) under
        /// this directory instead of the platform data dir.
        #[arg(long)]
        data_dir: Option<std::path::PathBuf>,
        /// E2E test mode: scripted auto-approving phone instead of
        /// BLE. Requires a build with the mock-phone feature; refuses
        /// to start otherwise (never silently).
        #[arg(long)]
        mock_phone: bool,
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
    /// Run the MCP shim over stdio for an external client (Claude
    /// Code, mcp-inspector). Exits when stdin closes.
    McpShim {
        /// Socket identity of the daemon (see `conveyance daemon`).
        #[arg(long)]
        socket: Option<String>,
    },
    /// Remove a paired phone by id (shown in `conveyance status`).
    Unpair {
        phone_id: String,
        /// Skip the interactive confirmation (non-interactive use).
        #[arg(long)]
        yes: bool,
        /// Redirect storage under this directory (must match the
        /// daemon's --data-dir).
        #[arg(long)]
        data_dir: Option<std::path::PathBuf>,
    },
    /// Query, verify, export, and reconcile the execution log.
    Log {
        #[command(subcommand)]
        cmd: LogCommand,
    },
}

#[derive(Subcommand)]
enum LogCommand {
    /// Query the execution log.
    Query {
        /// Only rows newer than this. Duration with required unit:
        /// 45s, 30m, 2h, 1d.
        #[arg(long)]
        since: Option<String>,
        /// Only rows belonging to this service/tool name.
        #[arg(long)]
        tool: Option<String>,
        /// Only execute_result rows with this status (ok/error/denied).
        #[arg(long)]
        status: Option<String>,
        /// Print full payloads instead of one-line summaries.
        #[arg(long)]
        verbose: bool,
        /// Only security-relevant rows (timeouts, failed executions,
        /// integrity notes).
        #[arg(long)]
        anomalous: bool,
        #[arg(long)]
        data_dir: Option<std::path::PathBuf>,
    },
    /// Walk the hash chain. Exit codes: 0 intact, 1 verification
    /// failed, 2 chain intact but derived head metadata stale.
    Verify {
        /// Recompute derived metadata when stale. Dry run unless
        /// --yes; refuses entirely if the chain itself is broken.
        #[arg(long)]
        repair: bool,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        data_dir: Option<std::path::PathBuf>,
    },
    /// Export the log as JSONL (for offline analysis or diffing).
    Export {
        #[arg(long, default_value = "jsonl")]
        format: String,
        /// Write to a file atomically instead of stdout.
        #[arg(long)]
        output: Option<std::path::PathBuf>,
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        tool: Option<String>,
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        data_dir: Option<std::path::PathBuf>,
    },
    /// Reconcile a signed phone export against the local execution
    /// log. Exits nonzero on any security-relevant mismatch.
    Diff {
        phone_export: std::path::PathBuf,
        #[arg(long)]
        data_dir: Option<std::path::PathBuf>,
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

/// Create the long-term identity if none exists. Generation happens
/// ONLY inside this explicit user-invoked command -- never as a side
/// effect of some other command loading storage.
#[derive(Subcommand)]
enum Init {
    /// Generate the PC identity (no-op when one already exists).
    Identity {
        /// Redirect storage under this directory instead of the
        /// platform data dir (must match the daemon's --data-dir).
        #[arg(long)]
        data_dir: Option<std::path::PathBuf>,
    },
}

/// The daemon's data-file set for a CLI command: honours a `--data-dir`
/// override, otherwise the platform data directory. Single source of the
/// `identity.enc` / `pairings.db` / `executions.db` filenames -- see
/// [`conveyance_core::paths::DataPaths`].
fn data_paths(
    over: Option<std::path::PathBuf>,
) -> Result<conveyance_core::paths::DataPaths, String> {
    conveyance_core::paths::DataPaths::resolve(over).map_err(|e| e.to_string())
}

// Used only by the BLE pairing flow; kept compiled so a --features ble
// build cannot break on it.
#[cfg_attr(not(feature = "ble"), allow(dead_code))]
fn hostname_fallback() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "this-pc".to_string())
}

/// Load the long-term identity, generating + persisting it on first run.
/// Generation happens ONLY inside this explicit user-invoked command --
/// never as a side effect of some other command loading storage.
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

/// A failed command: message for stderr plus the process exit code.
/// Most commands are plain 0/1; `log verify` carries the spec's
/// three-state 0/1/2.
#[derive(Debug)]
struct CliError {
    message: String,
    code: i32,
}

impl CliError {
    fn fail(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: 1,
        }
    }

    fn with_code(code: i32, message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code,
        }
    }
}

impl From<String> for CliError {
    fn from(message: String) -> Self {
        CliError::fail(message)
    }
}

impl Command {
    async fn run(self) -> Result<(), CliError> {
        match self {
            Command::Init { cmd } => match cmd {
                Init::Identity { data_dir } => init_identity(data_dir).map_err(CliError::from),
            },
            Command::Pair { name } => pair(name).await.map_err(CliError::from),
            Command::Daemon {
                config,
                socket,
                data_dir,
                mock_phone,
            } => daemon(config, socket, data_dir, mock_phone)
                .await
                .map_err(CliError::from),
            Command::Status { socket } => status(conveyance_daemon::resolve_client_socket(socket)?)
                .await
                .map_err(CliError::from),
            Command::Session { cmd } => match cmd {
                SessionCommand::Start { socket } => session_cmd(
                    conveyance_daemon::ipc::IpcRequest::SessionStart,
                    socket,
                    "session started",
                )
                .await
                .map_err(CliError::from),
                SessionCommand::End { socket } => session_cmd(
                    conveyance_daemon::ipc::IpcRequest::SessionEnd,
                    socket,
                    "session ended",
                )
                .await
                .map_err(CliError::from),
            },
            Command::McpShim { socket } => {
                let sock = conveyance_daemon::resolve_client_socket(socket)?;
                conveyance_shim::run(&sock).await.map_err(CliError::from)
            }
            Command::Unpair {
                phone_id,
                yes,
                data_dir,
            } => unpair(&phone_id, yes, data_dir),
            Command::Log { cmd } => match cmd {
                LogCommand::Query {
                    since,
                    tool,
                    status,
                    verbose,
                    anomalous,
                    data_dir,
                } => logcmd::query(
                    logcmd::QueryFilter {
                        since,
                        tool,
                        status,
                        verbose,
                        anomalous,
                    },
                    data_paths(data_dir).map_err(CliError::fail)?.executions,
                ),
                LogCommand::Verify {
                    repair,
                    yes,
                    data_dir,
                } => logcmd::verify(
                    repair,
                    yes,
                    data_paths(data_dir).map_err(CliError::fail)?.executions,
                )
                .map_err(|e| CliError::with_code(e.code, e.message)),
                LogCommand::Export {
                    format,
                    output,
                    since,
                    tool,
                    status,
                    data_dir,
                } => {
                    if format != "jsonl" {
                        return Err(CliError::fail(format!(
                            "unsupported format '{format}' (only jsonl is defined)"
                        )));
                    }
                    logcmd::export(
                        logcmd::QueryFilter {
                            since,
                            tool,
                            status,
                            verbose: false,
                            anomalous: false,
                        },
                        output,
                        data_paths(data_dir).map_err(CliError::fail)?.executions,
                    )
                }
                LogCommand::Diff {
                    phone_export,
                    data_dir,
                } => {
                    let dp = data_paths(data_dir).map_err(CliError::fail)?;
                    logcmd::diff(
                        &phone_export,
                        logcmd::DiffPaths {
                            pairings_db: dp.pairings,
                            executions_db: dp.executions,
                        },
                    )
                }
            },
        }
    }
}

fn init_identity(data_dir_override: Option<std::path::PathBuf>) -> Result<(), String> {
    let path = data_paths(data_dir_override)?.identity;
    // load_or_create_identity prints generation progress itself.
    let _identity = load_or_create_identity(&path)?;
    Ok(())
}

fn unpair(
    phone_id: &str,
    yes: bool,
    data_dir_override: Option<std::path::PathBuf>,
) -> Result<(), CliError> {
    let pairings_db = data_paths(data_dir_override)
        .map_err(CliError::fail)?
        .pairings;
    if !yes {
        // Non-interactive use without --yes is refused rather than
        // guessed: a revoked phone that keeps believing it is paired is
        // exactly the state this command exists to create, deliberately.
        eprintln!("Remove pairing {phone_id}? This cannot be undone. Pass --yes to confirm.");
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .map_err(|e| CliError::fail(format!("cannot read confirmation: {e}")))?;
        let answer = answer.trim().to_ascii_lowercase();
        if answer != "y" && answer != "yes" {
            return Err(CliError::fail("aborted"));
        }
    }

    let store = conveyance_core::storage::pairings::PairingsDb::open(&pairings_db)
        .map_err(|e| CliError::fail(e.to_string()))?;
    match store.remove(phone_id) {
        Ok(true) => {
            println!("pairing {phone_id} removed");
            println!("note: any active session should be ended (`conveyance session end`)");
            Ok(())
        }
        Ok(false) => Err(CliError::fail(format!("no such pairing '{phone_id}'"))),
        Err(e) => Err(CliError::fail(e.to_string())),
    }
}

async fn daemon(
    config_path: Option<std::path::PathBuf>,
    socket: Option<String>,
    data_dir: Option<std::path::PathBuf>,
    mock_phone: bool,
) -> Result<(), String> {
    let mut config = conveyance_daemon::resolve_runtime_config(config_path.as_deref(), socket)?;
    // Storage redirection happens AFTER resolution so every derived
    // path moves together -- a daemon must never straddle two data
    // directories.
    if let Some(dir) = data_dir {
        let dp = conveyance_core::paths::DataPaths::under(&dir);
        config.pairings_db = dp.pairings;
        config.executions_db = dp.executions;
        config.identity_file = dp.identity;
    }

    match (mock_phone, cfg!(feature = "mock-phone")) {
        (false, _) => conveyance_daemon::run(config)
            .await
            .map_err(|e| e.to_string()),
        // Test mode requested and compiled in: the only caller is E2E
        // tooling, never production muscle memory.
        (true, true) => {
            #[cfg(feature = "mock-phone")]
            {
                conveyance_daemon::run_with_mock_phone(config)
                    .await
                    .map_err(|e| e.to_string())
            }
            // The cfg!() above is compile-time constant false here, but
            // both match arms must still typecheck.
            #[cfg(not(feature = "mock-phone"))]
            {
                Err("mock-phone feature not compiled".to_string())
            }
        }
        // Refuse loudly rather than silently ignoring the flag --
        // pretending to run test mode would be worse than refusing.
        (true, false) => Err("this build lacks mock-phone support; rebuild with:\n  \
             cargo build --release --features conveyance-daemon/mock-phone"
            .to_string()),
    }
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

    let socket = conveyance_daemon::resolve_client_socket(socket)?;
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

    let dp = data_paths(None)?;
    let mut transport = BleTransport::new()
        .await
        .map_err(|e| format!("Bluetooth unavailable on this machine: {e}"))?;

    let identity = load_or_create_identity(&dp.identity)?;
    let signer = identity.identity_key();
    let store = conveyance_core::storage::pairings::PairingsDb::open(&dp.pairings)
        .map_err(|e| e.to_string())?;
    // The replay bloom filter sits alongside the other data files.
    let mut nonces = NonceGuard::open(&dp.pairings.with_file_name("pairing-nonce-bloom.bin"));

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
    if let Err(e) = cli.command.run().await {
        // Exit codes: 1 = operation failed. `log verify` returns the
        // spec's 0/1/2 through CliError.code; everything else uses
        // plain 0/1.
        eprintln!("{}", e.message);
        std::process::exit(e.code);
    }
}
