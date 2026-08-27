//! Long-running daemon: refuse-to-start chain, session ownership, IPC
//! server, clean shutdown.
//!
//! Phase 7.0 scope: skeleton + IPC + session lifecycle. Request routing
//! arrives in 7.1.
//!
//! Assembly order is the refuse-to-start chain from the phases doc:
//! config -> data dirs -> keychain identity -> databases -> socket bind.
//! Each failure is a typed [`StartupError`] whose Display is written for
//! stderr -- actionable text is part of the contract, since these are
//! the messages a user sees when the daemon exits nonzero.

pub mod ipc;
#[cfg(feature = "mock-phone")]
pub mod mockphone;
pub mod phone;
pub mod recovery;
pub mod server;
pub mod session;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use conveyance_core::session::{EndReason, SessionParams};
use conveyance_core::storage::StorageError;
use conveyance_core::storage::identity::{KeyProvider, OsKeyring, StoredIdentity};
use conveyance_core::storage::logdb::LogDb;
use conveyance_core::storage::pairings::PairingsDb;

use crate::ipc::{IpcRequest, IpcResponse};
use crate::session::{OpError, SessionHandle};

// ---- config -------------------------------------------------------------------

/// Concrete daemon settings after resolution. Tests construct this
/// directly to point every piece at a temp directory.
#[derive(Clone, Debug)]
pub struct DaemonConfig {
    /// Local-socket identity. Interpretation is platform-specific and
    /// shared with clients via [`ipc::local_name`]:
    /// * Unix path-looking strings are filesystem socket paths;
    /// * otherwise the string is a namespaced name (abstract namespace
    ///   on Linux, `/tmp/<name>` elsewhere, `\\.\pipe\<name>` on
    ///   Windows).
    pub socket: String,
    pub pairings_db: PathBuf,
    pub executions_db: PathBuf,
    pub identity_file: PathBuf,
    /// Validated at resolution time; use afterwards is infallible.
    pub session_params: SessionParams,
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
    #[error("config invalid: {0}")]
    Config(String),
    #[error(
        "socket '{socket}' is already in use -- \
         is another daemon running? Check with: conveyance status"
    )]
    SocketInUse { socket: String },
    #[error("socket bind failed at '{socket}': {source}")]
    SocketBind {
        socket: String,
        #[source]
        source: std::io::Error,
    },
}

impl From<conveyance_core::paths::PathError> for StartupError {
    fn from(e: conveyance_core::paths::PathError) -> Self {
        StartupError::DataDir(e.to_string())
    }
}

fn default_socket_name() -> String {
    // Bare namespaced name on purpose: interprocess maps it to the
    // abstract namespace (Linux), /tmp/<name> (other Unix), or
    // \\.\pipe\<name> (Windows), with automatic reclamation on drop and
    // no filesystem cleanup concerns.
    "conveyance-daemon".to_string()
}

/// The socket identity a client should dial for the given config.
///
/// Platform split mirrors the spec's config section: `socket_path`
/// (a filesystem path) is the Unix knob; `named_pipe` is the Windows
/// knob. On Windows a configured pipe may arrive with its full
/// `\\.\pipe\` prefix; the prefix is stripped so the value rides the
/// namespaced mapping like everything else.
pub fn effective_socket(raw: &conveyance_core::config::Config) -> String {
    #[cfg(windows)]
    {
        raw.daemon
            .named_pipe
            .as_deref()
            .map(|p| p.strip_prefix(r"\\.\pipe\").unwrap_or(p).to_string())
            .unwrap_or_else(default_socket_name)
    }
    #[cfg(unix)]
    {
        match &raw.daemon.socket_path {
            Some(path) => expand_tilde(path).to_string_lossy().into_owned(),
            None => default_socket_name(),
        }
    }
}

/// Resolve raw TOML config into concrete daemon settings. Timer bounds
/// are enforced HERE, fail-closed, per the spec MUST-NOT-bypass rule --
/// an out-of-bounds config refuses startup rather than clamping.
pub fn resolve_config(raw: &conveyance_core::config::Config) -> Result<DaemonConfig, StartupError> {
    // Full semantic validation BEFORE anything else: unknown fields,
    // malformed high-risk rules, then the timer bounds below.
    raw.validated()
        .map_err(|e| StartupError::Config(e.to_string()))?;
    let paths = conveyance_core::paths::DataPaths::resolve(None)?;
    let session_params = SessionParams::validated(
        Duration::from_secs(raw.session.idle_timeout_seconds),
        Duration::from_secs(raw.session.warn_before_seconds),
        Duration::from_secs(raw.session.hard_cap_seconds),
    )
    .map_err(|_| StartupError::Config("session timers violate spec bounds".into()))?;

    Ok(DaemonConfig {
        socket: effective_socket(raw),
        pairings_db: paths.pairings,
        // `logging.executions_db` in config.toml overrides the default
        // location for the log specifically.
        executions_db: match &raw.logging.executions_db {
            Some(p) => expand_tilde(p),
            None => paths.executions,
        },
        identity_file: paths.identity,
        session_params,
    })
}

/// Config-or-defaults loading for CLI entry points. A missing file is
/// NOT an error: defaults are documented behavior, and refusing to run
/// without a config would make first-run needlessly hostile. A file
/// that exists but cannot be parsed IS fatal -- silently running on
/// settings the user believes they changed is worse.
pub fn load_config_or_defaults() -> Result<conveyance_core::config::Config, String> {
    let dir = conveyance_core::paths::config_dir().map_err(|e| e.to_string())?;
    let path = dir.join("config.toml");
    if !path.exists() {
        return conveyance_core::config::Config::from_toml_str("").map_err(|e| e.to_string());
    }
    conveyance_core::config::Config::load_from_path(&path)
        .map_err(|e| format!("cannot load {}: {e}", path.display()))
}

/// Resolve a runnable [`DaemonConfig`] from an optional explicit config
/// path and an optional socket override. This is the load -> resolve ->
/// override-socket sequence shared by the `conveyance daemon` subcommand
/// and the standalone `conveyance-daemon` binary; neither should
/// re-implement it. The CLI's `--data-dir` redirection, if any, is
/// applied by the caller afterwards.
pub fn resolve_runtime_config(
    config_path: Option<&Path>,
    socket_override: Option<String>,
) -> Result<DaemonConfig, String> {
    let raw = match config_path {
        Some(path) => conveyance_core::config::Config::load_from_path(path)
            .map_err(|e| format!("cannot load {}: {e}", path.display()))?,
        None => load_config_or_defaults()?,
    };
    let mut config = resolve_config(&raw).map_err(|e| e.to_string())?;
    if let Some(s) = socket_override {
        config.socket = s;
    }
    Ok(config)
}

/// The daemon socket a client (CLI subcommand or `conveyance-mcp-shim`
/// binary) should dial: an explicit `--socket` wins, otherwise the
/// configured or default identity.
pub fn resolve_client_socket(socket_override: Option<String>) -> Result<String, String> {
    match socket_override {
        Some(s) => Ok(s),
        None => Ok(effective_socket(&load_config_or_defaults()?)),
    }
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

// ---- shared state ---------------------------------------------------------------

/// State shared by IPC connection handlers.
pub struct DaemonState {
    pub started_at: Instant,
    /// Spec's five-field status wants the version; single source here.
    pub sessions: SessionHandle,
    pub store_pairings: Arc<PairingsDb>,
    /// Held here (not only inside the session owner) so clean shutdown
    /// can checkpoint the execution log after the owner has finished
    /// writing its final rows.
    pub log: Arc<LogDb>,
}

impl DaemonState {
    async fn status_response(&self) -> IpcResponse {
        let paired_phones = self
            .store_pairings
            .list()
            .unwrap_or_default()
            .into_iter()
            .map(|p| p.phone_id)
            .collect();
        IpcResponse::Status {
            version: env!("CARGO_PKG_VERSION").into(),
            uptime_seconds: self.started_at.elapsed().as_secs(),
            session_active: self.sessions.is_active(),
            paired_phones,
        }
    }

    async fn dispatch(&self, req: IpcRequest) -> IpcResponse {
        match req {
            IpcRequest::Status => self.status_response().await,
            IpcRequest::CheckSession => {
                if !self.sessions.is_active() {
                    return no_session_error();
                }
                match self.sessions.inspect().await {
                    Some(view) => IpcResponse::SessionActive {
                        idle_seconds_remaining: view.idle_seconds_remaining,
                        hard_cap_seconds_remaining: view.hard_cap_seconds_remaining,
                    },
                    // Raced with an end between the watch read and the
                    // owner's answer: report truthfully as gone.
                    None => no_session_error(),
                }
            }
            IpcRequest::SessionEnd => match self.sessions.end(EndReason::UserEnded).await {
                Ok(()) => IpcResponse::SessionEnded,
                Err(err) => op_error_response(&err),
            },
            IpcRequest::SessionStart => match self.sessions.start().await {
                Ok(()) => IpcResponse::SessionStarted,
                Err(err) => op_error_response(&err),
            },
            IpcRequest::AuthenticatedRequest {
                service,
                method,
                endpoint,
                params,
                requested_by,
            } => {
                // Cold-start gate fires BEFORE anything else: while
                // NO_SESSION there is no channel to a phone at all.
                if !self.sessions.is_active() {
                    return no_session_error();
                }
                let op = session::RoutedOp::AuthenticatedRequest {
                    service,
                    method,
                    endpoint,
                    params,
                    requested_by,
                };
                match self.sessions.route(op).await {
                    Ok(resp) => resp,
                    Err(err) => op_error_response(&err),
                }
            }
            IpcRequest::ListServices => {
                if !self.sessions.is_active() {
                    return no_session_error();
                }
                match self.sessions.route(session::RoutedOp::ListServices).await {
                    Ok(resp) => resp,
                    Err(err) => op_error_response(&err),
                }
            }
        }
    }
}

fn op_error_response(err: &OpError) -> IpcResponse {
    IpcResponse::Error {
        code: err.code.clone(),
        message: err.message.clone(),
        retryable: err.retryable,
    }
}

pub(crate) fn no_session_error() -> IpcResponse {
    IpcResponse::Error {
        code: "conveyance/no_session".into(),
        message: "No active Conveyance session. User must start one on the paired phone.".into(),
        retryable: true,
    }
}

// ---- refuse-to-start ----------------------------------------------------------

pub struct OpenStores {
    pub identity: StoredIdentity,
    pub store: Arc<PairingsDb>,
    pub log: Arc<LogDb>,
}

/// Refuse-to-start chain against the production OS keychain.
pub fn refuse_to_start(config: &DaemonConfig) -> Result<OpenStores, StartupError> {
    refuse_to_start_with(config, &OsKeyring)
}

/// The chain itself, parameterized over the keychain so tests can run
/// without touching any real credential store.
///
/// Order matters and matches the phases doc: data dirs, then keychain
/// identity, then databases. Earlier failures must not create later
/// artifacts -- e.g. a keychain failure leaves no empty DB files behind.
pub fn refuse_to_start_with<P: KeyProvider>(
    config: &DaemonConfig,
    keys: &P,
) -> Result<OpenStores, StartupError> {
    let parent = config.pairings_db.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)
        .map_err(|e| StartupError::DataDir(format!("{}: {e}", parent.display())))?;

    let identity = StoredIdentity::load(&config.identity_file, keys).map_err(|e| match e {
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
        store: Arc::new(store),
        log: Arc::new(log),
    })
}

// ---- assembly -----------------------------------------------------------------

/// Everything `run` needs that varies between production and tests.
pub struct DaemonDeps {
    pub dialer: Box<dyn phone::PhoneDialer>,
    /// Window overrides (tests only): production leaves both None to
    /// get the spec's 60 s.
    pub approval_window: Option<Duration>,
    pub execute_window: Option<Duration>,
}

impl DaemonDeps {
    /// Production-shaped deps: spec windows, injected dialer.
    pub fn new(dialer: Box<dyn phone::PhoneDialer>) -> Self {
        Self {
            dialer,
            approval_window: None,
            execute_window: None,
        }
    }
}

/// Build the full daemon state (owner task included) from resolved
/// config plus opened stores. Exposed for tests; production callers go
/// through [`run`].
pub fn assemble_state(
    config: &DaemonConfig,
    stores: OpenStores,
    deps: DaemonDeps,
) -> Arc<DaemonState> {
    let local_static = stores.identity.x25519_secret.clone();
    let sessions = session::spawn_session_owner(session::SessionDeps {
        dialer: deps.dialer,
        store: stores.store.clone(),
        log: stores.log.clone(),
        local_static,
        params: config.session_params,
        approval_window: deps.approval_window.unwrap_or(session::APPROVAL_WINDOW),
        execute_window: deps.execute_window.unwrap_or(session::EXECUTE_WINDOW),
    });

    Arc::new(DaemonState {
        started_at: Instant::now(),
        sessions,
        store_pairings: stores.store,
        log: stores.log,
    })
}

/// Full daemon lifecycle: refuse-to-start, crash-recovery sweep, serve
/// until SIGTERM/SIGINT/Ctrl-C, then drain within bounds. Returns when
/// it is safe to exit 0; errors mean exit nonzero with `.to_string()`
/// on stderr.
pub async fn run(config: DaemonConfig) -> Result<(), StartupError> {
    run_with(config, DaemonDeps::new(production_dialer())).await
}

/// The transport a production build dials with. BLE-only today; the
/// seam exists so nothing else in the daemon knows that.
///
/// Deliberately lazy: constructing the BLE adapter can fail on machines
/// without radios, and the daemon must still come up to answer
/// `status`. A missing radio surfaces as `phone_unreachable` at session
/// start instead of blocking startup.
fn production_dialer() -> Box<dyn phone::PhoneDialer> {
    #[cfg(feature = "ble")]
    {
        Box::new(phone::LazyBleDialer::default())
    }
    #[cfg(not(feature = "ble"))]
    {
        Box::new(phone::NoTransportDialer)
    }
}

/// Like [`run`] with injected dependencies (tests).
pub async fn run_with(config: DaemonConfig, deps: DaemonDeps) -> Result<(), StartupError> {
    let stores = refuse_to_start(&config)?;

    // Crash-recovery sweep runs BEFORE the socket binds: by the time
    // any shim can talk to us, every orphaned req_id from a previous
    // life already has its request_timeout row.
    let swept = recovery::sweep_orphaned_requests(&stores.log).map_err(|e| StartupError::Open {
        what: "executions database (recovery sweep)".to_string(),
        message: e.to_string(),
    })?;
    if swept > 0 {
        eprintln!("conveyance daemon: marked {swept} orphaned request(s) as request_timeout");
    }

    let state = assemble_state(&config, stores, deps);
    server::serve_until_signal(config, state).await
}

/// End-to-end test mode: serve with a scripted auto-approving phone
/// instead of BLE. Requires the `mock-phone` feature AND is reachable
/// only through the explicit --mock-phone flag; production binaries
/// carry neither.
#[cfg(feature = "mock-phone")]
pub async fn run_with_mock_phone(config: DaemonConfig) -> Result<(), StartupError> {
    use conveyance_core::crypto::dh::DhSecret;

    let stores = refuse_to_start(&config)?;

    let swept = recovery::sweep_orphaned_requests(&stores.log).map_err(|e| StartupError::Open {
        what: "executions database (recovery sweep)".to_string(),
        message: e.to_string(),
    })?;
    if swept > 0 {
        eprintln!("conveyance daemon: marked {swept} orphaned request(s) as request_timeout");
    }

    // The mock phone needs the PC's DH static for KK -- exactly what a
    // real phone learns during pairing.
    let pc_dh_pub = DhSecret::from_bytes(*stores.identity.x25519_secret.expose())
        .public_key()
        .to_bytes();
    let phone = std::sync::Arc::new(mockphone::MockPhone::new(pc_dh_pub));
    phone
        .record_pairing(&stores.store)
        .map_err(|e| StartupError::Open {
            what: "pairings database (mock pairing)".to_string(),
            message: e.to_string(),
        })?;
    eprintln!(
        "conveyance daemon: TEST MODE -- scripted phone paired ({})",
        phone.phone_id()
    );

    let state = assemble_state(&config, stores, DaemonDeps::new(Box::new(phone.dialer())));
    server::serve_until_signal(config, state).await
}

// ---- test support -------------------------------------------------------------
//
// Everything a test needs to stand up a complete daemon against a fake
// phone: an in-memory keychain, a dialer that hands the phone half of
// each connection to a harness task, and that harness -- a Noise KK
// INITIATOR (the role the spec assigns the phone) speaking the same
// framing the real BLE path would carry.

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use conveyance_core::crypto::Secret;
    use conveyance_core::crypto::dh::DhSecret;
    use conveyance_core::crypto::sign::IdentitySecretKey;
    use conveyance_core::session::{Role, SessionHandshake};
    use conveyance_core::transport::mock::{MockLink, MockTransport};
    use conveyance_core::transport::{Link, Transport};
    use conveyance_core::wire::message::{
        ApprovalResponse, Decision, ExecuteResponse, ListServicesResponse, Status,
    };
    use std::future::Future;
    use std::sync::Mutex as StdMutex;
    use tokio::sync::mpsc;
    use tokio::sync::watch;

    /// The in-memory keychain stub lives in conveyance-core so it is not
    /// re-implemented per crate (see conveyance_core::test_support).
    pub(crate) use conveyance_core::test_support::MockKeyProvider;

    /// Produces a fresh cross-wired transport pair on every dial: the
    /// daemon gets one half, the phone-harness task the other. Fresh
    /// pairs matter because sessions come and go within one daemon's
    /// life and MockLink is single-use.
    pub(crate) struct HarnessDialer {
        phone_tx: mpsc::Sender<MockLink>,
    }

    impl phone::PhoneDialer for HarnessDialer {
        fn dial(
            &mut self,
            _timeout: Duration,
        ) -> std::pin::Pin<
            Box<
                dyn Future<
                        Output = Result<
                            Box<dyn phone::PhoneLink>,
                            conveyance_core::transport::TransportError,
                        >,
                    > + Send,
            >,
        > {
            let tx = self.phone_tx.clone();
            Box::pin(async move {
                let (mut t_daemon, mut t_phone) = MockTransport::pair();
                let daemon_link = t_daemon.connect(Duration::ZERO).await?;
                let phone_link = t_phone.connect(Duration::ZERO).await?;
                tx.send(phone_link)
                    .await
                    .map_err(|_| conveyance_core::transport::TransportError::Disconnected)?;
                Ok(Box::new(daemon_link) as Box<dyn phone::PhoneLink>)
            })
        }
    }

    use conveyance_core::crypto::OsEntropy;

    /// How the mock phone answers each ApprovalRequest, consumed in
    /// order; a missing entry defaults to Approve.
    #[derive(Clone, Copy, Debug, PartialEq)]
    pub(crate) enum PhoneAction {
        /// Sign + approve normally.
        Approve,
        /// Sign + deny with reason "user_tap".
        Deny,
        /// Sign + decision "expired" (phone-side window lapsed).
        Expire,
        /// Stay silent -- drives the daemon's live timeout path.
        NoReply,
        /// Approve but corrupt the signature byte -- drives the
        /// verification-rejection path.
        BadSignature,
    }

    /// One fully assembled daemon against a live mock phone.
    pub(crate) struct TestDaemon {
        pub config: DaemonConfig,
        pub state: Arc<DaemonState>,
        pub shutdown: watch::Sender<bool>,
        pub keys: Arc<MockKeyProvider>,
        /// Scripted answers, one per ApprovalRequest in arrival order.
        pub phone_ctl: mpsc::Sender<PhoneAction>,
        /// What the phone saw/sent, in order -- the "both sides" half
        /// of the log-row exit criterion.
        pub phone_log: Arc<StdMutex<Vec<String>>>,
        pub _dir: tempfile::TempDir,
    }

    fn unique_socket(tag: &str) -> String {
        use std::sync::atomic::{AtomicU32, Ordering};
        static SEQ: AtomicU32 = AtomicU32::new(0);
        format!(
            "conveyance-test-{}-{}-{tag}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::SeqCst)
        )
    }

    /// Same generator, exposed for tests outside this module.
    pub(crate) fn unique_socket_pub(tag: &str) -> String {
        unique_socket(tag)
    }

    fn test_params() -> SessionParams {
        // Real spec bounds (the validated constructor refuses anything
        // weaker); nothing in these tests depends on short timers --
        // timer-driven ends are exercised in core, and the daemon-level
        // handling is driven through the same command queue as user
        // ends.
        SessionParams::validated(
            SessionParams::IDLE_MIN,
            Duration::from_secs(60),
            SessionParams::CAP_MIN,
        )
        .unwrap()
    }

    /// Same parameters, for tests outside this module.
    pub(crate) fn pub_test_params() -> SessionParams {
        test_params()
    }

    /// Dialer for daemons that will never be asked to start a session
    /// (restart/refusal cases): any dial fails honestly.
    pub(crate) struct NoDialer;

    impl phone::PhoneDialer for NoDialer {
        fn dial(
            &mut self,
            _timeout: Duration,
        ) -> std::pin::Pin<
            Box<
                dyn Future<
                        Output = Result<
                            Box<dyn phone::PhoneLink>,
                            conveyance_core::transport::TransportError,
                        >,
                    > + Send,
            >,
        > {
            Box::pin(async { Err(conveyance_core::transport::TransportError::Disconnected) })
        }
    }

    /// Spawn a daemon + mock phone with a completed pairing row and
    /// short routing windows (tests must not wait spec minutes).
    pub(crate) async fn spawn_daemon(tag: &str) -> TestDaemon {
        spawn_daemon_opts(tag, Opts::default()).await
    }

    /// Unpaired variant for cold-start / refusal cases.
    pub(crate) async fn spawn_daemon_unpaired(tag: &str) -> TestDaemon {
        spawn_daemon_opts(
            tag,
            Opts {
                paired: false,
                ..Opts::default()
            },
        )
        .await
    }

    #[derive(Clone, Copy)]
    pub(crate) struct Opts {
        pub paired: bool,
        /// Approval/execute response windows. Short by default: tests
        /// exercise timeout paths without waiting real minutes.
        pub approval_window: Duration,
        pub execute_window: Duration,
    }

    impl Default for Opts {
        fn default() -> Self {
            Self {
                paired: true,
                approval_window: Duration::from_millis(300),
                execute_window: Duration::from_millis(300),
            }
        }
    }

    pub(crate) async fn spawn_daemon_opts(tag: &str, opts: Opts) -> TestDaemon {
        let dir = tempfile::tempdir().unwrap();
        let keys = Arc::new(MockKeyProvider::new());

        let dp = conveyance_core::paths::DataPaths::under(dir.path());
        let pc_identity = StoredIdentity::generate(&OsEntropy).unwrap();
        pc_identity
            .save(&dp.identity, keys.as_ref(), &OsEntropy)
            .unwrap();

        // Phone identity halves. The X25519 secret stays on the phone;
        // only the public half lands in the pairing row, exactly like
        // the ceremony would leave things.
        let phone_dh = DhSecret::generate(&OsEntropy).unwrap();
        let phone_signer = IdentitySecretKey::generate(&OsEntropy).unwrap();

        let config = DaemonConfig {
            socket: unique_socket(tag),
            pairings_db: dp.pairings,
            executions_db: dp.executions,
            identity_file: dp.identity.clone(),
            session_params: test_params(),
        };

        let stores = refuse_to_start_with(&config, keys.as_ref()).unwrap();

        if opts.paired {
            stores
                .store
                .record(
                    phone_signer.public_key().to_bytes(),
                    phone_dh.public_key().to_bytes(),
                    1_700_000_000,
                )
                .unwrap();
        }

        let (phone_tx, phone_rx) = mpsc::channel::<MockLink>(4);
        let deps = DaemonDeps {
            dialer: Box::new(HarnessDialer { phone_tx }),
            approval_window: Some(opts.approval_window),
            execute_window: Some(opts.execute_window),
        };
        let state = assemble_state(&config, stores, deps);

        let params = config.session_params;
        let phone_log = Arc::new(StdMutex::new(Vec::new()));
        let (ctl_tx, ctl_rx) = mpsc::channel::<PhoneAction>(16);
        tokio::spawn(mock_phone_task(
            phone_rx,
            Secret::from_bytes(phone_dh.to_bytes()),
            DhSecret::from_bytes(*pc_identity.x25519_secret.expose())
                .public_key()
                .to_bytes(),
            params,
            phone_signer.clone(),
            ctl_rx,
            phone_log.clone(),
        ));

        let shutdown = server::start_ipc_server(&config, state.clone())
            .await
            .expect("test daemon binds its own unique socket");

        TestDaemon {
            config,
            state,
            shutdown,
            keys,
            phone_ctl: ctl_tx,
            phone_log,
            _dir: dir,
        }
    }

    /// The phone side of the world: for every delivered link, run the
    /// KK handshake as INITIATOR (its permanent role), then serve the
    /// protocol -- pings, scripted approval decisions, execute
    /// responses, list_services -- until the daemon drops the
    /// transport.
    ///
    /// Kept separate from [`mockphone::mock_phone_serve`] on purpose,
    /// not by accident: that one is the always-approve phone a *real*
    /// MCP client drives against a *real* daemon binary (transcript to
    /// a file + stderr), and it must never block on a scripted channel.
    /// This one is the in-process negative-path harness -- it scripts
    /// denials, expiries, silence, and forged signatures through
    /// [`PhoneAction`] and keeps its transcript in memory for tests to
    /// assert on. The overlapping happy-path arms are small; unifying
    /// them behind one cfg would cost more indirection than it saves.
    #[allow(clippy::too_many_lines)]
    async fn mock_phone_task(
        mut rx: mpsc::Receiver<MockLink>,
        phone_static: Secret<32>,
        pc_dh_pub: [u8; 32],
        params: SessionParams,
        signer: IdentitySecretKey,
        mut actions: mpsc::Receiver<PhoneAction>,
        transcript: Arc<StdMutex<Vec<String>>>,
    ) {
        fn note(t: &StdMutex<Vec<String>>, s: &str) {
            t.lock().unwrap().push(s.to_string());
        }

        while let Some(mut link) = rx.recv().await {
            let peer = conveyance_core::session::PeerIdentity {
                local_static: phone_static.clone(),
                remote_static: pc_dh_pub,
            };
            let mut hs = match SessionHandshake::begin(Role::Initiator, &peer) {
                Ok(hs) => hs,
                Err(_) => continue,
            };

            // One IO half serves the WHOLE connection so framing
            // sequence numbers and reassembly state stay continuous
            // across handshake -> transport.
            let mut io = PhoneHalf::new(&mut link);

            // Message 1 goes out first (initiator).
            let m1 = match hs.write_message(b"") {
                Ok(m) => m,
                Err(_) => continue,
            };
            if io.send_app(&m1).await.is_err() {
                continue;
            }
            // Message 2 comes back.
            let Some(m2) = io.recv_app().await else {
                continue;
            };
            if hs.read_message(&m2).is_err() {
                continue;
            }
            let mut session = match hs.establish(params) {
                Ok(s) => s,
                Err(_) => continue,
            };

            // Serve the session like a real phone would.
            loop {
                let Some(cipher) = io.recv_app().await else {
                    break;
                };
                // Decrypt through the session BEFORE decoding: frames
                // carry Noise ciphertext, not plaintext.
                let Ok(msg) = session.receive(&cipher) else {
                    break;
                };
                let decoded: Option<conveyance_core::wire::message::WireMessage> =
                    ciborium::de::from_reader(&mut &msg[..]).ok();
                match decoded {
                    Some(conveyance_core::wire::message::WireMessage::Ping(p)) => {
                        let pong = conveyance_core::wire::message::WireMessage::Pong(
                            conveyance_core::wire::message::Pong {
                                req_id: p.req_id,
                                timestamp: p.timestamp,
                            },
                        );
                        if let Ok(plain) = conveyance_core::wire::message::encode(&pong)
                            && io.send_encrypted(&mut session, &plain).await.is_err()
                        {
                            break;
                        }
                    }
                    Some(conveyance_core::wire::message::WireMessage::ApprovalRequest(req)) => {
                        note(&transcript, "recv ApprovalRequest");
                        // Next scripted action; default approve.
                        let action = actions.try_recv().unwrap_or(PhoneAction::Approve);
                        let decision = match action {
                            PhoneAction::Approve => Decision::Approved,
                            PhoneAction::Deny => Decision::Denied,
                            PhoneAction::Expire => Decision::Expired,
                            PhoneAction::NoReply => {
                                note(&transcript, "action NoReply (silence)");
                                continue;
                            }
                            PhoneAction::BadSignature => Decision::Approved,
                        };
                        let reason = match action {
                            PhoneAction::Deny => Some("user_tap".to_string()),
                            PhoneAction::Expire => Some("phone_window".to_string()),
                            _ => None,
                        };
                        let mut rsp = ApprovalResponse::approved_or_denied(
                            req.req_id, decision, reason, &signer,
                        );
                        if action == PhoneAction::BadSignature {
                            rsp.signature[0] ^= 0xff;
                        }
                        note(&transcript, &format!("sent ApprovalResponse {decision:?}"));
                        if let Ok(plain) = conveyance_core::wire::message::encode(
                            &conveyance_core::wire::message::WireMessage::ApprovalResponse(rsp),
                        ) && io.send_encrypted(&mut session, &plain).await.is_err()
                        {
                            break;
                        }
                    }
                    Some(conveyance_core::wire::message::WireMessage::ExecuteRequest(req)) => {
                        note(&transcript, "recv ExecuteRequest");
                        let body = serde_json::json!({
                            "echo": {
                                "service": req.service,
                                "method": req.method,
                                "endpoint": req.endpoint,
                                "params": req.params,
                            },
                            "phone": "mock",
                        });
                        let rsp = ExecuteResponse::new(
                            req.req_id,
                            Status::Ok,
                            Some(200),
                            body,
                            conveyance_core::time::unix_now(),
                        )
                        .expect("mock body is canonical")
                        .sign(&signer);
                        note(&transcript, "sent ExecuteResponse ok");
                        if let Ok(plain) = conveyance_core::wire::message::encode(
                            &conveyance_core::wire::message::WireMessage::ExecuteResponse(rsp),
                        ) && io.send_encrypted(&mut session, &plain).await.is_err()
                        {
                            break;
                        }
                    }
                    Some(conveyance_core::wire::message::WireMessage::ListServicesRequest(req)) => {
                        note(&transcript, "recv ListServicesRequest");
                        let rsp = conveyance_core::wire::message::WireMessage::ListServicesResponse(
                            ListServicesResponse {
                                req_id: req.req_id,
                                services: vec!["github".into(), "aws".into()],
                            },
                        );
                        note(&transcript, "sent ListServicesResponse");
                        if let Ok(plain) = conveyance_core::wire::message::encode(&rsp)
                            && io.send_encrypted(&mut session, &plain).await.is_err()
                        {
                            break;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// Framed app-message IO over a MockLink for the phone side.
    struct PhoneHalf<'a> {
        link: &'a mut MockLink,
        assembler: conveyance_core::transport::InboundAssembler,
        tx_seq: u16,
    }

    impl<'a> PhoneHalf<'a> {
        fn new(link: &'a mut MockLink) -> Self {
            Self {
                link,
                assembler: conveyance_core::transport::InboundAssembler::new(),
                tx_seq: 0,
            }
        }

        async fn send_app(&mut self, bytes: &[u8]) -> Result<(), ()> {
            let max = self.link.max_write_len();
            let (frames, next) =
                conveyance_core::wire::framing::split_message(bytes, max, self.tx_seq)
                    .map_err(|_| ())?;
            self.tx_seq = next;
            for f in frames {
                self.link.send(&f).await.map_err(|_| ())?;
            }
            Ok(())
        }

        async fn recv_app(&mut self) -> Option<Vec<u8>> {
            loop {
                match self.link.recv().await {
                    Err(_) => return None,
                    Ok(chunk) => match self.assembler.ingest(&chunk) {
                        Ok(msgs) if !msgs.is_empty() => return msgs.into_iter().next(),
                        Ok(_) => continue,
                        Err(_) => return None,
                    },
                }
            }
        }

        async fn send_encrypted(
            &mut self,
            session: &mut conveyance_core::session::Session,
            plaintext: &[u8],
        ) -> Result<(), ()> {
            let cipher = session.send(plaintext).map_err(|_| ())?;
            self.send_app(&cipher).await
        }
    }
}

// ---- tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{IpcRequest, IpcResponse, single_request};
    use crate::test_support::{MockKeyProvider, spawn_daemon, spawn_daemon_unpaired};
    use conveyance_core::crypto::OsEntropy;
    use conveyance_core::storage::identity::StoredIdentity;
    use serde_json::json;

    async fn status_roundtrip(socket: &str) -> IpcResponse {
        single_request(socket, IpcRequest::Status)
            .await
            .expect("status roundtrip over a real local socket")
    }

    /// Exit criterion: "IPC roundtrip works over a real local socket".
    /// Client writes one framed CBOR request; daemon answers with the
    /// correct structured response.
    #[tokio::test]
    async fn ipc_roundtrip_status_over_real_socket() {
        let d = spawn_daemon("roundtrip").await;

        match status_roundtrip(&d.config.socket).await {
            IpcResponse::Status {
                version,
                uptime_seconds: _,
                session_active,
                paired_phones,
            } => {
                assert_eq!(version, env!("CARGO_PKG_VERSION"));
                assert!(!session_active, "fresh daemon has no session");
                assert_eq!(paired_phones.len(), 1, "the pairing row is visible");
            }
            other => panic!("expected Status response, got {other:?}"),
        }
    }

    /// Exit criterion: "Cold-start: any request while NO_SESSION returns
    /// conveyance/no_session."
    ///
    /// Scope note: the gate covers everything that REQUIRES a session.
    /// SessionStart is the operation that CREATES one (cold by
    /// definition), and SessionEnd is spec-defined idempotent -- both
    /// have their own contracts and are covered elsewhere.
    #[tokio::test]
    async fn cold_start_rejects_session_requiring_requests() {
        let d = spawn_daemon_unpaired("coldstart").await;

        let requests = vec![
            IpcRequest::CheckSession,
            IpcRequest::AuthenticatedRequest {
                service: "github".into(),
                method: "GET".into(),
                endpoint: "/user".into(),
                params: json!({}),
                requested_by: Some("test-shim".into()),
            },
            IpcRequest::ListServices,
        ];
        for req in requests {
            let resp = single_request(&d.config.socket, req).await.unwrap();
            match resp {
                IpcResponse::Error {
                    code, retryable, ..
                } => {
                    assert_eq!(code, "conveyance/no_session", "wrong cold-start code");
                    assert!(retryable, "no_session is retryable per the spec table");
                }
                other => panic!("expected no_session error, got {other:?}"),
            }
        }
    }

    /// Exit criterion: "Session start/end via IPC reach ACTIVE /
    /// NO_SESSION against the mock phone" plus log durability of both
    /// transitions.
    #[tokio::test]
    async fn session_lifecycle_against_mock_phone_reaches_active_then_no_session() {
        let d = spawn_daemon("lifecycle").await;
        let handle = &d.state.sessions;

        // Start: dial + full KK handshake against the harness phone.
        handle.start().await.expect("session start succeeds");
        handle.wait_active(true).await;

        // ACTIVE view reports real remaining budget from spec bounds.
        let view = handle.inspect().await.expect("active implies a view");
        assert!(view.idle_seconds_remaining > 0 && view.idle_seconds_remaining <= 300);
        // as_secs() floors, so allow one second of startup slop.
        assert!(
            view.hard_cap_seconds_remaining >= SessionParams::CAP_MIN.as_secs() - 1,
            "cap budget should start at CAP_MIN"
        );

        // Second start while ACTIVE is idempotent success.
        handle.start().await.expect("second start idempotent");

        // CheckSession through the IPC surface reflects activity.
        match single_request(&d.config.socket, IpcRequest::CheckSession)
            .await
            .unwrap()
        {
            IpcResponse::SessionActive { .. } => {}
            other => panic!("expected SessionActive over IPC, got {other:?}"),
        }

        // End: back to NO_SESSION, keys zeroized inside the core type.
        handle.end(EndReason::UserEnded).await.unwrap();
        handle.wait_active(false).await;
        match single_request(&d.config.socket, IpcRequest::CheckSession)
            .await
            .unwrap()
        {
            IpcResponse::Error { code, .. } => assert_eq!(code, "conveyance/no_session"),
            other => panic!("expected no_session after end, got {other:?}"),
        }

        // Both lifecycle rows are durable and chained intact.
        let log = LogDb::open(&d.config.executions_db).unwrap();
        let events = log.events().unwrap();
        let types: Vec<_> = events.iter().map(|e| e.event_type.as_str()).collect();
        assert!(
            types.contains(&"session_start") && types.contains(&"session_end"),
            "lifecycle rows missing: {types:?}"
        );
        assert_eq!(
            log.verify().unwrap(),
            Ok(events.len()),
            "chain must be intact"
        );
    }

    /// Exit criterion: "two concurrent IPC clients observe consistent
    /// state." Six clients hammer Status/CheckSession across an
    /// active->end transition; every response must parse, carry the
    /// right version, and never contradict the lifecycle order.
    #[tokio::test]
    async fn concurrent_clients_observe_consistent_state() {
        let d = spawn_daemon("concurrent").await;
        let socket = d.config.socket.clone();
        let handle = d.state.sessions.clone();

        const CLIENTS: usize = 6;
        let mut collectors = Vec::new();
        for _ in 0..CLIENTS {
            let sock = socket.clone();
            collectors.push(tokio::spawn(async move {
                let mut seen_active = Vec::new();
                for _ in 0..40 {
                    match single_request(&sock, IpcRequest::Status).await.unwrap() {
                        IpcResponse::Status { session_active, .. } => {
                            seen_active.push(session_active)
                        }
                        other => panic!("corrupt status during concurrency: {other:?}"),
                    }
                    tokio::task::yield_now().await;
                }
                seen_active
            }));
        }

        // Drive one full lifecycle under the readers.
        handle.start().await.unwrap();
        handle.wait_active(true).await;
        // Let readers observe the active window.
        tokio::time::sleep(Duration::from_millis(20)).await;
        handle.end(EndReason::UserEnded).await.unwrap();
        handle.wait_active(false).await;

        let mut any_true = false;
        for c in collectors {
            let seen = c.await.unwrap();
            // Consistency: once true was observed, it may only flip back
            // to false once (the end) -- never flicker arbitrarily.
            let mut flips = 0;
            for w in seen.windows(2) {
                if w[0] != w[1] {
                    flips += 1;
                }
            }
            assert!(flips <= 2, "state flapped more than the lifecycle allows");
            any_true |= seen.iter().any(|b| *b);
        }
        assert!(any_true, "readers must observe the active window");

        // Post-end ground truth for every late reader.
        match status_roundtrip(&socket).await {
            IpcResponse::Status { session_active, .. } => {
                assert!(!session_active);
            }
            other => panic!("{other:?}"),
        }
    }

    /// Exit criterion: "Shutdown is clean and restartable (no stale
    /// socket lock)." After the flag, the daemon stops answering; the
    /// same name binds again and serves correctly.
    #[tokio::test]
    async fn shutdown_is_clean_and_restartable() {
        let d = spawn_daemon_unpaired("restart").await;
        let socket = d.config.socket.clone();

        let _ = status_roundtrip(&socket).await;

        d.shutdown.send(true).expect("shutdown flag accepted");
        drop(d.shutdown.clone());

        // Wait until nothing answers anymore (bounded).
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if single_request(&socket, IpcRequest::Status).await.is_err() {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "daemon still answering after shutdown"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Restart on the SAME name: probe sees nothing, bind succeeds
        // (stale-file reclamation covers any leftover race), serving
        // resumes.
        let state2 = {
            let stores = refuse_to_start_with(&d.config, d.keys.as_ref()).unwrap();
            assemble_state(
                &d.config,
                stores,
                DaemonDeps::new(Box::new(test_support::NoDialer)),
            )
        };
        let shutdown2 = server::start_ipc_server(&d.config, state2)
            .await
            .expect("rebind after clean shutdown must succeed");
        let _ = shutdown2;

        match status_roundtrip(&socket).await {
            IpcResponse::Status { uptime_seconds, .. } => {
                assert!(uptime_seconds < 5, "restart yields a fresh daemon");
            }
            other => panic!("{other:?}"),
        }
    }

    /// A second daemon on the same name refuses with SocketInUse --
    /// decided by PROBING the live endpoint, not by trusting create
    /// results (which lie on Windows named pipes).
    #[tokio::test]
    async fn second_daemon_on_same_socket_is_refused() {
        let d = spawn_daemon_unpaired("inuse").await;
        let stores = refuse_to_start_with(&d.config, d.keys.as_ref()).unwrap();
        let state = assemble_state(
            &d.config,
            stores,
            DaemonDeps::new(Box::new(test_support::NoDialer)),
        );
        match server::start_ipc_server(&d.config, state).await {
            Err(StartupError::SocketInUse { .. }) => {}
            Err(other) => panic!("expected SocketInUse, got {other}"),
            Ok(_) => panic!("second daemon must not bind"),
        }
    }

    /// Refuse-to-start: keychain down => typed error with actionable
    /// text, and NO database artifacts created before the failure.
    #[tokio::test]
    async fn refuse_to_start_when_keychain_down_leaves_no_databases() {
        let dir = tempfile::tempdir().unwrap();
        let mut keys = MockKeyProvider::new();

        let identity = StoredIdentity::generate(&OsEntropy).unwrap();
        let dp = conveyance_core::paths::DataPaths::under(dir.path());
        let config = DaemonConfig {
            socket: test_support::unique_socket_pub("refuse-kc"),
            pairings_db: dp.pairings,
            executions_db: dp.executions,
            identity_file: dp.identity,
            session_params: test_support::pub_test_params(),
        };
        identity
            .save(&config.identity_file, &keys, &OsEntropy)
            .unwrap();

        keys.fail = true;
        let err = match refuse_to_start_with(&config, &keys) {
            Err(e) => e,
            Ok(_) => panic!("daemon assembled despite dead keychain"),
        };
        match err {
            ref e @ StartupError::KeychainUnavailable { .. } => {
                let text = e.to_string().to_lowercase();
                assert!(text.contains("keychain"), "actionable text missing: {text}");
                assert!(text.contains("refuses"), "fallback posture missing: {text}");
            }
            other => panic!("expected KeychainUnavailable, got {other:?}"),
        }
        assert!(
            !config.pairings_db.exists(),
            "keychain failure must precede database creation"
        );
    }

    /// Refuse-to-start: a database that cannot open (here: a directory
    /// squatting the path) fails startup with the actionable Open error.
    #[tokio::test]
    async fn refuse_to_start_when_database_cannot_open() {
        let dir = tempfile::tempdir().unwrap();
        let keys = MockKeyProvider::new();

        let identity = StoredIdentity::generate(&OsEntropy).unwrap();
        let dp = conveyance_core::paths::DataPaths::under(dir.path());
        std::fs::create_dir_all(&dp.executions).unwrap(); // sabotage

        let config = DaemonConfig {
            socket: test_support::unique_socket_pub("refuse-db"),
            pairings_db: dp.pairings,
            executions_db: dp.executions,
            identity_file: dp.identity,
            session_params: test_support::pub_test_params(),
        };
        identity
            .save(&config.identity_file, &keys, &OsEntropy)
            .unwrap();

        match refuse_to_start_with(&config, &keys) {
            Err(StartupError::Open { what, .. }) => {
                assert!(what.contains("executions database"), "{what}");
            }
            Err(other) => panic!("expected Open failure, got {other:?}"),
            Ok(_) => panic!("daemon started despite unopenable database"),
        }
    }
}

// ---- phase 7.1 tests ----------------------------------------------------------

#[cfg(test)]
mod routing_tests {
    use super::*;
    use crate::ipc::{IpcRequest, IpcResponse, single_request};
    use crate::recovery::{CRASHED_BEFORE_TERMINAL, sweep_orphaned_requests};
    use crate::test_support::{PhoneAction, TestDaemon, spawn_daemon};
    use conveyance_core::crypto::OsEntropy;
    use conveyance_core::crypto::hashchain::LogEvent;
    use conveyance_core::storage::identity::StoredIdentity;
    use serde_json::json;

    fn auth_req() -> IpcRequest {
        IpcRequest::AuthenticatedRequest {
            service: "github".into(),
            method: "POST".into(),
            endpoint: "/v1/deploy".into(),
            params: json!({"env": "prod", "replicas": 3}),
            requested_by: Some("test-shim".into()),
        }
    }

    async fn start_session(d: &TestDaemon) {
        d.state.sessions.start().await.unwrap();
        d.state.sessions.wait_active(true).await;
    }

    /// Exit criterion (7.1): full flow against the mock phone -- log
    /// rows on BOTH sides and the body propagating back to the shim.
    #[tokio::test]
    async fn full_authenticated_request_flow() {
        let d = spawn_daemon("route-happy").await;
        start_session(&d).await;

        let resp = single_request(&d.config.socket, auth_req()).await.unwrap();
        match resp {
            IpcResponse::Body(body) => {
                assert_eq!(body["phone"], json!("mock"));
                assert_eq!(body["echo"]["service"], json!("github"));
                assert_eq!(body["echo"]["params"]["env"], json!("prod"));
            }
            other => panic!("expected Body response, got {other:?}"),
        }

        // PC-side rows for this req_id, in order.
        let log = LogDb::open(&d.config.executions_db).unwrap();
        let events = log.events().unwrap();
        let lifecycle_skipped = |e: &LogEvent| e.req_id != [0u8; 16];
        let trail: Vec<&str> = events
            .iter()
            .filter(|e| lifecycle_skipped(e))
            .map(|e| e.event_type.as_str())
            .collect();
        assert_eq!(
            trail,
            vec![
                "approval_request",
                "approval_granted",
                "execute_sent",
                "execute_result"
            ],
            "PC log trail mismatch: {trail:?}"
        );
        assert_eq!(log.verify().unwrap(), Ok(events.len()), "chain intact");

        // Phone side saw exactly the two protocol requests.
        let phone = d.phone_log.lock().unwrap().clone();
        assert_eq!(
            phone,
            vec![
                "recv ApprovalRequest",
                "sent ApprovalResponse Approved",
                "recv ExecuteRequest",
                "sent ExecuteResponse ok",
            ],
            "phone transcript mismatch: {phone:?}"
        );
    }

    /// Exit criterion (7.1): denial produces the right spec error, no
    /// execution happens, rows are recorded.
    #[tokio::test]
    async fn denied_approval_produces_spec_error_without_execution() {
        let d = spawn_daemon("route-deny").await;
        d.phone_ctl.send(PhoneAction::Deny).await.unwrap();
        start_session(&d).await;

        match single_request(&d.config.socket, auth_req()).await.unwrap() {
            IpcResponse::Error {
                code,
                retryable,
                message,
            } => {
                assert_eq!(code, "conveyance/approval_denied");
                assert!(!retryable, "denial is final per the spec table");
                assert!(message.contains("denied"));
            }
            other => panic!("expected structured error, got {other:?}"),
        }

        let log = LogDb::open(&d.config.executions_db).unwrap();
        let trail: Vec<String> = log
            .events()
            .unwrap()
            .into_iter()
            .filter(|e| e.req_id != [0u8; 16])
            .map(|e| e.event_type)
            .collect();
        assert_eq!(trail, vec!["approval_request", "approval_denied"]);

        // The phone never received an ExecuteRequest.
        let phone = d.phone_log.lock().unwrap().clone();
        assert!(!phone.iter().any(|s| s.contains("Execute")), "{phone:?}");
    }

    /// Phone-side expiry maps onto the approval_timeout code (the
    /// shim-facing table has no separate code; both mean ask again).
    #[tokio::test]
    async fn expired_decision_maps_to_approval_timeout() {
        let d = spawn_daemon("route-expired").await;
        d.phone_ctl.send(PhoneAction::Expire).await.unwrap();
        start_session(&d).await;

        match single_request(&d.config.socket, auth_req()).await.unwrap() {
            IpcResponse::Error {
                code, retryable, ..
            } => {
                assert_eq!(code, "conveyance/approval_timeout");
                assert!(retryable);
            }
            other => panic!("expected timeout error, got {other:?}"),
        }
    }

    /// Silence from the phone hits the daemon's deadline: the client
    /// sees conveyance/approval_timeout AND the log records a LIVE
    /// timeout (reason "timeout") -- distinct from crash recovery.
    #[tokio::test]
    async fn silent_phone_times_out_with_live_timeout_row() {
        let d = spawn_daemon("route-silent").await;
        d.phone_ctl.send(PhoneAction::NoReply).await.unwrap();
        start_session(&d).await;

        match single_request(&d.config.socket, auth_req()).await.unwrap() {
            IpcResponse::Error {
                code, retryable, ..
            } => {
                assert_eq!(code, "conveyance/approval_timeout");
                assert!(retryable);
            }
            other => panic!("expected timeout error, got {other:?}"),
        }

        let timeouts: Vec<LogEvent> = LogDb::open(&d.config.executions_db)
            .unwrap()
            .events()
            .unwrap()
            .into_iter()
            .filter(|e| e.event_type == "request_timeout")
            .collect();
        assert_eq!(timeouts.len(), 1);
        let payload: serde_json::Value = serde_json::from_str(&timeouts[0].payload_json).unwrap();
        assert_eq!(payload["reason"], json!("timeout"), "live timeout reason");
    }

    /// A corrupted phone signature must be refused BEFORE any
    /// execution, loudly logged, and the session kept alive.
    #[tokio::test]
    async fn bad_signature_rejected_before_execution() {
        let d = spawn_daemon("route-badsig").await;
        d.phone_ctl.send(PhoneAction::BadSignature).await.unwrap();
        start_session(&d).await;

        match single_request(&d.config.socket, auth_req()).await.unwrap() {
            IpcResponse::Error {
                code, retryable, ..
            } => {
                assert_eq!(code, "conveyance/internal");
                assert!(!retryable);
            }
            other => panic!("expected rejection, got {other:?}"),
        }

        let events = LogDb::open(&d.config.executions_db)
            .unwrap()
            .events()
            .unwrap();
        assert!(
            !events.iter().any(|e| e.event_type == "execute_sent"),
            "nothing may execute on a bad signature"
        );
        assert!(
            events.iter().any(|e| e.event_type == "daemon_note"
                && e.payload_json.contains("approval_signature_invalid")),
            "rejection should be durably noted"
        );

        // Session survives: a subsequent request still routes.
        let resp = single_request(&d.config.socket, auth_req()).await.unwrap();
        assert!(matches!(resp, IpcResponse::Body(_)));
    }

    /// Exit criterion (7.1): ListServices routed over the session.
    #[tokio::test]
    async fn list_services_roundtrip() {
        let d = spawn_daemon("route-services").await;
        start_session(&d).await;

        let resp = single_request(&d.config.socket, IpcRequest::ListServices)
            .await
            .unwrap();
        match resp {
            IpcResponse::Services(names) => assert_eq!(names, vec!["github", "aws"]),
            other => panic!("expected Services, got {other:?}"),
        }
    }

    /// Exit criterion (7.1): concurrent shims during one active request
    /// see consistent state -- the second request serializes behind the
    /// first (no interleaved protocol state), status stays readable,
    /// and every answer is well-formed.
    #[tokio::test]
    async fn concurrent_requests_serialize_and_state_stays_consistent() {
        let d = spawn_daemon("route-concurrent").await;
        // First request gets silence (times out); the queued one gets
        // approved once it reaches the phone.
        d.phone_ctl.send(PhoneAction::NoReply).await.unwrap();
        d.phone_ctl.send(PhoneAction::Approve).await.unwrap();
        start_session(&d).await;
        let socket = d.config.socket.clone();

        let s1 = socket.clone();
        let first = tokio::spawn(async move { single_request(&s1, auth_req()).await.unwrap() });
        let s2 = socket.clone();
        let second = tokio::spawn(async move { single_request(&s2, auth_req()).await.unwrap() });
        let s3 = socket.clone();
        let reader = tokio::spawn(async move {
            for _ in 0..10 {
                match single_request(&s3, IpcRequest::Status).await.unwrap() {
                    IpcResponse::Status { .. } => {}
                    other => panic!("status corrupted during routing: {other:?}"),
                }
            }
        });

        // First times out (short window), second completes after its
        // queued turn.
        match first.await.unwrap() {
            IpcResponse::Error {
                code, retryable, ..
            } => {
                assert_eq!(code, "conveyance/approval_timeout");
                assert!(retryable);
            }
            other => panic!("expected timeout on first, got {other:?}"),
        }
        assert!(matches!(second.await.unwrap(), IpcResponse::Body(_)));
        reader.await.unwrap();

        let types: Vec<String> = LogDb::open(&d.config.executions_db)
            .unwrap()
            .events()
            .unwrap()
            .into_iter()
            .filter(|e| e.req_id != [0u8; 16])
            .map(|e| e.event_type)
            .collect();
        assert_eq!(
            types,
            vec![
                "approval_request",
                "request_timeout",
                "approval_request",
                "approval_granted",
                "execute_sent",
                "execute_result",
            ],
            "serialized trails expected: {types:?}"
        );
    }

    /// Exit criterion (7.1): after restart, an orphaned req_id is
    /// visible as request_timeout with the crashed_before_terminal
    /// reason. Mirrors run_with's ordering exactly (refuse -> sweep ->
    /// serve) minus the signal wait.
    #[tokio::test]
    async fn crash_recovery_sweep_marks_orphans_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let keys = test_support::MockKeyProvider::new();
        let pc_identity = StoredIdentity::generate(&OsEntropy).unwrap();
        let dp = conveyance_core::paths::DataPaths::under(dir.path());
        let config = DaemonConfig {
            socket: test_support::unique_socket_pub("crash-sweep"),
            pairings_db: dp.pairings,
            executions_db: dp.executions,
            identity_file: dp.identity,
            session_params: test_support::pub_test_params(),
        };
        pc_identity
            .save(&config.identity_file, &keys, &OsEntropy)
            .unwrap();

        // Simulate the previous life: one request died between execute
        //_sent and any terminal row.
        {
            let db = LogDb::open(&config.executions_db).unwrap();
            let mut orphan = [0u8; 16];
            orphan[0] = 0xAB;
            for event_type in ["approval_request", "execute_sent"] {
                db.append(&LogEvent {
                    req_id: orphan,
                    event_type: event_type.into(),
                    payload_json: r#"{"op":"authenticated_request"}"#.into(),
                    timestamp: 1_700_000_000,
                })
                .unwrap();
            }
        }

        // "Restart": refuse -> sweep (run_with's startup order).
        let stores = refuse_to_start_with(&config, &keys).unwrap();
        let swept = sweep_orphaned_requests(&stores.log).unwrap();
        assert_eq!(swept, 1);

        let rows: Vec<LogEvent> = stores
            .log
            .events()
            .unwrap()
            .into_iter()
            .filter(|e| e.event_type == "request_timeout")
            .collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].req_id[0], 0xAB);
        let payload: serde_json::Value = serde_json::from_str(&rows[0].payload_json).unwrap();
        assert_eq!(payload["reason"], json!(CRASHED_BEFORE_TERMINAL));
        assert_eq!(payload["orphaned_after"], json!("execute_sent"));

        // And the restarted daemon serves with a verifiable chain.
        let state = assemble_state(
            &config,
            stores,
            DaemonDeps::new(Box::new(test_support::NoDialer)),
        );
        let shutdown = server::start_ipc_server(&config, state.clone())
            .await
            .expect("restarted daemon binds");
        match single_request(&config.socket, IpcRequest::Status)
            .await
            .unwrap()
        {
            IpcResponse::Status { .. } => {}
            other => panic!("{other:?}"),
        }
        shutdown.send(true).unwrap();
    }
}
