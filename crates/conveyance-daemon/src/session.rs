//! The session owner: one task that exclusively drives the phone
//! connection and the lifecycle machine.
//!
//! Everything that mutates or observes the session funnels through a
//! single command channel to this task. That is a deliberate concurrency
//! posture, not an aesthetic one: the alternatives (a shared
//! `Mutex<Option<Session>>`, scattered tasks holding transport halves)
//! either serialize IPC handlers behind long phone round-trips or let
//! two writers race the same Noise cipher state. With an owner:
//!
//! * IPC handlers get non-blocking answers (`is_active` rides a watch
//!   channel and never touches the owner),
//! * timer events, user ends, kill switches and peer disconnects are
//!   applied in arrival order with no locking discipline to get wrong,
//! * framing reassembly state and Noise cipher state have exactly one
//!   writer, so concurrent shims cannot corrupt them.
//!
//! The active-session state ([`ActiveParts`]) is held in an `Option`
//! slot and handed to handlers by reference. The inbound receive future
//! is recreated each loop iteration; that is safe rather than sloppy,
//! because every transport here delivers whole chunks -- cancelling a
//! pending recv never loses data, it only re-registers interest.
//!
//! Phase 7.1 routes authenticated requests through this same loop; the
//! chunk-handling arm is where those messages land.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use conveyance_core::crypto::hashchain::LogEvent;
use conveyance_core::crypto::sign::IdentityPublicKey;
use conveyance_core::crypto::{OsEntropy, Secret};
use conveyance_core::error::ConveyanceError;
use conveyance_core::session::{
    EndReason, PeerIdentity, Role, Session as CoreSession, SessionHandshake, SessionParams,
    TimerEvent,
};
use conveyance_core::storage::logdb::LogDb;
use conveyance_core::storage::pairings::PairingsDb;
use conveyance_core::transport::{InboundAssembler, TransportError};
use conveyance_core::wire::binding::ApprovedRequestTracker;
use conveyance_core::wire::framing;
use conveyance_core::wire::message::{
    self as wire, ApprovalRequest, ApprovalResponse, Decision, ExecuteRequest, ExecuteResponse,
    OpType, Status,
};

use tokio::sync::{mpsc, oneshot, watch};

use crate::ipc::IpcResponse;
use crate::phone::{PhoneDialer, PhoneLink};

/// How long any single step toward an ACTIVE session may take: the
/// spec's 30 s reachability window covers dial AND handshake exchange.
/// A phone that advertises but stalls mid-handshake fails closed here
/// rather than wedging the owner task.
const HANDSHAKE_TOTAL_BUDGET: Duration = Duration::from_secs(30);

/// Spec's approval window: the user has 60 s to respond on the phone.
pub(crate) const APPROVAL_WINDOW: Duration = Duration::from_secs(60);
/// Execution window: the phone performs the HTTP round-trip after
/// approval. The spec names no number; 60 s covers slow APIs without
/// letting a dead session pin a shim request indefinitely. Overridable
/// in [`SessionDeps`] so tests do not wait real minutes.
pub(crate) const EXECUTE_WINDOW: Duration = Duration::from_secs(60);

/// Bound on queued routed requests while one is in flight. One shim =
/// one outstanding tool call in practice; anything past this gets an
/// immediate retryable busy error rather than growing unbounded.
const ROUTE_QUEUE_CAP: usize = 8;

/// Terminal log states for a req_id: once one of these exists, crash
/// recovery (phase 7.1 sweep) considers the request fully accounted
/// for. See `recovery::sweep_orphaned_requests`.
pub(crate) const TERMINAL_EVENT_TYPES: [&str; 3] =
    ["execute_result", "approval_denied", "request_timeout"];

/// Reserved correlation id for log rows that belong to no tool call
/// (session lifecycle rows today; the recovery sweep writes real
/// req_ids). Zeroed bytes cannot collide with a random ReqId in
/// practice and are trivially filterable by log tooling.
pub(crate) const LIFECYCLE_REQ_ID: [u8; 16] = [0u8; 16];

// ---- errors -------------------------------------------------------------------

/// A failed operation, already carrying the spec's error shape. Plain
/// data rather than an enum because the meaningful taxonomy lives in
/// `ConveyanceError`; what this module adds beyond it is operational
/// detail that carries no security weight.
#[derive(Clone, Debug, PartialEq)]
pub struct OpError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

impl OpError {
    pub fn new(code: &str, message: impl Into<String>, retryable: bool) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            retryable,
        }
    }

    /// Map a core error onto the named-code table. Codes and retryable
    /// flags stay owned by the core type so they cannot drift here.
    pub fn from_conveyance(err: &conveyance_core::error::ConveyanceError) -> Self {
        let json = err.to_error_json();
        Self {
            code: json.code.to_string(),
            message: json.message,
            retryable: json.retryable,
        }
    }

    fn phone_unreachable(context: &str) -> Self {
        Self::new(
            "conveyance/phone_unreachable",
            format!("Could not reach the paired phone to establish a session ({context})."),
            true,
        )
    }

    fn handshake_failed() -> Self {
        // Generic by mandate: no hint about which validation failed.
        Self::new(
            "conveyance/handshake_failed",
            "Session handshake failed.",
            false,
        )
    }

    /// No pairing exists. The spec's session-start section names this
    /// case `PhoneNotPaired`, but the error-model table -- the surface
    /// clients parse -- defines no such code, so it rides the nearest
    /// defined one. The distinction survives in the message text.
    fn no_pairing() -> Self {
        Self::new(
            "conveyance/phone_unreachable",
            "No paired phone. Run `conveyance pair` first.",
            true,
        )
    }

    fn internal(context: &str) -> Self {
        Self::new("conveyance/internal", context, false)
    }

    fn from_core(err: ConveyanceError) -> Self {
        Self::from_conveyance(&err)
    }

    /// Busy, not broken: a routed request arrived while the queue was
    /// full. Retryable so the shim can back off.
    fn busy() -> Self {
        Self::new(
            "conveyance/internal",
            "another request is awaiting the phone; retry shortly",
            true,
        )
    }
}

fn dead_owner() -> OpError {
    OpError::internal("session owner stopped")
}

// ---- commands -----------------------------------------------------------------

/// What the rest of the daemon may ask of the owner.
enum SessionCmd {
    /// Dial, handshake, reach ACTIVE. Idempotent while ACTIVE.
    Start {
        reply: oneshot::Sender<Result<(), OpError>>,
    },
    /// Tear down for `reason`. Replies AFTER keys are zeroized and the
    /// end row is logged -- shutdown awaits this before checkpointing
    /// databases precisely so that durability ordering holds.
    End {
        reason: EndReason,
        reply: oneshot::Sender<Result<(), OpError>>,
    },
    /// Remaining timer budget. `None` = no active session.
    Inspect {
        reply: oneshot::Sender<Option<SessionView>>,
    },
    /// Watchdog output, forwarded by a small pump task so the owner
    /// selects over ONE queue instead of racing two sources.
    Timer(TimerEvent),
    /// Route an authenticated operation to the phone over the live
    /// session. Serialized behind any already-in-flight request; see
    /// [`Router`](ActiveParts) queue semantics.
    Route {
        op: RoutedOp,
        reply: oneshot::Sender<Result<IpcResponse, OpError>>,
    },
}

/// The two operations 7.1 routes across the Noise session. Everything
/// else the shim can ask is answered locally (status/check/session).
#[derive(Clone, Debug)]
pub enum RoutedOp {
    AuthenticatedRequest {
        service: String,
        method: String,
        endpoint: String,
        params: serde_json::Value,
        requested_by: Option<String>,
    },
    ListServices,
}

/// Snapshot of the session's timing budget, for `check_session`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionView {
    pub idle_seconds_remaining: u64,
    pub hard_cap_seconds_remaining: u64,
}

// ---- handle -------------------------------------------------------------------

/// Cloneable client side of the owner. `is_active()` reads a watch
/// channel and never blocks on the owner, so Status/CheckSession stay
/// responsive even while a dial or a phone round-trip is in flight.
#[derive(Clone)]
pub struct SessionHandle {
    cmd_tx: mpsc::Sender<SessionCmd>,
    active_rx: watch::Receiver<bool>,
}

impl SessionHandle {
    pub fn is_active(&self) -> bool {
        *self.active_rx.borrow()
    }

    pub async fn start(&self) -> Result<(), OpError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(SessionCmd::Start { reply: tx })
            .await
            .map_err(|_| dead_owner())?;
        rx.await.map_err(|_| dead_owner())?
    }

    pub async fn end(&self, reason: EndReason) -> Result<(), OpError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(SessionCmd::End { reason, reply: tx })
            .await
            .map_err(|_| dead_owner())?;
        rx.await.map_err(|_| dead_owner())?
    }

    pub async fn inspect(&self) -> Option<SessionView> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(SessionCmd::Inspect { reply: tx })
            .await
            .ok()?;
        rx.await.ok().flatten()
    }

    /// Route an authenticated operation over the active session.
    /// Errors carry the spec code table verbatim; cold-start callers
    /// are expected to have checked `is_active()` first (the owner
    /// re-checks anyway).
    pub async fn route(&self, op: RoutedOp) -> Result<IpcResponse, OpError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(SessionCmd::Route { op, reply: tx })
            .await
            .map_err(|_| dead_owner())?;
        rx.await.map_err(|_| dead_owner())?
    }

    #[cfg(test)]
    pub(crate) async fn wait_active(&self, want: bool) {
        let mut rx = self.active_rx.clone();
        loop {
            let current = *rx.borrow();
            if current == want {
                return;
            }
            if rx.changed().await.is_err() {
                return;
            }
        }
    }
}

// ---- active state -------------------------------------------------------------

/// Everything that exists only while a session is up. Held in an
/// Option slot so ending a session from inside any handler is a plain
/// `take()` with no borrow gymnastics.
struct ActiveParts {
    session: CoreSession,
    link: Box<dyn PhoneLink>,
    /// Persists across chunks within one ACTIVE stretch -- reassembly
    /// spanning several notifications is its whole purpose.
    assembler: InboundAssembler,
    /// Outbound frame sequence. The framer enforces continuity, so the
    /// counter lives as long as the connection does, NOT per message.
    tx_seq: u16,
    started_at: Instant,
    last_activity: Instant,

    // ---- routing (phase 7.1) -------------------------------------
    /// Ed25519 public half of the paired phone, captured at start so
    /// every Approval/Execute signature verifies against the identity
    /// this session actually authenticated (KK guarantees the DH peer;
    /// signatures make each response independently portable evidence).
    phone_id_pub: IdentityPublicKey,
    /// Anti-TOCTOU + replay defense: approvals are consumed on first
    /// execution. Per-session by design -- approvals never survive a
    /// session boundary.
    binding: ApprovedRequestTracker,
    /// Routed requests waiting for the current one to finish.
    route_queue: VecDeque<RouteCmd>,
    in_flight: Option<InFlight>,
}

/// A queued routed request awaiting its turn at the phone.
struct RouteCmd {
    op: RoutedOp,
    reply: oneshot::Sender<Result<IpcResponse, OpError>>,
}

/// One routed request's position in the approval->execute pipeline.
struct InFlight {
    stage: Stage,
    req_id: wire::ReqId,
    /// The ApprovalRequest while waiting for its response; kept so an
    /// approval can be bound and the matching ExecuteRequest built from
    /// exactly the bytes that were shown to the user.
    approval: Option<ApprovalRequest>,
    /// Request coordinates kept for the whole flight so timeout and
    /// execute_result rows carry them (`log query --tool` filters on
    /// these).
    service: Option<String>,
    method: Option<String>,
    endpoint: Option<String>,
    deadline: Instant,
    reply: oneshot::Sender<Result<IpcResponse, OpError>>,
}

enum Stage {
    Approval,
    Execute,
    Services,
}

impl ActiveParts {
    fn view(&self, params: &SessionParams) -> SessionView {
        SessionView {
            idle_seconds_remaining: params
                .idle_timeout()
                .saturating_sub(self.last_activity.elapsed())
                .as_secs(),
            hard_cap_seconds_remaining: params
                .hard_cap()
                .saturating_sub(self.started_at.elapsed())
                .as_secs(),
        }
    }

    /// Encrypt + frame + transmit one application message through the
    /// live session, advancing the shared outbound sequence.
    async fn send_over_session(&mut self, plaintext: &[u8]) -> Result<(), TransportError> {
        let ciphertext = self
            .session
            .send(plaintext)
            .map_err(|_| TransportError::Disconnected)?;
        let max = self.link.max_write_len();
        let (frames, next_seq) = framing::split_message(&ciphertext, max, self.tx_seq)
            .map_err(|_| TransportError::InvalidState("split failed"))?;
        self.tx_seq = next_seq;
        for frame in frames {
            self.link.send(&frame).await?;
        }
        Ok(())
    }
}

// ---- owner --------------------------------------------------------------------

/// Everything the owner task needs for its whole life. Constructed once
/// during daemon assembly; nothing here is reloaded per request except
/// the pairing row (picked fresh at each start, so pairing between
/// sessions takes effect without a daemon restart).
pub struct SessionDeps {
    pub dialer: Box<dyn PhoneDialer>,
    pub store: Arc<PairingsDb>,
    pub log: Arc<LogDb>,
    pub local_static: Secret<32>,
    pub params: SessionParams,
    /// Approval/execute response windows. Production uses the spec's
    /// 60 s for both; tests shorten them so timeout paths stay fast.
    /// Not user-configurable: shortening the approval window is a UX
    /// tradeoff the spec already fixed at 60 s.
    pub approval_window: Duration,
    pub execute_window: Duration,
}

struct Owner {
    deps: SessionDeps,
    cmd_rx: mpsc::Receiver<SessionCmd>,
    /// Kept alongside the receiver so the timer pump can feed us back.
    cmd_tx: mpsc::Sender<SessionCmd>,
    active_tx: watch::Sender<bool>,
}

enum Flow {
    KeepGoing,
    BackToIdle,
}

/// Spawn the owner. Must be called inside a tokio runtime.
pub fn spawn_session_owner(deps: SessionDeps) -> SessionHandle {
    let (cmd_tx, cmd_rx) = mpsc::channel(32);
    let (active_tx, active_rx) = watch::channel(false);

    let owner = Owner {
        deps,
        cmd_tx: cmd_tx.clone(),
        cmd_rx,
        active_tx,
    };
    let join = tokio::spawn(owner.run());
    #[cfg(test)]
    tokio::spawn(async move {
        if let Err(e) = join.await {
            eprintln!("SESSION OWNER TASK DIED: {e}");
        }
    });
    #[cfg(not(test))]
    drop(join);

    SessionHandle { cmd_tx, active_rx }
}

impl Owner {
    async fn run(mut self) {
        loop {
            // ---- IDLE -------------------------------------------------
            let Some(first) = self.cmd_rx.recv().await else {
                return;
            };
            let mut slot: Option<ActiveParts> = None;
            self.on_command(first, &mut slot).await;
            let Some(parts) = slot else {
                continue;
            };
            if !self.run_active(parts).await {
                return;
            }
        }
    }

    /// Drive one ACTIVE stretch. Returns false when the owner should
    /// exit entirely.
    async fn run_active(&mut self, parts: ActiveParts) -> bool {
        let mut slot: Option<ActiveParts> = Some(parts);
        loop {
            // Deadline snapshot BEFORE any mutable borrow: the inbound
            // future below holds `slot` mutably across the select, so
            // this arm must not capture it.
            let deadline = slot
                .as_ref()
                .and_then(|p| p.in_flight.as_ref())
                .map(|f| f.deadline);
            let route_deadline = async {
                match deadline {
                    Some(d) => tokio::time::sleep_until(tokio::time::Instant::from_std(d)).await,
                    None => std::future::pending::<()>().await,
                }
            };
            // Recreated each iteration (see module docs for why that is
            // safe rather than sloppy).
            let Some(live) = slot.as_mut() else {
                return true;
            };
            let inbound = live.link.recv();
            tokio::select! {
                cmd = self.cmd_rx.recv() => {
                    let Some(cmd) = cmd else { return false };
                    match self.on_command(cmd, &mut slot).await {
                        Flow::BackToIdle => return true,
                        Flow::KeepGoing => {}
                    }
                }
                chunk = inbound => {
                    let Some(live) = slot.as_mut() else {
                        return true;
                    };
                    if self.on_chunk(live, chunk).await {
                        return true; // ended; caller falls back to IDLE
                    }
                }
                _ = route_deadline => {
                    let Some(live) = slot.as_mut() else {
                        return true;
                    };
                    self.route_timed_out(live).await;
                }
            }
        }
    }

    async fn on_command(&mut self, cmd: SessionCmd, slot: &mut Option<ActiveParts>) -> Flow {
        match cmd {
            SessionCmd::Start { reply } => {
                if slot.is_some() {
                    // Idempotent while ACTIVE: a second shim asking for
                    // a session gets success, not a spurious error.
                    let _ = reply.send(Ok(()));
                } else {
                    let result = match self.begin_session().await {
                        Ok(parts) => {
                            let _ = self.active_tx.send(true);
                            *slot = Some(parts);
                            Ok(())
                        }
                        Err(err) => Err(err),
                    };
                    let _ = reply.send(result);
                }
                Flow::KeepGoing
            }
            SessionCmd::End { reason, reply } => {
                if let Some(parts) = slot.as_mut() {
                    self.teardown(parts, reason);
                }
                *slot = None;
                // Ending a session that does not exist succeeds: the
                // operation is defined idempotent for shim-facing CLI.
                let _ = reply.send(Ok(()));
                Flow::BackToIdle
            }
            SessionCmd::Inspect { reply } => {
                let _ = reply.send(slot.as_ref().map(|p| p.view(&self.deps.params)));
                Flow::KeepGoing
            }
            SessionCmd::Timer(event) => {
                let Some(parts) = slot.as_mut() else {
                    return Flow::KeepGoing;
                };
                match parts.session.handle_timer_event(event) {
                    Some(reason) => {
                        self.teardown(parts, reason);
                        *slot = None;
                        Flow::BackToIdle
                    }
                    None => Flow::KeepGoing,
                }
            }
            SessionCmd::Route { op, reply } => {
                let Some(parts) = slot.as_mut() else {
                    // Defense in depth: dispatch gates on the watch
                    // channel first; this arm only fires on a race
                    // between the two.
                    let _ = reply.send(Err(OpError::from_core(ConveyanceError::NoSession)));
                    return Flow::KeepGoing;
                };

                if parts.in_flight.is_some() {
                    // Serialize: one conversation with the phone at a
                    // time. Queued requests see consistent state (their
                    // own turn arrives, or session_ended if the session
                    // dies first) -- never interleaved protocol state.
                    if parts.route_queue.len() >= ROUTE_QUEUE_CAP {
                        let _ = reply.send(Err(OpError::busy()));
                    } else {
                        parts.route_queue.push_back(RouteCmd { op, reply });
                    }
                    return Flow::KeepGoing;
                }

                self.start_route(parts, op, reply).await;
                Flow::KeepGoing
            }
        }
    }

    /// Handle one inbound chunk. Returns true when the session ended
    /// (caller falls back to IDLE).
    async fn on_chunk(
        &mut self,
        parts: &mut ActiveParts,
        chunk: Result<Vec<u8>, TransportError>,
    ) -> bool {
        let Ok(bytes) = chunk else {
            // Any transport failure -- disconnection included -- ends
            // the session. No auto-reconnect (spec): restarts are
            // deliberate user actions.
            self.teardown(parts, EndReason::PeerDisconnected);
            return true;
        };

        let messages = match parts.assembler.ingest(&bytes) {
            Ok(m) => m,
            Err(_) => {
                // Framing violation mid-session is terminal.
                self.teardown(parts, EndReason::ProtocolViolation);
                return true;
            }
        };

        for message in messages {
            // Assembled frames are Noise CIPHERTEXT; nothing below the
            // cipher boundary may be interpreted as protocol data.
            let plaintext = match parts.session.receive(&message) {
                Ok(p) => p,
                Err(_) => {
                    // Tampering or desynchronization: terminal per the
                    // phase-3 contract (receive errors end the session).
                    self.teardown(parts, EndReason::ProtocolViolation);
                    return true;
                }
            };
            let decoded: Option<wire::WireMessage> =
                ciborium::de::from_reader(&mut &plaintext[..]).ok();

            // In-flight interception runs BEFORE the generic arms: a
            // response that answers our routed request is consumed by
            // it. SessionEnd and Ping still take priority below because
            // they can never match a stage.
            if let Some(ended) = self.try_complete_route(parts, &decoded).await {
                if ended {
                    return true;
                }
                continue;
            }

            match decoded {
                Some(wire::WireMessage::SessionEnd(_)) => {
                    // Kill switch / phone-side end arrives as traffic.
                    self.teardown(parts, EndReason::RemoteEnded);
                    return true;
                }
                Some(wire::WireMessage::Ping(p)) => {
                    // Liveness traffic counts as activity and gets the
                    // symmetric answer.
                    let _ = parts.session.on_activity();
                    parts.last_activity = Instant::now();
                    let pong = wire::WireMessage::Pong(wire::Pong {
                        req_id: p.req_id,
                        timestamp: unix_now(),
                    });
                    match wire::encode(&pong) {
                        Ok(encoded) => {
                            if parts.send_over_session(&encoded).await.is_err() {
                                self.teardown(parts, EndReason::ProtocolViolation);
                                return true;
                            }
                        }
                        Err(_) => {
                            // Our own constant-shaped message failing to
                            // encode is unreachable; treat as violation
                            // rather than silently dropping traffic.
                            self.teardown(parts, EndReason::ProtocolViolation);
                            return true;
                        }
                    }
                }
                Some(wire::WireMessage::ApprovalRequest(_))
                | Some(wire::WireMessage::ExecuteRequest(_))
                | Some(wire::WireMessage::ListServicesRequest(_))
                | Some(wire::WireMessage::ApprovalResponse(_))
                | Some(wire::WireMessage::ExecuteResponse(_))
                | Some(wire::WireMessage::ListServicesResponse(_))
                | Some(wire::WireMessage::Pong(_))
                | Some(wire::WireMessage::PairingConfirm(_))
                | Some(wire::WireMessage::PairingAck(_)) => {
                    // Unsolicited traffic in these directions is not
                    // part of the protocol as run today. Ignore-and-note
                    // keeps a chatty or malicious peer from ending
                    // sessions at will; phase 7.1 replaces this arm
                    // with real routing.
                    self.note("unsolicited_wire_message");
                }
                None => {
                    // Undecodable plaintext inside valid frames.
                    self.teardown(parts, EndReason::ProtocolViolation);
                    return true;
                }
            }
        }
        false
    }

    /// Full end-of-life: state-machine end (wiping held buffers and
    /// stopping the watchdog), link teardown, durable log row,
    /// broadcast. Order matters: the log row lands before any shutdown
    /// waiter proceeds to checkpoint the database.
    ///
    /// Any routed request still in flight or queued is answered with
    /// `conveyance/session_ended` -- a session boundary is exactly the
    /// "ended mid-request" case that code exists for.
    fn teardown(&self, parts: &mut ActiveParts, reason: EndReason) {
        parts.session.end(reason);
        parts.link.shutdown();

        let ended = Err(OpError::from_core(ConveyanceError::SessionEnded));
        if let Some(flight) = parts.in_flight.take() {
            let _ = flight.reply.send(ended.clone());
        }
        while let Some(cmd) = parts.route_queue.pop_front() {
            let _ = cmd.reply.send(ended.clone());
        }

        let _ = self.deps.log.append(&LogEvent {
            req_id: LIFECYCLE_REQ_ID,
            event_type: "session_end".into(),
            payload_json: format!(r#"{{"reason":"{}"}}"#, reason.as_str()),
            timestamp: unix_now(),
        });
        let _ = self.active_tx.send(false);
    }

    /// Operational note row. Security-adjacent oddities deserve durable
    /// evidence; they are rare enough that volume never matters.
    fn note(&self, note: &str) {
        let _ = self.deps.log.append(&LogEvent {
            req_id: LIFECYCLE_REQ_ID,
            event_type: "daemon_note".into(),
            payload_json: format!(r#"{{"note":"{note}"}}"#),
            timestamp: unix_now(),
        });
    }

    /// Canonical-JSON log row tied to a specific req_id. Payloads are
    /// built through `canonicalize` so PC rows compare byte-for-byte
    /// with phone rows during phase 9 diffing -- a plain `to_string()`
    /// would serialize maps in insertion order and quietly break that.
    fn log_req(&self, req_id: wire::ReqId, event_type: &str, payload: serde_json::Value) {
        use conveyance_core::crypto::canonical_json::canonicalize;
        let payload_json = canonicalize(&payload).unwrap_or_else(|_| payload.to_string());
        let _ = self.deps.log.append(&LogEvent {
            req_id: req_id.0,
            event_type: event_type.into(),
            payload_json,
            timestamp: unix_now(),
        });
    }

    // ---- routing (phase 7.1) -----------------------------------------

    /// Kick off one routed conversation with the phone. The reply is
    /// either installed into `in_flight` (answered later by a chunk or
    /// the deadline), answered immediately (validation failures), or --
    /// if the transport died mid-send -- answered `session_ended` after
    /// full teardown.
    async fn start_route(
        &mut self,
        parts: &mut ActiveParts,
        op: RoutedOp,
        reply: oneshot::Sender<Result<IpcResponse, OpError>>,
    ) {
        let prepared = match &op {
            RoutedOp::AuthenticatedRequest {
                service,
                method,
                endpoint,
                params,
                requested_by,
            } => {
                let req_id = match wire::ReqId::generate(&OsEntropy) {
                    Ok(id) => id,
                    Err(_) => {
                        let _ = reply.send(Err(OpError::internal("entropy failure")));
                        return;
                    }
                };
                let approval = match ApprovalRequest::new(
                    req_id,
                    OpType::AuthenticatedRequest,
                    service.clone(),
                    method.clone(),
                    endpoint.clone(),
                    params.clone(),
                    requested_by.clone(),
                    unix_now(),
                ) {
                    Ok(a) => a,
                    Err(_) => {
                        let _ =
                            reply.send(Err(OpError::internal("request outside canonical domain")));
                        return;
                    }
                };

                let mut detail = serde_json::json!({
                    "op_type": "authenticated_request",
                    "service": service,
                    "method": method,
                    "endpoint": endpoint,
                });
                if let Some(by) = requested_by {
                    detail["requested_by"] = serde_json::Value::String(by.clone());
                }
                self.log_req(req_id, "approval_request", detail);

                match wire::encode(&wire::WireMessage::ApprovalRequest(approval.clone())) {
                    Ok(bytes) => Some((req_id, bytes, Stage::Approval, Some(approval))),
                    Err(_) => {
                        let _ =
                            reply.send(Err(OpError::internal("could not encode approval request")));
                        return;
                    }
                }
            }
            RoutedOp::ListServices => {
                let req_id = match wire::ReqId::generate(&OsEntropy) {
                    Ok(id) => id,
                    Err(_) => {
                        let _ = reply.send(Err(OpError::internal("entropy failure")));
                        return;
                    }
                };
                self.log_req(req_id, "list_services_request", serde_json::json!({}));
                let msg =
                    wire::WireMessage::ListServicesRequest(wire::ListServicesRequest { req_id });
                match wire::encode(&msg) {
                    Ok(bytes) => Some((req_id, bytes, Stage::Services, None)),
                    Err(_) => {
                        let _ = reply.send(Err(OpError::internal("could not encode request")));
                        return;
                    }
                }
            }
        };
        let Some((req_id, bytes, stage, approval)) = prepared else {
            return;
        };
        if parts.send_over_session(&bytes).await.is_err() {
            // Broken link mid-send: tear down fully (which answers every
            // OTHER waiter), then answer this caller too.
            self.teardown(parts, EndReason::PeerDisconnected);
            let _ = reply.send(Err(OpError::from_core(ConveyanceError::SessionEnded)));
            return;
        }

        let window = match stage {
            Stage::Approval => self.deps.approval_window,
            Stage::Services | Stage::Execute => self.deps.execute_window,
        };
        let (service, method, endpoint) = match &approval {
            Some(a) => (
                Some(a.service.clone()),
                Some(a.method.clone()),
                Some(a.endpoint.clone()),
            ),
            None => (None, None, None),
        };
        parts.in_flight = Some(InFlight {
            stage,
            req_id,
            approval,
            service,
            method,
            endpoint,
            deadline: Instant::now() + window,
            reply,
        });
        // Activity: routing traffic is legitimate interaction.
        let _ = parts.session.on_activity();
        parts.last_activity = Instant::now();
    }

    /// If an inbound message completes the in-flight request, handle it
    /// end-to-end and return `Some(_)`. `None` means "not mine" -- the
    /// generic arms (ping, session end, unsolicited) take over.
    ///
    /// `Some(false)`: handled, session lives. `Some(true)`: handled but
    /// the session ended (transport died mid-handling).
    async fn try_complete_route(
        &mut self,
        parts: &mut ActiveParts,
        decoded: &Option<wire::WireMessage>,
    ) -> Option<bool> {
        let flight = parts.in_flight.as_ref()?;
        match (decoded.as_ref(), &flight.stage) {
            (Some(wire::WireMessage::ApprovalResponse(rsp)), Stage::Approval)
                if rsp.req_id == flight.req_id =>
            {
                let flight = parts.in_flight.take().expect("checked above");
                let ended = self.finish_approval(parts, rsp, flight).await;
                if !ended {
                    self.drain_route_queue(parts).await;
                }
                Some(ended)
            }
            (Some(wire::WireMessage::ExecuteResponse(rsp)), Stage::Execute)
                if rsp.req_id == flight.req_id =>
            {
                let flight = parts.in_flight.take().expect("checked above");
                let ended = self.finish_execute(parts, rsp, flight).await;
                if !ended {
                    self.drain_route_queue(parts).await;
                }
                Some(ended)
            }
            (Some(wire::WireMessage::ListServicesResponse(rsp)), Stage::Services)
                if rsp.req_id == flight.req_id =>
            {
                let flight = parts.in_flight.take().expect("checked above");
                let _ = flight
                    .reply
                    .send(Ok(IpcResponse::Services(rsp.services.clone())));
                self.drain_route_queue(parts).await;
                Some(false)
            }
            _ => None,
        }
    }

    /// Verify + act on the phone's approval decision.
    ///
    /// Returns true only when the session had to be torn down. Takes
    /// the flight by value: every path either answers its reply or
    /// re-installs a new flight, so ownership is linear here.
    #[allow(clippy::too_many_lines)]
    async fn finish_approval(
        &mut self,
        parts: &mut ActiveParts,
        rsp: &ApprovalResponse,
        mut flight: InFlight,
    ) -> bool {
        let approval = match flight.approval.take() {
            Some(a) => a,
            None => {
                let _ = flight
                    .reply
                    .send(Err(OpError::internal("approval state lost")));
                return false;
            }
        };

        // Signature FIRST: nothing about the response is trusted until
        // it verifies against the identity this session authenticated.
        if rsp.verify_signature(&parts.phone_id_pub).is_err() {
            self.note("approval_signature_invalid");
            let _ = flight.reply.send(Err(OpError::new(
                "conveyance/internal",
                "phone response rejected",
                false,
            )));
            return false;
        }

        match rsp.decision {
            Decision::Denied => {
                self.log_req(
                    approval.req_id,
                    "approval_denied",
                    approval_payload(
                        "denied",
                        rsp.reason.clone(),
                        &approval,
                        Some(&rsp.signature),
                    ),
                );
                let _ = flight
                    .reply
                    .send(Err(OpError::from_core(ConveyanceError::ApprovalDenied)));
                false
            }
            Decision::Expired => {
                // Phone's own window lapsed before the user chose. From
                // the shim's seat this is indistinguishable from our
                // own timeout -- both mean "ask again".
                self.log_req(
                    approval.req_id,
                    "approval_denied",
                    approval_payload(
                        "expired",
                        rsp.reason.clone(),
                        &approval,
                        Some(&rsp.signature),
                    ),
                );
                let _ = flight
                    .reply
                    .send(Err(OpError::from_core(ConveyanceError::ApprovalTimeout)));
                false
            }
            Decision::Approved => {
                self.log_req(
                    approval.req_id,
                    "approval_granted",
                    approval_payload(
                        "approved",
                        rsp.reason.clone(),
                        &approval,
                        Some(&rsp.signature),
                    ),
                );

                if parts.binding.record_approval(&approval, rsp).is_err() {
                    // record_approval only mismatches req_ids between
                    // the pair we just matched -- unreachable, but a
                    // loud refusal beats executing on bad state.
                    let _ = flight.reply.send(Err(OpError::internal("binding failure")));
                    return false;
                }

                let execute = match ExecuteRequest::new(
                    approval.req_id,
                    approval.op_type,
                    approval.service.clone(),
                    approval.method.clone(),
                    approval.endpoint.clone(),
                    approval.params.clone(),
                    approval.requested_by.clone(),
                    approval.timestamp,
                ) {
                    Ok(e) => e,
                    Err(_) => {
                        let _ = flight
                            .reply
                            .send(Err(OpError::internal("rebuild failed binding")));
                        return false;
                    }
                };

                // Local half of the anti-TOCTOU check: consumes the
                // approval so this req_id can never execute twice from
                // our side, even if the phone were lenient.
                if parts.binding.validate_execute(&execute).is_err() {
                    let _ = flight
                        .reply
                        .send(Err(OpError::from_core(ConveyanceError::ApprovalMismatch)));
                    return false;
                }

                self.log_req(
                    execute.req_id,
                    "execute_sent",
                    serde_json::json!({
                        "service": approval.service,
                        "method": approval.method,
                        "endpoint": approval.endpoint,
                    }),
                );

                let bytes = match wire::encode(&wire::WireMessage::ExecuteRequest(execute)) {
                    Ok(b) => b,
                    Err(_) => {
                        let _ = flight.reply.send(Err(OpError::internal("encode failed")));
                        return false;
                    }
                };
                if parts.send_over_session(&bytes).await.is_err() {
                    self.teardown(parts, EndReason::PeerDisconnected);
                    let _ = flight
                        .reply
                        .send(Err(OpError::from_core(ConveyanceError::SessionEnded)));
                    return true;
                }

                // Still awaiting the execution outcome: re-install the
                // flight with the execute deadline, keeping the same
                // reply channel.
                parts.in_flight = Some(InFlight {
                    stage: Stage::Execute,
                    req_id: flight.req_id,
                    approval: None,
                    service: Some(approval.service.clone()),
                    method: Some(approval.method.clone()),
                    endpoint: Some(approval.endpoint.clone()),
                    deadline: Instant::now() + self.deps.execute_window,
                    reply: flight.reply,
                });
                let _ = parts.session.on_activity();
                parts.last_activity = Instant::now();
                false
            }
        }
    }

    /// Verify + log the executed outcome; propagate the body verbatim
    /// to the shim.
    async fn finish_execute(
        &mut self,
        parts: &mut ActiveParts,
        rsp: &ExecuteResponse,
        flight: InFlight,
    ) -> bool {
        if rsp.verify_signature(&parts.phone_id_pub).is_err() {
            self.note("execute_signature_invalid");
            let _ = flight.reply.send(Err(OpError::new(
                "conveyance/internal",
                "phone response rejected",
                false,
            )));
            return false;
        }

        let mut detail = serde_json::json!({
            "status": match rsp.status {
                Status::Ok => "ok",
                Status::Error => "error",
                Status::Denied => "denied",
            },
            // Request coordinates ride along for `log query --tool`.
            "service": flight.service,
            "method": flight.method,
            "endpoint": flight.endpoint,
            "body": rsp.body,
        });
        if let Some(code) = rsp.http_status {
            detail["http_status"] = serde_json::Value::from(code);
        }
        // Embedded response signature: lets `log diff` re-verify this
        // row offline against the phone's identity key (phase 9).
        detail["executed_at"] = serde_json::Value::from(rsp.executed_at);
        detail["signature"] =
            serde_json::Value::String(conveyance_core::crypto::hex_encode(&rsp.signature));
        self.log_req(rsp.req_id, "execute_result", detail);

        let _ = flight.reply.send(Ok(IpcResponse::Body(rsp.body.clone())));
        false
    }

    /// Deadline fired for the in-flight request. Live timeouts are
    /// recorded distinctly from crash recovery's
    /// `crashed_before_terminal` (phase 7.1 sweep).
    async fn route_timed_out(&mut self, parts: &mut ActiveParts) {
        let Some(flight) = parts.in_flight.take() else {
            return;
        };
        let (op_kind, err) = match flight.stage {
            Stage::Approval | Stage::Execute => (
                "authenticated_request",
                OpError::from_core(ConveyanceError::ApprovalTimeout),
            ),
            Stage::Services => (
                "list_services",
                OpError::new(
                    "conveyance/internal",
                    "phone did not answer the list_services request",
                    true,
                ),
            ),
        };
        let mut timeout_payload = serde_json::json!({
            "reason": crate::recovery::TIMEOUT_REASON,
            "op": op_kind,
        });
        if let Some(service) = &flight.service {
            timeout_payload["service"] = serde_json::Value::String(service.clone());
        }
        if let Some(endpoint) = &flight.endpoint {
            timeout_payload["endpoint"] = serde_json::Value::String(endpoint.clone());
        }
        self.log_req(flight.req_id, "request_timeout", timeout_payload);
        let _ = flight.reply.send(Err(err));
        self.drain_route_queue(parts).await;
    }

    /// Start the next queued routed request, if any.
    async fn drain_route_queue(&mut self, parts: &mut ActiveParts) {
        if let Some(cmd) = parts.route_queue.pop_front() {
            self.start_route(parts, cmd.op, cmd.reply).await;
        }
    }

    /// Dial + handshake + timers. On success returns the live parts;
    /// the caller publishes activity and installs them.
    ///
    /// `&mut self`: the dialer is stateful (BLE adapter cache), so two
    /// session starts can never race it -- they queue behind the command
    /// channel instead, which is exactly the serialization we want.
    async fn begin_session(&mut self) -> Result<ActiveParts, OpError> {
        // Most recently paired phone wins. v1 is one-phone; taking the
        // newest row is deterministic if several exist.
        let pairings = self
            .deps
            .store
            .list()
            .map_err(|e| OpError::internal(&format!("pairings database unreadable: {e}")))?;
        let Some(peer_row) = pairings.last() else {
            return Err(OpError::no_pairing());
        };

        // ---- dial -----------------------------------------------------
        let mut link = self
            .deps
            .dialer
            .dial(HANDSHAKE_TOTAL_BUDGET)
            .await
            .map_err(|e| match e {
                TransportError::Timeout => {
                    OpError::phone_unreachable("not advertising within 30 s")
                }
                other => OpError::phone_unreachable(&other.to_string()),
            })?;

        // ---- handshake ---------------------------------------------------
        let peer = PeerIdentity {
            local_static: self.deps.local_static.clone(),
            remote_static: peer_row.dh_pub,
        };
        let (mut session, tx_seq, inbound) =
            match responder_handshake(link.as_mut(), &peer, self.deps.params).await {
                Ok(triple) => triple,
                Err(err) => {
                    link.shutdown();
                    return Err(err);
                }
            };
        // ---- timers ---------------------------------------------------------
        // Watchdog output is pumped into our command queue so timer
        // events contend with IPC commands in one place, in order.
        let (event_tx, mut event_rx) = mpsc::channel::<TimerEvent>(8);
        session.start_timers(event_tx);
        let pump_tx = self.cmd_tx.clone();
        tokio::spawn(async move {
            while let Some(ev) = event_rx.recv().await {
                if pump_tx.send(SessionCmd::Timer(ev)).await.is_err() {
                    return;
                }
            }
        });

        let _ = self.deps.log.append(&LogEvent {
            req_id: LIFECYCLE_REQ_ID,
            event_type: "session_start".into(),
            payload_json: r#"{"reason":"user_started"}"#.into(),
            timestamp: unix_now(),
        });

        Ok(ActiveParts {
            session,
            link,
            // Continues the handshake's inbound framing state; the
            // outbound tx_seq likewise continues its numbering. Both
            // directions are per-CONNECTION sequences.
            assembler: inbound,
            tx_seq,
            started_at: Instant::now(),
            last_activity: Instant::now(),
            phone_id_pub: IdentityPublicKey::from_bytes(&peer_row.id_pub)
                .map_err(|_| OpError::internal("stored pairing holds a malformed identity key"))?,
            binding: ApprovedRequestTracker::new(),
            route_queue: VecDeque::new(),
            in_flight: None,
        })
    }
}

pub(crate) fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Log payload for an approval decision row. Mirrors the signature-
/// omission rule (absent reason stays absent) and carries the request
/// coordinates plus the response's Ed25519 signature so `log query
/// --tool` can filter and `log diff` can re-verify offline.
fn approval_payload(
    decision: &str,
    reason: Option<String>,
    approval: &ApprovalRequest,
    signature: Option<&[u8; 64]>,
) -> serde_json::Value {
    let mut v = serde_json::json!({
        "decision": decision,
        "service": approval.service,
        "method": approval.method,
        "endpoint": approval.endpoint,
    });
    if let Some(r) = reason {
        v["reason"] = serde_json::Value::String(r);
    }
    if let Some(sig) = signature {
        v["signature"] = serde_json::Value::String(conveyance_core::crypto::hex_encode(sig));
    }
    v
}
/// Responder half of Noise_KK over a live link: read message 1, write
/// message 2, promote to an ACTIVE session. Returns the session, the
/// next free outbound frame sequence, AND the half-warmed inbound
/// assembler -- both directions must continue exactly where the
/// handshake stopped, because framers enforce sequence continuity per
/// CONNECTION, not per phase.
///
/// The initiator is always the phone (spec "Session start"); production
/// code never takes the initiator role anywhere.
async fn responder_handshake(
    link: &mut dyn PhoneLink,
    identity: &PeerIdentity,
    params: SessionParams,
) -> Result<(CoreSession, u16, InboundAssembler), OpError> {
    let mut hs = SessionHandshake::begin(Role::Responder, identity)
        .map_err(|_| OpError::handshake_failed())?;

    let deadline = Instant::now() + HANDSHAKE_TOTAL_BUDGET;
    let mut assembler = InboundAssembler::new();
    let mut tx_seq: u16 = 0;

    loop {
        if hs.is_finished() {
            return establish(hs, params).map(|s| (s, tx_seq, assembler));
        }

        let chunk = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), link.recv())
            .await
            .map_err(|_| OpError::phone_unreachable("handshake stalled"))?
            .map_err(|e| {
                if e.is_disconnection() {
                    OpError::phone_unreachable("peer vanished mid-handshake")
                } else {
                    OpError::phone_unreachable("transport error")
                }
            })?;

        for message in assembler
            .ingest(&chunk)
            .map_err(|_| OpError::handshake_failed())?
        {
            hs.read_message(&message)
                .map_err(|_| OpError::handshake_failed())?;
            if hs.needs_write() {
                let reply = hs
                    .write_message(b"")
                    .map_err(|_| OpError::handshake_failed())?;
                let (frames, next) = framing::split_message(&reply, link.max_write_len(), tx_seq)
                    .map_err(|_| OpError::handshake_failed())?;
                tx_seq = next;
                for frame in frames {
                    link.send(&frame)
                        .await
                        .map_err(|_| OpError::phone_unreachable("write failed mid-handshake"))?;
                }
            }
            if hs.is_finished() {
                return establish(hs, params).map(|s| (s, tx_seq, assembler));
            }
        }
    }
}

fn establish(hs: SessionHandshake, params: SessionParams) -> Result<CoreSession, OpError> {
    hs.establish(params)
        .map_err(|_| OpError::handshake_failed())
}
