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

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use conveyance_core::crypto::Secret;
use conveyance_core::crypto::hashchain::LogEvent;
use conveyance_core::session::{
    EndReason, PeerIdentity, Role, Session as CoreSession, SessionHandshake, SessionParams,
    TimerEvent,
};
use conveyance_core::storage::logdb::LogDb;
use conveyance_core::storage::pairings::PairingsDb;
use conveyance_core::transport::{InboundAssembler, TransportError};
use conveyance_core::wire::framing;
use conveyance_core::wire::message as wire;

use tokio::sync::{mpsc, oneshot, watch};

use crate::phone::{PhoneDialer, PhoneLink};

/// How long any single step toward an ACTIVE session may take: the
/// spec's 30 s reachability window covers dial AND handshake exchange.
/// A phone that advertises but stalls mid-handshake fails closed here
/// rather than wedging the owner task.
const HANDSHAKE_TOTAL_BUDGET: Duration = Duration::from_secs(30);

/// Reserved correlation id for log rows that belong to no tool call
/// (session lifecycle rows). Zeroed bytes cannot collide with a random
/// ReqId in practice and are trivially filterable by log tooling.
const LIFECYCLE_REQ_ID: [u8; 16] = [0u8; 16];

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
    tokio::spawn(owner.run());

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
            let decoded: Option<wire::WireMessage> =
                ciborium::de::from_reader(&mut &message[..]).ok();
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
    fn teardown(&self, parts: &mut ActiveParts, reason: EndReason) {
        parts.session.end(reason);
        parts.link.shutdown();
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
        let mut session = match responder_handshake(link.as_mut(), &peer, self.deps.params).await {
            Ok(s) => s,
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
            assembler: InboundAssembler::new(),
            tx_seq: 0,
            started_at: Instant::now(),
            last_activity: Instant::now(),
        })
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Responder half of Noise_KK over a live link: read message 1, write
/// message 2, promote to an ACTIVE session.
///
/// The initiator is always the phone (spec "Session start"); production
/// code never takes the initiator role anywhere.
async fn responder_handshake(
    link: &mut dyn PhoneLink,
    identity: &PeerIdentity,
    params: SessionParams,
) -> Result<CoreSession, OpError> {
    let mut hs = SessionHandshake::begin(Role::Responder, identity)
        .map_err(|_| OpError::handshake_failed())?;

    let deadline = Instant::now() + HANDSHAKE_TOTAL_BUDGET;
    let mut assembler = InboundAssembler::new();

    loop {
        if hs.is_finished() {
            return establish(hs, params);
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
                let (frames, _) = framing::split_message(&reply, link.max_write_len(), 0)
                    .map_err(|_| OpError::handshake_failed())?;
                for frame in frames {
                    link.send(&frame)
                        .await
                        .map_err(|_| OpError::phone_unreachable("write failed mid-handshake"))?;
                }
            }
            if hs.is_finished() {
                return establish(hs, params);
            }
        }
    }
}

fn establish(hs: SessionHandshake, params: SessionParams) -> Result<CoreSession, OpError> {
    hs.establish(params)
        .map_err(|_| OpError::handshake_failed())
}
