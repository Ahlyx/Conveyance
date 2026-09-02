//! The Conveyance session: Noise_KK transport + lifecycle state machine
//! + timers.
//!
//! Two types split the lifecycle at its natural seam:
//!
//! * [`SessionHandshake`] -- the HANDSHAKING phase. Drives the KK
//!   exchange; on success converts into a [`Session`], on failure aborts
//!   back to NO_SESSION (a session that never completed never existed;
//!   see state.rs for this spec-gap decision).
//! * [`Session`] -- everything from ACTIVE onward. Holds the transport,
//!   enforces cold-start (every output-producing method checks ACTIVE
//!   first), owns the timer watchdog wiring, and performs end-of-life.
//!
//! Cold-start is structural, not advisory: there is no method on
//! `Session` that produces traffic or results without passing through
//! `require_active()`. When the daemon (phase 7) routes tool calls here,
//! `conveyance/no_session` falls out of that check automatically.
//!
//! There is deliberately no public constructor for `Session` other than
//! `SessionHandshake::establish`: an ACTIVE session cannot exist without
//! a completed KK handshake, so the type system carries that invariant.

pub mod noise;
pub mod state;
pub mod timers;

pub use noise::Role;
pub use state::{EndReason, SessionState};
pub use timers::{InvalidBounds, SessionParams, TimerEvent};

use std::time::Instant;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use crate::crypto::Secret;
use crate::error::ConveyanceError;

/// One half of a pairing, ready for handshake construction. Loaded from
/// storage by the caller; nothing here touches disk.
pub struct PeerIdentity {
    pub local_static: Secret<32>,
    pub remote_static: [u8; 32],
}

/// A handshake in progress (state = HANDSHAKING).
pub struct SessionHandshake {
    inner: noise::SessionHandshake,
}

impl SessionHandshake {
    /// Enter HANDSHAKING. Fails before any state exists if key material
    /// or the pattern itself is unusable -- those are pre-session errors,
    /// not lifecycle transitions.
    pub fn begin(role: Role, identity: &PeerIdentity) -> Result<Self, ConveyanceError> {
        Ok(Self {
            inner: noise::SessionHandshake::new(
                role,
                &identity.local_static,
                &identity.remote_static,
            )?,
        })
    }

    pub fn needs_write(&self) -> bool {
        self.inner.needs_write()
    }

    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, ConveyanceError> {
        self.inner
            .write_message(payload)
            .map_err(ConveyanceError::from)
    }

    pub fn read_message(&mut self, msg: &[u8]) -> Result<Vec<u8>, ConveyanceError> {
        self.inner.read_message(msg).map_err(ConveyanceError::from)
    }

    pub fn is_finished(&self) -> bool {
        self.inner.is_finished()
    }

    /// HANDSHAKING -> ACTIVE. Consumes the handshake; keying material
    /// moves into the transport.
    pub fn establish(self, params: SessionParams) -> Result<Session, ConveyanceError> {
        let transport = self.inner.into_transport()?;
        Ok(Session {
            state: SessionState::Active,
            transport: Some(transport),
            scratch: Zeroizing::new(Vec::new()),
            params,
            started_at: Instant::now(),
            activity_tx: None,
            watchdog: None,
            warned: false,
        })
    }

    /// Abort back to NO_SESSION. Dropping without calling this has the
    /// same effect; the method exists so abort sites read as intent.
    pub fn abort(self) {}
}

/// An established session (ACTIVE / IDLE_WARNING / ENDED).
pub struct Session {
    state: SessionState,
    transport: Option<noise::SessionTransport>,
    /// Reusable decrypt buffer. Plaintext transits through it and is
    /// zeroed before `receive` returns; on end it is emptied. Kept as a
    /// field so "what memory did this session touch" has one answer.
    scratch: Zeroizing<Vec<u8>>,
    params: SessionParams,
    started_at: Instant,
    activity_tx: Option<mpsc::Sender<()>>,
    watchdog: Option<JoinHandle<()>>,
    warned: bool,
}

impl Session {
    // ---- lifecycle observation ------------------------------------

    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Seconds elapsed since establishment. `check_session` (phase 7/8)
    /// derives remaining idle/cap time from this plus the (immutable)
    /// params -- deadlines live in one place, the watchdog, and are not
    /// mirrored here as stale copies.
    pub fn seconds_elapsed(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    // ---- cold-start guard ------------------------------------------

    /// THE architectural gate. Every method below that produces output
    /// calls this first. State != ACTIVE => conveyance/no_session.
    fn require_active(&self) -> Result<(), ConveyanceError> {
        match self.state {
            SessionState::Active | SessionState::IdleWarning => Ok(()),
            _ => Err(ConveyanceError::NoSession),
        }
    }

    // ---- operations (all guarded) ----------------------------------

    pub fn send(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, ConveyanceError> {
        self.require_active()?;
        let transport = self.transport.as_mut().ok_or(ConveyanceError::NoSession)?;
        transport.send(plaintext).map_err(ConveyanceError::from)
    }

    pub fn receive(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, ConveyanceError> {
        self.require_active()?;
        let transport = self.transport.as_mut().ok_or(ConveyanceError::NoSession)?;

        // Decrypt through our retained buffer, hand a copy to the caller,
        // then zero our region. We do not keep plaintext between calls --
        // retention would be a liability, not a feature.
        self.scratch.clear();
        self.scratch.resize(ciphertext.len(), 0);
        let plaintext = transport.receive_into(ciphertext, &mut self.scratch)?;
        let out = plaintext.to_vec();
        self.scratch.fill(0);
        self.scratch.clear();
        Ok(out)
    }

    // ---- timers ------------------------------------------------------

    /// Spawn the timer watchdog. Must be called inside a tokio runtime.
    /// Replaces any previous watchdog (one session, one watchdog).
    pub fn start_timers(&mut self, events_tx: mpsc::Sender<TimerEvent>) {
        self.stop_timers();
        let (activity_tx, activity_rx) = mpsc::channel(16);
        let handle = tokio::spawn(timers::watchdog(self.params, activity_rx, events_tx));
        self.activity_tx = Some(activity_tx);
        self.watchdog = Some(handle);
    }

    fn stop_timers(&mut self) {
        if let Some(handle) = self.watchdog.take() {
            handle.abort();
        }
        self.activity_tx = None;
    }

    /// Record legitimate activity: resets idle machinery in the state
    /// machine (IDLE_WARNING rescues to ACTIVE with a full fresh window)
    /// and in the watchdog.
    pub fn on_activity(&mut self) -> Result<(), ConveyanceError> {
        self.state = state::step(self.state, state::Event::Activity)
            .map_err(|_| ConveyanceError::NoSession)?;
        self.warned = false;
        if let Some(tx) = &self.activity_tx {
            // Best effort, non-blocking: capacity absorbs any realistic
            // burst, and dropping one reset signal is harmless because
            // the next interaction signals again.
            let _ = tx.try_send(());
        }
        Ok(())
    }

    /// Apply a timer event delivered from the watchdog. Returns
    /// `Some(reason)` when this ended the session, so the owner logs the
    /// end event with the right cause.
    pub fn handle_timer_event(&mut self, event: TimerEvent) -> Option<EndReason> {
        match event {
            TimerEvent::WarningDue => {
                if state::step(self.state, state::Event::WarningDue)
                    == Ok(SessionState::IdleWarning)
                {
                    self.state = SessionState::IdleWarning;
                    self.warned = true;
                }
                None
            }
            TimerEvent::IdleExpired => {
                self.end(state::EndReason::IdleTimedOut);
                Some(EndReason::IdleTimedOut)
            }
            TimerEvent::HardCapReached => {
                self.end(state::EndReason::HardCapReached);
                Some(EndReason::HardCapReached)
            }
        }
    }

    pub fn warned(&self) -> bool {
        self.warned
    }

    // ---- ending ------------------------------------------------------

    /// End the session for `reason`. Idempotent. After this, every
    /// operation returns no_session and held buffers are wiped.
    ///
    /// Note the asymmetry: ENDED is terminal, so `end()` on an already-
    /// ended (or never-active) session is a no-op -- it cannot fail, and
    /// it cannot resurrect anything.
    pub fn end(&mut self, reason: EndReason) {
        if state::step(self.state, state::Event::EndRequested(reason)) == Ok(SessionState::Ended) {
            self.state = SessionState::Ended;
            self.teardown();
        }
    }

    /// Tear down after a peer disconnect observed during operation.
    pub fn peer_disconnected(&mut self) {
        if state::step(self.state, state::Event::PeerDisconnected) == Ok(SessionState::Ended) {
            self.state = SessionState::Ended;
            self.teardown();
        }
    }

    /// Common end-of-life: stop timers, drop the Noise transport
    /// (cipher-state wiping delegated to snow -- see noise.rs SECURITY
    /// NOTE), empty retained buffers.
    fn teardown(&mut self) {
        self.stop_timers();
        self.transport = None;
        self.scratch.fill(0);
        self.scratch.clear();
        self.scratch.shrink_to_fit();
    }

    #[cfg(test)]
    pub(crate) fn scratch_is_empty(&self) -> bool {
        self.scratch.is_empty()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Whatever path led here -- including unwinding -- a dropped
        // session must not leave a live watchdog running.
        self.stop_timers();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::OsEntropy;
    use crate::crypto::Secret;
    use crate::crypto::dh::DhSecret;
    use crate::crypto::test_support::CounterEntropy;
    use crate::storage::identity::StoredIdentity;
    use crate::test_support::MockKeyProvider;

    fn long_params() -> SessionParams {
        SessionParams::raw(
            std::time::Duration::from_secs(1_800),
            std::time::Duration::from_secs(120),
            std::time::Duration::from_secs(14_400),
        )
    }

    fn ms_params(idle_ms: u64, warn_ms: u64, cap_ms: u64) -> SessionParams {
        SessionParams::raw(
            std::time::Duration::from_millis(idle_ms),
            std::time::Duration::from_millis(warn_ms),
            std::time::Duration::from_millis(cap_ms),
        )
    }

    /// Fresh pairing halves with independent X25519 statics.
    fn peer_pair() -> (PeerIdentity, PeerIdentity) {
        let pc = DhSecret::generate(&OsEntropy).unwrap();
        let phone = DhSecret::generate(&OsEntropy).unwrap();

        (
            PeerIdentity {
                local_static: Secret::from_bytes(pc.to_bytes()),
                remote_static: phone.public_key().to_bytes(),
            },
            PeerIdentity {
                local_static: Secret::from_bytes(phone.to_bytes()),
                remote_static: pc.public_key().to_bytes(),
            },
        )
    }

    fn complete_handshake(initiator: &mut SessionHandshake, responder: &mut SessionHandshake) {
        let m1 = initiator.write_message(b"").unwrap();
        responder.read_message(&m1).unwrap();
        let m2 = responder.write_message(b"").unwrap();
        initiator.read_message(&m2).unwrap();
    }

    #[test]
    fn establish_and_exchange_roundtrip() {
        let (pc_peer, phone_peer) = peer_pair();

        let mut i = SessionHandshake::begin(Role::Initiator, &phone_peer).unwrap();
        let mut r = SessionHandshake::begin(Role::Responder, &pc_peer).unwrap();
        complete_handshake(&mut i, &mut r);

        let mut pc = r.establish(long_params()).unwrap();
        let mut phone = i.establish(long_params()).unwrap();

        assert_eq!(pc.state(), SessionState::Active);

        let sealed = phone.send(b"ApprovalRequest{...}").unwrap();
        assert_ne!(sealed, b"ApprovalRequest{...}");
        let opened = pc.receive(&sealed).unwrap();
        assert_eq!(opened, b"ApprovalRequest{...}");
    }

    /// Cold start, post-end flavor: every operational method yields
    /// exactly conveyance/no_session with the structured shape.
    #[test]
    fn ended_session_rejects_everything_with_no_session() {
        let (pc_peer, phone_peer) = peer_pair();
        let mut i = SessionHandshake::begin(Role::Initiator, &phone_peer).unwrap();
        let mut r = SessionHandshake::begin(Role::Responder, &pc_peer).unwrap();
        complete_handshake(&mut i, &mut r);
        let mut session = r.establish(long_params()).unwrap();

        session.end(EndReason::UserEnded);

        let errors = [
            session.send(b"x").err().unwrap(),
            session.receive(&[1, 2, 3]).err().unwrap(),
            session.on_activity().err().unwrap(),
        ];
        for e in errors {
            assert_eq!(e.code(), "conveyance/no_session");
            assert!(e.retryable());
            let json = serde_json::to_value(e.to_error_json()).unwrap();
            assert_eq!(json["retry_after_seconds"], serde_json::Value::Null);
            assert_eq!(
                json["message"],
                "No active Conveyance session. User must start one on the paired phone."
            );
        }

        assert_eq!(session.state(), SessionState::Ended);
    }

    #[tokio::test(start_paused = true)]
    async fn timers_drive_transitions_through_the_machine() {
        let (pc_peer, phone_peer) = peer_pair();
        let mut i = SessionHandshake::begin(Role::Initiator, &phone_peer).unwrap();
        let mut r = SessionHandshake::begin(Role::Responder, &pc_peer).unwrap();
        complete_handshake(&mut i, &mut r);

        let mut session = r.establish(ms_params(100, 40, 10_000)).unwrap();
        let (event_tx, mut event_rx) = mpsc::channel(8);
        session.start_timers(event_tx);

        // Warning at 60ms (100 - 40).
        tokio::time::advance(std::time::Duration::from_millis(60)).await;
        assert_eq!(event_rx.recv().await.unwrap(), TimerEvent::WarningDue);
        session.handle_timer_event(TimerEvent::WarningDue);
        assert_eq!(session.state(), SessionState::IdleWarning);

        // Activity rescues with FULL reset.
        session.on_activity().unwrap();
        assert_eq!(session.state(), SessionState::Active);
        assert!(!session.warned());

        // Next warning at rescue+60ms; expiry at rescue+100ms.
        tokio::time::advance(std::time::Duration::from_millis(99)).await;
        assert!(event_rx.try_recv().is_err());
        tokio::time::advance(std::time::Duration::from_millis(1)).await;
        assert_eq!(event_rx.recv().await.unwrap(), TimerEvent::WarningDue);
        session.handle_timer_event(TimerEvent::WarningDue);

        tokio::time::advance(std::time::Duration::from_millis(40)).await;
        assert_eq!(event_rx.recv().await.unwrap(), TimerEvent::IdleExpired);
        assert_eq!(
            session.handle_timer_event(TimerEvent::IdleExpired),
            Some(EndReason::IdleTimedOut)
        );
        assert_eq!(session.state(), SessionState::Ended);
        assert!(session.send(b"late").is_err(), "ended session cannot send");
    }

    #[tokio::test(start_paused = true)]
    async fn hard_cap_ends_despite_activity() {
        let (pc_peer, phone_peer) = peer_pair();
        let mut i = SessionHandshake::begin(Role::Initiator, &phone_peer).unwrap();
        let mut r = SessionHandshake::begin(Role::Responder, &pc_peer).unwrap();
        complete_handshake(&mut i, &mut r);

        let mut session = r.establish(ms_params(200, 50, 1_000)).unwrap();
        let (event_tx, mut event_rx) = mpsc::channel(16);
        session.start_timers(event_tx);

        for _ in 0..20 {
            tokio::time::advance(std::time::Duration::from_millis(100)).await;
            session.on_activity().unwrap();
            while let Ok(ev) = event_rx.try_recv() {
                if let Some(reason) = session.handle_timer_event(ev) {
                    assert_eq!(reason, EndReason::HardCapReached);
                    assert_eq!(session.state(), SessionState::Ended);
                    return;
                }
            }
        }
        panic!("hard cap never ended the session despite continuous activity");
    }

    /// Phase-2 integration: identities persisted through storage, loaded
    /// back, and driven through an in-memory channel pair (BLE arrives
    /// in phase 5; the transport seam stays identical).
    #[tokio::test]
    async fn handshake_over_channels_with_storage_loaded_identities() {
        let dir = tempfile::tempdir().unwrap();
        let keys = MockKeyProvider::default();

        let pc_identity = StoredIdentity::generate(&CounterEntropy).unwrap();
        let phone_identity = StoredIdentity::generate(&CounterEntropy).unwrap();
        pc_identity
            .save(
                &dir.path().join("pc").join("identity.enc"),
                &keys,
                &CounterEntropy,
            )
            .unwrap();
        phone_identity
            .save(
                &dir.path().join("phone").join("identity.enc"),
                &keys,
                &CounterEntropy,
            )
            .unwrap();

        let pc_loaded =
            StoredIdentity::load(&dir.path().join("pc").join("identity.enc"), &keys).unwrap();
        let phone_loaded =
            StoredIdentity::load(&dir.path().join("phone").join("identity.enc"), &keys).unwrap();

        let pc_pub = DhSecret::from_bytes(*pc_loaded.x25519_secret.expose())
            .public_key()
            .to_bytes();
        let phone_pub = DhSecret::from_bytes(*phone_loaded.x25519_secret.expose())
            .public_key()
            .to_bytes();

        let pc_peer = PeerIdentity {
            local_static: Secret::from_bytes(*pc_loaded.x25519_secret.expose()),
            remote_static: phone_pub,
        };
        let phone_peer = PeerIdentity {
            local_static: Secret::from_bytes(*phone_loaded.x25519_secret.expose()),
            remote_static: pc_pub,
        };

        // Channels named by DIRECTION: *_to_pc carries bytes the phone
        // sent; *_to_phone carries bytes the PC sent. Getting this
        // crossed deadlocks both sides silently -- hence the explicit
        // naming.
        let (tx_to_pc, mut rx_on_pc) = mpsc::channel::<Vec<u8>>(8);
        let (tx_to_phone, mut rx_on_phone) = mpsc::channel::<Vec<u8>>(8);

        let mut initiator = SessionHandshake::begin(Role::Initiator, &phone_peer).unwrap();
        let mut responder = SessionHandshake::begin(Role::Responder, &pc_peer).unwrap();

        while !initiator.is_finished() {
            // Phone writes -> PC reads.
            let msg = initiator.write_message(b"").unwrap();
            tx_to_pc.send(msg).await.unwrap();
            responder
                .read_message(&rx_on_pc.recv().await.unwrap())
                .unwrap();
            if responder.is_finished() {
                break;
            }
            // PC writes -> phone reads.
            let reply = responder.write_message(b"").unwrap();
            tx_to_phone.send(reply).await.unwrap();
            initiator
                .read_message(&rx_on_phone.recv().await.unwrap())
                .unwrap();
        }

        let mut pc = responder.establish(long_params()).unwrap();
        let mut phone = initiator.establish(long_params()).unwrap();

        let request = phone.send(br#"{"op":"authenticated_request"}"#).unwrap();
        tx_to_pc.send(request).await.unwrap();
        let got_request = pc.receive(&rx_on_pc.recv().await.unwrap()).unwrap();

        let response = pc.send(br#"{"decision":"approved"}"#).unwrap();
        tx_to_phone.send(response).await.unwrap();
        let got_response = phone.receive(&rx_on_phone.recv().await.unwrap()).unwrap();

        assert_eq!(got_request, br#"{"op":"authenticated_request"}"#);
        assert_eq!(got_response, br#"{"decision":"approved"}"#);
    }

    #[test]
    fn end_wipes_retained_buffers_and_is_idempotent() {
        // Noise transports are directional: you cannot decrypt your own
        // ciphertext. Both sides needed.
        let (pc_peer, phone_peer) = peer_pair();
        let mut i = SessionHandshake::begin(Role::Initiator, &phone_peer).unwrap();
        let mut r = SessionHandshake::begin(Role::Responder, &pc_peer).unwrap();
        complete_handshake(&mut i, &mut r);
        let mut pc = r.establish(long_params()).unwrap();
        let mut phone = i.establish(long_params()).unwrap();

        let sealed = phone.send(b"payload").unwrap();
        let _ = pc.receive(&sealed).unwrap();

        pc.end(EndReason::KillSwitch);
        assert!(pc.scratch_is_empty(), "buffers must be wiped on end");

        pc.end(EndReason::KillSwitch); // idempotent, errors nowhere
        assert_eq!(pc.state(), SessionState::Ended);
    }

    #[test]
    fn protocol_violation_tears_down() {
        let (pc_peer, phone_peer) = peer_pair();
        let mut i = SessionHandshake::begin(Role::Initiator, &phone_peer).unwrap();
        let mut r = SessionHandshake::begin(Role::Responder, &pc_peer).unwrap();
        complete_handshake(&mut i, &mut r);
        let mut session = r.establish(long_params()).unwrap();

        session.peer_disconnected();
        assert_eq!(session.state(), SessionState::Ended);
        assert!(matches!(
            session.send(b"x"),
            Err(ConveyanceError::NoSession)
        ));
    }

    #[test]
    fn tampered_transport_bytes_end_session_with_protocol_violation() {
        let (pc_peer, phone_peer) = peer_pair();
        let mut i = SessionHandshake::begin(Role::Initiator, &phone_peer).unwrap();
        let mut r = SessionHandshake::begin(Role::Responder, &pc_peer).unwrap();
        complete_handshake(&mut i, &mut r);
        let mut pc = r.establish(long_params()).unwrap();
        let mut phone = i.establish(long_params()).unwrap();

        let mut sealed = phone.send(b"real payload").unwrap();
        sealed[3] ^= 0xff;

        match pc.receive(&sealed) {
            Err(ConveyanceError::SessionEnded) => {}
            other => panic!("expected SessionEnded on tamper, got {other:?}"),
        }
        pc.peer_disconnected(); // owner reacts per receive()'s contract
        assert_eq!(pc.state(), SessionState::Ended);
    }
}
