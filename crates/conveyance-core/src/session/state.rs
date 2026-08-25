//! The session lifecycle state machine, as pure logic.
//!
//! States and legal transitions come verbatim from the spec's "Session
//! lifecycle" diagram:
//!
//! ```text
//! NO_SESSION --> HANDSHAKING --> ACTIVE
//!                                  |  ^
//!                    idle warning  |  | activity
//!                                  v  |
//!                              IDLE_WARNING
//! ACTIVE / IDLE_WARNING --> ENDED   (idle expiry, hard cap, disconnect,
//!                                    explicit end, kill switch, remote end)
//! ```
//!
//! Keeping this pure buys two things: the full legal/illegal matrix is
//! unit-testable without tokio or crypto, and every state change in the
//! live [`super::Session`] goes through `step`, so there is exactly one
//! place where the rules live.
//!
//! One gap the spec diagram does not draw: aborting out of HANDSHAKING
//! (peer vanished mid-handshake, user cancelled). A session that never
//! completed its handshake never existed, so abort returns to
//! NO_SESSION -- allowing a clean retry -- rather than to ENDED. This is
//! an interpretation, recorded here and in the tests; if the spec is
//! amended, this file changes in exactly one place.

/// Lifecycle states, spec spelling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    NoSession,
    Handshaking,
    Active,
    IdleWarning,
    Ended,
}

/// Why a session ended. One variant per end path in the spec; these
/// strings land in the log's session-end event, so they are stable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndReason {
    IdleTimedOut,
    HardCapReached,
    PeerDisconnected,
    UserEnded,
    KillSwitch,
    RemoteEnded,
    ProtocolViolation,
}

impl EndReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::IdleTimedOut => "idle_timeout",
            Self::HardCapReached => "hard_cap",
            Self::PeerDisconnected => "peer_disconnected",
            Self::UserEnded => "user_ended",
            Self::KillSwitch => "kill_switch",
            Self::RemoteEnded => "remote_ended",
            Self::ProtocolViolation => "protocol_violation",
        }
    }
}

impl std::fmt::Display for EndReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Inputs to the state machine. Everything that can happen to a session
/// is one of these; there is no side door.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// User started a session on the phone.
    BeginHandshake,
    /// Noise KK handshake finished on this side.
    HandshakeCompleted,
    /// Any legitimate traffic or user interaction: resets idle time.
    Activity,
    /// The idle-warning deadline fired (idle_timeout - warn_before).
    WarningDue,
    /// The idle deadline fired with no activity in the grace window.
    IdleExpired,
    /// The hard-cap deadline fired. Always wins, regardless of activity.
    HardCapReached,
    /// Peer dropped the transport mid-session.
    PeerDisconnected,
    /// Explicit teardown from either side, for any policy reason.
    EndRequested(EndReason),
    /// Handshake failed or was cancelled before completion.
    Aborted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitionError {
    Illegal { from: SessionState, event: Event },
}

impl std::fmt::Display for TransitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransitionError::Illegal { from, event } => {
                write!(f, "illegal transition: event {event:?} in state {from:?}")
            }
        }
    }
}

/// Apply `event` to `state`. The single authority for what may happen
/// when.
pub fn step(state: SessionState, event: Event) -> Result<SessionState, TransitionError> {
    use SessionState::*;
    match (state, event) {
        // Only a fresh session can begin handshaking.
        (NoSession, Event::BeginHandshake) => Ok(Handshaking),
        // A handshake in progress completes into ACTIVE...
        (Handshaking, Event::HandshakeCompleted) => Ok(Active),
        // ...or aborts back to NO_SESSION (see module docs for why not
        // ENDED).
        (Handshaking, Event::Aborted) => Ok(NoSession),

        // Activity keeps ACTIVE alive and rescues IDLE_WARNING with a
        // FULL idle reset (spec: the warning is a nudge, not a stricter
        // deadline).
        (Active, Event::Activity) => Ok(Active),
        (IdleWarning, Event::Activity) => Ok(Active),
        // The warning deadline only moves ACTIVE into IDLE_WARNING.
        (Active, Event::WarningDue) => Ok(IdleWarning),

        // End paths, per the diagram, from the two established states.
        (Active, Event::IdleExpired) | (IdleWarning, Event::IdleExpired) => Ok(Ended),
        (Active, Event::HardCapReached) | (IdleWarning, Event::HardCapReached) => Ok(Ended),
        (Active, Event::PeerDisconnected) | (IdleWarning, Event::PeerDisconnected) => Ok(Ended),
        (Active, Event::EndRequested(_)) | (IdleWarning, Event::EndRequested(_)) => Ok(Ended),

        // ENDED is terminal within one Session instance. A new session
        // means a new Session object starting at NO_SESSION.
        (NoSession, Event::EndRequested(_))
        | (Handshaking, Event::EndRequested(_))
        | (Ended, Event::EndRequested(_)) => Err(TransitionError::Illegal { from: state, event }),

        (state, event) => Err(TransitionError::Illegal { from: state, event }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(state: SessionState, event: Event, expect: SessionState) {
        assert_eq!(step(state, event), Ok(expect), "{state:?} + {event:?}");
    }

    fn illegal(state: SessionState, event: Event) {
        assert_eq!(
            step(state, event),
            Err(TransitionError::Illegal { from: state, event }),
            "{state:?} + {event:?} must be illegal"
        );
    }

    /// Every cell of the matrix, asserted explicitly. Adding a state or
    /// event without deciding every row fails here first.
    #[test]
    fn full_transition_matrix_matches_spec() {
        use Event::*;
        use SessionState::*;

        // BeginHandshake: fresh sessions only.
        ok(NoSession, BeginHandshake, Handshaking);
        illegal(Handshaking, BeginHandshake);
        illegal(Active, BeginHandshake);
        illegal(IdleWarning, BeginHandshake);
        illegal(Ended, BeginHandshake);

        // Completion: only from HANDSHAKING.
        ok(Handshaking, HandshakeCompleted, Active);
        illegal(NoSession, HandshakeCompleted);
        illegal(Active, HandshakeCompleted);
        illegal(IdleWarning, HandshakeCompleted);
        illegal(Ended, HandshakeCompleted);

        // Abort: HANDSHAKING returns to NO_SESSION; elsewhere meaningless.
        ok(Handshaking, Aborted, NoSession);
        illegal(NoSession, Aborted);
        illegal(Active, Aborted);
        illegal(IdleWarning, Aborted);
        illegal(Ended, Aborted);

        // Activity: sustains ACTIVE, rescues IDLE_WARNING.
        ok(Active, Activity, Active);
        ok(IdleWarning, Activity, Active);
        illegal(NoSession, Activity);
        illegal(Handshaking, Activity);
        illegal(Ended, Activity);

        // Warning: only ACTIVE can be warned.
        ok(Active, WarningDue, IdleWarning);
        illegal(IdleWarning, WarningDue); // no double-warn: activity reset required first
        illegal(NoSession, WarningDue);
        illegal(Handshaking, WarningDue);
        illegal(Ended, WarningDue);

        // Idle expiry: established states only.
        ok(Active, IdleExpired, Ended);
        ok(IdleWarning, IdleExpired, Ended);
        illegal(NoSession, IdleExpired);
        illegal(Handshaking, IdleExpired);
        illegal(Ended, IdleExpired);

        // Hard cap: same reach, always terminal.
        ok(Active, HardCapReached, Ended);
        ok(IdleWarning, HardCapReached, Ended);
        illegal(NoSession, HardCapReached);
        illegal(Handshaking, HardCapReached);
        illegal(Ended, HardCapReached);

        // Disconnect: established states only.
        ok(Active, PeerDisconnected, Ended);
        ok(IdleWarning, PeerDisconnected, Ended);
        illegal(NoSession, PeerDisconnected);
        illegal(Handshaking, PeerDisconnected);
        illegal(Ended, PeerDisconnected);

        // Explicit end requests, all reasons, established states.
        let reasons = [
            EndReason::UserEnded,
            EndReason::KillSwitch,
            EndReason::RemoteEnded,
            EndReason::ProtocolViolation,
            EndReason::IdleTimedOut,
            EndReason::HardCapReached,
        ];
        for reason in reasons {
            ok(Active, EndRequested(reason), Ended);
            ok(IdleWarning, EndRequested(reason), Ended);
            illegal(NoSession, EndRequested(reason));
            illegal(Handshaking, EndRequested(reason));
            illegal(Ended, EndRequested(reason));
        }

        // ENDED is terminal for everything.
        for event in [
            BeginHandshake,
            HandshakeCompleted,
            Activity,
            WarningDue,
            IdleExpired,
            HardCapReached,
            PeerDisconnected,
            Aborted,
        ] {
            illegal(Ended, event);
        }
    }

    #[test]
    fn end_reason_strings_are_stable() {
        // These land in log events; changing them silently would break
        // phase 9's query filters.
        assert_eq!(EndReason::IdleTimedOut.as_str(), "idle_timeout");
        assert_eq!(EndReason::HardCapReached.as_str(), "hard_cap");
        assert_eq!(EndReason::PeerDisconnected.as_str(), "peer_disconnected");
        assert_eq!(EndReason::UserEnded.as_str(), "user_ended");
        assert_eq!(EndReason::KillSwitch.as_str(), "kill_switch");
        assert_eq!(EndReason::RemoteEnded.as_str(), "remote_ended");
        assert_eq!(EndReason::ProtocolViolation.as_str(), "protocol_violation");
    }

    #[test]
    fn typical_lifecycle_walks_cleanly() {
        let s = SessionState::NoSession;
        let s = step(s, Event::BeginHandshake).unwrap();
        let s = step(s, Event::HandshakeCompleted).unwrap();
        let s = step(s, Event::Activity).unwrap();
        let s = step(s, Event::WarningDue).unwrap();
        let s = step(s, Event::Activity).unwrap(); // rescued
        let s = step(s, Event::WarningDue).unwrap(); // warned again later
        let s = step(s, Event::IdleExpired).unwrap(); // grace lapsed
        assert_eq!(s, SessionState::Ended);
    }

    #[test]
    fn hard_cap_wins_over_activity_in_the_machine() {
        // Even with activity interleaved, once HardCapReached arrives the
        // result is ENDED -- the timer layer guarantees it fires despite
        // activity; the machine guarantees nothing else overrides it.
        let s = SessionState::Active;
        let s = step(s, Event::Activity).unwrap();
        let s = step(s, Event::HardCapReached).unwrap();
        assert_eq!(s, SessionState::Ended);
    }
}
