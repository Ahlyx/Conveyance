package com.ahlyxlabs.conveyance.session

/**
 * The session lifecycle state machine, as pure logic — a Kotlin port of
 * `conveyance_core::session::state`. States and legal transitions come
 * verbatim from the spec's "Session lifecycle" diagram:
 *
 * ```text
 * NO_SESSION --> HANDSHAKING --> ACTIVE
 *                                  |  ^
 *                    idle warning  |  | activity
 *                                  v  |
 *                              IDLE_WARNING
 * ACTIVE / IDLE_WARNING --> ENDED   (idle expiry, hard cap, disconnect,
 *                                    explicit end, kill switch, remote end)
 * ```
 *
 * Keeping this pure buys the same two things it buys the daemon: the full
 * legal/illegal matrix is unit-testable without coroutines or crypto, and
 * every state change in [PhoneSession] goes through [SessionStateMachine.step],
 * so the rules live in exactly one place.
 *
 * One gap the spec diagram does not draw: aborting out of HANDSHAKING (peer
 * vanished mid-handshake, handshake failed). A session that never completed
 * its handshake never existed, so [SessionEvent.Aborted] returns to
 * NO_SESSION — allowing a clean retry — rather than to ENDED, and no
 * session-end row is logged for it (CONVEYANCE_SPEC "Session lifecycle",
 * amended in commit 1631310). Unlike the daemon's `Session::establish`,
 * which shortcuts straight to ACTIVE, [PhoneSession] drives this machine
 * through HANDSHAKING explicitly.
 */
enum class SessionState {
    NoSession,
    Handshaking,
    Active,
    IdleWarning,
    Ended,
}

/**
 * Why a session ended. One variant per end path in the spec; [asStr] values
 * land in the phone log's session-end event (10.2b) and must stay stable —
 * they are the strings `log query` filters on. Ported one-for-one from
 * `conveyance_core::session::state::EndReason`.
 */
enum class EndReason {
    IdleTimedOut,
    HardCapReached,
    PeerDisconnected,
    UserEnded,
    KillSwitch,
    RemoteEnded,
    ProtocolViolation;

    fun asStr(): String = when (this) {
        IdleTimedOut -> "idle_timeout"
        HardCapReached -> "hard_cap"
        PeerDisconnected -> "peer_disconnected"
        UserEnded -> "user_ended"
        KillSwitch -> "kill_switch"
        RemoteEnded -> "remote_ended"
        ProtocolViolation -> "protocol_violation"
    }
}

/**
 * Inputs to the state machine. Everything that can happen to a session is
 * one of these; there is no side door. Mirrors
 * `conveyance_core::session::state::Event`.
 */
sealed interface SessionEvent {
    /** User started a session on the phone. */
    data object BeginHandshake : SessionEvent

    /** Noise KK handshake finished on this side. */
    data object HandshakeCompleted : SessionEvent

    /** Any legitimate traffic or user interaction: resets idle time. */
    data object Activity : SessionEvent

    /** The idle-warning deadline fired (idle_timeout - warn_before). */
    data object WarningDue : SessionEvent

    /** The idle deadline fired with no activity in the grace window. */
    data object IdleExpired : SessionEvent

    /** The hard-cap deadline fired. Always wins, regardless of activity. */
    data object HardCapReached : SessionEvent

    /** Peer dropped the transport mid-session. */
    data object PeerDisconnected : SessionEvent

    /** Explicit teardown from either side, for any policy reason. */
    data class EndRequested(val reason: EndReason) : SessionEvent

    /** Handshake failed or was cancelled before completion. */
    data object Aborted : SessionEvent
}

/** The outcome of [SessionStateMachine.step]. */
sealed interface TransitionResult {
    /** `event` was legal in `from`; the machine is now in [to]. */
    data class Moved(val to: SessionState) : TransitionResult

    /** `event` has no meaning in [from]; the machine did not move. */
    data class Illegal(val from: SessionState, val event: SessionEvent) : TransitionResult
}

/**
 * The single authority for what may happen when. A statement `when` over
 * `(state, event)`; every pair not named below is [TransitionResult.Illegal].
 */
object SessionStateMachine {

    fun step(from: SessionState, event: SessionEvent): TransitionResult {
        val to: SessionState? = when (from) {
            SessionState.NoSession -> when (event) {
                SessionEvent.BeginHandshake -> SessionState.Handshaking
                else -> null
            }

            SessionState.Handshaking -> when (event) {
                // A handshake in progress completes into ACTIVE...
                SessionEvent.HandshakeCompleted -> SessionState.Active
                // ...or aborts back to NO_SESSION (see the file docs for why
                // not ENDED, and why no session-end row is logged).
                SessionEvent.Aborted -> SessionState.NoSession
                else -> null
            }

            SessionState.Active -> when (event) {
                // Activity keeps ACTIVE alive.
                SessionEvent.Activity -> SessionState.Active
                // The warning deadline only moves ACTIVE into IDLE_WARNING.
                SessionEvent.WarningDue -> SessionState.IdleWarning
                SessionEvent.IdleExpired -> SessionState.Ended
                SessionEvent.HardCapReached -> SessionState.Ended
                SessionEvent.PeerDisconnected -> SessionState.Ended
                is SessionEvent.EndRequested -> SessionState.Ended
                else -> null
            }

            SessionState.IdleWarning -> when (event) {
                // Activity rescues IDLE_WARNING with a FULL idle reset (spec:
                // the warning is a nudge, not a stricter deadline). A second
                // WarningDue without an intervening Activity is illegal.
                SessionEvent.Activity -> SessionState.Active
                SessionEvent.IdleExpired -> SessionState.Ended
                SessionEvent.HardCapReached -> SessionState.Ended
                SessionEvent.PeerDisconnected -> SessionState.Ended
                is SessionEvent.EndRequested -> SessionState.Ended
                else -> null
            }

            // ENDED is terminal within one PhoneSession instance. A new
            // session means a new PhoneSession starting at NO_SESSION.
            SessionState.Ended -> null
        }

        return if (to != null) TransitionResult.Moved(to) else TransitionResult.Illegal(from, event)
    }
}
