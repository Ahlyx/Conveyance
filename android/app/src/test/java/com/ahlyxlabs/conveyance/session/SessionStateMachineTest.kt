package com.ahlyxlabs.conveyance.session

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The full legal/illegal transition matrix, **generated** from the state and
 * event enums rather than hand-written cell by cell (the 10.3b constraint,
 * carried forward). Adding a [SessionState] or a [SessionEvent] forces this
 * file to be updated or it stops compiling / starts failing:
 *
 *  * a new [SessionState] enters [SessionState.entries] automatically, is
 *    tested against every event, and every untabled cell is asserted
 *    ILLEGAL — so a machine that quietly returns `Moved` for it fails here;
 *  * a new [SessionEvent] subtype breaks [discriminator]'s exhaustive `when`
 *    and [allSampleEvents]'s, neither of which compiles until the event is
 *    named.
 *
 * Kotlin 2.0 (`enum.entries` is stable since 1.9), so the compile-time
 * exhaustiveness guarantee holds; `values()` would be a silent fallback.
 */
class SessionStateMachineTest {

    /**
     * A stable key per event *kind* — all [SessionEvent.EndRequested] reasons
     * share one, because the machine treats them identically. The exhaustive
     * `when` is one of the two compile-time tripwires for a new event.
     */
    private fun discriminator(event: SessionEvent): String = when (event) {
        SessionEvent.BeginHandshake -> "BeginHandshake"
        SessionEvent.HandshakeCompleted -> "HandshakeCompleted"
        SessionEvent.Activity -> "Activity"
        SessionEvent.WarningDue -> "WarningDue"
        SessionEvent.IdleExpired -> "IdleExpired"
        SessionEvent.HardCapReached -> "HardCapReached"
        SessionEvent.PeerDisconnected -> "PeerDisconnected"
        SessionEvent.Aborted -> "Aborted"
        is SessionEvent.EndRequested -> "EndRequested"
    }

    /** One representative instance of every event kind. */
    private fun allSampleEvents(): List<SessionEvent> {
        // Exhaustive marker `when`: the second compile-time tripwire.
        val marker: SessionEvent = SessionEvent.BeginHandshake
        @Suppress("UNUSED_VARIABLE")
        val exhaustive: Unit = when (marker) {
            SessionEvent.BeginHandshake,
            SessionEvent.HandshakeCompleted,
            SessionEvent.Activity,
            SessionEvent.WarningDue,
            SessionEvent.IdleExpired,
            SessionEvent.HardCapReached,
            SessionEvent.PeerDisconnected,
            SessionEvent.Aborted,
            is SessionEvent.EndRequested,
            -> Unit
        }
        return buildList {
            add(SessionEvent.BeginHandshake)
            add(SessionEvent.HandshakeCompleted)
            add(SessionEvent.Activity)
            add(SessionEvent.WarningDue)
            add(SessionEvent.IdleExpired)
            add(SessionEvent.HardCapReached)
            add(SessionEvent.PeerDisconnected)
            add(SessionEvent.Aborted)
            // Every reason, so the matrix proves they all behave alike.
            EndReason.entries.forEach { add(SessionEvent.EndRequested(it)) }
        }
    }

    /** `(state, event-discriminator) -> resulting state`. Every pair absent here MUST be illegal. */
    private val legal: Map<Pair<SessionState, String>, SessionState> = buildMap {
        put(SessionState.NoSession to "BeginHandshake", SessionState.Handshaking)

        put(SessionState.Handshaking to "HandshakeCompleted", SessionState.Active)
        put(SessionState.Handshaking to "Aborted", SessionState.NoSession)

        put(SessionState.Active to "Activity", SessionState.Active)
        put(SessionState.Active to "WarningDue", SessionState.IdleWarning)
        put(SessionState.Active to "IdleExpired", SessionState.Ended)
        put(SessionState.Active to "HardCapReached", SessionState.Ended)
        put(SessionState.Active to "PeerDisconnected", SessionState.Ended)
        put(SessionState.Active to "EndRequested", SessionState.Ended)

        put(SessionState.IdleWarning to "Activity", SessionState.Active)
        put(SessionState.IdleWarning to "IdleExpired", SessionState.Ended)
        put(SessionState.IdleWarning to "HardCapReached", SessionState.Ended)
        put(SessionState.IdleWarning to "PeerDisconnected", SessionState.Ended)
        put(SessionState.IdleWarning to "EndRequested", SessionState.Ended)
    }

    @Test
    fun fullTransitionMatrixMatchesSpec() {
        for (from in SessionState.entries) {
            for (event in allSampleEvents()) {
                val expected = legal[from to discriminator(event)]
                val result = SessionStateMachine.step(from, event)
                if (expected != null) {
                    assertEquals("$from + $event", TransitionResult.Moved(expected), result)
                } else {
                    assertTrue(
                        "$from + $event must be illegal, got $result",
                        result is TransitionResult.Illegal,
                    )
                }
            }
        }
    }

    @Test
    fun illegalTransitionCarriesFromAndEvent() {
        val r = SessionStateMachine.step(SessionState.Ended, SessionEvent.Activity)
        assertEquals(TransitionResult.Illegal(SessionState.Ended, SessionEvent.Activity), r)
    }

    @Test
    fun typicalLifecycleWalksCleanly() {
        var s: SessionState = SessionState.NoSession
        fun go(e: SessionEvent) {
            s = (SessionStateMachine.step(s, e) as TransitionResult.Moved).to
        }
        go(SessionEvent.BeginHandshake)
        go(SessionEvent.HandshakeCompleted)
        go(SessionEvent.Activity)
        go(SessionEvent.WarningDue)
        go(SessionEvent.Activity) // rescued
        go(SessionEvent.WarningDue) // warned again later
        go(SessionEvent.IdleExpired) // grace lapsed
        assertEquals(SessionState.Ended, s)
    }

    @Test
    fun hardCapWinsOverActivityInTheMachine() {
        var s: SessionState = SessionState.Active
        s = (SessionStateMachine.step(s, SessionEvent.Activity) as TransitionResult.Moved).to
        s = (SessionStateMachine.step(s, SessionEvent.HardCapReached) as TransitionResult.Moved).to
        assertEquals(SessionState.Ended, s)
    }

    @Test
    fun abortedHandshakeReturnsToNoSessionNotEnded() {
        val r = SessionStateMachine.step(SessionState.Handshaking, SessionEvent.Aborted)
        assertEquals(TransitionResult.Moved(SessionState.NoSession), r)
    }

    @Test
    fun secondWarningWithoutActivityIsIllegal() {
        val r = SessionStateMachine.step(SessionState.IdleWarning, SessionEvent.WarningDue)
        assertTrue(r is TransitionResult.Illegal)
    }

    @Test
    fun endReasonStringsAreStable() {
        // These land in phone-log session-end rows; changing one silently
        // breaks 10.2b's `log query` filters.
        assertEquals("idle_timeout", EndReason.IdleTimedOut.asStr())
        assertEquals("hard_cap", EndReason.HardCapReached.asStr())
        assertEquals("peer_disconnected", EndReason.PeerDisconnected.asStr())
        assertEquals("user_ended", EndReason.UserEnded.asStr())
        assertEquals("kill_switch", EndReason.KillSwitch.asStr())
        assertEquals("remote_ended", EndReason.RemoteEnded.asStr())
        assertEquals("protocol_violation", EndReason.ProtocolViolation.asStr())
    }
}
