package com.ahlyxlabs.conveyance.session

import com.ahlyxlabs.conveyance.crypto.UnlockedIdentity
import com.ahlyxlabs.conveyance.crypto.X25519PublicKey
import com.ahlyxlabs.conveyance.transport.framing.FramingException
import com.ahlyxlabs.conveyance.transport.framing.InboundAssembler
import com.ahlyxlabs.conveyance.transport.framing.MessageSplitter
import com.ahlyxlabs.conveyance.transport.link.LinkClosedException
import com.ahlyxlabs.conveyance.transport.link.LinkEvent
import com.ahlyxlabs.conveyance.transport.link.LinkTeardown
import com.ahlyxlabs.conveyance.transport.link.PhoneLink
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.InternalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ClosedSendChannelException
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.util.concurrent.atomic.AtomicReference

/**
 * Outer bound on the whole "start a session" operation — advertise, wait for
 * the PC's central to connect and subscribe, run the Noise handshake to
 * completion. The [SessionController] (10.9) wraps its start flow in this;
 * [PhoneSession.start] itself only bounds the framed handshake exchange,
 * with [HANDSHAKE_BUDGET_MS].
 *
 * 60 s is the daemon's 30 s BLE-unreachable budget (CONVEYANCE_SPEC "Session
 * start") plus connect/discover/subscribe slack. It **must stay strictly
 * greater than** [HANDSHAKE_BUDGET_MS]: the inner handshake timer has to be
 * able to run to completion inside the outer one, or the outer would abort a
 * handshake still legitimately in progress. Ordering matters — outer (this) >
 * inner (handshake). A documented constant, not a spec value (10.4 plan
 * review).
 */
const val SESSION_START_TIMEOUT_MS: Long = 60_000

/**
 * Bound on the framed Noise handshake exchange itself, once the link is up.
 * [PhoneSession.start] wraps the msg1 -> msg2 round in this.
 *
 * Mirrors `conveyance-daemon/src/session.rs` `HANDSHAKE_TOTAL_BUDGET`
 * (`Duration::from_secs(30)`) — deliberately the **same value**. That
 * constant lives in a binary crate, so this is not compile-checked: **if you
 * change one, change both.** The daemon's window spans scan -> connect -> ...
 * -> handshake; this one spans only the handshake exchange after the link is
 * ready — narrower scope, same numeric bound. Must stay strictly less than
 * [SESSION_START_TIMEOUT_MS].
 */
const val HANDSHAKE_BUDGET_MS: Long = 30_000

/**
 * The phone's live Noise KK session: handshake-over-link, the framed
 * transport loop, timer wiring, cold-start gating, and end-of-life — the
 * Kotlin counterpart of `conveyance_core::session::Session` plus the
 * daemon's `responder_handshake` / owner loop, minus the daemon's routing
 * (that is 10.7).
 *
 * **Confinement.** Every state mutation runs on `@SessionDispatcher` (one
 * thread), so [SessionStateMachine], [SessionTimers], [txSeq] and the
 * [assembler] have exactly one writer and need no lock. [start] and [send]
 * hop onto it via `withContext`; the link and timer collectors are launched
 * on [scope], which is bound to that dispatcher. [sendMutex] also keeps each
 * framed outbound message contiguous when `PhoneLink.send` suspends and a
 * second caller enters [send].
 *
 * **One shot.** [start] may be called once. A failed handshake leaves this
 * instance spent (its [scope] is cancelled); recovery is a fresh
 * `PhoneSession` from [PhoneSessionFactory], which holds no per-call state.
 * That is the spec-1631310 guarantee — a failed start returns to NO_SESSION
 * and a fresh start with the same identity proceeds cleanly.
 *
 * **Cold-start is structural.** [send] passes [requireActive]; [inbound]
 * only emits while ACTIVE/IDLE_WARNING and completes on end. No method hands
 * out or consumes application plaintext without that gate, and 10.7 gets its
 * send/receive surface from here — never the raw [NoiseSession] handle.
 */
class PhoneSession internal constructor(
    private val identity: UnlockedIdentity,
    private val pcStaticPublic: X25519PublicKey,
    private val link: PhoneLink,
    private val params: SessionParams,
    private val noiseCrypto: NoiseSessionCrypto,
    private val dispatcher: CoroutineDispatcher,
    private val onEnded: (EndReason) -> Unit,
) {

    private enum class HandshakeDecision {
        Pending,
        Cancelled,
        Promoted,
    }

    private val scope = CoroutineScope(dispatcher + SupervisorJob())

    private val _state = MutableStateFlow(SessionState.NoSession)

    /** Observable lifecycle state for 10.6 (approval flow) and 10.10 (status UI). */
    val state: StateFlow<SessionState> = _state.asStateFlow()

    /**
     * Decrypted application plaintext, one message per emission, in order.
     * **Single-consumer** (10.6/10.7). Completes when the session ends.
     * Collecting it back-pressures the inbound link loop — the consumer must
     * drain promptly, mirroring the daemon owner processing one chunk at a
     * time.
     */
    private val inboundChannel = Channel<ByteArray>(Channel.BUFFERED)
    val inbound: Flow<ByteArray> = inboundChannel.receiveAsFlow()

    // ---- session state, confined to @SessionDispatcher ------------------

    /** One assembler + one tx sequence for the whole connection: framers
     *  enforce continuity per CONNECTION, so both span handshake -> transport. */
    private val assembler = InboundAssembler()
    private var txSeq: Int = 0
    private val sendMutex = Mutex()

    private var noise: NoiseSession? = null
    private var timers: SessionTimers? = null

    private val handshakeDone = CompletableDeferred<Unit>()
    private var startCalled = false
    private var handshakeTornDown = false
    private val handshakeDecision = AtomicReference(HandshakeDecision.Pending)

    // ---- start --------------------------------------------------------------

    /**
     * Drive the KK handshake as **initiator** to ACTIVE. Suspends until the
     * session is ACTIVE, or throws [SessionException.HandshakeFailed] (any
     * failure, generic by mandate). Call once.
     */
    @OptIn(InternalCoroutinesApi::class)
    suspend fun start() {
        val callerJob = currentCoroutineContext()[Job]
        val cancellationHandle = callerJob?.invokeOnCompletion(
            onCancelling = true,
            invokeImmediately = true,
        ) { cause ->
            if (cause is CancellationException) {
                // Runs synchronously when cancellation begins, possibly on a
                // caller thread. Atomic state is the only cross-thread touch.
                handshakeDecision.compareAndSet(
                    HandshakeDecision.Pending,
                    HandshakeDecision.Cancelled,
                )
            }
        }
        try {
            withContext(dispatcher) {
                check(!startCalled) { "start() already called on this PhoneSession" }
                startCalled = true
                applyEvent(SessionEvent.BeginHandshake) // NO_SESSION -> HANDSHAKING

                val session = try {
                    noiseCrypto.initiate(identity, pcStaticPublic)
                } catch (e: SessionException) {
                    abortHandshake(e)
                    throw e
                }
                noise = session

                // Collector up before msg1, so a fast PC's msg2 is never missed.
                scope.launch { collectLink() }

                try {
                    sendFramed(session.writeHandshakeMessage()) // msg1 (initiator writes first)
                } catch (e: SessionException) {
                    abortHandshake(e)
                    throw e
                }

                try {
                    withTimeout(HANDSHAKE_BUDGET_MS) { handshakeDone.await() }
                } catch (e: TimeoutCancellationException) {
                    val failed = SessionException.HandshakeFailed()
                    abortHandshake(failed)
                    throw failed
                } catch (e: SessionException) {
                    // completeExceptionally path: abortHandshake already ran in
                    // the collector. Rethrow the category to the caller.
                    throw e
                }
                // Resolved OK: promote() ran on this dispatcher, state == ACTIVE,
                // timers armed.
            }
        } catch (e: CancellationException) {
            // The link collector belongs to this PhoneSession, not to the
            // caller awaiting start(). Explicitly abort it when that caller
            // goes away; otherwise the independent collector could later
            // receive msg2 and promote an abandoned session to ACTIVE.
            withContext(NonCancellable + dispatcher) {
                when (_state.value) {
                    SessionState.Handshaking ->
                        abortHandshake(SessionException.HandshakeFailed())
                    // Handshake completion won the race before cancellation
                    // was observable. The session existed, so close it through
                    // the normal end path rather than orphaning it ACTIVE.
                    SessionState.Active, SessionState.IdleWarning ->
                        end(EndReason.UserEnded)
                    SessionState.NoSession, SessionState.Ended -> Unit
                }
            }
            throw e
        } finally {
            cancellationHandle?.dispose()
        }
    }

    // ---- outbound (10.7 seam) ---------------------------------------------

    /**
     * Encrypt, frame and transmit one application message over the live
     * session.
     *
     * @throws SessionException.NotActive if there is no ACTIVE/IDLE_WARNING session.
     * @throws SessionException.SessionEnded if the link died mid-send (the
     *   session is torn down first) or the transport desynchronized.
     */
    suspend fun send(plaintext: ByteArray) {
        withContext(dispatcher) {
            sendMutex.withLock {
                requireActive()
                val ciphertext = try {
                    noise!!.encrypt(plaintext)
                } catch (e: SessionException) {
                    end(EndReason.ProtocolViolation)
                    throw e
                }
                sendFramed(ciphertext)
                recordActivity()
            }
        }
    }

    // ---- link collector --------------------------------------------------

    private suspend fun collectLink() {
        link.events.collect { route(it) }
        // A conforming PhoneLink always emits a terminal Torn, which route()
        // handles, so control only reaches here on a contract violation
        // (events completed with no Torn). Fail safe rather than wedge.
        when (_state.value) {
            SessionState.Handshaking -> abortHandshake(SessionException.HandshakeFailed())
            SessionState.Active, SessionState.IdleWarning ->
                terminate(SessionEvent.PeerDisconnected, EndReason.PeerDisconnected)
            SessionState.NoSession, SessionState.Ended -> Unit
        }
    }

    private suspend fun route(ev: LinkEvent) {
        when (_state.value) {
            SessionState.Handshaking -> routeHandshaking(ev)
            SessionState.Active, SessionState.IdleWarning -> routeActive(ev)
            SessionState.NoSession, SessionState.Ended -> Unit
        }
    }

    private suspend fun routeHandshaking(ev: LinkEvent) {
        val session = noise ?: return
        when (ev) {
            is LinkEvent.Chunk -> {
                val messages = try {
                    assembler.ingest(ev.bytes)
                } catch (e: FramingException) {
                    abortHandshake(SessionException.HandshakeFailed())
                    return
                }
                for (msg in messages) {
                    try {
                        session.readHandshakeMessage(msg)
                        // Dead branch for a KK initiator: after writing msg1
                        // it is never this side's turn again (KK = 2
                        // messages). Kept for symmetry with the daemon's
                        // responder_handshake loop; a defensive instrumented
                        // test pins that needsWrite() stays false here.
                        if (session.needsWrite()) sendFramed(session.writeHandshakeMessage())
                    } catch (e: SessionException) {
                        abortHandshake(e)
                        return
                    }
                    if (session.isHandshakeComplete()) {
                        if (promote()) handshakeDone.complete(Unit)
                        return
                    }
                }
            }
            is LinkEvent.Torn -> {
                // Peer vanished mid-handshake -> Aborted -> NO_SESSION (spec
                // 1631310), NOT PeerDisconnected -> ENDED. mapTeardown is not
                // consulted in this phase.
                abortHandshake(SessionException.HandshakeFailed())
            }
        }
    }

    private suspend fun routeActive(ev: LinkEvent) {
        when (ev) {
            is LinkEvent.Chunk -> {
                val messages = try {
                    assembler.ingest(ev.bytes)
                } catch (e: FramingException) {
                    end(EndReason.ProtocolViolation)
                    return
                }
                for (msg in messages) {
                    val plaintext = try {
                        noise!!.decrypt(msg)
                    } catch (e: SessionException) {
                        // MAC failure / desync: terminal, matching the
                        // daemon's receive() contract.
                        end(EndReason.ProtocolViolation)
                        return
                    }
                    recordActivity()
                    try {
                        inboundChannel.send(plaintext)
                    } catch (e: ClosedSendChannelException) {
                        return // session ended under us
                    }
                }
            }
            is LinkEvent.Torn -> endFromTeardown(ev.reason)
        }
    }

    // ---- promotion + timers --------------------------------------------

    private fun promote(): Boolean {
        // The collector has its own SupervisorJob and can be scheduled before
        // start()'s cancellation continuation. Both caller cancellation and
        // endNow() atomically claim Cancelled; promotion must atomically claim
        // Promoted rather than relying on dispatcher queue order.
        if (!handshakeDecision.compareAndSet(
                HandshakeDecision.Pending,
                HandshakeDecision.Promoted,
            )
        ) {
            abortHandshake(SessionException.HandshakeFailed())
            return false
        }
        applyEvent(SessionEvent.HandshakeCompleted) // HANDSHAKING -> ACTIVE
        val t = SessionTimers(params, scope)
        timers = t
        t.start()
        scope.launch { t.events.collect { onTimerEvent(it) } }
        return true
    }

    private fun onTimerEvent(ev: TimerEvent) {
        when (ev) {
            // ACTIVE -> IDLE_WARNING; a no-op if activity already moved us on.
            TimerEvent.WarningDue -> applyEvent(SessionEvent.WarningDue)
            TimerEvent.IdleExpired -> terminate(SessionEvent.IdleExpired, EndReason.IdleTimedOut)
            TimerEvent.HardCapReached ->
                terminate(SessionEvent.HardCapReached, EndReason.HardCapReached)
        }
    }

    private fun recordActivity() {
        // Recorded on BOTH inbound decrypt and outbound send. The daemon
        // records activity once per request at its routing layer; the phone
        // records at the transport layer, both directions, because "any
        // legitimate traffic" (CONVEYANCE_SPEC, state.rs Event::Activity)
        // covers a response as much as a request. Recording twice per
        // round-trip is a harmless extra idle reset.
        applyEvent(SessionEvent.Activity)
        timers?.recordActivity()
    }

    // ---- framing --------------------------------------------------------

    /**
     * Split [message] into frames and push each to the link, advancing the
     * shared [txSeq].
     *
     * Runs on `@SessionDispatcher`. `link.send()` suspends on the BLE
     * dispatcher's outbound backpressure (10.3b `GattPhoneLink`: one
     * notification in flight), so a slow radio back-pressures the whole
     * session loop right here — intended flow control, not a bug. A dead
     * link surfaces as [LinkClosedException], which this translates to a
     * [SessionException] so 10.7 only ever handles one exception hierarchy.
     */
    private suspend fun sendFramed(message: ByteArray) {
        val split = MessageSplitter.split(message, link.maxWriteLen, txSeq)
        txSeq = split.nextSeq
        try {
            for (frame in split.frames) link.send(frame)
        } catch (e: LinkClosedException) {
            when (_state.value) {
                SessionState.Handshaking -> throw SessionException.HandshakeFailed()
                SessionState.Active, SessionState.IdleWarning -> {
                    endFromTeardown(e.reason)
                    throw SessionException.SessionEnded()
                }
                SessionState.NoSession, SessionState.Ended ->
                    throw SessionException.SessionEnded()
            }
        }
    }

    // ---- ending --------------------------------------------------------

    /**
     * Abort out of HANDSHAKING back to NO_SESSION with **no** [onEnded]
     * callback. The callback's future owner therefore cannot persist a
     * session-end row for a handshake that never reached ACTIVE (spec
     * 1631310). Idempotent.
     */
    private fun abortHandshake(cause: SessionException) {
        // INVARIANT (protects spec 1631310): this path is HANDSHAKING-only.
        // Once ACTIVE, every teardown MUST go through end() so onEnded fires
        // and its owner can persist the session-end row. Reaching here from ACTIVE /
        // IDLE_WARNING is a bug in this class's own routing, not a runtime
        // condition — fail loud so a test catches it.
        check(_state.value == SessionState.Handshaking || _state.value == SessionState.NoSession) {
            "abortHandshake() from ${_state.value}; ACTIVE teardown must use end()"
        }
        handshakeDecision.compareAndSet(
            HandshakeDecision.Pending,
            HandshakeDecision.Cancelled,
        )
        applyEvent(SessionEvent.Aborted) // HANDSHAKING -> NO_SESSION (no-op if already there)
        if (!handshakeDone.isCompleted) handshakeDone.completeExceptionally(cause)
        if (handshakeTornDown) return
        handshakeTornDown = true
        noise?.close()
        noise = null
        inboundChannel.close()
        link.shutdown()
        scope.cancel()
    }

    /**
     * End an ACTIVE / IDLE_WARNING session for [reason]. Idempotent (an
     * already-ENDED session steps ILLEGAL and this returns).
     */
    private fun end(reason: EndReason) {
        terminate(SessionEvent.EndRequested(reason), reason)
    }

    private fun endFromTeardown(teardown: LinkTeardown) {
        val reason = mapTeardown(teardown)
        if (reason == EndReason.PeerDisconnected) {
            terminate(SessionEvent.PeerDisconnected, reason)
        } else {
            end(reason)
        }
    }

    /** Apply one terminal state-machine event, then run the single cleanup path. */
    private fun terminate(event: SessionEvent, reason: EndReason) {
        if (!applyEvent(event)) return // ENDED already (or not live) -> no-op

        // Cleanup ordering is deliberate and load-bearing:
        //   1. timers + noise released (Rust wipes the snow keys on close())
        //   2. inbound flow COMPLETES  -> 10.7's collector sees the stream end
        //   3. onEnded(reason) fires    -> app-level "session over" callback
        //   4. scope cancelled          -> kills the collectors, LAST, after 1-3
        // 10.7 therefore always observes inbound completion BEFORE the onEnded
        // callback. If future code must hand 10.7 one final plaintext *before*
        // telling it the session ended, that plaintext has to be emitted above
        // step 2 — after scope.cancel() nothing in this class runs again.
        timers?.cancel()
        timers = null
        noise?.close()
        noise = null
        inboundChannel.close()
        link.shutdown()
        try {
            onEnded(reason)
        } finally {
            scope.cancel()
        }
    }

    /**
     * End the session on an explicit request (kill switch, user end).
     * Public seam for 10.10 / 10.9. A no-op if the session is not live.
     */
    fun endNow(reason: EndReason) {
        if (_state.value == SessionState.Handshaking) {
            // Linearizes a caller-thread cancellation against promote() even
            // when msg2 has already made the independent collector runnable.
            handshakeDecision.compareAndSet(
                HandshakeDecision.Pending,
                HandshakeDecision.Cancelled,
            )
        }
        scope.launch {
            when (_state.value) {
                SessionState.Handshaking ->
                    abortHandshake(SessionException.HandshakeFailed())
                SessionState.Active, SessionState.IdleWarning -> end(reason)
                SessionState.NoSession, SessionState.Ended -> Unit
            }
        }
    }

    // ---- helpers ------------------------------------------------------

    private fun requireActive() {
        when (_state.value) {
            SessionState.Active, SessionState.IdleWarning -> Unit
            else -> throw SessionException.NotActive()
        }
    }

    private fun applyEvent(event: SessionEvent): Boolean =
        when (val r = SessionStateMachine.step(_state.value, event)) {
            is TransitionResult.Moved -> {
                _state.value = r.to
                true
            }
            is TransitionResult.Illegal -> false
        }

    private fun mapTeardown(reason: LinkTeardown): EndReason = when (reason) {
        LinkTeardown.PeerDisconnected -> EndReason.PeerDisconnected
        // No phone-side AdapterOff end reason; disconnection is the honest
        // mapping and the spec's EndReason set is the authority.
        LinkTeardown.AdapterOff -> EndReason.PeerDisconnected
        // Spec: a cleared CCCD is "equivalent to disconnection".
        LinkTeardown.SubscriptionLost -> EndReason.PeerDisconnected
        // Only reachable as a redundant no-op after end() already recorded the
        // real reason and called link.shutdown() (see end()). The value here
        // is never actually logged.
        LinkTeardown.LocalShutdown -> EndReason.UserEnded
        is LinkTeardown.ProtocolViolation -> EndReason.ProtocolViolation
    }

    // KNOWN IMPRECISION (PHASE_10.4a_EXIT.md; picked up in 10.6): a
    // PC-originated `conveyance session end` arrives as a Noise-encrypted
    // SessionEnd WireMessage. PhoneSession hands decrypted plaintext to 10.6
    // opaquely, so it is NOT decoded here — such an end reaches the phone
    // only as the subsequent BLE link drop -> PeerDisconnected.
    // EndReason.RemoteEnded stays unreachable until 10.6 wires WireMessage
    // dispatch.
}
