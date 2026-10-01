package com.ahlyxlabs.conveyance.session

import com.ahlyxlabs.conveyance.storage.identity.Tier1AuthMethod
import com.ahlyxlabs.conveyance.storage.identity.UnlockedPhoneSession
import com.ahlyxlabs.conveyance.transport.framing.Frame
import com.ahlyxlabs.conveyance.transport.framing.InboundAssembler
import com.ahlyxlabs.conveyance.transport.framing.MessageSplitter
import com.ahlyxlabs.conveyance.transport.link.LinkClosedException
import com.ahlyxlabs.conveyance.transport.link.LinkEvent
import com.ahlyxlabs.conveyance.transport.link.LinkTeardown
import com.ahlyxlabs.conveyance.transport.link.LoopbackLink
import com.ahlyxlabs.conveyance.transport.link.PhoneLink
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes

/**
 * Lifecycle, timer/state-machine interaction, framing continuity and
 * multi-writer teardown for [PhoneSession], on the JVM with
 * [FakeNoiseSessionCrypto] + [LoopbackLink]. Real Noise is
 * `PhoneSessionRealNoiseTest` (instrumented).
 */
@OptIn(ExperimentalCoroutinesApi::class)
class PhoneSessionTest {

    private suspend inline fun <reified T : Throwable> assertFailsWith(
        crossinline block: suspend () -> Unit,
    ): T {
        try {
            block()
        } catch (thrown: Throwable) {
            if (thrown is T) return thrown
            throw AssertionError("expected ${T::class.java.name}, got ${thrown::class.java.name}", thrown)
        }
        throw AssertionError("expected ${T::class.java.name} to be thrown")
    }

    private val dispatcher = StandardTestDispatcher()
    private val pcPub = com.ahlyxlabs.conveyance.crypto.X25519PublicKey(ByteArray(32))
    private val mtu23 = Frame.maxFramePayload(23)

    private fun testUnlockedSession(
        identity: FakeUnlockedIdentity = FakeUnlockedIdentity(),
    ) = UnlockedPhoneSession(
        identity = identity,
        authMethod = Tier1AuthMethod.BIOMETRIC,
        generation = ByteArray(16),
        vaultKey = ByteArray(32) { 0x4a },
    )

    private class Harness(
        val session: PhoneSession,
        val crypto: FakeNoiseSessionCrypto,
        val pc: FakePc,
        val ended: MutableList<EndReason>,
        val phoneLink: LoopbackLink,
        val pcLink: LoopbackLink,
    )

    private fun CoroutineScope.newHarness(
        params: SessionParams = SessionParams.specDefaults(),
        completeAfterReads: Int = 1,
        failFirstRead: Boolean = false,
        maxWriteLen: Int = 247,
    ): Harness {
        val (a, b) = LoopbackLink.pair(maxWriteLen = maxWriteLen)
        val crypto = FakeNoiseSessionCrypto(completeAfterReads, failFirstRead)
        val ended = mutableListOf<EndReason>()
        val unlockedSession = testUnlockedSession()
        val session = PhoneSession(
            unlockedSession = unlockedSession,
            pcStaticPublic = pcPub,
            link = a,
            params = params,
            noiseCrypto = crypto,
            dispatcher = dispatcher,
            onEnded = { ended += it },
        )
        val pc = FakePc(b)
        return Harness(session, crypto, pc, ended, a, b)
    }

    /** The far side: reads msg1, writes msg2, then decrypts/encrypts transport. */
    private class FakePc(
        private val link: PhoneLink,
        val noise: FakeNoiseSession = FakeNoiseSession(isInitiator = false),
    ) {
        val received = mutableListOf<ByteArray>()
        private val asm = InboundAssembler()
        private var seq = 0

        fun collectIn(scope: CoroutineScope): Job = scope.launch {
            link.events.collect { ev ->
                when (ev) {
                    is LinkEvent.Chunk -> for (m in asm.ingest(ev.bytes)) onMessage(m)
                    is LinkEvent.Torn -> Unit
                }
            }
        }

        private suspend fun onMessage(m: ByteArray) {
            if (!noise.isHandshakeComplete()) {
                noise.readHandshakeMessage(m)
                if (noise.needsWrite()) sendRaw(noise.writeHandshakeMessage())
            } else {
                received += noise.decrypt(m)
            }
        }

        suspend fun sendPlaintext(bytes: ByteArray) = sendRaw(noise.encrypt(bytes))

        private suspend fun sendRaw(message: ByteArray) {
            val out = MessageSplitter.split(message, link.maxWriteLen, seq)
            seq = out.nextSeq
            out.frames.forEach { link.send(it) }
        }
    }

    /** Records the real frame order and can park one transport send. */
    private class GateablePhoneLink(
        private val delegate: PhoneLink,
    ) : PhoneLink {
        override val maxWriteLen: Int get() = delegate.maxWriteLen
        override val events get() = delegate.events

        val sent = mutableListOf<ByteArray>()
        val blocked = CompletableDeferred<Unit>()
        private val release = CompletableDeferred<Unit>()
        private var captureOnly = false
        private var gateNext = false

        fun captureTransportAndGateNextSend() {
            captureOnly = true
            gateNext = true
        }

        fun releaseSend() {
            release.complete(Unit)
        }

        override suspend fun send(chunk: ByteArray) {
            sent += chunk.copyOf()
            if (!captureOnly) {
                delegate.send(chunk)
                return
            }
            if (gateNext) {
                gateNext = false
                blocked.complete(Unit)
                release.await()
            }
        }

        override fun shutdown() = delegate.shutdown()
    }

    // -- handshake ------------------------------------------------------------

    @Test
    fun startDrivesTheHandshakeToActive() = runTest(dispatcher) {
        val h = newHarness()
        h.pc.collectIn(backgroundScope)
        h.session.start()

        assertEquals(SessionState.Active, h.session.state.value)
        assertTrue(h.ended.isEmpty())
        h.session.endNow(EndReason.UserEnded)
        advanceUntilIdle()
    }

    @Test
    fun handshakeFailureAbortsToNoSessionWithNoOnEnded() = runTest(dispatcher) {
        val h = newHarness(failFirstRead = true)
        h.pc.collectIn(backgroundScope)

        assertFailsWith<SessionException.HandshakeFailed> { h.session.start() }
        advanceUntilIdle()

        assertEquals(SessionState.NoSession, h.session.state.value)
        assertTrue("aborted start emits no session-end callback", h.ended.isEmpty())
    }

    @Test
    fun midHandshakeLinkTearAbortsToNoSessionNotEnded() = runTest(dispatcher) {
        val h = newHarness()
        // No fake PC: msg2 never arrives. Tear the far side mid-handshake.
        val starting = async { runCatching { h.session.start() } }
        runCurrent() // msg1 goes out; start() parks on handshakeDone
        h.pcLink.failWith(LinkTeardown.PeerDisconnected)
        advanceUntilIdle()

        assertTrue(starting.await().exceptionOrNull() is SessionException.HandshakeFailed)
        assertEquals(SessionState.NoSession, h.session.state.value)
        assertTrue(h.ended.isEmpty())
    }

    @Test
    fun handshakeTimeoutAbortsToNoSession() = runTest(dispatcher) {
        val h = newHarness()
        // No fake PC at all: msg2 never comes, the HANDSHAKE_BUDGET_MS timer wins.
        val starting = async { runCatching { h.session.start() } }
        advanceTimeBy(HANDSHAKE_BUDGET_MS + 1)
        runCurrent()

        assertTrue(starting.await().exceptionOrNull() is SessionException.HandshakeFailed)
        assertEquals(SessionState.NoSession, h.session.state.value)
        assertTrue(h.ended.isEmpty())
    }

    @Test
    fun handshakeTimeoutWinsOverReplyAtTheDeadline() = runTest(dispatcher) {
        val h = newHarness()
        val starting = async { runCatching { h.session.start() } }
        runCurrent()
        val phoneNoise = h.crypto.last!!
        val reply = MessageSplitter.split("msg2".toByteArray(), h.pcLink.maxWriteLen, 0)

        // Registered after withTimeout's deadline. At the same virtual-time
        // instant, timeout cancellation is therefore the earlier event; a
        // subsequently runnable collector must not promote the session.
        launch {
            delay(HANDSHAKE_BUDGET_MS)
            reply.frames.forEach { h.pcLink.send(it) }
        }
        advanceTimeBy(HANDSHAKE_BUDGET_MS)
        runCurrent()

        assertTrue(starting.await().exceptionOrNull() is SessionException.HandshakeFailed)
        assertEquals(SessionState.NoSession, h.session.state.value)
        assertTrue(phoneNoise.closed)
        assertTrue(h.ended.isEmpty())
    }

    @Test
    fun callerCancellationDuringHandshakeAbortsAndTearsDown() = runTest(dispatcher) {
        val h = newHarness()
        val starting = launch { h.session.start() }
        runCurrent() // msg1 is buffered; no fake PC exists to answer it
        assertEquals(SessionState.Handshaking, h.session.state.value)
        val phoneNoise = h.crypto.last!!

        starting.cancelAndJoin()
        runCurrent()

        assertEquals(SessionState.NoSession, h.session.state.value)
        assertTrue(phoneNoise.closed)
        assertTrue("an aborted handshake is not a session-end event", h.ended.isEmpty())
        assertFailsWith<LinkClosedException> {
            h.phoneLink.send(Frame.encode(1, Frame.FLAG_START or Frame.FLAG_END, ByteArray(0)))
        }

        advanceTimeBy(HANDSHAKE_BUDGET_MS + 1)
        runCurrent()
        assertEquals("an abandoned session must never promote", SessionState.NoSession, h.session.state.value)
    }

    @Test
    fun callerCancellationWinsOverAQueuedHandshakeReply() = runTest(dispatcher) {
        val h = newHarness()
        val starting = launch { h.session.start() }
        runCurrent() // phone msg1 sent; phone collector is waiting for msg2
        val phoneNoise = h.crypto.last!!

        // Queue msg2 so the independent link collector is runnable, but cancel
        // the caller before that collector gets another dispatcher turn.
        val reply = MessageSplitter.split("msg2".toByteArray(), h.pcLink.maxWriteLen, 0)
        reply.frames.forEach { h.pcLink.send(it) }
        starting.cancel()
        runCurrent()
        starting.join()

        assertEquals(SessionState.NoSession, h.session.state.value)
        assertTrue(phoneNoise.closed)
        assertTrue("cancellation before promotion is not a session end", h.ended.isEmpty())
        assertFailsWith<LinkClosedException> {
            h.phoneLink.send(Frame.encode(1, Frame.FLAG_START or Frame.FLAG_END, ByteArray(0)))
        }
    }

    @Test
    fun explicitEndDuringHandshakeAbortsWithoutSessionEnd() = runTest(dispatcher) {
        val h = newHarness()
        val starting = async { runCatching { h.session.start() } }
        runCurrent() // HANDSHAKING, waiting for a deliberately absent msg2
        assertEquals(SessionState.Handshaking, h.session.state.value)
        val phoneNoise = h.crypto.last!!

        h.session.endNow(EndReason.UserEnded)
        runCurrent()

        assertEquals(SessionState.NoSession, h.session.state.value)
        assertTrue(phoneNoise.closed)
        assertTrue("a cancelled start must not call onEnded", h.ended.isEmpty())
        assertTrue(starting.await().exceptionOrNull() is SessionException.HandshakeFailed)
        assertFailsWith<LinkClosedException> {
            h.phoneLink.send(Frame.encode(1, Frame.FLAG_START or Frame.FLAG_END, ByteArray(0)))
        }
    }

    @Test
    fun explicitEndWinsOverAQueuedHandshakeReply() = runTest(dispatcher) {
        val h = newHarness()
        val starting = async { runCatching { h.session.start() } }
        runCurrent()
        val phoneNoise = h.crypto.last!!

        val reply = MessageSplitter.split("msg2".toByteArray(), h.pcLink.maxWriteLen, 0)
        reply.frames.forEach { h.pcLink.send(it) }
        h.session.endNow(EndReason.UserEnded)
        runCurrent()

        assertEquals(SessionState.NoSession, h.session.state.value)
        assertTrue(phoneNoise.closed)
        assertTrue("cancellation requested before promotion is not a session end", h.ended.isEmpty())
        assertTrue(starting.await().exceptionOrNull() is SessionException.HandshakeFailed)
    }

    @Test
    fun handshakeFailureRecoversWithTheSameIdentity() = runTest(dispatcher) {
        val identity = FakeUnlockedIdentity()
        val unlockedSession = testUnlockedSession(identity)

        // Attempt 1: crypto set to fail the first read.
        run {
            val (a, b) = LoopbackLink.pair()
            val ended = mutableListOf<EndReason>()
            val s1 = PhoneSession(
                unlockedSession, pcPub, a, SessionParams.specDefaults(),
                FakeNoiseSessionCrypto(failFirstRead = true), dispatcher,
            ) { ended += it }
            FakePc(b).collectIn(backgroundScope)
            assertFailsWith<SessionException.HandshakeFailed> { s1.start() }
            advanceUntilIdle()
            assertEquals(SessionState.NoSession, s1.state.value)
            assertTrue(ended.isEmpty())
        }

        // Attempt 2: same identity, fresh link + crypto, no per-call state — clean.
        val (a2, b2) = LoopbackLink.pair()
        val ended2 = mutableListOf<EndReason>()
        val s2 = PhoneSession(
            unlockedSession, pcPub, a2, SessionParams.specDefaults(),
            FakeNoiseSessionCrypto(), dispatcher,
        ) { ended2 += it }
        FakePc(b2).collectIn(backgroundScope)
        s2.start()

        assertEquals(SessionState.Active, s2.state.value)
        s2.send("ok".toByteArray())
        advanceUntilIdle()
        s2.endNow(EndReason.UserEnded)
        advanceUntilIdle()
        assertTrue(identity.closed) // active-session end wipes the owned Tier 1 session
        assertTrue(runCatching { unlockedSession.vaultKeyCopy() }.isFailure)
    }

    // -- transport ---------------------------------------------------------

    @Test
    fun sendEncryptsFramesAndTheFarSideDecrypts() = runTest(dispatcher) {
        val h = newHarness()
        h.pc.collectIn(backgroundScope)
        h.session.start()

        h.session.send("first".toByteArray())
        h.session.send("second".toByteArray())
        advanceUntilIdle()

        assertEquals(listOf("first", "second"), h.pc.received.map { String(it) })
        h.session.endNow(EndReason.UserEnded)
        advanceUntilIdle()
    }

    @Test
    fun inboundDeliversDecryptedPlaintextInOrder() = runTest(dispatcher) {
        val h = newHarness()
        h.pc.collectIn(backgroundScope)
        h.session.start()

        val got = mutableListOf<String>()
        val collector = backgroundScope.launch {
            h.session.inbound.collect { got += String(it.bytes) }
        }

        h.pc.sendPlaintext("a".toByteArray())
        h.pc.sendPlaintext("bb".toByteArray())
        h.pc.sendPlaintext("ccc".toByteArray())
        advanceUntilIdle()

        assertEquals(listOf("a", "bb", "ccc"), got)
        h.session.endNow(EndReason.UserEnded)
        advanceUntilIdle()
        collector.join() // inbound completed on end
    }

    @Test
    fun multiFrameHandshakeAndTransportKeepSequenceContinuityAtMtu23() = runTest(dispatcher) {
        val h = newHarness(maxWriteLen = mtu23)
        h.pc.collectIn(backgroundScope)
        h.session.start()
        assertEquals(SessionState.Active, h.session.state.value)

        // 500-byte payloads span many frames each way; a txSeq discontinuity
        // across the handshake -> transport boundary would desync the XOR.
        val up = ByteArray(500) { (it % 251).toByte() }
        val down = ByteArray(400) { ((it * 7) % 251).toByte() }
        val got = mutableListOf<ByteArray>()
        backgroundScope.launch { h.session.inbound.collect { got += it.bytes } }

        h.session.send(up)
        h.pc.sendPlaintext(down)
        advanceUntilIdle()

        assertArrayEquals(up, h.pc.received.single())
        assertArrayEquals(down, got.single())
        h.session.endNow(EndReason.UserEnded)
        advanceUntilIdle()
    }

    @Test
    fun concurrentSendsKeepEachFramedMessageContiguous() = runTest(dispatcher) {
        val (rawPhone, pcLink) = LoopbackLink.pair(maxWriteLen = mtu23)
        val link = GateablePhoneLink(rawPhone)
        val crypto = FakeNoiseSessionCrypto()
        val session = PhoneSession(
            unlockedSession = testUnlockedSession(),
            pcStaticPublic = pcPub,
            link = link,
            params = SessionParams.specDefaults(),
            noiseCrypto = crypto,
            dispatcher = dispatcher,
            onEnded = {},
        )
        val pc = FakePc(pcLink)
        val pcJob = pc.collectIn(backgroundScope)
        session.start()
        pcJob.cancelAndJoin()

        link.captureTransportAndGateNextSend()
        val first = async { session.send(ByteArray(500) { 0x31 }) }
        link.blocked.await()
        val second = async { session.send(ByteArray(400) { 0x62 }) }
        runCurrent()
        link.releaseSend()
        first.await()
        second.await()

        // One handshake message plus two transport ciphertexts. A second
        // START while the first transport message is incomplete throws here.
        val assembler = InboundAssembler()
        val messages = link.sent.flatMap { assembler.ingest(it) }
        assertEquals(3, messages.size)

        session.endNow(EndReason.UserEnded)
        advanceUntilIdle()
    }

    @Test
    fun sendBeforeActiveThrowsNotActive() = runTest(dispatcher) {
        val h = newHarness()
        assertFailsWith<SessionException.NotActive> { h.session.send(ByteArray(1)) }

        h.pc.collectIn(backgroundScope)
        h.session.start()
        h.session.endNow(EndReason.UserEnded)
        advanceUntilIdle()
        assertFailsWith<SessionException.NotActive> { h.session.send(ByteArray(1)) }
    }

    @Test
    fun decryptFailureEndsWithProtocolViolation() = runTest(dispatcher) {
        val h = newHarness()
        h.pc.collectIn(backgroundScope)
        h.session.start()

        h.crypto.last!!.failNextDecrypt = true
        h.pc.sendPlaintext("boom".toByteArray())
        advanceUntilIdle()

        assertEquals(SessionState.Ended, h.session.state.value)
        assertEquals(listOf(EndReason.ProtocolViolation), h.ended)
    }

    // -- timers ----------------------------------------------------------

    @Test
    fun idleExpiryEndsTheSession() = runTest(dispatcher) {
        val h = newHarness(params = SessionParams.validated(30.minutes, 2.minutes, 4.hours))
        h.pc.collectIn(backgroundScope)
        h.session.start()

        advanceTimeBy(28.minutes.inWholeMilliseconds); runCurrent()
        assertEquals(SessionState.IdleWarning, h.session.state.value)
        advanceTimeBy(2.minutes.inWholeMilliseconds); runCurrent()

        assertEquals(SessionState.Ended, h.session.state.value)
        assertEquals(listOf(EndReason.IdleTimedOut), h.ended)
    }

    @Test
    fun activityRescuesFromIdleWarning() = runTest(dispatcher) {
        val h = newHarness(params = SessionParams.validated(30.minutes, 2.minutes, 4.hours))
        h.pc.collectIn(backgroundScope)
        h.session.start()

        advanceTimeBy(28.minutes.inWholeMilliseconds); runCurrent()
        assertEquals(SessionState.IdleWarning, h.session.state.value)

        h.session.send("keepalive".toByteArray())
        runCurrent()
        assertEquals(SessionState.Active, h.session.state.value)

        // Full fresh window: still Active ~28 min later.
        advanceTimeBy(27.minutes.inWholeMilliseconds); runCurrent()
        assertEquals(SessionState.Active, h.session.state.value)

        h.session.endNow(EndReason.UserEnded); advanceUntilIdle()
    }

    @Test
    fun hardCapEndsTheSessionThroughContinuousActivity() = runTest(dispatcher) {
        val h = newHarness(params = SessionParams.validated(30.minutes, 2.minutes, 4.hours))
        h.pc.collectIn(backgroundScope)
        h.session.start()

        repeat(20) {
            advanceTimeBy(15.minutes.inWholeMilliseconds); runCurrent()
            if (h.session.state.value == SessionState.Active ||
                h.session.state.value == SessionState.IdleWarning
            ) {
                h.session.send("poke".toByteArray())
                runCurrent()
            }
        }

        assertEquals(SessionState.Ended, h.session.state.value)
        assertEquals(listOf(EndReason.HardCapReached), h.ended)
    }

    // -- teardown mapping + the abort invariant -------------------------

    @Test
    fun everyLinkTeardownMapsToTheRightEndReason() = runTest(dispatcher) {
        for ((teardown, expected) in listOf(
            LinkTeardown.PeerDisconnected to EndReason.PeerDisconnected,
            LinkTeardown.AdapterOff to EndReason.PeerDisconnected,
            LinkTeardown.SubscriptionLost to EndReason.PeerDisconnected,
        )) {
            val h = newHarness()
            h.pc.collectIn(backgroundScope)
            h.session.start()
            h.pcLink.failWith(teardown)
            advanceUntilIdle()
            assertEquals("$teardown", SessionState.Ended, h.session.state.value)
            assertEquals("$teardown", listOf(expected), h.ended)
        }
    }

    /**
     * Protects spec 1631310: once ACTIVE, **every** teardown trigger must
     * route through `end()` (`onEnded`, whose owner persists the row), never the
     * handshake `abortHandshake()` path — whose `check` would throw
     * `IllegalStateException` and fail this test if any path regressed.
     */
    @Test
    fun abortIsUnreachableFromActive() = runTest(dispatcher) {
        fun scenario(name: String, trigger: suspend (Harness) -> Unit, expect: EndReason) {
            val h = newHarness(params = SessionParams.validated(30.minutes, 2.minutes, 4.hours))
            h.pc.collectIn(backgroundScope)
            launch {
                h.session.start()
                trigger(h)
            }
            advanceUntilIdle()
            assertEquals(name, SessionState.Ended, h.session.state.value)
            assertEquals(name, listOf(expect), h.ended)
        }

        scenario("link torn", { it.pcLink.failWith(LinkTeardown.PeerDisconnected) }, EndReason.PeerDisconnected)
        scenario("protocol violation link", {
            it.phoneLink.failWith(LinkTeardown.ProtocolViolation(com.ahlyxlabs.conveyance.transport.framing.FramingException.StrayMiddleFrame()))
        }, EndReason.ProtocolViolation)
        scenario("decrypt failure", {
            it.crypto.last!!.failNextDecrypt = true
            it.pc.sendPlaintext("x".toByteArray())
        }, EndReason.ProtocolViolation)
        scenario("explicit kill switch", { it.session.endNow(EndReason.KillSwitch) }, EndReason.KillSwitch)
        scenario("idle expiry", {
            advanceTimeBy(32.minutes.inWholeMilliseconds); runCurrent()
        }, EndReason.IdleTimedOut)
    }

    @Test
    fun endIsIdempotent() = runTest(dispatcher) {
        val h = newHarness()
        h.pc.collectIn(backgroundScope)
        h.session.start()

        h.session.endNow(EndReason.UserEnded)
        h.session.endNow(EndReason.KillSwitch)
        advanceUntilIdle()

        assertEquals(SessionState.Ended, h.session.state.value)
        assertEquals(listOf(EndReason.UserEnded), h.ended)
    }

    @Test
    fun endClosesTheNoiseHandleAndCompletesInbound() = runTest(dispatcher) {
        val h = newHarness()
        h.pc.collectIn(backgroundScope)
        h.session.start()
        val phoneNoise = h.crypto.last!!

        var inboundCompleted = false
        val collector = backgroundScope.launch {
            h.session.inbound.collect { }
            inboundCompleted = true
        }

        h.session.endNow(EndReason.UserEnded)
        advanceUntilIdle()
        collector.join()

        assertTrue(phoneNoise.closed)
        assertTrue(inboundCompleted)
    }
}
