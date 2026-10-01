package com.ahlyxlabs.conveyance.session

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ahlyxlabs.conveyance.crypto.RecoveryPhrase
import com.ahlyxlabs.conveyance.crypto.UniffiSealedIdentityCrypto
import com.ahlyxlabs.conveyance.crypto.UnlockedIdentity
import com.ahlyxlabs.conveyance.crypto.X25519PublicKey
import com.ahlyxlabs.conveyance.storage.identity.Tier1AuthMethod
import com.ahlyxlabs.conveyance.storage.identity.UnlockedPhoneSession
import com.ahlyxlabs.conveyance.testutil.hexToBytes
import com.ahlyxlabs.conveyance.transport.framing.Frame
import com.ahlyxlabs.conveyance.transport.framing.InboundAssembler
import com.ahlyxlabs.conveyance.transport.framing.MessageSplitter
import com.ahlyxlabs.conveyance.transport.link.LinkEvent
import com.ahlyxlabs.conveyance.transport.link.LinkTeardown
import com.ahlyxlabs.conveyance.transport.link.LoopbackLink
import com.ahlyxlabs.conveyance.transport.link.PhoneLink
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Composition coverage for the production session path. Unlike the Noise
 * parity tests, this drives [PhoneSession] itself with [UniffiNoiseSessionCrypto]
 * and passes every native Noise message through the real framing/link boundary.
 * The far endpoint is the debug-only native responder used by the existing
 * two-party Noise test; no second cryptographic implementation exists here.
 */
@RunWith(AndroidJUnit4::class)
class PhoneSessionRealNoiseTest {

    private lateinit var fixture: JSONObject

    @Before
    fun loadFixture() {
        val context = InstrumentationRegistry.getInstrumentation().context
        fixture = JSONObject(
            context.assets.open("noise_fixtures.json").bufferedReader().use { it.readText() },
        )
    }

    @Test
    fun realNoiseHandshakeAndTransportComposeThroughPhoneSession() = runBlocking {
        newHarness().useSuspending { h ->
            h.startPc(this)
            h.session.start()

            assertEquals(SessionState.Active, h.session.state.value)
            assertTrue(h.pc.phoneHandshakeFrames.get() > 1)
            assertTrue(h.pc.pcHandshakeFrames.get() > 1)

            val phoneToPc = ByteArray(96) { (it * 17).toByte() }
            h.session.send(phoneToPc)
            assertArrayEquals(phoneToPc, withTimeout(TEST_TIMEOUT_MS) { h.pc.received.receive() })
            assertTrue(h.pc.phoneTransportFrames.get() > 1)

            val pcToPhone = ByteArray(83) { (255 - it * 11).toByte() }
            val inbound = async { h.session.inbound.first() }
            h.pc.sendPlaintext(pcToPhone)
            assertArrayEquals(pcToPhone, withTimeout(TEST_TIMEOUT_MS) { inbound.await() })
            assertTrue(h.pc.pcTransportFrames.get() > 1)

            h.session.endNow(EndReason.UserEnded)
            assertEquals(EndReason.UserEnded, withTimeout(TEST_TIMEOUT_MS) { h.ended.await() })
            assertEquals(SessionState.Ended, h.session.state.value)
            assertTrue(h.phoneNoise.closed.get())
            assertEquals(
                LinkTeardown.PeerDisconnected,
                withTimeout(TEST_TIMEOUT_MS) { h.pc.torn.await() },
            )
        }
    }

    @Test
    fun tamperedNativeCiphertextEndsTheComposedSession() = runBlocking {
        newHarness().useSuspending { h ->
            h.startPc(this)
            h.session.start()
            assertEquals(SessionState.Active, h.session.state.value)

            h.pc.sendTampered("authenticated by the native responder".toByteArray())

            assertEquals(
                EndReason.ProtocolViolation,
                withTimeout(TEST_TIMEOUT_MS) { h.ended.await() },
            )
            assertEquals(SessionState.Ended, h.session.state.value)
            assertTrue(h.phoneNoise.closed.get())
        }
    }

    private fun newHarness(): Harness {
        val sealedCrypto = UniffiSealedIdentityCrypto()
        val sealed = sealedCrypto.createSealedIdentity(
            RecoveryPhrase(ZERO_PHRASE),
            CONTENT_KEY,
        )
        val identity = sealedCrypto.openSealedIdentity(sealed.blob, CONTENT_KEY).getOrThrow()
        val unlockedSession = UnlockedPhoneSession(
            identity = identity,
            authMethod = Tier1AuthMethod.BIOMETRIC,
            generation = ByteArray(16),
            vaultKey = CONTENT_KEY,
        )
        val dispatcher = Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "phone-session-real-noise-test")
        }.asCoroutineDispatcher()
        val (phoneLink, pcLink) = LoopbackLink.pair(Frame.maxFramePayload(23))
        val trackingCrypto = TrackingRealNoiseCrypto()
        val ended = CompletableDeferred<EndReason>()
        val factory = PhoneSessionFactory(dispatcher, trackingCrypto)
        val session = factory.create(
            unlockedSession = unlockedSession,
            pcStaticPublic = X25519PublicKey(pc("x25519_public_hex")),
            link = phoneLink,
            onEnded = { ended.complete(it) },
        )
        val pc = NativePc(
            link = pcLink,
            responder = NoiseTestVectors.respond(
                pc("x25519_secret_hex"),
                identity.x25519PublicKey().bytes,
            ),
        )
        return Harness(unlockedSession, dispatcher, session, trackingCrypto, pc, ended)
    }

    private fun pc(key: String): ByteArray =
        fixture.getJSONObject("pc").getString(key).hexToBytes()

    private class TrackingRealNoiseCrypto : NoiseSessionCrypto {
        private val delegate = UniffiNoiseSessionCrypto()
        lateinit var opened: CloseTrackingNoiseSession
            private set

        override fun initiate(
            identity: UnlockedIdentity,
            pcStaticPublic: X25519PublicKey,
        ): NoiseSession = CloseTrackingNoiseSession(delegate.initiate(identity, pcStaticPublic))
            .also { opened = it }
    }

    private class CloseTrackingNoiseSession(
        private val delegate: NoiseSession,
    ) : NoiseSession by delegate {
        val closed = AtomicBoolean(false)

        override fun close() {
            delegate.close()
            closed.set(true)
        }
    }

    private class NativePc(
        private val link: PhoneLink,
        private val responder: NoiseSession,
    ) : AutoCloseable {
        val received = Channel<ByteArray>(Channel.BUFFERED)
        val torn = CompletableDeferred<LinkTeardown>()
        val phoneHandshakeFrames = AtomicInteger()
        val pcHandshakeFrames = AtomicInteger()
        val phoneTransportFrames = AtomicInteger()
        val pcTransportFrames = AtomicInteger()

        private val assembler = InboundAssembler()
        private var txSeq = 0

        suspend fun collect() {
            link.events.collect { event ->
                when (event) {
                    is LinkEvent.Chunk -> {
                        val handshaking = !responder.isHandshakeComplete()
                        if (handshaking) {
                            phoneHandshakeFrames.incrementAndGet()
                        } else {
                            phoneTransportFrames.incrementAndGet()
                        }
                        for (message in assembler.ingest(event.bytes)) {
                            if (handshaking) {
                                responder.readHandshakeMessage(message)
                                if (responder.needsWrite()) {
                                    sendFramed(
                                        responder.writeHandshakeMessage(),
                                        pcHandshakeFrames,
                                    )
                                }
                            } else {
                                received.send(responder.decrypt(message))
                            }
                        }
                    }
                    is LinkEvent.Torn -> torn.complete(event.reason)
                }
            }
        }

        suspend fun sendPlaintext(plaintext: ByteArray) {
            sendFramed(responder.encrypt(plaintext), pcTransportFrames)
        }

        suspend fun sendTampered(plaintext: ByteArray) {
            val ciphertext = responder.encrypt(plaintext)
            ciphertext[ciphertext.lastIndex] = (ciphertext.last().toInt() xor 0x01).toByte()
            sendFramed(ciphertext, pcTransportFrames)
        }

        private suspend fun sendFramed(message: ByteArray, counter: AtomicInteger) {
            val split = MessageSplitter.split(message, link.maxWriteLen, txSeq)
            txSeq = split.nextSeq
            counter.addAndGet(split.frames.size)
            split.frames.forEach { link.send(it) }
        }

        override fun close() {
            responder.close()
            received.close()
        }
    }

    private class Harness(
        private val unlockedSession: UnlockedPhoneSession,
        private val dispatcher: kotlinx.coroutines.ExecutorCoroutineDispatcher,
        val session: PhoneSession,
        private val crypto: TrackingRealNoiseCrypto,
        val pc: NativePc,
        val ended: CompletableDeferred<EndReason>,
    ) {
        private var pcJob: Job? = null

        val phoneNoise: CloseTrackingNoiseSession
            get() = crypto.opened

        fun startPc(scope: CoroutineScope) {
            pcJob = scope.launch(Dispatchers.Default) { pc.collect() }
        }

        suspend fun close() {
            session.endNow(EndReason.UserEnded)
            withTimeoutOrNull(TEST_TIMEOUT_MS) {
                session.state.first {
                    it == SessionState.NoSession || it == SessionState.Ended
                }
            }
            pcJob?.cancelAndJoin()
            pc.close()
            unlockedSession.close()
            dispatcher.close()
        }
    }

    private suspend inline fun <T> Harness.useSuspending(block: suspend (Harness) -> T): T =
        try {
            block(this)
        } finally {
            close()
        }

    private companion object {
        const val TEST_TIMEOUT_MS = 10_000L
        val CONTENT_KEY = ByteArray(32) { (it + 1).toByte() }
        const val ZERO_PHRASE =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon " +
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon " +
                "abandon abandon abandon abandon abandon art"
    }
}
