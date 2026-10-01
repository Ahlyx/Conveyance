package com.ahlyxlabs.conveyance.pairing

import android.content.Context
import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ahlyxlabs.conveyance.crypto.RecoveryPhrase
import com.ahlyxlabs.conveyance.storage.FakeBiometricGate
import com.ahlyxlabs.conveyance.storage.IdentityStorageFixture
import com.ahlyxlabs.conveyance.storage.db.SqlCipherFactory
import com.ahlyxlabs.conveyance.storage.identity.Tier1AuthInput
import com.ahlyxlabs.conveyance.storage.identity.UnlockedPhoneSession
import com.ahlyxlabs.conveyance.storage.pairings.PairingEntity
import com.ahlyxlabs.conveyance.storage.pairings.PairingStore
import com.ahlyxlabs.conveyance.storage.pairings.PairingsDatabase
import com.ahlyxlabs.conveyance.transport.framing.InboundAssembler
import com.ahlyxlabs.conveyance.transport.framing.MessageSplitter
import com.ahlyxlabs.conveyance.transport.link.LinkEvent
import com.ahlyxlabs.conveyance.transport.link.PhoneLink
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.runBlocking
import java.io.File
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** Exercises the production coordinator around the shared protocol boundary. */
@RunWith(AndroidJUnit4::class)
class PairingCoordinatorTest {

    private val context: Context =
        InstrumentationRegistry.getInstrumentation().targetContext
    private val databaseName = "pairing-coordinator-test.db"
    private val databaseKey = ByteArray(32) { (it + 29).toByte() }
    private val pcIdPub = ByteArray(32) { (it + 1).toByte() }
    private val pcDhPub = ByteArray(32) { (it + 33).toByte() }
    private val expectedConfirm = ByteArray(91) { (it + 5).toByte() }
    private val expectedAck = ByteArray(103) { (it + 80).toByte() }

    private lateinit var database: PairingsDatabase
    private lateinit var store: PairingStore
    private lateinit var identityFixture: IdentityStorageFixture
    private lateinit var session: UnlockedPhoneSession

    @Before
    fun setUp() {
        runBlocking {
            context.getDatabasePath(databaseName).also {
                it.parentFile?.mkdirs()
                it.delete()
            }
            database = Room.databaseBuilder(context, PairingsDatabase::class.java, databaseName)
                .openHelperFactory(SqlCipherFactory.create(databaseKey.copyOf()))
                .build()
            store = PairingStore(database.pairingDao())

            identityFixture = IdentityStorageFixture(context)
            File(context.filesDir, "identity.enc").delete()
            identityFixture.vault.createFromPhrase(
                RecoveryPhrase(TEST_PHRASE),
                Tier1AuthInput.Biometric(FakeBiometricGate()),
            )
            session = identityFixture.vault.unlock(
                Tier1AuthInput.Biometric(FakeBiometricGate()),
            ).getOrThrow()
        }
    }

    @After
    fun tearDown() {
        if (::database.isInitialized) database.close()
        context.getDatabasePath(databaseName).delete()
        if (::session.isInitialized) session.close()
        if (::identityFixture.isInitialized) identityFixture.close()
    }

    @Test
    fun savesOnlyAfterAckVerificationAndPreservesRePairHistory() = runBlocking {
        val previous = PairingEntity(
            pcIdPub = pcIdPub,
            pcDhPub = ByteArray(32) { 7 },
            pcName = "old-name",
            firstPairedAt = 1_700_000_010,
            lastSessionAt = 1_800_000_010,
        )
        store.save(previous)

        val protocol = TestPairingProtocol(store, expectedAck, acceptsAck = true)
        val link = TestPhoneLink(expectedAck)
        val radio = TestPairingRadio(link)
        val paired = coordinator(protocol, radio).pair(
            encodedQr = "test-qr",
            session = session,
        )

        assertTrue(protocol.ackVerified)
        assertEquals(previous, protocol.rowAtVerification)
        assertEquals(previous.firstPairedAt, paired.firstPairedAt)
        assertEquals(previous.lastSessionAt, paired.lastSessionAt)
        assertEquals("new-pc", paired.pcName)
        assertArrayEquals(pcIdPub, paired.pcIdPub)
        assertArrayEquals(pcDhPub, paired.pcDhPub)
        assertEquals(paired, store.get(pcIdPub))
        assertEquals(4, link.sentFrames.size)
        assertTrue(link.sentFrames.all { it.size <= link.maxWriteLen + 6 })
        val confirmAssembler = InboundAssembler()
        val confirms = link.sentFrames.flatMap(confirmAssembler::ingest)
        assertEquals(1, confirms.size)
        assertArrayEquals(expectedConfirm, confirms.single())
        assertTrue(link.wasShutdown)
        assertTrue(radio.wasStopped)
    }

    @Test
    fun invalidAckDoesNotCreateOrReplacePairing() = runBlocking {
        val protocol = TestPairingProtocol(store, expectedAck, acceptsAck = false)
        val prior = PairingEntity(
            pcIdPub = pcIdPub,
            pcDhPub = ByteArray(32) { 9 },
            pcName = "existing-pc",
            firstPairedAt = 1_700_000_020,
            lastSessionAt = 1_800_000_020,
        )
        store.save(prior)
        val radio = TestPairingRadio(TestPhoneLink(expectedAck))

        val result = runCatching {
            coordinator(protocol, radio).pair("test-qr", session)
        }

        assertTrue(result.exceptionOrNull() is PairingProtocolException)
        assertFalse(protocol.ackVerified)
        assertEquals(prior, protocol.rowAtVerification)
        assertEquals(prior, store.get(pcIdPub))
    }

    private fun coordinator(protocol: PairingProtocol, radio: PairingRadio) =
        PairingCoordinator(protocol, store, radio)

    private inner class TestPairingProtocol(
        private val pairings: PairingStore,
        private val ack: ByteArray,
        private val acceptsAck: Boolean,
    ) : PairingProtocol {
        var ackVerified = false
            private set
        var rowAtVerification: PairingEntity? = null
            private set

        override fun parse(encoded: String, nowUnixSeconds: Long): PairingRequest =
            object : PairingRequest {
                override val pcName = "new-pc"
                override val pcIdPub = this@PairingCoordinatorTest.pcIdPub.copyOf()
                override val pcDhPub = this@PairingCoordinatorTest.pcDhPub.copyOf()
                override val expires = nowUnixSeconds + 60

                override fun createConfirm(identity: com.ahlyxlabs.conveyance.crypto.UnlockedIdentity) =
                    PairingConfirmData(
                        phoneIdPub = identity.ed25519PublicKey().bytes,
                        phoneDhPub = identity.x25519PublicKey().bytes,
                        wireMessage = expectedConfirm,
                    )

                override fun verifyAck(wireMessage: ByteArray) {
                    rowAtVerification = runBlocking { pairings.get(pcIdPub) }
                    if (!wireMessage.contentEquals(ack) || !acceptsAck) {
                        throw PairingProtocolException(PairingProtocolException.Kind.FAILED)
                    }
                    ackVerified = true
                }
            }
    }

    private class TestPairingRadio(private val link: TestPhoneLink) : PairingRadio {
        var wasStopped = false
            private set

        override suspend fun connect(timeoutMillis: Long): PhoneLink = link

        override fun stop() {
            wasStopped = true
        }
    }

    private class TestPhoneLink(ack: ByteArray) : PhoneLink {
        override val maxWriteLen = 24
        val sentFrames = mutableListOf<ByteArray>()
        var wasShutdown = false
            private set

        private val ackFrames = MessageSplitter.split(ack, maxWriteLen, startSeq = 0).frames
        override val events: Flow<LinkEvent> = flow {
            ackFrames.forEach { emit(LinkEvent.Chunk(it)) }
        }

        override suspend fun send(chunk: ByteArray) {
            require(chunk.size <= maxWriteLen + 6)
            sentFrames += chunk.copyOf()
        }

        override fun shutdown() {
            wasShutdown = true
        }
    }

    private companion object {
        const val TEST_PHRASE =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon " +
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon " +
                "abandon abandon abandon abandon abandon art"
    }
}
