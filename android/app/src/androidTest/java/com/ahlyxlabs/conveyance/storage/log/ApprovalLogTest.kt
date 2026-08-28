package com.ahlyxlabs.conveyance.storage.log

import android.content.Context
import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ahlyxlabs.conveyance.crypto.ChainBreak
import com.ahlyxlabs.conveyance.crypto.ChainVerification
import com.ahlyxlabs.conveyance.crypto.ConveyanceCrypto
import com.ahlyxlabs.conveyance.crypto.Ed25519PublicKey
import com.ahlyxlabs.conveyance.crypto.Ed25519Signature
import com.ahlyxlabs.conveyance.crypto.LogEvent
import com.ahlyxlabs.conveyance.crypto.RecoveryPhrase
import com.ahlyxlabs.conveyance.crypto.SigningContext
import com.ahlyxlabs.conveyance.crypto.UniffiConveyanceCrypto
import com.ahlyxlabs.conveyance.crypto.UniffiSealedIdentityCrypto
import com.ahlyxlabs.conveyance.storage.db.SqlCipherFactory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ApprovalLogTest {

    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private val crypto: ConveyanceCrypto = UniffiConveyanceCrypto()
    private val dbName = "approvals-test.db"
    private val passphrase = ByteArray(32) { (it + 7).toByte() }

    private lateinit var db: ApprovalDatabase
    private lateinit var log: ApprovalLog

    @Before
    fun setUp() {
        context.getDatabasePath(dbName).also { it.parentFile?.mkdirs(); it.delete() }
        db = Room.databaseBuilder(context, ApprovalDatabase::class.java, dbName)
            .openHelperFactory(SqlCipherFactory.create(passphrase.copyOf()))
            .build()
        log = ApprovalLog(db.logDao(), crypto)
    }

    @After
    fun tearDown() {
        if (::db.isInitialized) db.close()
        context.getDatabasePath(dbName).delete()
    }

    private suspend fun appendN(n: Int) {
        for (i in 1..n) {
            log.append(
                reqId = ByteArray(16) { i.toByte() },
                eventType = "approval_granted",
                payloadJson = """{"decision":"approved","n":$i}""",
                timestamp = 1_700_000_000L + i,
            )
        }
    }

    @Test
    fun appendBuildsAVerifiableChain() = runBlocking {
        appendN(5)
        assertEquals(5, log.count())
        when (val v = log.verify()) {
            is ChainVerification.Intact -> assertEquals(5L, v.verifiedRows)
            else -> throw AssertionError("expected Intact, got $v")
        }
    }

    @Test
    fun tamperedRowIsContentTampered() = runBlocking {
        appendN(4)
        // Alter row 3 (id 3) directly, bypassing append's chaining.
        db.openHelper.writableDatabase.execSQL(
            "UPDATE entries SET payload_json = ? WHERE id = ?",
            arrayOf("""{"decision":"approved","n":999}""", 3),
        )
        val v = log.verify()
        v as? ChainVerification.Broken ?: throw AssertionError("expected Broken, got $v")
        assertEquals(2L, v.index) // zero-based: the 3rd row
        assertTrue(v.reason is ChainBreak.ContentTampered)
    }

    @Test
    fun removedInteriorRowIsLinkBroken() = runBlocking {
        appendN(4)
        db.openHelper.writableDatabase.execSQL("DELETE FROM entries WHERE id = 2")
        val v = log.verify()
        v as? ChainVerification.Broken ?: throw AssertionError("expected Broken, got $v")
        assertEquals(1L, v.index)
        assertTrue(v.reason is ChainBreak.LinkBroken)
    }

    @Test
    fun concurrentAppendsSerializeToOneValidChain() = runBlocking {
        val n = 25
        withContext(Dispatchers.Default) {
            (1..n).map { i ->
                async {
                    log.append(
                        reqId = ByteArray(16) { i.toByte() },
                        eventType = "approval_granted",
                        payloadJson = """{"n":$i}""",
                        timestamp = 1_700_000_000L + i,
                    )
                }
            }.awaitAll()
        }

        assertEquals(n, log.count())
        when (val v = log.verify()) {
            is ChainVerification.Intact -> assertEquals(n.toLong(), v.verifiedRows)
            else -> throw AssertionError("expected Intact after concurrent appends, got $v")
        }
        // All chain hashes distinct (also enforced by the UNIQUE index).
        val rows = db.logDao().allOrdered()
        assertEquals(n, rows.map { it.hash.toList() }.toSet().size)
    }

    @Test
    fun exportJsonlEmitsOneSignedLinePerRowThatVerifies() = runBlocking {
        appendN(3)

        val zeros = "abandon abandon abandon abandon abandon abandon abandon abandon abandon " +
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon " +
            "abandon abandon abandon abandon abandon art"
        val sealedCrypto = UniffiSealedIdentityCrypto()
        val contentKey = ByteArray(32) { 0x33 }
        val sealed = sealedCrypto.createSealedIdentity(RecoveryPhrase(zeros), contentKey)

        val jsonl = sealedCrypto.openSealedIdentity(sealed.blob, contentKey).getOrThrow().use { id ->
            log.exportJsonl(id)
        }

        val lines = jsonl.split("\n")
        assertEquals(3, lines.size)
        val pub = Ed25519PublicKey(sealed.ed25519Public.bytes)
        lines.forEach { line ->
            val o = JSONObject(line)
            val event = LogEvent(
                reqId = o.getString("req_id").hexToBytes(),
                eventType = o.getString("event_type"),
                payloadJson = o.getString("payload_json"),
                timestamp = o.getLong("timestamp"),
            )
            val payload = crypto.signingPayload(SigningContext.PHONE_LOG, crypto.eventContentJson(event))
            val sig = Ed25519Signature(o.getString("signature").hexToBytes())
            assertTrue("row signature must verify", crypto.verify(pub, payload, sig).isSuccess)
        }
    }

    @Test
    fun emptyLogVerifiesAsIntactZero() = runBlocking {
        val v = log.verify()
        v as? ChainVerification.Intact ?: throw AssertionError("expected Intact, got $v")
        assertEquals(0L, v.verifiedRows)
        assertNotEquals(0, crypto.genesisPrevHash().size)
    }

    private fun String.hexToBytes(): ByteArray =
        ByteArray(length / 2) { substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
