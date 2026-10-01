package com.ahlyxlabs.conveyance.storage.log

import com.ahlyxlabs.conveyance.approval.ApprovalDestination
import com.ahlyxlabs.conveyance.crypto.ChainRow
import com.ahlyxlabs.conveyance.crypto.ChainVerification
import com.ahlyxlabs.conveyance.crypto.ConveyanceCrypto
import com.ahlyxlabs.conveyance.crypto.LogEvent
import com.ahlyxlabs.conveyance.crypto.SigningContext
import com.ahlyxlabs.conveyance.crypto.UnlockedIdentity
import androidx.room.withTransaction
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONObject

/**
 * The phone-authoritative approval log (spec "Logging"): every row
 * carries `SHA256(prev_hash || event_content_json(event))`, so any
 * alteration, removal, or reorder of an interior row is detectable.
 *
 * [append] serializes on a mutex — the single-writer discipline auditmcp
 * uses — so concurrent approvals still produce one valid chain.
 * [exportJsonl] emits the format `conveyance log diff` parses: one signed
 * JSON object per line, keyed by `req_id`.
 */
@Singleton
class ApprovalLog @Inject constructor(
    private val database: ApprovalDatabase,
    private val crypto: ConveyanceCrypto,
) {
    private val dao get() = database.logDao()
    private val writeLock = Mutex()

    /** Append one event; returns the new chain-head hash. */
    suspend fun append(
        reqId: ByteArray,
        eventType: String,
        payloadJson: String,
        timestamp: Long,
    ): ByteArray = writeLock.withLock {
        database.withTransaction {
            appendUnlocked(reqId, eventType, payloadJson, timestamp)
        }
    }

    /**
     * Stage the terminal row, run a final synchronous authorization/signing
     * hook, and commit the append atomically. If the hook rejects because the
     * deadline/session changed, Room rolls the row back. The callback must not
     * suspend: the approval's final deadline check must be adjacent to signing.
     */
    suspend fun <T> appendWithBeforeCommit(
        reqId: ByteArray,
        eventType: String,
        payloadJson: String,
        timestamp: Long,
        beforeCommit: () -> T,
    ): T = writeLock.withLock {
        database.withTransaction {
            appendUnlocked(reqId, eventType, payloadJson, timestamp)
            beforeCommit()
        }
    }

    private suspend fun appendUnlocked(
        reqId: ByteArray,
        eventType: String,
        payloadJson: String,
        timestamp: Long,
    ): ByteArray {
        val prev = dao.lastHash() ?: crypto.genesisPrevHash()
        val event = LogEvent(reqId, eventType, payloadJson, timestamp)
        val hash = crypto.rowHash(prev, event)
        dao.insert(
            LogEntryEntity(
                reqId = reqId,
                eventType = eventType,
                payloadJson = payloadJson,
                timestamp = timestamp,
                prevHash = prev,
                hash = hash,
            ),
        )
        return hash
    }

    suspend fun count(): Int = dao.count()

    /**
     * Exact `(service, endpoint)` pairs from the last successful approvals,
     * newest first. The caller applies the protocol's 30-row policy window.
     * Malformed old payloads are omitted, which can only make a destination
     * novel and require stronger authentication.
     */
    suspend fun successfulDestinationsNewestFirst(limit: Int): List<ApprovalDestination> =
        dao.latestByEventType(EVENT_APPROVAL_GRANTED, limit).mapNotNull { row ->
            runCatching {
                val json = JSONObject(row.payloadJson)
                val service = json.opt("service") as? String ?: return@mapNotNull null
                val endpoint = json.opt("endpoint") as? String ?: return@mapNotNull null
                ApprovalDestination(service, endpoint)
            }.getOrNull()
        }

    /** Walk the whole chain. */
    suspend fun verify(): ChainVerification =
        crypto.verifyChain(
            dao.allOrdered().map { row ->
                ChainRow(
                    event = LogEvent(row.reqId, row.eventType, row.payloadJson, row.timestamp),
                    prevHash = row.prevHash,
                    hash = row.hash,
                )
            },
        )

    /**
     * Export every row as newline-delimited JSON for `conveyance log diff`.
     * Each line is `{req_id, event_type, payload_json, timestamp, signature}`;
     * `signature` is Ed25519 by [signer] over
     * `"conveyance-phone-log-v1" || event_content_json(row)`. Unsigned
     * rows are never emitted — every row is signed here.
     */
    suspend fun exportJsonl(signer: UnlockedIdentity): String =
        dao.allOrdered().joinToString("\n") { row ->
            val event = LogEvent(row.reqId, row.eventType, row.payloadJson, row.timestamp)
            val payload = crypto.signingPayload(SigningContext.PHONE_LOG, crypto.eventContentJson(event))
            val signature = signer.sign(payload)
            JSONObject()
                .put("req_id", row.reqId.toHex())
                .put("event_type", row.eventType)
                .put("payload_json", row.payloadJson)
                .put("timestamp", row.timestamp)
                .put("signature", signature.bytes.toHex())
                .toString()
        }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xFF) }

    private companion object {
        const val EVENT_APPROVAL_GRANTED = "approval_granted"
    }
}
