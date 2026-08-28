package com.ahlyxlabs.conveyance.storage.log

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * One row of the hash-chained approval log. Schema is the spec's
 * "Logging" table verbatim; column names match so the DB is legible to
 * anyone inspecting it. `hash` is UNIQUE — a duplicate chained hash means
 * a re-inserted row.
 */
@Entity(
    tableName = "entries",
    indices = [
        Index(value = ["hash"], unique = true),
        Index(value = ["req_id"]),
        Index(value = ["timestamp"]),
    ],
)
data class LogEntryEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    @ColumnInfo(name = "req_id") val reqId: ByteArray,
    @ColumnInfo(name = "event_type") val eventType: String,
    @ColumnInfo(name = "payload_json") val payloadJson: String,
    val timestamp: Long,
    @ColumnInfo(name = "prev_hash") val prevHash: ByteArray,
    val hash: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is LogEntryEntity) return false
        return id == other.id &&
            reqId.contentEquals(other.reqId) &&
            eventType == other.eventType &&
            payloadJson == other.payloadJson &&
            timestamp == other.timestamp &&
            prevHash.contentEquals(other.prevHash) &&
            hash.contentEquals(other.hash)
    }

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + reqId.contentHashCode()
        result = 31 * result + eventType.hashCode()
        result = 31 * result + payloadJson.hashCode()
        result = 31 * result + timestamp.hashCode()
        result = 31 * result + prevHash.contentHashCode()
        result = 31 * result + hash.contentHashCode()
        return result
    }
}
