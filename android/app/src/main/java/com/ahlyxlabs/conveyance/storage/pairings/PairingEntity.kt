package com.ahlyxlabs.conveyance.storage.pairings

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * A paired PC (spec "Storage layout / Phone side / pairings.db"). This
 * sub-phase provides the schema and DAO only — the pairing ceremony that
 * writes these rows is Phase 10.5.
 */
@Entity(tableName = "pairings")
data class PairingEntity(
    /** The PC's long-term Ed25519 identity public key (32 bytes). */
    @PrimaryKey @ColumnInfo(name = "pc_id_pub") val pcIdPub: ByteArray,
    /** The PC's long-term X25519 static public key (32 bytes). */
    @ColumnInfo(name = "pc_dh_pub") val pcDhPub: ByteArray,
    @ColumnInfo(name = "pc_name") val pcName: String,
    @ColumnInfo(name = "first_paired_at") val firstPairedAt: Long,
    @ColumnInfo(name = "last_session_at") val lastSessionAt: Long? = null,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PairingEntity) return false
        return pcIdPub.contentEquals(other.pcIdPub) &&
            pcDhPub.contentEquals(other.pcDhPub) &&
            pcName == other.pcName &&
            firstPairedAt == other.firstPairedAt &&
            lastSessionAt == other.lastSessionAt
    }

    override fun hashCode(): Int {
        var result = pcIdPub.contentHashCode()
        result = 31 * result + pcDhPub.contentHashCode()
        result = 31 * result + pcName.hashCode()
        result = 31 * result + firstPairedAt.hashCode()
        result = 31 * result + (lastSessionAt?.hashCode() ?: 0)
        return result
    }
}
