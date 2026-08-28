package com.ahlyxlabs.conveyance.storage.pairings

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query

@Dao
interface PairingDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(entity: PairingEntity)

    @Query("SELECT * FROM pairings WHERE pc_id_pub = :pcIdPub")
    suspend fun get(pcIdPub: ByteArray): PairingEntity?

    @Query("SELECT * FROM pairings ORDER BY first_paired_at ASC")
    suspend fun all(): List<PairingEntity>

    @Query("DELETE FROM pairings WHERE pc_id_pub = :pcIdPub")
    suspend fun delete(pcIdPub: ByteArray): Int

    @Query("UPDATE pairings SET last_session_at = :timestamp WHERE pc_id_pub = :pcIdPub")
    suspend fun touchLastSession(pcIdPub: ByteArray, timestamp: Long): Int
}
