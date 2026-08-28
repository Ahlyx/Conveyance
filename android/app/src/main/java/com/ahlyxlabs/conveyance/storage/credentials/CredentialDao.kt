package com.ahlyxlabs.conveyance.storage.credentials

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query

@Dao
interface CredentialDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(entity: CredentialEntity)

    /** Names only — no secret material, never requires a Tier 1 auth. */
    @Query("SELECT service FROM credentials ORDER BY service ASC")
    suspend fun listServices(): List<String>

    /** Exactly one row — the store never reads the table in bulk. */
    @Query("SELECT * FROM credentials WHERE service = :service")
    suspend fun get(service: String): CredentialEntity?

    @Query("DELETE FROM credentials WHERE service = :service")
    suspend fun delete(service: String): Int
}
