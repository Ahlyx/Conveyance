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

    @Query("SELECT service FROM credentials WHERE dekWrapVersion = 1 ORDER BY service ASC")
    suspend fun legacyServices(): List<String>

    @Query("SELECT COUNT(*) FROM credentials WHERE dekWrapVersion = 1")
    suspend fun countLegacyRows(): Int

    @Query("SELECT COUNT(*) FROM credentials")
    suspend fun countRows(): Int

    @Query("SELECT COUNT(*) FROM credentials WHERE pendingMigrationId = :migrationId AND pendingWrappedDek IS NOT NULL")
    suspend fun countStagedRows(migrationId: String): Int

    @Query("UPDATE credentials SET pendingWrappedDek = :wrapped, pendingMigrationId = :migrationId WHERE service = :service AND dekWrapVersion = 1 AND pendingWrappedDek IS NULL")
    suspend fun stageLegacyDek(service: String, migrationId: String, wrapped: ByteArray): Int

    @Query("UPDATE credentials SET wrappedDek = pendingWrappedDek, dekWrapVersion = 2, pendingWrappedDek = NULL, pendingMigrationId = NULL WHERE pendingMigrationId = :migrationId AND pendingWrappedDek IS NOT NULL AND dekWrapVersion = 1")
    suspend fun promoteStagedDeks(migrationId: String): Int

    @Query("UPDATE credentials SET pendingWrappedDek = NULL, pendingMigrationId = NULL WHERE pendingMigrationId = :migrationId")
    suspend fun clearStagedDeks(migrationId: String): Int

    @androidx.room.Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun insertMigration(entity: CredentialWrapMigrationEntity)

    @Query("SELECT * FROM credential_wrap_migration WHERE singletonId = 1")
    suspend fun migration(): CredentialWrapMigrationEntity?

    @Query("DELETE FROM credential_wrap_migration WHERE singletonId = 1 AND migrationId = :migrationId")
    suspend fun deleteMigration(migrationId: String): Int
}
