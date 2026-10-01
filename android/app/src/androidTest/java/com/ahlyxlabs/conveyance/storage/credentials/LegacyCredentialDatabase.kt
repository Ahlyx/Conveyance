package com.ahlyxlabs.conveyance.storage.credentials

import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.RoomDatabase

/** Room v1 fixture matching the schema shipped before Phase 10.2c. */
@Entity(tableName = "credentials")
data class LegacyCredentialEntity(
    @PrimaryKey val service: String,
    val secretCiphertext: ByteArray,
    val wrappedDek: ByteArray,
    val createdAt: Long,
)

@Dao
interface LegacyCredentialDao {
    @Insert
    suspend fun insert(row: LegacyCredentialEntity)

    @Query("SELECT * FROM credentials WHERE service = :service")
    suspend fun get(service: String): LegacyCredentialEntity?
}

@Database(entities = [LegacyCredentialEntity::class], version = 1, exportSchema = false)
abstract class LegacyCredentialDatabase : RoomDatabase() {
    abstract fun credentialDao(): LegacyCredentialDao
}
