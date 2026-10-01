package com.ahlyxlabs.conveyance.storage.credentials

import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

/**
 * `credentials.enc` — Room over SQLCipher. The explicit 1→2 migration
 * preserves legacy Keystore-wrapped rows and adds staged wrap metadata.
 */
@Database(
    entities = [CredentialEntity::class, CredentialWrapMigrationEntity::class],
    version = 2,
    exportSchema = false,
)
abstract class CredentialDatabase : RoomDatabase() {
    abstract fun credentialDao(): CredentialDao

    companion object {
        const val FILE_NAME = "credentials.enc"

        val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "ALTER TABLE credentials ADD COLUMN dekWrapVersion INTEGER NOT NULL DEFAULT 1",
                )
                db.execSQL("ALTER TABLE credentials ADD COLUMN pendingWrappedDek BLOB")
                db.execSQL("ALTER TABLE credentials ADD COLUMN pendingMigrationId TEXT")
                db.execSQL(
                    """
                    CREATE TABLE IF NOT EXISTS credential_wrap_migration (
                        singletonId INTEGER NOT NULL PRIMARY KEY,
                        migrationId TEXT NOT NULL,
                        sourceIdentityHash BLOB NOT NULL,
                        targetGeneration BLOB NOT NULL,
                        targetAuthMethod TEXT NOT NULL,
                        expectedRows INTEGER NOT NULL
                    )
                    """.trimIndent(),
                )
            }
        }
    }
}
