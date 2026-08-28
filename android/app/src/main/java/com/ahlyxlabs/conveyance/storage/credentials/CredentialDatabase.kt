package com.ahlyxlabs.conveyance.storage.credentials

import androidx.room.Database
import androidx.room.RoomDatabase

/**
 * `credentials.enc` — Room over SQLCipher. exportSchema is off until
 * migrations exist (v1 only); revisit when the schema first changes.
 */
@Database(entities = [CredentialEntity::class], version = 1, exportSchema = false)
abstract class CredentialDatabase : RoomDatabase() {
    abstract fun credentialDao(): CredentialDao

    companion object {
        const val FILE_NAME = "credentials.enc"
    }
}
