package com.ahlyxlabs.conveyance.storage.log

import androidx.room.Database
import androidx.room.RoomDatabase

/** `approvals.db` — the phone-authoritative hash-chained approval log. */
@Database(entities = [LogEntryEntity::class], version = 1, exportSchema = false)
abstract class ApprovalDatabase : RoomDatabase() {
    abstract fun logDao(): LogDao

    companion object {
        const val FILE_NAME = "approvals.db"
    }
}
