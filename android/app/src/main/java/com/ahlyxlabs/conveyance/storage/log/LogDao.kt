package com.ahlyxlabs.conveyance.storage.log

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query

@Dao
interface LogDao {
    @Insert
    suspend fun insert(entry: LogEntryEntity): Long

    /** The head of the chain, or null for an empty log. */
    @Query("SELECT hash FROM entries ORDER BY id DESC LIMIT 1")
    suspend fun lastHash(): ByteArray?

    @Query("SELECT * FROM entries ORDER BY id ASC")
    suspend fun allOrdered(): List<LogEntryEntity>

    @Query("SELECT COUNT(*) FROM entries")
    suspend fun count(): Int
}
