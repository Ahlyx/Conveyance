package com.ahlyxlabs.conveyance.storage.pairings

import androidx.room.Database
import androidx.room.RoomDatabase

/** `pairings.db` — paired PC identities and metadata. */
@Database(entities = [PairingEntity::class], version = 1, exportSchema = false)
abstract class PairingsDatabase : RoomDatabase() {
    abstract fun pairingDao(): PairingDao

    companion object {
        const val FILE_NAME = "pairings.db"
    }
}
