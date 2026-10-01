package com.ahlyxlabs.conveyance.storage.credentials

import androidx.room.Entity
import androidx.room.PrimaryKey

/** Durable marker for the cross-file / Room DEK-wrap migration. */
@Entity(tableName = "credential_wrap_migration")
data class CredentialWrapMigrationEntity(
    @PrimaryKey val singletonId: Int = 1,
    val migrationId: String,
    /** SHA-256 of the exact source identity.enc bytes. */
    val sourceIdentityHash: ByteArray,
    /** Must match the generation in the target identity.enc before promotion. */
    val targetGeneration: ByteArray,
    val targetAuthMethod: String,
    val expectedRows: Int,
)
