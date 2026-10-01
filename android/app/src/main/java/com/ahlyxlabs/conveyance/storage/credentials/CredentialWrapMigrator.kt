package com.ahlyxlabs.conveyance.storage.credentials

import androidx.room.withTransaction
import java.security.MessageDigest
import javax.inject.Inject
import javax.inject.Singleton

/** A legacy DEK unwrap needs the legacy authenticator for each row. */
fun interface LegacyDekUnwrapper {
    suspend fun unwrap(row: CredentialEntity): ByteArray
}

class CredentialWrapMigrationException(message: String, cause: Throwable? = null) :
    Exception(message, cause)

/** Journaled v1-Keystore to v2-vault-key credential wrapping migration. */
@Singleton
class CredentialWrapMigrator @Inject constructor(
    private val database: CredentialDatabase,
    private val dao: CredentialDao,
    private val envelope: CredentialDekEnvelope,
    private val accessLock: CredentialAccessLock,
) {
    suspend fun pending(): CredentialWrapMigrationEntity? = dao.migration()

    suspend fun legacyRowCount(): Int = accessLock.withLock { dao.countLegacyRows() }

    suspend fun legacyRowCountUnlocked(): Int = dao.countLegacyRows()

    suspend fun credentialRowCountUnlocked(): Int = dao.countRows()

    suspend fun <T> withMigrationLock(block: suspend () -> T): T = accessLock.withLock(block)

    /**
     * Stage a new wrapper for every legacy DEK without changing the live
     * wrapper. Safe to retry after interruption: rows staged by the same
     * migration id are skipped, while unexpected pending values fail closed.
     */
    suspend fun stageLegacyRows(
        migration: CredentialWrapMigrationEntity,
        vaultKey: ByteArray,
        unwrapLegacy: LegacyDekUnwrapper,
        onProgress: suspend (completed: Int, total: Int) -> Unit = { _, _ -> },
    ) = accessLock.withLock {
        stageLegacyRowsUnlocked(migration, vaultKey, unwrapLegacy, onProgress)
    }

    suspend fun stageLegacyRowsUnlocked(
        migration: CredentialWrapMigrationEntity,
        vaultKey: ByteArray,
        unwrapLegacy: LegacyDekUnwrapper,
        onProgress: suspend (completed: Int, total: Int) -> Unit = { _, _ -> },
    ) {
        require(migration.singletonId == SINGLETON_ID)
        require(migration.sourceIdentityHash.size == HASH_LEN)
        require(migration.targetGeneration.size == GENERATION_LEN)
        require(migration.expectedRows >= 0)
        val active = dao.migration()
        if (active == null) {
            database.withTransaction { dao.insertMigration(migration.copyBytes()) }
        } else if (!active.sameMigration(migration)) {
            throw CredentialWrapMigrationException("a different credential migration is pending")
        }

        val services = dao.legacyServices()
        if (services.size != migration.expectedRows || dao.countRows() != migration.expectedRows) {
            throw CredentialWrapMigrationException("credential set changed during migration")
        }

        var completed = dao.countStagedRows(migration.migrationId)
        onProgress(completed, migration.expectedRows)
        for (service in services) {
            val row = dao.get(service)
                ?: throw CredentialWrapMigrationException("credential disappeared during migration")
            if (row.pendingMigrationId == migration.migrationId && row.pendingWrappedDek != null) {
                continue
            }
            if (row.pendingMigrationId != null || row.pendingWrappedDek != null) {
                throw CredentialWrapMigrationException("credential has an unrelated pending wrap")
            }
            if (row.dekWrapVersion != CredentialEntity.LEGACY_DEK_WRAP_VERSION) {
                throw CredentialWrapMigrationException("credential wrap version changed during migration")
            }

            val dek = unwrapLegacy.unwrap(row)
            val wrapped = try {
                envelope.wrap(service, dek, vaultKey)
            } finally {
                dek.fill(0)
            }
            val staged = try {
                dao.stageLegacyDek(service, migration.migrationId, wrapped)
            } finally {
                wrapped.fill(0)
            }
            if (staged != 1) {
                val latest = dao.get(service)
                if (latest?.pendingMigrationId != migration.migrationId ||
                    latest.pendingWrappedDek == null
                ) {
                    throw CredentialWrapMigrationException("could not stage credential wrap")
                }
            } else {
                completed++
                onProgress(completed, migration.expectedRows)
            }
        }

        if (dao.countRows() != migration.expectedRows ||
            dao.countLegacyRows() != migration.expectedRows ||
            dao.countStagedRows(migration.migrationId) != migration.expectedRows
        ) {
            throw CredentialWrapMigrationException("credential migration staging is incomplete")
        }
    }

    /**
     * Promote all staged wraps and remove the journal in one Room
     * transaction. The caller must first verify that identity.enc contains
     * [migration]'s target generation.
     */
    suspend fun promote(migration: CredentialWrapMigrationEntity) = accessLock.withLock {
        promoteUnlocked(migration)
    }

    suspend fun promoteUnlocked(migration: CredentialWrapMigrationEntity) {
        database.withTransaction {
            val active = dao.migration()
                ?: return@withTransaction
            if (!active.sameMigration(migration)) {
                throw CredentialWrapMigrationException("credential migration journal changed")
            }
            val stagedCount = dao.countStagedRows(migration.migrationId)
            val legacyCount = dao.countLegacyRows()
            if (stagedCount != migration.expectedRows ||
                legacyCount != migration.expectedRows ||
                dao.countRows() != migration.expectedRows
            ) {
                throw CredentialWrapMigrationException("credential migration is not ready to commit")
            }
            dao.promoteStagedDeks(migration.migrationId)
            if (dao.countLegacyRows() != 0) {
                throw CredentialWrapMigrationException("credential promotion was incomplete")
            }
            if (dao.deleteMigration(migration.migrationId) != 1) {
                throw CredentialWrapMigrationException("could not clear credential migration journal")
            }
        }
    }

    /** Discard pre-commit staging while the source identity is still active. */
    suspend fun discardBeforeIdentityCommit(
        migration: CredentialWrapMigrationEntity,
        activeIdentityHash: ByteArray,
    ) = accessLock.withLock {
        discardBeforeIdentityCommitUnlocked(migration, activeIdentityHash)
    }

    suspend fun discardBeforeIdentityCommitUnlocked(
        migration: CredentialWrapMigrationEntity,
        activeIdentityHash: ByteArray,
    ) {
        if (!MessageDigest.isEqual(migration.sourceIdentityHash, activeIdentityHash)) {
            throw CredentialWrapMigrationException("cannot discard staging for a different identity file")
        }
        database.withTransaction {
            val active = dao.migration() ?: return@withTransaction
            if (!active.sameMigration(migration)) {
                throw CredentialWrapMigrationException("credential migration journal changed")
            }
            dao.clearStagedDeks(migration.migrationId)
            if (dao.deleteMigration(migration.migrationId) != 1) {
                throw CredentialWrapMigrationException("could not clear credential migration journal")
            }
        }
    }

    private fun CredentialWrapMigrationEntity.copyBytes() = copy(
        sourceIdentityHash = sourceIdentityHash.copyOf(),
        targetGeneration = targetGeneration.copyOf(),
    )

    private fun CredentialWrapMigrationEntity.sameMigration(other: CredentialWrapMigrationEntity) =
        singletonId == other.singletonId &&
            migrationId == other.migrationId &&
            MessageDigest.isEqual(sourceIdentityHash, other.sourceIdentityHash) &&
            MessageDigest.isEqual(targetGeneration, other.targetGeneration) &&
            targetAuthMethod == other.targetAuthMethod &&
            expectedRows == other.expectedRows

    private companion object {
        const val SINGLETON_ID = 1
        const val HASH_LEN = 32
        const val GENERATION_LEN = 16
    }
}
