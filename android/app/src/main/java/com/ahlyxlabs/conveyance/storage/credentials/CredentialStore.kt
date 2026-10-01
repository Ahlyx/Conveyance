package com.ahlyxlabs.conveyance.storage.credentials

import com.ahlyxlabs.conveyance.crypto.SealedIdentityCrypto
import com.ahlyxlabs.conveyance.storage.SecretBytes
import com.ahlyxlabs.conveyance.storage.identity.UnlockedPhoneSession
import javax.inject.Inject
import javax.inject.Singleton

/** Failures the credential store reports. */
sealed class CredentialException(message: String, cause: Throwable? = null) :
    Exception(message, cause) {

    class NotFound(service: String) : CredentialException("no credential stored for '$service'")

    class Undecryptable(service: String, cause: Throwable? = null) :
        CredentialException("the credential for '$service' will not decrypt", cause)

    class MigrationRequired : CredentialException("credential storage migration is not complete")
}

/**
 * Stores each service secret under its own random DEK. The DEK is
 * encrypted under the unlocked vault key through the shared Rust AEAD
 * primitive. A single Tier 1 session unlocks identity and credential
 * storage; rows are still opened one at a time.
 */
@Singleton
class CredentialStore @Inject constructor(
    private val dao: CredentialDao,
    private val sealed: SealedIdentityCrypto,
    private val envelope: CredentialDekEnvelope,
    private val accessLock: CredentialAccessLock,
) {
    suspend fun add(service: String, secret: ByteArray, session: UnlockedPhoneSession) =
        accessLock.withLock {
            ensureNoMigration()
            val dek = ByteArray(32).also(java.security.SecureRandom()::nextBytes)
            try {
                val ciphertext = sealed.sealCredential(secret, dek)
                val wrappedDek = session.withVaultKey { vaultKey ->
                    envelope.wrap(service, dek, vaultKey)
                }
                dao.upsert(
                    CredentialEntity(
                        service = service,
                        secretCiphertext = ciphertext,
                        wrappedDek = wrappedDek,
                        createdAt = System.currentTimeMillis() / 1000,
                        dekWrapVersion = CredentialEntity.VAULT_DEK_WRAP_VERSION,
                    ),
                )
            } finally {
                dek.fill(0)
            }
        }

    suspend fun listServices(): List<String> = accessLock.withLock { dao.listServices() }

    /** @return true if a row was removed. */
    suspend fun remove(service: String): Boolean = accessLock.withLock {
        ensureNoMigration()
        dao.delete(service) > 0
    }

    /** Opens one credential row. The returned [SecretBytes] is the caller's to close. */
    suspend fun open(service: String, session: UnlockedPhoneSession): Result<SecretBytes> =
        accessLock.withLock {
            try {
                ensureNoMigration()
                val row = dao.get(service)
                    ?: return@withLock Result.failure(CredentialException.NotFound(service))
                if (row.dekWrapVersion != CredentialEntity.VAULT_DEK_WRAP_VERSION) {
                    return@withLock Result.failure(CredentialException.MigrationRequired())
                }

                val dek = session.withVaultKey { vaultKey ->
                    envelope.unwrap(service, row.wrappedDek, vaultKey).getOrThrow()
                }
                try {
                    sealed.openCredential(row.secretCiphertext, dek)
                        .map { plaintext ->
                            SecretBytes(plaintext).also { plaintext.fill(0) }
                        }
                        .recoverCatching { throw CredentialException.Undecryptable(service, it) }
                } finally {
                    dek.fill(0)
                }
            } catch (error: CredentialException) {
                Result.failure(error)
            } catch (error: Exception) {
                Result.failure(CredentialException.Undecryptable(service, error))
            }
        }

    private suspend fun ensureNoMigration() {
        if (dao.migration() != null) throw CredentialException.MigrationRequired()
    }
}
