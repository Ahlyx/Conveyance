package com.ahlyxlabs.conveyance.storage.identity

import android.content.Context
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.util.AtomicFile
import com.ahlyxlabs.conveyance.crypto.Ed25519PublicKey
import com.ahlyxlabs.conveyance.crypto.RecoveryPhrase
import com.ahlyxlabs.conveyance.crypto.SealedIdentityCrypto
import com.ahlyxlabs.conveyance.crypto.UnlockedIdentity
import com.ahlyxlabs.conveyance.crypto.X25519PublicKey
import com.ahlyxlabs.conveyance.storage.credentials.CredentialEntity
import com.ahlyxlabs.conveyance.storage.credentials.CredentialWrapMigrationEntity
import com.ahlyxlabs.conveyance.storage.credentials.CredentialWrapMigrationException
import com.ahlyxlabs.conveyance.storage.credentials.CredentialWrapMigrator
import com.ahlyxlabs.conveyance.storage.credentials.LegacyDekUnwrapper
import com.ahlyxlabs.conveyance.storage.keystore.AuthPurpose
import com.ahlyxlabs.conveyance.storage.keystore.BiometricAuthException
import com.ahlyxlabs.conveyance.storage.keystore.WrappedKey
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** The two long-term identity public keys. Safe to hold and display. */
data class IdentityPublicKeys(
    val ed25519: Ed25519PublicKey,
    val x25519: X25519PublicKey,
)

/**
 * Owns `identity.enc`, vault-key unlock, and legacy credential-wrap
 * migration. Identity scalars are always opened into the Rust-owned
 * [UnlockedIdentity] handle. Only the random vault key crosses the JVM/FFI
 * boundary, and it is held in [UnlockedPhoneSession] as zeroizable bytes.
 */
@Singleton
class IdentityVault @Inject constructor(
    @ApplicationContext context: Context,
    private val sealed: SealedIdentityCrypto,
    private val tier1: Tier1KeyProvider,
    private val tier1Envelope: Tier1KeyEnvelope,
    private val credentialMigrator: CredentialWrapMigrator,
) {
    private val file = AtomicFile(File(context.filesDir, FILE_NAME))
    private val vaultMutex = Mutex()
    private val random = SecureRandom()

    fun exists(): Boolean = file.baseFile.exists()

    /** Legacy v1 identity files used the biometric Keystore method. */
    suspend fun configuredAuthMethod(): Tier1AuthMethod = vaultMutex.withLock {
        readContainer().authMethod ?: Tier1AuthMethod.BIOMETRIC
    }

    /**
     * First run or explicit restore. The recovery phrase derives the
     * identity only in Rust; a fresh random vault key seals it and is
     * wrapped using the selected Tier 1 method.
     */
    suspend fun createFromPhrase(
        phrase: RecoveryPhrase,
        input: Tier1AuthInput,
    ): IdentityPublicKeys {
        try {
            return vaultMutex.withLock {
                credentialMigrator.withMigrationLock {
                    check(!file.baseFile.exists()) { "an identity already exists" }
                    check(credentialMigrator.pending() == null) {
                        "cannot replace identity during credential migration"
                    }
                    check(credentialMigrator.credentialRowCountUnlocked() == 0) {
                        "cannot create a new identity while stored credentials remain"
                    }
                    val vaultKey = ByteArray(KEY_LEN).also(random::nextBytes)
                    val generation = ByteArray(GENERATION_LEN).also(random::nextBytes)
                    try {
                        val identity = sealed.createSealedIdentity(phrase, vaultKey)
                        val wrapped = tier1Envelope.wrap(
                            vaultKey = vaultKey,
                            generation = generation,
                            input = input,
                            purpose = AuthPurpose.SESSION_UNLOCK,
                        )
                        writeContainer(
                            IdentityContainer(
                                wrappedContentKey = wrapped.wrapped,
                                sealedBlob = identity.blob,
                                authMethod = wrapped.method,
                                salt = wrapped.salt,
                                nonce = wrapped.nonce,
                                generation = generation,
                                version = IdentityContainer.VERSION,
                            ),
                        )
                        IdentityPublicKeys(identity.ed25519Public, identity.x25519Public)
                    } finally {
                        vaultKey.fill(0)
                        generation.fill(0)
                    }
                }
            }
        } finally {
            input.close()
        }
    }

    /**
     * Authenticate and open a Tier 1 session. A v1 file is upgraded before
     * the session is returned; a committed v2 file with a pending Room
     * promotion is recovered before it can be used.
     */
    suspend fun unlock(
        input: Tier1AuthInput,
        onMigrationProgress: suspend (completed: Int, total: Int) -> Unit = { _, _ -> },
    ): Result<UnlockedPhoneSession> {
        try {
            return Result.success(
                vaultMutex.withLock { unlockInternal(input, onMigrationProgress) },
            )
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            return Result.failure(error)
        } finally {
            input.close()
        }
    }

    /**
     * Re-authenticate the selected Tier 1 method without opening, replacing,
     * or closing the active session. Used for Tier 3 approval only. The
     * freshly unwrapped key must match the active session's vault key and
     * envelope generation; method changes or stale sessions fail closed.
     */
    suspend fun reauthenticate(
        session: UnlockedPhoneSession,
        input: Tier1AuthInput,
    ): Result<Unit> {
        try {
            vaultMutex.withLock {
                session.requireOpen()
                val container = readContainer()
                val configuredMethod = container.authMethod ?: Tier1AuthMethod.BIOMETRIC
                if (configuredMethod != session.authMethod) throw AuthMethodMismatchException()

                val currentGeneration = container.generation
                    ?: throw IdentityCorruptException("versioned identity generation is missing")
                val sessionGeneration = session.generation
                val expectedVaultKey = session.vaultKeyCopy()
                try {
                    if (!MessageDigest.isEqual(sessionGeneration, currentGeneration)) {
                        throw IdentitySessionMismatchException()
                    }
                    val authenticatedVaultKey = tier1Envelope.unwrap(
                        container,
                        input,
                        AuthPurpose.HIGH_RISK_APPROVAL,
                    )
                    try {
                        session.requireOpen()
                        if (!MessageDigest.isEqual(expectedVaultKey, authenticatedVaultKey)) {
                            throw IdentitySessionMismatchException()
                        }
                    } finally {
                        authenticatedVaultKey.fill(0)
                    }
                } finally {
                    sessionGeneration.fill(0)
                    currentGeneration.fill(0)
                    expectedVaultKey.fill(0)
                }
            }
            return Result.success(Unit)
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            return Result.failure(error)
        } finally {
            input.close()
        }
    }

    /**
     * Change Tier 1 protection after authenticating the current method.
     * Credential DEKs stay wrapped under the same vault key and therefore
     * need no rewrite for a v2-to-v2 method change.
     */
    suspend fun changeAuthMethod(
        currentInput: Tier1AuthInput,
        replacementInput: Tier1AuthInput,
        onMigrationProgress: suspend (completed: Int, total: Int) -> Unit = { _, _ -> },
    ): Result<Unit> {
        try {
            vaultMutex.withLock {
                val session = unlockInternal(currentInput, onMigrationProgress)
                try {
                    val container = readContainer()
                    check(container.version == IdentityContainer.VERSION)
                    check(credentialMigrator.pending() == null) {
                        "credential migration must finish before changing protection"
                    }
                    val generation = requireNotNull(container.generation)
                    val vaultKey = session.vaultKeyCopy()
                    val wrapped = try {
                        tier1Envelope.wrap(
                            vaultKey = vaultKey,
                            generation = generation,
                            input = replacementInput,
                            purpose = AuthPurpose.CHANGE_AUTH_METHOD,
                        )
                    } finally {
                        vaultKey.fill(0)
                    }
                    writeContainer(
                        IdentityContainer(
                            wrappedContentKey = wrapped.wrapped,
                            sealedBlob = container.sealedBlob,
                            authMethod = wrapped.method,
                            salt = wrapped.salt,
                            nonce = wrapped.nonce,
                            generation = generation,
                            version = IdentityContainer.VERSION,
                        ),
                    )
                } finally {
                    session.close()
                }
            }
            return Result.success(Unit)
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            return Result.failure(error)
        } finally {
            currentInput.close()
            replacementInput.close()
        }
    }

    private suspend fun unlockInternal(
        input: Tier1AuthInput,
        onMigrationProgress: suspend (completed: Int, total: Int) -> Unit,
    ): UnlockedPhoneSession {
        val sourceBytes = readBytes()
        val container = IdentityContainer.decode(sourceBytes)
        val vaultKey = tier1Envelope.unwrap(container, input, AuthPurpose.SESSION_UNLOCK)
        var identity: UnlockedIdentity? = null
        try {
            identity = sealed.openSealedIdentity(container.sealedBlob, vaultKey)
                .getOrElse { throw IdentityCorruptException("identity.enc will not open", it) }

            val generation = if (container.version == IdentityContainer.LEGACY_VERSION) {
                migrateLegacyIdentity(sourceBytes, vaultKey, input, onMigrationProgress)
            } else {
                val currentGeneration = requireNotNull(container.generation)
                finishCommittedMigration(container, currentGeneration)
                currentGeneration.copyOf()
            }

            val openedIdentity = checkNotNull(identity)
            identity = null
            return UnlockedPhoneSession(
                identity = openedIdentity,
                authMethod = if (container.version == IdentityContainer.LEGACY_VERSION) {
                    Tier1AuthMethod.BIOMETRIC
                } else {
                    requireNotNull(container.authMethod)
                },
                generation = generation,
                vaultKey = vaultKey,
            ).also { generation.fill(0) }
        } catch (error: Exception) {
            identity?.close()
            throw error
        } finally {
            vaultKey.fill(0)
        }
    }

    private suspend fun migrateLegacyIdentity(
        sourceBytes: ByteArray,
        vaultKey: ByteArray,
        input: Tier1AuthInput,
        onProgress: suspend (completed: Int, total: Int) -> Unit,
    ): ByteArray {
        val biometric = input as? Tier1AuthInput.Biometric ?: throw AuthMethodMismatchException()
        val sourceHash = sha256(sourceBytes)
        return credentialMigrator.withMigrationLock {
            val existing = credentialMigrator.pending()
            val migration = existing ?: CredentialWrapMigrationEntity(
                migrationId = UUID.randomUUID().toString(),
                sourceIdentityHash = sourceHash.copyOf(),
                targetGeneration = ByteArray(GENERATION_LEN).also(random::nextBytes),
                targetAuthMethod = Tier1AuthMethod.BIOMETRIC.name,
                expectedRows = credentialMigrator.legacyRowCountUnlocked(),
            )
            if (!MessageDigest.isEqual(migration.sourceIdentityHash, sourceHash) ||
                migration.targetAuthMethod != Tier1AuthMethod.BIOMETRIC.name
            ) {
                throw CredentialWrapMigrationException("pending migration does not match the legacy identity")
            }

            credentialMigrator.stageLegacyRowsUnlocked(
                migration = migration,
                vaultKey = vaultKey,
                unwrapLegacy = LegacyDekUnwrapper { row ->
                    unwrapLegacyDek(row, biometric)
                },
                onProgress = onProgress,
            )

            val wrapped = tier1Envelope.wrap(
                vaultKey = vaultKey,
                generation = migration.targetGeneration,
                input = input,
                purpose = AuthPurpose.MIGRATE_IDENTITY,
            )
            writeContainer(
                IdentityContainer(
                    wrappedContentKey = wrapped.wrapped,
                    sealedBlob = IdentityContainer.decode(sourceBytes).sealedBlob,
                    authMethod = wrapped.method,
                    salt = wrapped.salt,
                    nonce = wrapped.nonce,
                    generation = migration.targetGeneration,
                    version = IdentityContainer.VERSION,
                ),
            )
            credentialMigrator.promoteUnlocked(migration)
            runCatching { tier1.deleteLegacyKey() }
            migration.targetGeneration.copyOf()
        }
    }

    private suspend fun unwrapLegacyDek(
        row: CredentialEntity,
        biometric: Tier1AuthInput.Biometric,
    ): ByteArray {
        val legacyKey = tier1.legacyKey() ?: throw IdentityInvalidatedException()
        return try {
            val cipher = WrappedKey.decryptCipher(legacyKey, row.wrappedDek)
            val authorized = biometric.gate.authorize(cipher, AuthPurpose.MIGRATE_CREDENTIAL)
            WrappedKey.finishDecrypt(authorized, row.wrappedDek)
        } catch (error: BiometricAuthException) {
            throw error
        } catch (error: KeyPermanentlyInvalidatedException) {
            throw IdentityInvalidatedException(error)
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            throw IdentityUnlockFailedException(error)
        }
    }

    /** Recover the only valid post-file-commit/pre-Room-promotion state. */
    private suspend fun finishCommittedMigration(
        container: IdentityContainer,
        generation: ByteArray,
    ) = credentialMigrator.withMigrationLock {
        val journal = credentialMigrator.pending()
        if (journal != null) {
            if (!MessageDigest.isEqual(journal.targetGeneration, generation) ||
                journal.targetAuthMethod != container.authMethod?.name
            ) {
                throw CredentialWrapMigrationException("identity and credential migration journal disagree")
            }
            credentialMigrator.promoteUnlocked(journal)
            runCatching { tier1.deleteLegacyKey() }
        } else if (credentialMigrator.legacyRowCountUnlocked() != 0) {
            throw CredentialWrapMigrationException("legacy credential wraps have no migration journal")
        }
    }

    private fun readContainer(): IdentityContainer = IdentityContainer.decode(readBytes())

    private fun readBytes(): ByteArray = try {
        file.openRead().use { it.readBytes() }
    } catch (error: Exception) {
        throw IdentityCorruptException("identity.enc not readable", error)
    }

    private fun writeContainer(container: IdentityContainer) {
        val bytes = container.encode()
        var stream: java.io.FileOutputStream? = null
        try {
            stream = file.startWrite()
            stream.write(bytes)
            file.finishWrite(stream)
            stream = null
        } catch (error: Exception) {
            stream?.let(file::failWrite)
            throw error
        } finally {
            bytes.fill(0)
        }
    }

    private fun sha256(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(bytes)

    private companion object {
        const val FILE_NAME = "identity.enc"
        const val KEY_LEN = 32
        const val GENERATION_LEN = 16
    }
}
