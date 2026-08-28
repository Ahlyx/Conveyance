package com.ahlyxlabs.conveyance.storage.credentials

import android.security.keystore.KeyPermanentlyInvalidatedException
import com.ahlyxlabs.conveyance.crypto.SealedIdentityCrypto
import com.ahlyxlabs.conveyance.storage.SecretBytes
import com.ahlyxlabs.conveyance.storage.identity.Tier1KeyProvider
import com.ahlyxlabs.conveyance.storage.keystore.AuthPurpose
import com.ahlyxlabs.conveyance.storage.keystore.BiometricGate
import com.ahlyxlabs.conveyance.storage.keystore.WrappedKey
import java.security.SecureRandom
import javax.inject.Inject
import javax.inject.Singleton

/** Failures the credential store reports. */
sealed class CredentialException(message: String, cause: Throwable? = null) :
    Exception(message, cause) {

    class NotFound(service: String) : CredentialException("no credential stored for '$service'")

    class Undecryptable(service: String, cause: Throwable? = null) :
        CredentialException("the credential for '$service' will not decrypt", cause)

    class KeyInvalidated(cause: Throwable? = null) :
        CredentialException(
            "the credential key was invalidated; restore from the recovery phrase",
            cause,
        )
}

/**
 * Add / list / remove / open stored service credentials.
 *
 * Each secret is sealed in Rust under its own random DEK; that DEK is
 * AES-GCM-wrapped under the biometric-gated `conveyance_tier1` key and
 * stored alongside the ciphertext. [open] unwraps exactly one row's DEK
 * (one Tier 1 auth) and decrypts exactly one secret — the table is never
 * read in bulk. [listServices] touches no DEK and needs no auth.
 *
 * Error convention mirrors [com.ahlyxlabs.conveyance.storage.identity.IdentityVault]:
 * [open] returns `Result`; a missing row, an undecryptable row, and an
 * invalidated key are branchable outcomes, not exceptions.
 */
@Singleton
class CredentialStore @Inject constructor(
    private val dao: CredentialDao,
    private val sealed: SealedIdentityCrypto,
    private val tier1: Tier1KeyProvider,
) {
    /** Store (or replace) the secret for [service]. One Tier 1 auth via [gate]. */
    suspend fun add(service: String, secret: ByteArray, gate: BiometricGate) {
        val dek = ByteArray(32).also { SecureRandom().nextBytes(it) }
        try {
            val ciphertext = sealed.sealCredential(secret, dek)
            val cipher = WrappedKey.encryptCipher(tier1.key())
            val authorized = gate.authorize(cipher, AuthPurpose.UNLOCK_CREDENTIAL)
            val wrappedDek = WrappedKey.finishEncrypt(authorized, dek)
            dao.upsert(
                CredentialEntity(
                    service = service,
                    secretCiphertext = ciphertext,
                    wrappedDek = wrappedDek,
                    createdAt = System.currentTimeMillis() / 1000,
                ),
            )
        } finally {
            dek.fill(0)
        }
    }

    suspend fun listServices(): List<String> = dao.listServices()

    /** @return true if a row was removed. */
    suspend fun remove(service: String): Boolean = dao.delete(service) > 0

    /**
     * Decrypt one credential. One Tier 1 auth via [gate]. The returned
     * [SecretBytes] is the caller's to `close()`.
     */
    suspend fun open(service: String, gate: BiometricGate): Result<SecretBytes> {
        val row = dao.get(service) ?: return Result.failure(CredentialException.NotFound(service))

        val dek = try {
            val cipher = WrappedKey.decryptCipher(tier1.key(), row.wrappedDek)
            val authorized = gate.authorize(cipher, AuthPurpose.UNLOCK_CREDENTIAL)
            WrappedKey.finishDecrypt(authorized, row.wrappedDek)
        } catch (e: KeyPermanentlyInvalidatedException) {
            return Result.failure(CredentialException.KeyInvalidated(e))
        }

        return try {
            sealed.openCredential(row.secretCiphertext, dek)
                .map { plaintext ->
                    SecretBytes(plaintext).also { plaintext.fill(0) }
                }
                .recoverCatching { throw CredentialException.Undecryptable(service, it) }
        } finally {
            dek.fill(0)
        }
    }
}
