package com.ahlyxlabs.conveyance.storage.identity

import android.content.Context
import android.security.keystore.KeyPermanentlyInvalidatedException
import com.ahlyxlabs.conveyance.crypto.Ed25519PublicKey
import com.ahlyxlabs.conveyance.crypto.RecoveryPhrase
import com.ahlyxlabs.conveyance.crypto.SealedIdentityCrypto
import com.ahlyxlabs.conveyance.crypto.UnlockedIdentity
import com.ahlyxlabs.conveyance.crypto.X25519PublicKey
import com.ahlyxlabs.conveyance.storage.keystore.AuthPurpose
import com.ahlyxlabs.conveyance.storage.keystore.BiometricGate
import com.ahlyxlabs.conveyance.storage.keystore.WrappedKey
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.SecureRandom
import javax.inject.Inject
import javax.inject.Singleton

/** The two long-term identity public keys. Safe to hold and display. */
data class IdentityPublicKeys(
    val ed25519: Ed25519PublicKey,
    val x25519: X25519PublicKey,
)

/**
 * Owns `identity.enc`: the phone's sealed long-term identity.
 *
 * The security property is inherited from [SealedIdentityCrypto]: the
 * Ed25519 / X25519 secret scalars are derived, sealed, opened, and signed
 * with inside Rust. This class handles the *storage* — a random 32-byte
 * content key seals the identity, that content key is AES-GCM-wrapped
 * under the biometric-gated `conveyance_tier1` Keystore key, and the two
 * are written to one file ([IdentityContainer]). The content key is the
 * only secret that touches the JVM heap, for the微秒 between the Keystore
 * cipher and the FFI call, and it is zeroed in a `finally`.
 *
 * Error convention: a cancelled / locked-out prompt throws
 * `BiometricAuthException` (transient — the caller retries). A destroyed
 * key or an unreadable `identity.enc` comes back as `Result.failure` with
 * [IdentityInvalidatedException] / [IdentityCorruptException] — the caller
 * must branch to the restore-from-phrase flow, not retry.
 */
@Singleton
class IdentityVault @Inject constructor(
    @param:ApplicationContext private val context: Context,
    private val sealed: SealedIdentityCrypto,
    private val tier1: Tier1KeyProvider,
) {
    private val file: File get() = File(context.filesDir, FILE_NAME)

    fun exists(): Boolean = file.exists()

    /**
     * First-run or restore: derive the identity from [phrase], seal it
     * under a fresh random content key, wrap that key under
     * `conveyance_tier1` (one Tier 1 auth via [gate]), and persist
     * `identity.enc`. Overwrites any existing file — the caller decides
     * whether this is a first run or a deliberate restore.
     */
    suspend fun createFromPhrase(
        phrase: RecoveryPhrase,
        gate: BiometricGate,
    ): IdentityPublicKeys {
        val contentKey = ByteArray(32).also { SecureRandom().nextBytes(it) }
        try {
            val blob = sealed.createSealedIdentity(phrase, contentKey)

            val cipher = WrappedKey.encryptCipher(tier1.key())
            val authorized = gate.authorize(cipher, AuthPurpose.UNLOCK_IDENTITY)
            val wrapped = WrappedKey.finishEncrypt(authorized, contentKey)

            writeAtomically(IdentityContainer(wrapped, blob.blob).encode())
            return IdentityPublicKeys(blob.ed25519Public, blob.x25519Public)
        } finally {
            contentKey.fill(0)
        }
    }

    /**
     * Unlock the sealed identity into a Rust-owned handle (one Tier 1
     * auth via [gate]). The caller closes the returned handle.
     */
    suspend fun unlock(gate: BiometricGate): Result<UnlockedIdentity> {
        val bytes = runCatching { file.readBytes() }.getOrElse {
            return Result.failure(IdentityCorruptException("identity.enc not readable", it))
        }
        val container = try {
            IdentityContainer.decode(bytes)
        } catch (e: IdentityCorruptException) {
            return Result.failure(e)
        }

        val contentKey = try {
            val cipher = WrappedKey.decryptCipher(tier1.key(), container.wrappedContentKey)
            val authorized = gate.authorize(cipher, AuthPurpose.UNLOCK_IDENTITY)
            WrappedKey.finishDecrypt(authorized, container.wrappedContentKey)
        } catch (e: KeyPermanentlyInvalidatedException) {
            return Result.failure(IdentityInvalidatedException(e))
        }

        return try {
            sealed.openSealedIdentity(container.sealedBlob, contentKey)
                .recoverCatching { throw IdentityCorruptException("identity.enc will not open", it) }
        } finally {
            contentKey.fill(0)
        }
    }

    private fun writeAtomically(bytes: ByteArray) {
        val tmp = File(context.filesDir, "$FILE_NAME.tmp")
        tmp.writeBytes(bytes)
        try {
            Files.move(
                tmp.toPath(),
                file.toPath(),
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING,
            )
        } catch (e: Exception) {
            tmp.delete()
            throw e
        }
    }

    private companion object {
        const val FILE_NAME = "identity.enc"
    }
}
