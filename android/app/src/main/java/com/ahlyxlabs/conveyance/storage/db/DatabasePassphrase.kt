package com.ahlyxlabs.conveyance.storage.db

import android.content.Context
import com.ahlyxlabs.conveyance.storage.keystore.KeystoreKeys
import com.ahlyxlabs.conveyance.storage.keystore.WrappedKey
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.SecureRandom
import javax.inject.Inject
import javax.inject.Singleton

/**
 * The 32-byte SQLCipher passphrase shared by the operational databases
 * (credentials.enc, approvals.db, pairings.db). Generated once from the
 * CSPRNG, AES-GCM-wrapped under `conveyance_db`, and persisted to a
 * sidecar file.
 *
 * `conveyance_db` is deliberately not biometric-gated (see the SECURITY
 * NOTE in `KeystoreKeys.generateDbKey`): the operational DBs must stay
 * usable throughout a session. This passphrase therefore lives in the JVM
 * heap while a DB is open — inherent, since SQLCipher takes a `byte[]`.
 * Its protection at rest is the `conveyance_db` wrapping; it is the
 * offline-extraction boundary, not the biometric one. Identity and
 * credential *contents* stay behind `conveyance_tier1`.
 */
@Singleton
class DatabasePassphrase @Inject constructor(
    @param:ApplicationContext private val context: Context,
    private val keys: KeystoreKeys,
) {
    private val file: File get() = File(context.filesDir, FILE_NAME)

    /** The raw passphrase. A fresh array each call; the caller/SQLCipher owns wiping it. */
    @Synchronized
    fun get(): ByteArray {
        // Only the non-auth db key — a missing lock screen must not block
        // the operational databases.
        keys.ensureDbKey()
        val wrapped =
            if (file.exists()) {
                file.readBytes()
            } else {
                val fresh = ByteArray(32).also { SecureRandom().nextBytes(it) }
                val w = try {
                    WrappedKey.wrap(keys.db(), fresh)
                } finally {
                    fresh.fill(0)
                }
                writeAtomically(w)
                w
            }
        return WrappedKey.decrypt(keys.db(), wrapped)
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
        const val FILE_NAME = "db.key"
    }
}
