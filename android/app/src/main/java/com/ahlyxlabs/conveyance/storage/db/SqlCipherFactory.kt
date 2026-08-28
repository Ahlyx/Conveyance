package com.ahlyxlabs.conveyance.storage.db

import androidx.sqlite.db.SupportSQLiteOpenHelper
import java.util.concurrent.atomic.AtomicBoolean
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory

/**
 * Builds the [SupportSQLiteOpenHelper.Factory] Room opens every
 * operational database through. Passing a SQLCipher factory is what makes
 * the DB file encrypted at rest — the app has no code path that opens an
 * unencrypted database.
 */
object SqlCipherFactory {
    private val nativeLoaded = AtomicBoolean(false)

    /**
     * @param passphrase the raw 32-byte SQLCipher key. SQLCipher reads it
     *   during `getWritableDatabase`; the caller cannot reliably wipe it
     *   afterwards (Room opens lazily). See [DatabasePassphrase] for why
     *   this JVM-resident key is acceptable.
     */
    fun create(passphrase: ByteArray): SupportSQLiteOpenHelper.Factory {
        if (nativeLoaded.compareAndSet(false, true)) {
            System.loadLibrary("sqlcipher")
        }
        return SupportOpenHelperFactory(passphrase)
    }
}
