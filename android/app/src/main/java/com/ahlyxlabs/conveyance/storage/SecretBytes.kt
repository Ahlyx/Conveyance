package com.ahlyxlabs.conveyance.storage

import java.io.Closeable
import java.util.Arrays

/**
 * An arbitrary-length secret whose backing bytes are wiped on [close].
 *
 * Best effort, not erasure — the JVM GC may have copied the array before
 * `close()` ran. Same limitation and posture as
 * `com.ahlyxlabs.conveyance.crypto.CryptoException`; used for credential
 * plaintext returned from the store to the request executor.
 */
class SecretBytes(bytes: ByteArray) : Closeable {
    private val backing: ByteArray = bytes.copyOf()
    private var open = true

    val size: Int get() = backing.size

    /** A copy of the bytes. Do not retain past [close]. */
    fun bytes(): ByteArray {
        check(open) { "secret has been closed" }
        return backing.copyOf()
    }

    override fun close() {
        Arrays.fill(backing, 0)
        open = false
    }

    override fun toString(): String = "SecretBytes(<redacted>, $size bytes)"
}
