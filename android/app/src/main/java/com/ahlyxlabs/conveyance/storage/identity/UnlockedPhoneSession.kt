package com.ahlyxlabs.conveyance.storage.identity

import com.ahlyxlabs.conveyance.crypto.UnlockedIdentity
import com.ahlyxlabs.conveyance.storage.SecretBytes
import java.io.Closeable

/**
 * One in-memory Tier 1 session. The identity scalars remain inside the
 * Rust-owned [UnlockedIdentity]; Kotlin only holds the zeroizable vault
 * key needed to open individual credential-DEK envelopes.
 */
class UnlockedPhoneSession internal constructor(
    val identity: UnlockedIdentity,
    val authMethod: Tier1AuthMethod,
    generation: ByteArray,
    vaultKey: ByteArray,
) : Closeable {
    private val key = SecretBytes(vaultKey)
    private val generationBytes = generation.copyOf()
    private var closed = false

    val generation: ByteArray get() = generationBytes.copyOf()

    @Synchronized
    internal fun <T> withVaultKey(block: (ByteArray) -> T): T {
        check(!closed) { "Tier 1 session is closed" }
        val copy = key.bytes()
        return try {
            block(copy)
        } finally {
            copy.fill(0)
        }
    }

    /** Copy for an operation that must suspend while authenticating; caller must wipe. */
    @Synchronized
    internal fun vaultKeyCopy(): ByteArray {
        check(!closed) { "Tier 1 session is closed" }
        return key.bytes()
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        key.close()
        identity.close()
        generationBytes.fill(0)
    }
}
