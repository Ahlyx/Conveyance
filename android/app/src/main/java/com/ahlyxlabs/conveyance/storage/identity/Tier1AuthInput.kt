package com.ahlyxlabs.conveyance.storage.identity

import com.ahlyxlabs.conveyance.storage.keystore.BiometricGate
import java.io.Closeable

/** Per-call authentication material; passphrase bytes are kept mutable and zeroizable. */
sealed class Tier1AuthInput : Closeable {
    abstract val method: Tier1AuthMethod

    class Biometric(val gate: BiometricGate) : Tier1AuthInput() {
        override val method = Tier1AuthMethod.BIOMETRIC
        override fun close() = Unit
        override fun toString(): String = "Tier1AuthInput.Biometric"
    }

    class Passphrase(passphraseUtf8: ByteArray) : Tier1AuthInput() {
        override val method = Tier1AuthMethod.PASSPHRASE

        init {
            Tier1PassphrasePolicy.requireValidUtf8(passphraseUtf8)
        }

        private val backing = passphraseUtf8.copyOf()
        private var open = true

        @Synchronized
        internal fun <T> useBytes(block: (ByteArray) -> T): T {
            check(open) { "passphrase input has been closed" }
            val copy = backing.copyOf()
            return try {
                block(copy)
            } finally {
                copy.fill(0)
            }
        }

        @Synchronized
        override fun close() {
            backing.fill(0)
            open = false
        }

        override fun toString(): String = "Tier1AuthInput.Passphrase(<redacted>)"
    }
}
