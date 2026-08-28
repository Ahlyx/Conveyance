package com.ahlyxlabs.conveyance.storage

import com.ahlyxlabs.conveyance.storage.keystore.AuthPurpose
import com.ahlyxlabs.conveyance.storage.keystore.BiometricGate
import javax.crypto.Cipher

/**
 * Stands in for the real BiometricPrompt gate in instrumented tests: no
 * device auth is possible headlessly. [behavior] transforms the cipher —
 * identity (authorize it) by default, or throw to simulate a lockout /
 * an invalidated key.
 */
class FakeBiometricGate(
    private val behavior: (Cipher) -> Cipher = { it },
) : BiometricGate {

    var calls: Int = 0
        private set
    var lastPurpose: AuthPurpose? = null
        private set

    override suspend fun authorize(cipher: Cipher, purpose: AuthPurpose): Cipher {
        calls++
        lastPurpose = purpose
        return behavior(cipher)
    }
}
