package com.ahlyxlabs.conveyance.storage.keystore

import javax.crypto.Cipher

/** What a Tier 1 unlock is for; the real prompt shows this to the user. */
enum class AuthPurpose {
    SESSION_UNLOCK,
    CHANGE_AUTH_METHOD,
    MIGRATE_IDENTITY,
    MIGRATE_CREDENTIAL,
    HIGH_RISK_APPROVAL,
}

/**
 * Gates an Android Keystore operation behind a strong biometric prompt.
 *
 * Android's `BiometricPrompt` `CryptoObject` returns the cipher authorized
 * for a single key use. No device-credential or weaker-auth fallback is
 * provided. The interface keeps this activity-bound prompt out of storage
 * logic and lets deterministic tests authorize the cipher directly.
 */
interface BiometricGate {
    /**
     * Show a Tier 1 auth prompt bound to [cipher] (as a `CryptoObject`).
     *
     * @return the same [cipher], now authorized for one `doFinal`.
     * @throws BiometricAuthException on user cancel, lockout, or failure.
     */
    suspend fun authorize(cipher: Cipher, purpose: AuthPurpose): Cipher
}

class BiometricAuthException(message: String, cause: Throwable? = null) :
    Exception(message, cause)
