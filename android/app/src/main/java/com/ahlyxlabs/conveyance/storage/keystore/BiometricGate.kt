package com.ahlyxlabs.conveyance.storage.keystore

import javax.crypto.Cipher

/** What a Tier 1 unlock is for; the real prompt shows this to the user. */
enum class AuthPurpose {
    UNLOCK_IDENTITY,
    UNLOCK_CREDENTIAL,
    HIGH_RISK_APPROVAL,
}

/**
 * Gates a `conveyance_tier1` key operation behind a biometric /
 * device-credential prompt.
 *
 * The concrete implementation (Android `BiometricPrompt` +
 * `CryptoObject`) needs a UI host and arrives with the approval-UI phase.
 * Phase 10.2a depends only on this seam, so [IdentityVault] can be tested
 * with a fake that authorizes the cipher directly.
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
