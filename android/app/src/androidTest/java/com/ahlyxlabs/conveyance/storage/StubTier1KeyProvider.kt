package com.ahlyxlabs.conveyance.storage

import com.ahlyxlabs.conveyance.storage.identity.Tier1KeyProvider
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * A plain in-memory AES-256 key standing in for `conveyance_tier1`. A
 * real `setUserAuthenticationRequired(true)` key cannot complete a
 * `doFinal` without satisfying a biometric prompt, which headless CI
 * can't; the real key's spec-mandated flags are asserted by
 * `KeystoreKeysTest`.
 */
class StubTier1KeyProvider : Tier1KeyProvider {
    private val key: SecretKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    override fun key(): SecretKey = key
}
