package com.ahlyxlabs.conveyance.storage.identity

import com.ahlyxlabs.conveyance.storage.keystore.KeystoreKeys
import javax.crypto.SecretKey
import javax.inject.Inject

/**
 * Supplies the new biometric envelope key and, when present, the legacy
 * v1 key used only during migration.
 *
 * A seam, not indirection for its own sake: an instrumented test cannot
 * satisfy a real biometric prompt headlessly, so it substitutes a
 * functionally-equivalent non-auth AES key here. The real key's flags are
 * asserted separately by `KeystoreKeysTest`.
 */
interface Tier1KeyProvider {
    /** Ensure and return the biometric-only v2 alias. */
    fun key(): SecretKey

    /** Return the v1 alias without recreating it. Tests default to [key]. */
    fun legacyKey(): SecretKey? = key()

    /** Delete the v1 key only after all v1 envelopes have been promoted. */
    fun deleteLegacyKey() = Unit
}

class KeystoreTier1KeyProvider @Inject constructor(
    private val keys: KeystoreKeys,
) : Tier1KeyProvider {
    override fun key(): SecretKey {
        keys.ensureTier1Key()
        return keys.tier1()
    }

    override fun legacyKey(): SecretKey? = keys.legacyTier1OrNull()

    override fun deleteLegacyKey() = keys.deleteLegacyTier1()
}
