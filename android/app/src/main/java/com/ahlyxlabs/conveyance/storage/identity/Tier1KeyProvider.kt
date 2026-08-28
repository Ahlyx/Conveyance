package com.ahlyxlabs.conveyance.storage.identity

import com.ahlyxlabs.conveyance.storage.keystore.KeystoreKeys
import javax.crypto.SecretKey
import javax.inject.Inject

/**
 * Supplies the `conveyance_tier1` key to [IdentityVault].
 *
 * A seam, not indirection for its own sake: an instrumented test cannot
 * satisfy a real biometric prompt headlessly, so it substitutes a
 * functionally-equivalent non-auth AES key here. The real key's flags are
 * asserted separately by `KeystoreKeysTest`.
 */
interface Tier1KeyProvider {
    fun key(): SecretKey
}

class KeystoreTier1KeyProvider @Inject constructor(
    private val keys: KeystoreKeys,
) : Tier1KeyProvider {
    override fun key(): SecretKey {
        keys.ensureTier1Key()
        return keys.tier1()
    }
}
