package com.ahlyxlabs.conveyance.storage.keystore

import android.app.KeyguardManager
import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.security.KeyStore
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Verifies the AndroidKeyStore keys provision with the flags that
 * actually protect them. Real biometric enrollment-change invalidation
 * can only be exercised on hardware (Phase 11); here we assert
 * `KeyInfo.isInvalidatedByBiometricEnrollment` is set, which is what
 * causes that behaviour.
 *
 * `conveyance_tier1` needs a device secure lock screen to provision, so
 * the flag test is `assumeTrue`-guarded on `isDeviceSecure` and the CI
 * emulator sets a PIN before this runs.
 */
@RunWith(AndroidJUnit4::class)
class KeystoreKeysTest {

    private val context: Context =
        InstrumentationRegistry.getInstrumentation().targetContext
    private val keys = KeystoreKeys(context)
    private val keyguard: KeyguardManager
        get() = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager

    @Before
    fun clearAliases() {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        for (alias in listOf(KeystoreKeys.TIER1_ALIAS, KeystoreKeys.DB_ALIAS)) {
            if (ks.containsAlias(alias)) ks.deleteEntry(alias)
        }
    }

    @Test
    fun dbKeyProvisionsWithoutAuthAndWrapUnwrapRoundTrips() {
        try {
            keys.ensureProvisioned()
        } catch (e: MissingLockScreenException) {
            // db key is still created even when tier1 cannot be.
        }
        val info = keys.dbKeyInfo()
        assertFalse("conveyance_db must not be user-auth-required", info.isUserAuthenticationRequired)
        assertEquals(256, info.keySize)
        assertEquals("AES", keys.db().algorithm)

        val contentKey = ByteArray(32) { it.toByte() }
        val wrapped = WrappedKey.wrap(keys.db(), contentKey)
        assertArrayEquals(contentKey, WrappedKey.decrypt(keys.db(), wrapped))
        // Fresh IV each wrap.
        assertFalse(wrapped.contentEquals(WrappedKey.wrap(keys.db(), contentKey)))
    }

    @Test
    fun tier1KeyCarriesTheSpecMandatedFlags() {
        assumeTrue(
            "device needs a secure lock screen to provision conveyance_tier1",
            keyguard.isDeviceSecure,
        )
        keys.ensureProvisioned()
        val info = keys.tier1KeyInfo()
        assertTrue("Tier 1 must require user authentication", info.isUserAuthenticationRequired)
        assertTrue(
            "Tier 1 must be invalidated by a biometric enrollment change",
            info.isInvalidatedByBiometricEnrollment,
        )
    }

    @Test
    fun missingLockScreenSurfacesAsTypedException() {
        assumeTrue("this path only exists without a secure lock screen", !keyguard.isDeviceSecure)
        try {
            keys.ensureProvisioned()
            fail("expected MissingLockScreenException without a secure lock screen")
        } catch (e: MissingLockScreenException) {
            assertFalse(keys.isTier1Provisioned())
            assertEquals(256, keys.dbKeyInfo().keySize)
        }
    }

    @Test
    fun ensureProvisionedIsIdempotent() {
        try {
            keys.ensureProvisioned()
            keys.ensureProvisioned()
        } catch (e: MissingLockScreenException) {
            keys.ensureProvisioned() // still must not throw for the db key
        }
        assertEquals("AES", keys.db().algorithm)
    }
}
