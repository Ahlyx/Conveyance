package com.ahlyxlabs.conveyance.storage.keystore

import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import dagger.hilt.android.qualifiers.ApplicationContext
import java.security.InvalidAlgorithmParameterException
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Provisions and loads the two AndroidKeyStore keys the phone's storage
 * layer wraps its content keys under. The two are on the security axis
 * that matters:
 *
 * - **`conveyance_tier1`** wraps the identity content key and every
 *   per-service credential DEK. It is biometric / device-credential
 *   gated ([setUserAuthenticationRequired]) with a 0-second validity
 *   window, so every use needs a fresh `CryptoObject`-bound auth, and it
 *   is destroyed on any biometric enrollment change
 *   ([setInvalidatedByBiometricEnrollment]) — the two flags the spec's
 *   "Phone-side components" section mandates for Tier 1.
 * - **`conveyance_db`** wraps the shared SQLCipher passphrase for the
 *   operational databases (approvals.db, pairings.db). Deliberately not
 *   auth-gated — see the SECURITY NOTE at its provisioning site.
 *
 * Both are StrongBox-backed when the device advertises the feature, with
 * a silent fall-back to the TEE.
 */
@Singleton
class KeystoreKeys @Inject constructor(
    @param:ApplicationContext private val context: Context,
) {
    private val keyStore: KeyStore by lazy {
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    }

    /**
     * Create whichever keys are absent. Idempotent.
     *
     * @throws MissingLockScreenException if `conveyance_tier1` cannot be
     *   created because the device has no secure lock screen. `conveyance_db`
     *   is created regardless.
     */
    fun ensureProvisioned() {
        if (!keyStore.containsAlias(DB_ALIAS)) generateDbKey()
        if (!keyStore.containsAlias(TIER1_ALIAS)) generateTier1Key()
    }

    fun tier1(): SecretKey = loadKey(TIER1_ALIAS)

    fun db(): SecretKey = loadKey(DB_ALIAS)

    fun tier1KeyInfo(): KeyInfo = keyInfoOf(tier1())

    fun dbKeyInfo(): KeyInfo = keyInfoOf(db())

    fun isTier1Provisioned(): Boolean = keyStore.containsAlias(TIER1_ALIAS)

    private fun loadKey(alias: String): SecretKey =
        (keyStore.getEntry(alias, null) as? KeyStore.SecretKeyEntry)?.secretKey
            ?: error("keystore alias $alias is not provisioned")

    private fun keyInfoOf(key: SecretKey): KeyInfo {
        val factory = SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
        return factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
    }

    private val strongBoxAvailable: Boolean
        get() = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    private fun generateTier1Key() {
        fun spec(strongBox: Boolean) =
            aesGcmBuilder(TIER1_ALIAS)
                .setUserAuthenticationRequired(true)
                // 0-second window: every use requires a fresh
                // CryptoObject-bound biometric / device-credential auth.
                .setUserAuthenticationParameters(
                    0,
                    KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
                )
                // Destroy the key if biometric enrollment changes: defeats
                // "attacker enrolls their own fingerprint, then unlocks".
                .setInvalidatedByBiometricEnrollment(true)
                .setUnlockedDeviceRequired(true)
                .apply { if (strongBox) setIsStrongBoxBacked(true) }
                .build()

        try {
            generate(spec(strongBoxAvailable))
        } catch (e: StrongBoxUnavailableException) {
            generate(spec(false))
        } catch (e: InvalidAlgorithmParameterException) {
            // Thrown when there is no secure lock screen: the tier-1 key
            // cannot exist without one.
            throw MissingLockScreenException(e)
        }
    }

    private fun generateDbKey() {
        fun spec(strongBox: Boolean) =
            aesGcmBuilder(DB_ALIAS)
                // SECURITY NOTE — no setUserAuthenticationRequired here, on
                // purpose. This key wraps the SQLCipher passphrase for the
                // operational databases (approvals.db, pairings.db), which
                // must stay writable throughout an active session: the
                // foreground service appends approval-log rows with no user
                // present to re-authenticate per row. The threat this key
                // addresses is OFFLINE extraction of storage obtained
                // without a live session (lost/stolen device, disk image),
                // not a running compromised app — that is the Android app
                // sandbox's job, backed by the biometric gate on session
                // start. conveyance_tier1 (identity + credentials) is the
                // biometric-gated boundary; this key is not.
                .setUnlockedDeviceRequired(true)
                .apply { if (strongBox) setIsStrongBoxBacked(true) }
                .build()

        try {
            generate(spec(strongBoxAvailable))
        } catch (e: StrongBoxUnavailableException) {
            generate(spec(false))
        }
    }

    private fun aesGcmBuilder(alias: String) =
        KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)

    private fun generate(spec: KeyGenParameterSpec) {
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE).apply {
            init(spec)
            generateKey()
        }
    }

    companion object {
        const val TIER1_ALIAS = "conveyance.tier1.v1"
        const val DB_ALIAS = "conveyance.db.v1"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    }
}

/** `conveyance_tier1` cannot be provisioned without a device secure lock screen. */
class MissingLockScreenException(cause: Throwable) :
    Exception(
        "conveyance_tier1 requires a device secure lock screen " +
            "(biometric, PIN, pattern, or password)",
        cause,
    )
