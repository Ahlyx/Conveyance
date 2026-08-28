package com.ahlyxlabs.conveyance.storage.keystore

import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * AES-GCM wrap / unwrap of a 32-byte content key under an AndroidKeyStore
 * key. Wrapped layout: `iv(12) || ciphertext+tag`.
 *
 * A content key wrapped under `conveyance_tier1` cannot be unwrapped by a
 * plain `doFinal` — the key is auth-bound, so the decrypt `Cipher` must
 * pass through [BiometricGate] first. [decryptCipher] builds that cipher;
 * [decrypt] is the shortcut for a non-auth key (`conveyance_db`).
 *
 * Callers own the discipline of zeroing the unwrapped bytes as soon as
 * they have been handed to native code.
 */
object WrappedKey {
    private const val TRANSFORM = "AES/GCM/NoPadding"
    private const val IV_LEN = 12
    private const val TAG_BITS = 128

    /** Wrap [contentKey] (must be 32 bytes). */
    fun wrap(key: SecretKey, contentKey: ByteArray): ByteArray {
        require(contentKey.size == 32) { "content key must be 32 bytes, got ${contentKey.size}" }
        val cipher = Cipher.getInstance(TRANSFORM).apply { init(Cipher.ENCRYPT_MODE, key) }
        val iv = cipher.iv
        check(iv.size == IV_LEN) { "unexpected GCM IV length ${iv.size}" }
        return iv + cipher.doFinal(contentKey)
    }

    /**
     * Build the decrypt `Cipher` for [wrapped], initialized with its IV.
     * For a [conveyance_tier1][KeystoreKeys.tier1] key, hand this to
     * [BiometricGate.authorize] before calling [finishDecrypt].
     */
    fun decryptCipher(key: SecretKey, wrapped: ByteArray): Cipher {
        require(wrapped.size > IV_LEN + TAG_BITS / 8) { "wrapped key too short" }
        val iv = wrapped.copyOfRange(0, IV_LEN)
        return Cipher.getInstance(TRANSFORM).apply {
            init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
        }
    }

    /** Run the (already-authorized, if needed) [cipher] over [wrapped]'s ciphertext. */
    fun finishDecrypt(cipher: Cipher, wrapped: ByteArray): ByteArray =
        cipher.doFinal(wrapped.copyOfRange(IV_LEN, wrapped.size))

    /** Unwrap directly with a non-auth key ([conveyance_db][KeystoreKeys.db]). */
    fun decrypt(key: SecretKey, wrapped: ByteArray): ByteArray =
        finishDecrypt(decryptCipher(key, wrapped), wrapped)
}
