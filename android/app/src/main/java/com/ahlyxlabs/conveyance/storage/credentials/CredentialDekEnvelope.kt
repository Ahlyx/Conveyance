package com.ahlyxlabs.conveyance.storage.credentials

import com.ahlyxlabs.conveyance.crypto.AeadKey
import com.ahlyxlabs.conveyance.crypto.AeadNonce
import com.ahlyxlabs.conveyance.crypto.ConveyanceCrypto
import java.security.SecureRandom
import javax.inject.Inject
import javax.inject.Singleton

/** Credential DEK envelope version 2: nonce(12) || Rust AEAD ciphertext+tag. */
@Singleton
class CredentialDekEnvelope @Inject constructor(
    private val crypto: ConveyanceCrypto,
) {
    private val random = SecureRandom()

    fun wrap(service: String, dek: ByteArray, vaultKey: ByteArray): ByteArray {
        require(dek.size == KEY_LEN) { "credential DEK must be $KEY_LEN bytes" }
        require(vaultKey.size == KEY_LEN) { "vault key must be $KEY_LEN bytes" }
        val nonceBytes = ByteArray(NONCE_LEN).also(random::nextBytes)
        val key = AeadKey(vaultKey)
        return try {
            val ciphertext = crypto.seal(
                key = key,
                nonce = AeadNonce(nonceBytes),
                plaintext = dek,
                aad = associatedData(service),
            )
            nonceBytes + ciphertext
        } finally {
            key.destroy()
            nonceBytes.fill(0)
        }
    }

    fun unwrap(service: String, wrapped: ByteArray, vaultKey: ByteArray): Result<ByteArray> {
        require(vaultKey.size == KEY_LEN) { "vault key must be $KEY_LEN bytes" }
        if (wrapped.size < NONCE_LEN + TAG_LEN) {
            return Result.failure(CredentialEnvelopeException())
        }
        val nonceBytes = wrapped.copyOfRange(0, NONCE_LEN)
        val ciphertext = wrapped.copyOfRange(NONCE_LEN, wrapped.size)
        val key = AeadKey(vaultKey)
        return try {
            crypto.open(
                key = key,
                nonce = AeadNonce(nonceBytes),
                ciphertext = ciphertext,
                aad = associatedData(service),
            ).mapCatching { dek ->
                if (dek.size != KEY_LEN) {
                    dek.fill(0)
                    throw CredentialEnvelopeException()
                }
                dek
            }.recoverCatching { throw CredentialEnvelopeException(it) }
        } finally {
            key.destroy()
            nonceBytes.fill(0)
            ciphertext.fill(0)
        }
    }

    private fun associatedData(service: String): ByteArray =
        DOMAIN + service.toByteArray(Charsets.UTF_8)

    companion object {
        private const val KEY_LEN = 32
        private const val NONCE_LEN = 12
        private const val TAG_LEN = 16
        private val DOMAIN = "conveyance-credential-dek-v2\u0000".toByteArray(Charsets.US_ASCII)
    }
}

/** Opaque at the storage/UI boundary so wrong key and tampering look alike. */
internal class CredentialEnvelopeException(cause: Throwable? = null) :
    Exception("credential key envelope could not be opened", cause)
