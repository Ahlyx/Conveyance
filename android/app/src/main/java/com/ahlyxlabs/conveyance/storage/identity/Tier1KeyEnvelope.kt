package com.ahlyxlabs.conveyance.storage.identity

import android.security.keystore.KeyPermanentlyInvalidatedException
import com.ahlyxlabs.conveyance.crypto.AeadKey
import com.ahlyxlabs.conveyance.crypto.AeadNonce
import com.ahlyxlabs.conveyance.crypto.ConveyanceCrypto
import com.ahlyxlabs.conveyance.storage.keystore.AuthPurpose
import com.ahlyxlabs.conveyance.storage.keystore.BiometricAuthException
import com.ahlyxlabs.conveyance.storage.keystore.WrappedKey
import java.security.SecureRandom
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class WrappedVaultKey(
    val method: Tier1AuthMethod,
    val wrapped: ByteArray,
    val salt: ByteArray? = null,
    val nonce: ByteArray? = null,
)

/** Implements only the selected-method envelope using the existing Rust crypto primitives. */
@Singleton
class Tier1KeyEnvelope @Inject constructor(
    private val crypto: ConveyanceCrypto,
    private val tier1: Tier1KeyProvider,
) {
    private val random = SecureRandom()

    suspend fun wrap(
        vaultKey: ByteArray,
        generation: ByteArray,
        input: Tier1AuthInput,
        purpose: AuthPurpose,
    ): WrappedVaultKey {
        require(vaultKey.size == KEY_LEN)
        require(generation.size == GENERATION_LEN)
        return when (input) {
            is Tier1AuthInput.Biometric -> {
                val cipher = WrappedKey.encryptCipher(tier1.key())
                val authorized = input.gate.authorize(cipher, purpose)
                WrappedVaultKey(
                    method = Tier1AuthMethod.BIOMETRIC,
                    wrapped = WrappedKey.finishEncrypt(authorized, vaultKey),
                )
            }
            is Tier1AuthInput.Passphrase -> withContext(Dispatchers.Default) {
                input.useBytes { passphrase ->
                    Tier1PassphrasePolicy.requireValidUtf8(passphrase)
                    val salt = ByteArray(SALT_LEN).also(random::nextBytes)
                    val nonceBytes = ByteArray(NONCE_LEN).also(random::nextBytes)
                    val derived = crypto.deriveDek(passphrase, salt)
                    try {
                        val keyBytes = derived.bytes()
                        val key = AeadKey(keyBytes)
                        keyBytes.fill(0)
                        try {
                            WrappedVaultKey(
                                method = Tier1AuthMethod.PASSPHRASE,
                                wrapped = crypto.seal(
                                    key,
                                    AeadNonce(nonceBytes),
                                    vaultKey,
                                    associatedData(Tier1AuthMethod.PASSPHRASE, generation),
                                ),
                                salt = salt.copyOf(),
                                nonce = nonceBytes.copyOf(),
                            )
                        } finally {
                            key.destroy()
                        }
                    } finally {
                        derived.destroy()
                        salt.fill(0)
                        nonceBytes.fill(0)
                    }
                }
            }
        }
    }

    suspend fun unwrap(
        container: IdentityContainer,
        input: Tier1AuthInput,
        purpose: AuthPurpose,
    ): ByteArray {
        val storedMethod = container.authMethod ?: Tier1AuthMethod.BIOMETRIC
        if (input.method != storedMethod) throw AuthMethodMismatchException()
        return try {
            when (storedMethod) {
                Tier1AuthMethod.BIOMETRIC -> {
                    val key = if (container.version == IdentityContainer.LEGACY_VERSION) {
                        tier1.legacyKey() ?: throw IdentityInvalidatedException()
                    } else {
                        tier1.key()
                    }
                    val cipher = WrappedKey.decryptCipher(key, container.wrappedContentKey)
                    val authorized = (input as Tier1AuthInput.Biometric).gate.authorize(cipher, purpose)
                    WrappedKey.finishDecrypt(authorized, container.wrappedContentKey)
                }
                Tier1AuthMethod.PASSPHRASE -> withContext(Dispatchers.Default) {
                    val passphraseInput = input as Tier1AuthInput.Passphrase
                    val salt = requireNotNull(container.salt)
                    val nonce = requireNotNull(container.nonce)
                    val generation = requireNotNull(container.generation)
                    passphraseInput.useBytes { passphrase ->
                        Tier1PassphrasePolicy.requireValidUtf8(passphrase)
                        val derived = crypto.deriveDek(passphrase, salt)
                        try {
                            val keyBytes = derived.bytes()
                            val key = AeadKey(keyBytes)
                            keyBytes.fill(0)
                            try {
                                crypto.open(
                                    key,
                                    AeadNonce(nonce),
                                    container.wrappedContentKey,
                                    associatedData(Tier1AuthMethod.PASSPHRASE, generation),
                                ).getOrElse { throw IdentityUnlockFailedException() }
                            } finally {
                                key.destroy()
                            }
                        } finally {
                            derived.destroy()
                        }
                    }
                }
            }
        } catch (error: BiometricAuthException) {
            throw error
        } catch (error: CancellationException) {
            throw error
        } catch (error: KeyPermanentlyInvalidatedException) {
            throw IdentityInvalidatedException(error)
        } catch (error: AuthMethodMismatchException) {
            throw error
        } catch (error: IdentityInvalidatedException) {
            throw error
        } catch (error: IdentityUnlockFailedException) {
            throw error
        } catch (error: Exception) {
            throw IdentityUnlockFailedException(error)
        }
    }

    private fun associatedData(method: Tier1AuthMethod, generation: ByteArray): ByteArray =
        DOMAIN + method.wireTag + generation

    companion object {
        private const val KEY_LEN = 32
        private const val GENERATION_LEN = 16
        private const val SALT_LEN = 16
        private const val NONCE_LEN = 12
        private val DOMAIN = "conveyance-vault-key-v2\u0000".toByteArray(Charsets.US_ASCII)
    }
}

class AuthMethodMismatchException : Exception("select the configured Conveyance authentication method")

/** Wrong passphrase and a corrupt envelope intentionally share one outcome. */
class IdentityUnlockFailedException(cause: Throwable? = null) :
    Exception("the Conveyance vault could not be unlocked", cause)
