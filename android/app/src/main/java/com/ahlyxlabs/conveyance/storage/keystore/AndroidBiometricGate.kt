package com.ahlyxlabs.conveyance.storage.keystore

import android.content.Context
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import dagger.hilt.android.qualifiers.ActivityContext
import dagger.hilt.android.scopes.ActivityScoped
import javax.inject.Inject
import javax.crypto.Cipher
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

/** Minimal per-operation prompt used by identity creation and pairing. */
@ActivityScoped
class AndroidBiometricGate @Inject constructor(
    @ActivityContext context: Context,
) : BiometricGate {
    private val activity = context as FragmentActivity

    override suspend fun authorize(cipher: Cipher, purpose: AuthPurpose): Cipher {
        // This operation needs the authenticated Cipher back from the prompt.
        // Android cannot bind a CryptoObject to the device-credential fallback.
        val authenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG
        if (BiometricManager.from(activity).canAuthenticate(authenticators) !=
            BiometricManager.BIOMETRIC_SUCCESS
        ) {
            throw BiometricAuthException("No supported device authentication is configured")
        }

        val result = CompletableDeferred<Cipher>()
        val prompt = BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(
                    authenticationResult: BiometricPrompt.AuthenticationResult,
                ) {
                    val authorizedCipher = authenticationResult.cryptoObject?.cipher
                    if (authorizedCipher == null) {
                        result.completeExceptionally(BiometricAuthException("Authentication returned no cipher"))
                    } else {
                        result.complete(authorizedCipher)
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    result.completeExceptionally(BiometricAuthException(errString.toString()))
                }
            },
        )
        val title = when (purpose) {
            AuthPurpose.UNLOCK_IDENTITY -> "Unlock Conveyance identity"
            AuthPurpose.UNLOCK_CREDENTIAL -> "Unlock Conveyance credential"
            AuthPurpose.HIGH_RISK_APPROVAL -> "Confirm high-risk request"
        }
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setAllowedAuthenticators(authenticators)
            .setNegativeButtonText("Cancel")
            .build()

        try {
            withContext(Dispatchers.Main.immediate) {
                prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
            }
            return result.await()
        } catch (error: CancellationException) {
            throw error
        } catch (error: BiometricAuthException) {
            throw error
        } catch (error: Exception) {
            throw BiometricAuthException("Authentication was cancelled or unavailable", error)
        } finally {
            if (!result.isCompleted) {
                withContext(NonCancellable + Dispatchers.Main.immediate) {
                    prompt.cancelAuthentication()
                }
            }
        }
    }
}
