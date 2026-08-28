package com.ahlyxlabs.conveyance.storage.identity

import android.content.Context
import android.security.keystore.KeyPermanentlyInvalidatedException
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ahlyxlabs.conveyance.crypto.ConveyanceCrypto
import com.ahlyxlabs.conveyance.crypto.RecoveryPhrase
import com.ahlyxlabs.conveyance.crypto.SealedIdentityCrypto
import com.ahlyxlabs.conveyance.crypto.UniffiConveyanceCrypto
import com.ahlyxlabs.conveyance.crypto.UniffiSealedIdentityCrypto
import com.ahlyxlabs.conveyance.storage.FakeBiometricGate
import com.ahlyxlabs.conveyance.storage.StubTier1KeyProvider
import com.ahlyxlabs.conveyance.storage.keystore.AuthPurpose
import java.io.File
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The full 10.2a storage path: derive → seal (in Rust) → wrap the content
 * key → persist identity.enc → read back → unwrap → open the handle (in
 * Rust) → sign.
 *
 * The `conveyance_tier1` key is substituted with an equivalent non-auth
 * AES key via [Tier1KeyProvider] — a real auth-required key cannot be
 * exercised without satisfying a biometric prompt, which headless CI
 * can't. That key's spec-mandated flags are asserted by `KeystoreKeysTest`.
 */
@RunWith(AndroidJUnit4::class)
class IdentityVaultTest {

    private val context: Context =
        InstrumentationRegistry.getInstrumentation().targetContext
    private val sealed: SealedIdentityCrypto = UniffiSealedIdentityCrypto()
    private val crypto: ConveyanceCrypto = UniffiConveyanceCrypto()

    private val vault = IdentityVault(context, sealed, StubTier1KeyProvider())

    private val zeros =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon " +
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon " +
            "abandon abandon abandon abandon abandon art"

    @Before
    fun clearIdentityFile() {
        File(context.filesDir, "identity.enc").delete()
        File(context.filesDir, "identity.enc.tmp").delete()
    }

    @Test
    fun createThenUnlockYieldsAWorkingHandle() = runBlocking {
        assertFalse(vault.exists())

        val gate = FakeBiometricGate()
        val pub = vault.createFromPhrase(RecoveryPhrase(zeros), gate)
        assertTrue(vault.exists())
        assertEquals(1, gate.calls)
        assertEquals(AuthPurpose.UNLOCK_IDENTITY, gate.lastPurpose)

        // Public keys match the raw (test-only) derivation for the phrase.
        val raw = crypto.deriveIdentity(RecoveryPhrase(zeros))
        assertArrayEquals(raw.ed25519Public.bytes, pub.ed25519.bytes)
        assertArrayEquals(raw.x25519Public.bytes, pub.x25519.bytes)
        raw.destroy()

        vault.unlock(FakeBiometricGate()).getOrThrow().use { id ->
            assertArrayEquals(pub.ed25519.bytes, id.ed25519PublicKey().bytes)
            val message = "conveyance approval row".toByteArray()
            val sig = id.sign(message)
            assertTrue(crypto.verify(id.ed25519PublicKey(), message, sig).isSuccess)
        }
    }

    @Test
    fun unlockWithNoFileIsCorruptFailure() = runBlocking {
        val result = vault.unlock(FakeBiometricGate())
        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull() is IdentityCorruptException)
    }

    @Test
    fun unlockWithTamperedContainerIsCorruptFailure() = runBlocking {
        vault.createFromPhrase(RecoveryPhrase(zeros), FakeBiometricGate())
        val file = File(context.filesDir, "identity.enc")
        val bytes = file.readBytes()
        bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 0xFF).toByte()
        file.writeBytes(bytes)

        val result = vault.unlock(FakeBiometricGate())
        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull() is IdentityCorruptException)
    }

    @Test
    fun invalidatedKeyDuringUnlockSurfacesAsInvalidatedFailure() = runBlocking {
        vault.createFromPhrase(RecoveryPhrase(zeros), FakeBiometricGate())

        val gate = FakeBiometricGate { throw KeyPermanentlyInvalidatedException() }
        val result = vault.unlock(gate)
        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull() is IdentityInvalidatedException)
    }

    @Test
    fun createOverwritesAnExistingIdentity() = runBlocking {
        val first = vault.createFromPhrase(RecoveryPhrase(zeros), FakeBiometricGate())
        val second = vault.createFromPhrase(RecoveryPhrase(zeros), FakeBiometricGate())
        // Same phrase -> same identity; the file was replaced without error.
        assertArrayEquals(first.ed25519.bytes, second.ed25519.bytes)
        vault.unlock(FakeBiometricGate()).getOrThrow().close()
    }
}
