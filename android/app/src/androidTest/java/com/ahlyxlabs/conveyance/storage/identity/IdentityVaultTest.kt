package com.ahlyxlabs.conveyance.storage.identity

import android.content.Context
import android.security.keystore.KeyPermanentlyInvalidatedException
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ahlyxlabs.conveyance.crypto.RecoveryPhrase
import com.ahlyxlabs.conveyance.storage.FakeBiometricGate
import com.ahlyxlabs.conveyance.storage.IdentityStorageFixture
import com.ahlyxlabs.conveyance.storage.credentials.CredentialEntity
import com.ahlyxlabs.conveyance.storage.credentials.CredentialWrapMigrationEntity
import com.ahlyxlabs.conveyance.storage.credentials.LegacyDekUnwrapper
import com.ahlyxlabs.conveyance.storage.keystore.AuthPurpose
import com.ahlyxlabs.conveyance.storage.keystore.BiometricAuthException
import com.ahlyxlabs.conveyance.storage.keystore.WrappedKey
import java.io.File
import java.security.SecureRandom
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class IdentityVaultTest {

    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private lateinit var fixture: IdentityStorageFixture

    @Before
    fun setUp() {
        clearIdentityFiles()
        fixture = IdentityStorageFixture(context)
    }

    @After
    fun tearDown() {
        fixture.close()
        clearIdentityFiles()
    }

    @Test
    fun createThenUnlockYieldsAWorkingRustOwnedHandle() = runBlocking {
        val gate = FakeBiometricGate()
        val public = fixture.vault.createFromPhrase(RecoveryPhrase(TEST_PHRASE), Tier1AuthInput.Biometric(gate))
        assertTrue(fixture.vault.exists())
        assertEquals(1, gate.calls)
        assertEquals(AuthPurpose.SESSION_UNLOCK, gate.lastPurpose)
        assertEquals(Tier1AuthMethod.BIOMETRIC, fixture.vault.configuredAuthMethod())

        val session = fixture.vault.unlock(Tier1AuthInput.Biometric(FakeBiometricGate())).getOrThrow()
        try {
            assertArrayEquals(public.ed25519.bytes, session.identity.ed25519PublicKey().bytes)
            val message = "conveyance session identity".toByteArray()
            val signature = session.identity.sign(message)
            assertTrue(fixture.crypto.verify(public.ed25519, message, signature).isSuccess)
        } finally {
            session.close()
        }
    }

    @Test
    fun tierThreeBiometricReauthUsesFreshPurposeAndKeepsTheActiveSession() = runBlocking {
        fixture.vault.createFromPhrase(
            RecoveryPhrase(TEST_PHRASE),
            Tier1AuthInput.Biometric(FakeBiometricGate()),
        )
        val session = fixture.vault.unlock(Tier1AuthInput.Biometric(FakeBiometricGate())).getOrThrow()
        val gate = FakeBiometricGate()
        try {
            fixture.vault.reauthenticate(session, Tier1AuthInput.Biometric(gate)).getOrThrow()
            assertEquals(AuthPurpose.HIGH_RISK_APPROVAL, gate.lastPurpose)
            assertEquals(1, gate.calls)
            assertTrue(session.identity.ed25519PublicKey().bytes.isNotEmpty())

            val wrongMethodBytes = "this is a valid passphrase".toByteArray(Charsets.UTF_8)
            val wrongMethod = fixture.vault.reauthenticate(
                session,
                Tier1AuthInput.Passphrase(wrongMethodBytes),
            )
            wrongMethodBytes.fill(0)
            assertTrue(wrongMethod.isFailure)
            assertTrue(wrongMethod.exceptionOrNull() is AuthMethodMismatchException)
            assertEquals("method mismatch must not trigger biometric fallback", 1, gate.calls)
            assertTrue(session.identity.ed25519PublicKey().bytes.isNotEmpty())
        } finally {
            session.close()
        }
    }

    @Test
    fun tierThreePassphraseReauthVerifiesExactConfiguredMethodAndKeepsSession() = runBlocking {
        val chosen = "tier three  passphrase".toByteArray(Charsets.UTF_8)
        fixture.vault.createFromPhrase(
            RecoveryPhrase(TEST_PHRASE),
            Tier1AuthInput.Passphrase(chosen),
        )
        chosen.fill(0)
        val sessionBytes = "tier three  passphrase".toByteArray(Charsets.UTF_8)
        val session = fixture.vault.unlock(Tier1AuthInput.Passphrase(sessionBytes)).getOrThrow()
        sessionBytes.fill(0)
        try {
            val wrongBytes = "different passphrase".toByteArray(Charsets.UTF_8)
            val wrong = fixture.vault.reauthenticate(session, Tier1AuthInput.Passphrase(wrongBytes))
            wrongBytes.fill(0)
            assertTrue(wrong.isFailure)
            assertTrue(wrong.exceptionOrNull() is IdentityUnlockFailedException)
            assertTrue(session.identity.ed25519PublicKey().bytes.isNotEmpty())

            val exactBytes = "tier three  passphrase".toByteArray(Charsets.UTF_8)
            fixture.vault.reauthenticate(session, Tier1AuthInput.Passphrase(exactBytes)).getOrThrow()
            exactBytes.fill(0)
            assertTrue(session.identity.ed25519PublicKey().bytes.isNotEmpty())
        } finally {
            session.close()
        }
    }

    @Test
    fun passphraseUsesExactUtf8BytesAndWrongInputFailsClosed() = runBlocking {
        val exactInput = "  e\u0301🗝abcdefghijkl  ".toByteArray(Charsets.UTF_8)
        fixture.vault.createFromPhrase(
            RecoveryPhrase(TEST_PHRASE),
            Tier1AuthInput.Passphrase(exactInput),
        )
        exactInput.fill(0)
        assertEquals(Tier1AuthMethod.PASSPHRASE, fixture.vault.configuredAuthMethod())

        val normalizedOrTrimmed = "é🗝abcdefghijkl".toByteArray(Charsets.UTF_8)
        val wrong = fixture.vault.unlock(Tier1AuthInput.Passphrase(normalizedOrTrimmed))
        normalizedOrTrimmed.fill(0)
        assertTrue(wrong.isFailure)
        assertTrue(wrong.exceptionOrNull() is IdentityUnlockFailedException)

        val exact = "  e\u0301🗝abcdefghijkl  ".toByteArray(Charsets.UTF_8)
        val session = fixture.vault.unlock(Tier1AuthInput.Passphrase(exact)).getOrThrow()
        exact.fill(0)
        session.close()
    }

    @Test
    fun changingProtectionMethodRewrapsSameVaultKeyWithoutAntiRollback() = runBlocking {
        fixture.vault.createFromPhrase(
            RecoveryPhrase(TEST_PHRASE),
            Tier1AuthInput.Biometric(FakeBiometricGate()),
        )
        val initial = fixture.vault.unlock(Tier1AuthInput.Biometric(FakeBiometricGate())).getOrThrow()
        fixture.credentialStore.add("example", "secret".toByteArray(), initial)
        initial.close()
        val previousIdentitySnapshot = identityFile().readBytes()
        val previousContainer = IdentityContainer.decode(previousIdentitySnapshot)

        val newPassphrase = "método exacto".toByteArray(Charsets.UTF_8)
        fixture.vault.changeAuthMethod(
            Tier1AuthInput.Biometric(FakeBiometricGate()),
            Tier1AuthInput.Passphrase(newPassphrase),
        ).getOrThrow()
        newPassphrase.fill(0)
        assertEquals(Tier1AuthMethod.PASSPHRASE, fixture.vault.configuredAuthMethod())
        val changedContainer = IdentityContainer.decode(identityFile().readBytes())
        assertArrayEquals(previousContainer.generation, changedContainer.generation)
        assertArrayEquals(previousContainer.sealedBlob, changedContainer.sealedBlob)
        assertFalse(previousContainer.wrappedContentKey.contentEquals(changedContainer.wrappedContentKey))

        val passphrase = "método exacto".toByteArray(Charsets.UTF_8)
        val changed = fixture.vault.unlock(Tier1AuthInput.Passphrase(passphrase)).getOrThrow()
        passphrase.fill(0)
        fixture.credentialStore.open("example", changed).getOrThrow().use { opened ->
            assertArrayEquals("secret".toByteArray(), opened.bytes())
        }
        changed.close()

        // V1 intentionally has no anti-rollback anchor: restoring an older,
        // valid envelope restores its previous method and the same vault key.
        identityFile().writeBytes(previousIdentitySnapshot)
        assertEquals(Tier1AuthMethod.BIOMETRIC, fixture.vault.configuredAuthMethod())
        val restored = fixture.vault.unlock(Tier1AuthInput.Biometric(FakeBiometricGate())).getOrThrow()
        try {
            fixture.credentialStore.open("example", restored).getOrThrow().use { opened ->
                assertArrayEquals("secret".toByteArray(), opened.bytes())
            }
        } finally {
            restored.close()
            previousIdentitySnapshot.fill(0)
        }
    }

    @Test
    fun configuredMethodCannotSilentlyDowngradeAndCanBeChangedBack() = runBlocking {
        val phraseBytes = "no fallback!".toByteArray(Charsets.UTF_8)
        fixture.vault.createFromPhrase(
            RecoveryPhrase(TEST_PHRASE),
            Tier1AuthInput.Passphrase(phraseBytes),
        )
        phraseBytes.fill(0)

        val biometricAttempt = FakeBiometricGate()
        val wrongMethod = fixture.vault.unlock(Tier1AuthInput.Biometric(biometricAttempt))
        assertTrue(wrongMethod.isFailure)
        assertTrue(wrongMethod.exceptionOrNull() is AuthMethodMismatchException)
        assertEquals("method mismatch must not invoke biometric fallback", 0, biometricAttempt.calls)

        val currentBytes = "no fallback!".toByteArray(Charsets.UTF_8)
        val replacementGate = FakeBiometricGate()
        fixture.vault.changeAuthMethod(
            Tier1AuthInput.Passphrase(currentBytes),
            Tier1AuthInput.Biometric(replacementGate),
        ).getOrThrow()
        currentBytes.fill(0)
        assertEquals(Tier1AuthMethod.BIOMETRIC, fixture.vault.configuredAuthMethod())
        assertEquals(1, replacementGate.calls)
    }

    @Test
    fun missingOrTamperedIdentityFailsClosed() = runBlocking {
        val missing = fixture.vault.unlock(Tier1AuthInput.Biometric(FakeBiometricGate()))
        assertTrue(missing.isFailure)
        assertTrue(missing.exceptionOrNull() is IdentityCorruptException)

        fixture.vault.createFromPhrase(
            RecoveryPhrase(TEST_PHRASE),
            Tier1AuthInput.Biometric(FakeBiometricGate()),
        )
        val raw = identityFile().readBytes()
        raw[raw.lastIndex] = (raw.last().toInt() xor 0xff).toByte()
        identityFile().writeBytes(raw)

        val corrupt = fixture.vault.unlock(Tier1AuthInput.Biometric(FakeBiometricGate()))
        assertTrue(corrupt.isFailure)
        assertTrue(corrupt.exceptionOrNull() is IdentityCorruptException)
    }

    @Test
    fun biometricInvalidationSurfacesAsRecoveryFailure() = runBlocking {
        fixture.vault.createFromPhrase(
            RecoveryPhrase(TEST_PHRASE),
            Tier1AuthInput.Biometric(FakeBiometricGate()),
        )
        val gate = FakeBiometricGate { throw KeyPermanentlyInvalidatedException() }
        val result = fixture.vault.unlock(Tier1AuthInput.Biometric(gate))
        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull() is IdentityInvalidatedException)
    }

    @Test
    fun secondCreateCannotReplaceAnExistingIdentity() = runBlocking {
        fixture.vault.createFromPhrase(
            RecoveryPhrase(TEST_PHRASE),
            Tier1AuthInput.Biometric(FakeBiometricGate()),
        )
        val result = runCatching {
            fixture.vault.createFromPhrase(
                RecoveryPhrase(TEST_PHRASE),
                Tier1AuthInput.Biometric(FakeBiometricGate()),
            )
        }
        assertTrue(result.isFailure)
        assertTrue(fixture.vault.unlock(Tier1AuthInput.Biometric(FakeBiometricGate())).isSuccess)
    }

    @Test
    fun interruptedPartialStagingResumesOnRestartWithoutRepeatingCompletedRows() = runBlocking {
        val root = createLegacyIdentity(rowCount = 2)
        val gate = FakeBiometricGate(failAtCall = 3)
        val interrupted = fixture.vault.unlock(Tier1AuthInput.Biometric(gate))
        assertTrue(interrupted.isFailure)
        assertTrue(interrupted.exceptionOrNull() is BiometricAuthException)
        val journal = fixture.migrator.pending()
        assertNotNull(journal)
        assertEquals(2, journal!!.expectedRows)
        assertEquals(1, fixture.database.credentialDao().countStagedRows(journal.migrationId))
        assertEquals(IdentityContainer.LEGACY_VERSION, IdentityContainer.decode(identityFile().readBytes()).version)

        // A new vault instance represents process death/restart. The test provider
        // retains the same fake Keystore key, as Android Keystore does.
        val restarted = fixture.newVault()
        val retryGate = FakeBiometricGate()
        val session = restarted.unlock(Tier1AuthInput.Biometric(retryGate)).getOrThrow()
        try {
            assertEquals("one identity unwrap, one unstaged row, one new identity wrap", 3, retryGate.calls)
            assertNull(fixture.migrator.pending())
            assertEquals(0, fixture.database.credentialDao().countLegacyRows())
            assertEquals(IdentityContainer.VERSION, IdentityContainer.decode(identityFile().readBytes()).version)
            fixture.credentialStore.open("service-0", session).getOrThrow().use { secret ->
                assertArrayEquals("secret-0".toByteArray(), secret.bytes())
            }
        } finally {
            session.close()
            root.fill(0)
        }
    }

    @Test
    fun completedStagingBeforeFileCommitIsRestartable() = runBlocking {
        createLegacyIdentity(rowCount = 1)
        // 1 identity unwrap + 1 row unwrap + target identity wrap.
        val interrupted = fixture.vault.unlock(
            Tier1AuthInput.Biometric(FakeBiometricGate(failAtCall = 3)),
        )
        assertTrue(interrupted.isFailure)
        val journal = fixture.migrator.pending()!!
        assertEquals(1, fixture.database.credentialDao().countStagedRows(journal.migrationId))
        assertEquals(IdentityContainer.LEGACY_VERSION, IdentityContainer.decode(identityFile().readBytes()).version)

        fixture.newVault().unlock(Tier1AuthInput.Biometric(FakeBiometricGate())).getOrThrow().close()
        assertNull(fixture.migrator.pending())
        assertEquals(0, fixture.database.credentialDao().countLegacyRows())
    }

    @Test
    fun restartAfterIdentityFileCommitPromotesRowsBeforeReturningSession() = runBlocking {
        val root = createLegacyIdentity(rowCount = 1)
        val generation = ByteArray(16).also(SecureRandom()::nextBytes)
        val source = identityFile().readBytes()
        val migration = CredentialWrapMigrationEntity(
            migrationId = "crash-after-file-commit",
            sourceIdentityHash = java.security.MessageDigest.getInstance("SHA-256").digest(source),
            targetGeneration = generation.copyOf(),
            targetAuthMethod = Tier1AuthMethod.BIOMETRIC.name,
            expectedRows = 1,
        )
        fixture.migrator.stageLegacyRows(
            migration,
            root,
            LegacyDekUnwrapper { row ->
                val cipher = WrappedKey.decryptCipher(fixture.keyProvider.legacyKey()!!, row.wrappedDek)
                val authorized = FakeBiometricGate().authorize(cipher, AuthPurpose.MIGRATE_CREDENTIAL)
                WrappedKey.finishDecrypt(authorized, row.wrappedDek)
            },
        )
        val wrapped = Tier1KeyEnvelope(fixture.crypto, fixture.keyProvider).wrap(
            root,
            generation,
            Tier1AuthInput.Biometric(FakeBiometricGate()),
            AuthPurpose.MIGRATE_IDENTITY,
        )
        val sourceContainer = IdentityContainer.decode(source)
        identityFile().writeBytes(
            IdentityContainer(
                wrappedContentKey = wrapped.wrapped,
                sealedBlob = sourceContainer.sealedBlob,
                authMethod = Tier1AuthMethod.BIOMETRIC,
                generation = generation,
                version = IdentityContainer.VERSION,
            ).encode(),
        )

        val session = fixture.newVault().unlock(Tier1AuthInput.Biometric(FakeBiometricGate())).getOrThrow()
        try {
            assertNull(fixture.migrator.pending())
            assertEquals(0, fixture.database.credentialDao().countLegacyRows())
            assertEquals(2, fixture.database.credentialDao().get("service-0")!!.dekWrapVersion)
        } finally {
            session.close()
            root.fill(0)
        }
    }

    private suspend fun createLegacyIdentity(rowCount: Int): ByteArray {
        val root = ByteArray(32).also(SecureRandom()::nextBytes)
        val sealed = fixture.sealed.createSealedIdentity(RecoveryPhrase(TEST_PHRASE), root)
        val wrappedIdentity = WrappedKey.wrap(fixture.keyProvider.legacyKey()!!, root)
        identityFile().writeBytes(
            IdentityContainer(wrappedContentKey = wrappedIdentity, sealedBlob = sealed.blob).encode(),
        )
        repeat(rowCount) { index ->
            val service = "service-$index"
            val dek = ByteArray(32).also(SecureRandom()::nextBytes)
            try {
                fixture.database.credentialDao().upsert(
                    CredentialEntity(
                        service = service,
                        secretCiphertext = fixture.sealed.sealCredential("secret-$index".toByteArray(), dek),
                        wrappedDek = WrappedKey.wrap(fixture.keyProvider.legacyKey()!!, dek),
                        createdAt = index.toLong(),
                    ),
                )
            } finally {
                dek.fill(0)
            }
        }
        return root
    }

    private fun identityFile() = File(context.filesDir, "identity.enc")

    private fun clearIdentityFiles() {
        listOf("identity.enc", "identity.enc.bak", "identity.enc.new").forEach {
            File(context.filesDir, it).delete()
        }
    }

    private companion object {
        const val TEST_PHRASE =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon " +
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon " +
                "abandon abandon abandon abandon abandon art"
    }
}
