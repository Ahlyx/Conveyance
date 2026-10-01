package com.ahlyxlabs.conveyance.storage.credentials

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteException
import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ahlyxlabs.conveyance.crypto.RecoveryPhrase
import com.ahlyxlabs.conveyance.crypto.UniffiConveyanceCrypto
import com.ahlyxlabs.conveyance.crypto.UniffiSealedIdentityCrypto
import com.ahlyxlabs.conveyance.storage.FakeBiometricGate
import com.ahlyxlabs.conveyance.storage.StubTier1KeyProvider
import com.ahlyxlabs.conveyance.storage.db.SqlCipherFactory
import com.ahlyxlabs.conveyance.storage.identity.IdentityVault
import com.ahlyxlabs.conveyance.storage.identity.Tier1AuthInput
import com.ahlyxlabs.conveyance.storage.identity.Tier1KeyEnvelope
import com.ahlyxlabs.conveyance.storage.identity.UnlockedPhoneSession
import java.io.File
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class CredentialStoreTest {

    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private val dbName = "credtest.enc"
    private val passphrase = ByteArray(32) { (it + 1).toByte() }

    private lateinit var db: CredentialDatabase
    private lateinit var store: CredentialStore
    private lateinit var session: UnlockedPhoneSession
    private lateinit var accessLock: CredentialAccessLock
    private lateinit var sealed: UniffiSealedIdentityCrypto
    private lateinit var sessionUnlockGate: FakeBiometricGate

    private fun openDb(initializeIdentity: Boolean = true) {
        db = Room.databaseBuilder(context, CredentialDatabase::class.java, dbName)
            .openHelperFactory(SqlCipherFactory.create(passphrase.copyOf()))
            .addMigrations(CredentialDatabase.MIGRATION_1_2)
            .build()
        val crypto = UniffiConveyanceCrypto()
        sealed = UniffiSealedIdentityCrypto()
        val keys = StubTier1KeyProvider()
        accessLock = CredentialAccessLock()
        val envelope = CredentialDekEnvelope(crypto)
        val migrator = CredentialWrapMigrator(db, db.credentialDao(), envelope, accessLock)
        store = CredentialStore(db.credentialDao(), sealed, envelope, accessLock)
        val vault = IdentityVault(
            context,
            sealed,
            keys,
            Tier1KeyEnvelope(crypto, keys),
            migrator,
        )
        if (initializeIdentity) runBlocking {
            File(context.filesDir, "identity.enc").delete()
            vault.createFromPhrase(
                RecoveryPhrase(TEST_PHRASE),
                Tier1AuthInput.Biometric(FakeBiometricGate()),
            )
            sessionUnlockGate = FakeBiometricGate()
            session = vault.unlock(Tier1AuthInput.Biometric(sessionUnlockGate)).getOrThrow()
        }
    }

    @Before
    fun setUp() {
        context.getDatabasePath(dbName).also { it.parentFile?.mkdirs(); it.delete() }
        openDb()
    }

    @After
    fun tearDown() {
        if (::session.isInitialized) session.close()
        if (::db.isInitialized) db.close()
        context.getDatabasePath(dbName).delete()
        File(context.filesDir, "identity.enc").delete()
    }

    @Test
    fun addListRemoveAndOpenUseTheUnlockedVaultSession() = runBlocking {
        val secret = "AKIAIOSFODNN7EXAMPLE".toByteArray()
        store.add("aws", secret, session)
        store.add("github", "ghp_xxx".toByteArray(), session)

        assertEquals(listOf("aws", "github"), store.listServices())
        store.open("aws", session).getOrThrow().use { opened ->
            assertArrayEquals(secret, opened.bytes())
        }

        assertTrue(store.remove("github"))
        assertEquals(listOf("aws"), store.listServices())
        assertFalse(store.remove("github"))
    }

    @Test
    fun openingAnotherCredentialDoesNotTriggerAnotherTier1Prompt() = runBlocking {
        store.add("aws", "aws-secret".toByteArray(), session)
        store.add("github", "github-secret".toByteArray(), session)

        // Credential access consumes the in-memory vault key; it does not
        // reauthorize a Keystore operation per row.
        assertEquals(1, sessionUnlockGate.calls)
        store.open("aws", session).getOrThrow().close()
        store.open("github", session).getOrThrow().close()
        assertEquals(1, sessionUnlockGate.calls)
    }

    @Test
    fun openMissingServiceIsNotFoundFailure() = runBlocking {
        val result = store.open("nope", session)
        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull() is CredentialException.NotFound)
    }

    @Test
    fun openTamperedSecretCiphertextIsUndecryptableFailure() = runBlocking {
        store.add("aws", "secret".toByteArray(), session)
        val row = db.credentialDao().get("aws")!!
        val corrupted = row.secretCiphertext.copyOf()
        corrupted[corrupted.lastIndex] = (corrupted.last().toInt() xor 0xff).toByte()
        db.credentialDao().upsert(row.copy(secretCiphertext = corrupted))

        val result = store.open("aws", session)
        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull() is CredentialException.Undecryptable)
    }

    @Test
    fun wrongServiceCannotReuseWrappedDek() = runBlocking {
        store.add("aws", "secret".toByteArray(), session)
        val row = db.credentialDao().get("aws")!!
        db.credentialDao().upsert(row.copy(service = "different-service"))
        val result = store.open("different-service", session)
        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull() is CredentialException.Undecryptable)
    }

    /** SQLCipher is engaged: plain SQLite cannot open this database file. */
    @Test
    fun databaseFileIsEncryptedAtRest() = runBlocking {
        store.add("aws", "AKIA-super-secret-value".toByteArray(), session)
        session.close()
        db.close()

        val raw: File = context.getDatabasePath(dbName)
        assertThrows(SQLiteException::class.java) {
            val plain = SQLiteDatabase.openDatabase(raw.path, null, SQLiteDatabase.OPEN_READONLY)
            plain.rawQuery("SELECT name FROM sqlite_master", null).use { it.count }
            plain.close()
        }
        val sqliteMagic = byteArrayOf(
            0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66,
            0x6f, 0x72, 0x6d, 0x61, 0x74, 0x20, 0x33, 0x00,
        )
        val header = ByteArray(16)
        raw.inputStream().use { input ->
            var off = 0
            while (off < header.size) {
                val count = input.read(header, off, header.size - off)
                if (count < 0) break
                off += count
            }
        }
        assertFalse("file must not start with the SQLite magic", sqliteMagic.contentEquals(header))

        openDb(initializeIdentity = false)
        assertEquals(listOf("aws"), store.listServices())
    }

    private companion object {
        const val TEST_PHRASE =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon " +
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon " +
                "abandon abandon abandon abandon abandon art"
    }
}
