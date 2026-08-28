package com.ahlyxlabs.conveyance.storage.credentials

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteException
import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ahlyxlabs.conveyance.crypto.UniffiSealedIdentityCrypto
import com.ahlyxlabs.conveyance.storage.FakeBiometricGate
import com.ahlyxlabs.conveyance.storage.StubTier1KeyProvider
import com.ahlyxlabs.conveyance.storage.db.SqlCipherFactory
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

    private val context: Context =
        InstrumentationRegistry.getInstrumentation().targetContext
    private val dbName = "credtest.enc"
    private val passphrase = ByteArray(32) { (it + 1).toByte() }

    private lateinit var db: CredentialDatabase
    private lateinit var store: CredentialStore

    private fun newStore(): CredentialStore =
        CredentialStore(db.credentialDao(), UniffiSealedIdentityCrypto(), StubTier1KeyProvider())

    private fun openDb() {
        db = Room.databaseBuilder(context, CredentialDatabase::class.java, dbName)
            .openHelperFactory(SqlCipherFactory.create(passphrase.copyOf()))
            .build()
        store = newStore()
    }

    @Before
    fun setUp() {
        context.getDatabasePath(dbName).also { it.parentFile?.mkdirs(); it.delete() }
        openDb()
    }

    @After
    fun tearDown() {
        if (::db.isInitialized) db.close()
        context.getDatabasePath(dbName).delete()
    }

    @Test
    fun addListRemoveOpenRoundTrips() = runBlocking {
        val secret = "AKIAIOSFODNN7EXAMPLE".toByteArray()
        store.add("aws", secret, FakeBiometricGate())
        store.add("github", "ghp_xxx".toByteArray(), FakeBiometricGate())

        assertEquals(listOf("aws", "github"), store.listServices())

        store.open("aws", FakeBiometricGate()).getOrThrow().use { s ->
            assertArrayEquals(secret, s.bytes())
        }

        assertTrue(store.remove("github"))
        assertEquals(listOf("aws"), store.listServices())
        assertFalse(store.remove("github"))
    }

    @Test
    fun openingOneServiceAuthorizesOnceAndYieldsOnlyThatSecret() = runBlocking {
        store.add("aws", "aws-secret".toByteArray(), FakeBiometricGate())
        store.add("github", "github-secret".toByteArray(), FakeBiometricGate())

        val gate = FakeBiometricGate()
        store.open("aws", gate).getOrThrow().use { s ->
            assertArrayEquals("aws-secret".toByteArray(), s.bytes())
        }
        assertEquals("exactly one DEK unwrap for one row", 1, gate.calls)
    }

    @Test
    fun openMissingServiceIsNotFoundFailure() = runBlocking {
        val result = store.open("nope", FakeBiometricGate())
        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull() is CredentialException.NotFound)
    }

    @Test
    fun openTamperedCiphertextIsUndecryptableFailure() = runBlocking {
        store.add("aws", "secret".toByteArray(), FakeBiometricGate())
        val row = db.credentialDao().get("aws")!!
        val corrupted = row.secretCiphertext.copyOf()
        corrupted[corrupted.size - 1] = (corrupted[corrupted.size - 1].toInt() xor 0xFF).toByte()
        db.credentialDao().upsert(row.copy(secretCiphertext = corrupted))

        val result = store.open("aws", FakeBiometricGate())
        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull() is CredentialException.Undecryptable)
    }

    /**
     * Proves SQLCipher is actually engaged: a plain platform SQLite
     * driver cannot open or enumerate the file, and the file does not
     * carry the plaintext SQLite header. A grep-for-known-plaintext check
     * would pass even with encryption disabled; this does not.
     */
    @Test
    fun databaseFileIsEncryptedAtRest() = runBlocking {
        store.add("aws", "AKIA-super-secret-value".toByteArray(), FakeBiometricGate())
        db.close()

        val raw: File = context.getDatabasePath(dbName)

        assertThrows(SQLiteException::class.java) {
            val plain = SQLiteDatabase.openDatabase(raw.path, null, SQLiteDatabase.OPEN_READONLY)
            plain.rawQuery("SELECT name FROM sqlite_master", null).use { it.count }
            plain.close()
        }

        // The 16-byte plaintext SQLite header: "SQLite format 3" + NUL.
        val sqliteMagic = byteArrayOf(
            0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66,
            0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00,
        )
        val header = ByteArray(16)
        raw.inputStream().use { input ->
            var off = 0
            while (off < 16) {
                val n = input.read(header, off, 16 - off)
                if (n < 0) break
                off += n
            }
        }
        assertFalse("file must not start with the SQLite magic", sqliteMagic.contentEquals(header))

        // Reopen with the correct key: the row is intact — encryption, not corruption.
        openDb()
        assertEquals(listOf("aws"), newStore().listServices())
    }
}
