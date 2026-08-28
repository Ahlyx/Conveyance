package com.ahlyxlabs.conveyance.storage.pairings

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteException
import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ahlyxlabs.conveyance.storage.db.SqlCipherFactory
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class PairingStoreTest {

    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private val dbName = "pairings-test.db"
    private val passphrase = ByteArray(32) { (it + 13).toByte() }

    private lateinit var db: PairingsDatabase
    private lateinit var store: PairingStore

    private fun pairing(idByte: Int, name: String) = PairingEntity(
        pcIdPub = ByteArray(32) { idByte.toByte() },
        pcDhPub = ByteArray(32) { (idByte + 1).toByte() },
        pcName = name,
        firstPairedAt = 1_700_000_000L + idByte,
    )

    @Before
    fun setUp() {
        context.getDatabasePath(dbName).also { it.parentFile?.mkdirs(); it.delete() }
        db = Room.databaseBuilder(context, PairingsDatabase::class.java, dbName)
            .openHelperFactory(SqlCipherFactory.create(passphrase.copyOf()))
            .build()
        store = PairingStore(db.pairingDao())
    }

    @After
    fun tearDown() {
        if (::db.isInitialized) db.close()
        context.getDatabasePath(dbName).delete()
    }

    @Test
    fun saveGetAllDeleteRoundTrips() = runBlocking {
        val a = pairing(1, "workstation")
        val b = pairing(2, "laptop")
        store.save(a)
        store.save(b)

        assertEquals(a, store.get(a.pcIdPub))
        assertEquals(listOf(a, b), store.all())

        assertTrue(store.remove(a.pcIdPub))
        assertNull(store.get(a.pcIdPub))
        assertFalse(store.remove(a.pcIdPub))
        assertEquals(listOf(b), store.all())
    }

    @Test
    fun saveReplacesByPcIdPub() = runBlocking {
        store.save(pairing(1, "old-name"))
        store.save(pairing(1, "new-name"))
        assertEquals(1, store.all().size)
        assertEquals("new-name", store.get(ByteArray(32) { 1 })!!.pcName)
    }

    @Test
    fun touchLastSessionUpdatesOnlyThatRow() = runBlocking {
        store.save(pairing(1, "a"))
        store.save(pairing(2, "b"))
        assertTrue(store.touchLastSession(ByteArray(32) { 1 }, 1_800_000_000L))
        assertEquals(1_800_000_000L, store.get(ByteArray(32) { 1 })!!.lastSessionAt)
        assertNull(store.get(ByteArray(32) { 2 })!!.lastSessionAt)
        assertFalse(store.touchLastSession(ByteArray(32) { 9 }, 1L))
    }

    @Test
    fun databaseFileIsEncryptedAtRest() = runBlocking {
        store.save(pairing(1, "workstation-hostname"))
        db.close()

        val raw = context.getDatabasePath(dbName)
        assertThrows(SQLiteException::class.java) {
            val plain = SQLiteDatabase.openDatabase(raw.path, null, SQLiteDatabase.OPEN_READONLY)
            plain.rawQuery("SELECT name FROM sqlite_master", null).use { it.count }
            plain.close()
        }
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
        assertFalse(sqliteMagic.contentEquals(header))
    }
}
