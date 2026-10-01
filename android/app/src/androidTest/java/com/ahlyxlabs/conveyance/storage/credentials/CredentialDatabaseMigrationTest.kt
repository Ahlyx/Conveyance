package com.ahlyxlabs.conveyance.storage.credentials

import android.content.Context
import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class CredentialDatabaseMigrationTest {
    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private val name = "credential-v1-to-v2-test.db"
    private var legacy: LegacyCredentialDatabase? = null
    private var migrated: CredentialDatabase? = null

    @Before
    fun clear() {
        context.getDatabasePath(name).also { it.parentFile?.mkdirs(); it.delete() }
    }

    @After
    fun closeAndClear() {
        legacy?.close()
        migrated?.close()
        context.getDatabasePath(name).delete()
    }

    @Test
    fun oneToTwoMigrationPreservesRowsAsLegacyAndCreatesJournalTable() = runBlocking {
        legacy = Room.databaseBuilder(context, LegacyCredentialDatabase::class.java, name).build()
        val ciphertext = byteArrayOf(1, 2, 3, 4)
        val wrappedDek = byteArrayOf(9, 8, 7, 6)
        legacy!!.credentialDao().insert(
            LegacyCredentialEntity("service", ciphertext, wrappedDek, 123L),
        )
        legacy!!.close()
        legacy = null

        migrated = Room.databaseBuilder(context, CredentialDatabase::class.java, name)
            .addMigrations(CredentialDatabase.MIGRATION_1_2)
            .build()
        val row = migrated!!.credentialDao().get("service")!!

        assertArrayEquals(ciphertext, row.secretCiphertext)
        assertArrayEquals(wrappedDek, row.wrappedDek)
        assertEquals(123L, row.createdAt)
        assertEquals(CredentialEntity.LEGACY_DEK_WRAP_VERSION, row.dekWrapVersion)
        assertNull(row.pendingWrappedDek)
        assertNull(row.pendingMigrationId)
        assertEquals(1, migrated!!.credentialDao().countLegacyRows())
        assertNull(migrated!!.credentialDao().migration())
    }
}
