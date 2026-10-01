package com.ahlyxlabs.conveyance.storage

import android.content.Context
import androidx.room.Room
import com.ahlyxlabs.conveyance.crypto.UniffiConveyanceCrypto
import com.ahlyxlabs.conveyance.crypto.UniffiSealedIdentityCrypto
import com.ahlyxlabs.conveyance.storage.credentials.CredentialAccessLock
import com.ahlyxlabs.conveyance.storage.credentials.CredentialDatabase
import com.ahlyxlabs.conveyance.storage.credentials.CredentialDekEnvelope
import com.ahlyxlabs.conveyance.storage.credentials.CredentialStore
import com.ahlyxlabs.conveyance.storage.credentials.CredentialWrapMigrator
import com.ahlyxlabs.conveyance.storage.identity.IdentityVault
import com.ahlyxlabs.conveyance.storage.identity.Tier1KeyEnvelope
import java.io.Closeable

/** Real Rust crypto and Room, with only the hardware-bound key replaced. */
internal class IdentityStorageFixture(private val context: Context) : Closeable {
    val crypto = UniffiConveyanceCrypto()
    val sealed = UniffiSealedIdentityCrypto()
    val keyProvider = StubTier1KeyProvider()
    val database = Room.inMemoryDatabaseBuilder(
        context,
        CredentialDatabase::class.java,
    ).build()
    val accessLock = CredentialAccessLock()
    val envelope = CredentialDekEnvelope(crypto)
    val migrator = CredentialWrapMigrator(
        database,
        database.credentialDao(),
        envelope,
        accessLock,
    )
    val vault = newVault()
    val credentialStore = CredentialStore(
        database.credentialDao(),
        sealed,
        envelope,
        accessLock,
    )

    fun newVault() = IdentityVault(
        context,
        sealed,
        keyProvider,
        Tier1KeyEnvelope(crypto, keyProvider),
        migrator,
    )

    override fun close() {
        database.close()
    }
}
