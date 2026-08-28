package com.ahlyxlabs.conveyance.storage.di

import android.content.Context
import androidx.room.Room
import com.ahlyxlabs.conveyance.storage.credentials.CredentialDao
import com.ahlyxlabs.conveyance.storage.credentials.CredentialDatabase
import com.ahlyxlabs.conveyance.storage.db.DatabasePassphrase
import com.ahlyxlabs.conveyance.storage.db.SqlCipherFactory
import com.ahlyxlabs.conveyance.storage.log.ApprovalDatabase
import com.ahlyxlabs.conveyance.storage.log.LogDao
import com.ahlyxlabs.conveyance.storage.pairings.PairingDao
import com.ahlyxlabs.conveyance.storage.pairings.PairingsDatabase
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * Constructs the Room + SQLCipher databases. Split from the `@Binds`
 * module ([StorageModule]) because Hilt does not allow `@Provides` and
 * `@Binds` in the same abstract class.
 */
@Module
@InstallIn(SingletonComponent::class)
object StorageProvideModule {

    @Provides
    @Singleton
    fun credentialDatabase(
        @ApplicationContext context: Context,
        passphrase: DatabasePassphrase,
    ): CredentialDatabase =
        Room.databaseBuilder(context, CredentialDatabase::class.java, CredentialDatabase.FILE_NAME)
            .openHelperFactory(SqlCipherFactory.create(passphrase.get()))
            .build()

    @Provides
    fun credentialDao(db: CredentialDatabase): CredentialDao = db.credentialDao()

    @Provides
    @Singleton
    fun approvalDatabase(
        @ApplicationContext context: Context,
        passphrase: DatabasePassphrase,
    ): ApprovalDatabase =
        Room.databaseBuilder(context, ApprovalDatabase::class.java, ApprovalDatabase.FILE_NAME)
            .openHelperFactory(SqlCipherFactory.create(passphrase.get()))
            .build()

    @Provides
    fun logDao(db: ApprovalDatabase): LogDao = db.logDao()

    @Provides
    @Singleton
    fun pairingsDatabase(
        @ApplicationContext context: Context,
        passphrase: DatabasePassphrase,
    ): PairingsDatabase =
        Room.databaseBuilder(context, PairingsDatabase::class.java, PairingsDatabase.FILE_NAME)
            .openHelperFactory(SqlCipherFactory.create(passphrase.get()))
            .build()

    @Provides
    fun pairingDao(db: PairingsDatabase): PairingDao = db.pairingDao()
}
