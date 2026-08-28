package com.ahlyxlabs.conveyance.crypto.di

import com.ahlyxlabs.conveyance.crypto.ConveyanceCrypto
import com.ahlyxlabs.conveyance.crypto.SealedIdentityCrypto
import com.ahlyxlabs.conveyance.crypto.UniffiConveyanceCrypto
import com.ahlyxlabs.conveyance.crypto.UniffiSealedIdentityCrypto
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * Binds [ConveyanceCrypto] to its UniFFI-backed implementation.
 *
 * Consumers inject the interface; that they get [UniffiConveyanceCrypto]
 * today, and a Keystore-backed implementation in Phase 10.2, is settled
 * here and nowhere else. Singleton because the implementation is
 * stateless and the underlying native library loads once per process.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class CryptoModule {
    @Binds
    @Singleton
    abstract fun bindConveyanceCrypto(impl: UniffiConveyanceCrypto): ConveyanceCrypto

    @Binds
    @Singleton
    abstract fun bindSealedIdentityCrypto(impl: UniffiSealedIdentityCrypto): SealedIdentityCrypto
}
