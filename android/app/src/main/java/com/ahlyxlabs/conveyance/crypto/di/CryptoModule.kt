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
 * Consumers inject the primitive and sealed-identity interfaces; their
 * UniFFI implementations are bound here and nowhere else. Singleton
 * because the adapters are stateless and the native library loads once
 * per process. Identity keys remain in the sealed Rust handle, not these
 * bindings' Kotlin objects.
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
