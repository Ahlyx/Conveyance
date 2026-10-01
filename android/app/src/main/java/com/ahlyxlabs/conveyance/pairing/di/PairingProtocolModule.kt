package com.ahlyxlabs.conveyance.pairing.di

import com.ahlyxlabs.conveyance.pairing.PairingProtocol
import com.ahlyxlabs.conveyance.pairing.RustPairingProtocol
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
abstract class PairingProtocolModule {
    @Binds
    @Singleton
    abstract fun bindPairingProtocol(impl: RustPairingProtocol): PairingProtocol
}
