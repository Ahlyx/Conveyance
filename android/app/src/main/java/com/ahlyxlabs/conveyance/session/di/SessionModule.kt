package com.ahlyxlabs.conveyance.session.di

import com.ahlyxlabs.conveyance.session.NoiseSessionCrypto
import com.ahlyxlabs.conveyance.session.UniffiNoiseSessionCrypto
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * Session-layer DI. Grows in 10.4b with `@SessionDispatcher` and the
 * `PhoneSession` factory; for now it binds the Noise bridge.
 *
 * Singleton because the implementation is stateless (each session is its
 * own `NoiseSession` handle) and the native library loads once.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class SessionModule {

    @Binds
    @Singleton
    abstract fun bindNoiseSessionCrypto(impl: UniffiNoiseSessionCrypto): NoiseSessionCrypto
}
