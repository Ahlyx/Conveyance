package com.ahlyxlabs.conveyance.storage.di

import com.ahlyxlabs.conveyance.storage.identity.KeystoreTier1KeyProvider
import com.ahlyxlabs.conveyance.storage.identity.Tier1KeyProvider
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * Storage-layer DI bindings. Grows through 10.2 — for now it wires the
 * production `conveyance_tier1` key into [IdentityVault]; instrumented
 * tests substitute a non-auth key on this seam.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class StorageModule {
    @Binds
    @Singleton
    abstract fun bindTier1KeyProvider(impl: KeystoreTier1KeyProvider): Tier1KeyProvider
}
