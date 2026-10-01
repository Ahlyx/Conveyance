package com.ahlyxlabs.conveyance.storage.keystore.di

import com.ahlyxlabs.conveyance.storage.keystore.AndroidBiometricGate
import com.ahlyxlabs.conveyance.storage.keystore.BiometricGate
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.android.components.ActivityComponent
import dagger.hilt.android.scopes.ActivityScoped

@Module
@InstallIn(ActivityComponent::class)
abstract class BiometricModule {
    @Binds
    @ActivityScoped
    abstract fun bindBiometricGate(impl: AndroidBiometricGate): BiometricGate
}
