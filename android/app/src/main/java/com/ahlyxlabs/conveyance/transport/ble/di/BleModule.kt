package com.ahlyxlabs.conveyance.transport.ble.di

import com.ahlyxlabs.conveyance.transport.ble.AdapterWatch
import com.ahlyxlabs.conveyance.transport.ble.SystemAdapterWatch
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent

/**
 * BLE-layer bindings. [BlePermissions], [ConveyanceAdvertiser] and
 * [BlePeripheral] are `@Inject`-constructable; this only binds the one
 * interface with a non-trivial implementation.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class BleModule {

    @Binds
    abstract fun bindAdapterWatch(impl: SystemAdapterWatch): AdapterWatch
}
