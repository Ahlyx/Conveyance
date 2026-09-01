package com.ahlyxlabs.conveyance.transport.ble.di

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import java.util.concurrent.Executors
import javax.inject.Qualifier
import javax.inject.Singleton
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.asCoroutineDispatcher

/**
 * Marks the single-thread dispatcher that confines all BLE
 * connection/session state — the `ConnectionStateMachine`, the outbound
 * `Framer` + sequence counter, the `InboundAssembler`.
 *
 * `BluetoothGattServerCallback` methods arrive on binder threads; they
 * copy their bytes and hand the work to this dispatcher, and nothing
 * else ever touches that state, so there are no locks. Instrumented and
 * unit tests substitute a `StandardTestDispatcher` on this seam for
 * deterministic timing.
 */
@Qualifier
@Retention(AnnotationRetention.BINARY)
annotation class BleDispatcher

@Module
@InstallIn(SingletonComponent::class)
object BleDispatcherModule {

    /**
     * Process-lifetime: the thread is cheap and the alternative — tearing
     * a dispatcher down per session — invites use-after-close races. A
     * session's work runs in a `CoroutineScope(dispatcher + SupervisorJob())`
     * that IS cancelled on teardown; the dispatcher outlives it.
     */
    @Provides
    @Singleton
    @BleDispatcher
    fun bleDispatcher(): CoroutineDispatcher =
        Executors.newSingleThreadExecutor { r -> Thread(r, "conveyance-ble") }
            .asCoroutineDispatcher()
}
