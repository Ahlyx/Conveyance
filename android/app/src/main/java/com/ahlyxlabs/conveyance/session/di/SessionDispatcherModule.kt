package com.ahlyxlabs.conveyance.session.di

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
 * Marks the single-thread dispatcher that confines all Noise-session state —
 * the [com.ahlyxlabs.conveyance.session.SessionStateMachine], the
 * [com.ahlyxlabs.conveyance.session.SessionTimers], the outbound frame
 * sequence, and the `InboundAssembler` — for one `PhoneSession`.
 *
 * Deliberately **separate** from `@BleDispatcher` (10.3b). `PhoneSession`
 * talks to the BLE layer only through `PhoneLink`'s async seam
 * (`suspend send`, `events: Flow`): a slow radio back-pressures `send()`,
 * and blocking the BLE dispatcher on itself would deadlock. Two
 * single-thread dispatchers, communicating over channels, keep each side's
 * state lock-free.
 *
 * Tests substitute a `StandardTestDispatcher` on this seam for deterministic
 * timer virtual time.
 */
@Qualifier
@Retention(AnnotationRetention.BINARY)
annotation class SessionDispatcher

@Module
@InstallIn(SingletonComponent::class)
object SessionDispatcherModule {

    /**
     * Process-lifetime, exactly as `@BleDispatcher`: the thread is cheap and
     * tearing a dispatcher down per session invites use-after-close races. A
     * session's work runs in a `CoroutineScope(dispatcher + SupervisorJob())`
     * that IS cancelled on teardown; the dispatcher outlives it.
     */
    @Provides
    @Singleton
    @SessionDispatcher
    fun sessionDispatcher(): CoroutineDispatcher =
        Executors.newSingleThreadExecutor { r -> Thread(r, "conveyance-session") }
            .asCoroutineDispatcher()
}
