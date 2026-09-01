package com.ahlyxlabs.conveyance.transport.ble

import com.ahlyxlabs.conveyance.transport.ConnectionStateMachine
import com.ahlyxlabs.conveyance.transport.link.LinkTeardown
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * Confines one BLE connection's state to a single dispatcher.
 *
 * `BluetoothGattServerCallback` methods run on binder threads; they do
 * the minimum (copy bytes, answer the request) and then call [onEvent],
 * which only `trySend`s onto a channel. The loop that drains that
 * channel — and everything it touches: the [ConnectionStateMachine],
 * and (commit 4) the outbound `Framer` and the `InboundAssembler` — runs
 * exclusively on [dispatcher]. No locks.
 *
 * One actor per session. On teardown its scope is cancelled and the
 * server closed; a new session builds a new actor. The [dispatcher]
 * (a `@BleDispatcher` single thread) outlives it.
 */
class BleActor(private val dispatcher: CoroutineDispatcher) {

    private val scope = CoroutineScope(dispatcher + SupervisorJob())
    private val events = Channel<ConnectionStateMachine.Event>(Channel.UNLIMITED)
    private val machine = ConnectionStateMachine()
    private var server: GattServerHandle? = null

    private val _state = MutableStateFlow(ConnectionStateMachine.State.IDLE)
    val state: StateFlow<ConnectionStateMachine.State> = _state.asStateFlow()

    init {
        scope.launch {
            for (event in events) process(event)
        }
    }

    /** Wire the server handle once `openGattServer` has returned. */
    fun attachServer(handle: GattServerHandle) {
        server = handle
    }

    /** Thread-safe entry from binder callback threads. */
    fun onEvent(event: ConnectionStateMachine.Event) {
        events.trySend(event)
    }

    /** Idempotent local teardown — kill switch, session end, 10.4. */
    fun shutdown() = onEvent(ConnectionStateMachine.Event.ShutdownRequested)

    private fun process(event: ConnectionStateMachine.Event) {
        val effects = machine.on(event)
        _state.value = machine.state
        for (effect in effects) {
            when (effect) {
                is ConnectionStateMachine.Effect.SetMaxWriteLen -> onMaxWriteLen(effect.bytes)
                ConnectionStateMachine.Effect.LinkReady -> onLinkReady()
                is ConnectionStateMachine.Effect.TearDown -> teardown(effect.reason)
            }
        }
    }

    // Filled in by commit 4 (GattPhoneLink outbound/inbound wiring).
    private fun onMaxWriteLen(@Suppress("UNUSED_PARAMETER") bytes: Int) {}

    private fun onLinkReady() {}

    private fun teardown(@Suppress("UNUSED_PARAMETER") reason: LinkTeardown) {
        server?.close()
        server = null
        events.close()
        scope.cancel()
    }
}
