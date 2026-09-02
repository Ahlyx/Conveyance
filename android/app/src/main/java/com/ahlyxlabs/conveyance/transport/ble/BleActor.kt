package com.ahlyxlabs.conveyance.transport.ble

import com.ahlyxlabs.conveyance.transport.ConnectionStateMachine
import com.ahlyxlabs.conveyance.transport.framing.Frame
import com.ahlyxlabs.conveyance.transport.link.LinkClosedException
import com.ahlyxlabs.conveyance.transport.link.LinkEvent
import com.ahlyxlabs.conveyance.transport.link.LinkTeardown
import com.ahlyxlabs.conveyance.transport.link.PhoneLink
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Confines one BLE connection's state to a single dispatcher.
 *
 * `BluetoothGattServerCallback` methods run on binder threads; they do
 * the minimum (copy bytes, answer the request) and hand off to this
 * actor via [onEvent] / [onInboundBytes] / [onNotificationResult], each
 * of which only `trySend`s onto a channel. The [ConnectionStateMachine]
 * and the one-notification-in-flight gate run exclusively on
 * [dispatcher]. No locks on connection state; [sendMutex] serialises the
 * outbound path.
 *
 * One actor per session. On teardown its scope is cancelled, the server
 * closed, and [link]'s event stream ends with [LinkEvent.Torn]; a new
 * session builds a new actor. The [dispatcher] (a `@BleDispatcher` single
 * thread) outlives it.
 */
class BleActor(
    private val dispatcher: CoroutineDispatcher,
    private val adapterWatch: AdapterWatch? = null,
) {

    private val scope = CoroutineScope(dispatcher + SupervisorJob())
    private val events = Channel<ConnectionStateMachine.Event>(Channel.UNLIMITED)
    private val machine = ConnectionStateMachine()
    private var server: GattServerHandle? = null

    private val _state = MutableStateFlow(ConnectionStateMachine.State.IDLE)
    val state: StateFlow<ConnectionStateMachine.State> = _state.asStateFlow()

    // -- outbound / inbound (used once LinkReady) ---------------------------
    private val linkEvents = Channel<LinkEvent>(Channel.BUFFERED)
    private val notifyResults = Channel<Boolean>(Channel.CONFLATED)
    private val sendMutex = Mutex()
    private var currentMaxWriteLen = Frame.maxFramePayload(Frame.MIN_ATT_MTU)
    private var torn = false
    private var teardownReason: LinkTeardown? = null

    /** The usable link, non-null from `SUBSCRIBED` until teardown. */
    @Volatile
    var link: PhoneLink? = null
        private set

    init {
        scope.launch {
            for (event in events) process(event)
        }
    }

    /**
     * Wire the server handle once `openGattServer` has returned, and
     * start watching for the adapter turning off. Both are released in
     * [teardown].
     */
    fun attachServer(handle: GattServerHandle) {
        server = handle
        adapterWatch?.start { onEvent(ConnectionStateMachine.Event.AdapterOff) }
    }

    /** Thread-safe entry from binder callback threads. */
    fun onEvent(event: ConnectionStateMachine.Event) {
        events.trySend(event)
    }

    /** Inbound app bytes from a `pc_to_phone_tx` write. Thread-safe. */
    fun onInboundBytes(bytes: ByteArray) {
        linkEvents.trySend(LinkEvent.Chunk(bytes))
    }

    /** `onNotificationSent` result: `status == GATT_SUCCESS`. Thread-safe. */
    fun onNotificationResult(delivered: Boolean) {
        notifyResults.trySend(delivered)
    }

    /** Idempotent local teardown — kill switch, session end, 10.4. */
    fun shutdown() = onEvent(ConnectionStateMachine.Event.ShutdownRequested)

    private fun process(event: ConnectionStateMachine.Event) {
        val effects = machine.on(event)
        _state.value = machine.state
        for (effect in effects) {
            when (effect) {
                is ConnectionStateMachine.Effect.SetMaxWriteLen -> currentMaxWriteLen = effect.bytes
                ConnectionStateMachine.Effect.LinkReady -> link = GattPhoneLink()
                is ConnectionStateMachine.Effect.TearDown -> teardown(effect.reason)
            }
        }
    }

    /**
     * The single teardown path. Reached either from a
     * [ConnectionStateMachine.Effect.TearDown] on the event loop, or
     * directly from [notifyOnce] when a notification fails — so it sets
     * [_state] itself rather than relying on the loop, which stops here
     * (the event channel is closed). Idempotent.
     */
    private fun teardown(reason: LinkTeardown) {
        if (torn) return
        torn = true
        teardownReason = reason
        _state.value = ConnectionStateMachine.State.TORN
        link = null
        adapterWatch?.stop()
        server?.close()
        server = null
        linkEvents.trySend(LinkEvent.Torn(reason))
        linkEvents.close()
        events.close()
        scope.cancel()
    }

    private suspend fun notifyOnce(frame: ByteArray): Unit = sendMutex.withLock {
        withContext(dispatcher) {
            if (torn || _state.value != ConnectionStateMachine.State.SUBSCRIBED) {
                throw LinkClosedException(teardownReason ?: LinkTeardown.LocalShutdown)
            }
            require(frame.size <= currentMaxWriteLen + Frame.HEADER_LEN) {
                "frame ${frame.size} exceeds one PDU (${currentMaxWriteLen + Frame.HEADER_LEN})"
            }
            val srv = server ?: throw LinkClosedException(LinkTeardown.LocalShutdown)

            // Discard any late ack from a previous frame.
            while (notifyResults.tryReceive().isSuccess) { /* drain */ }

            if (!srv.notify(frame)) {
                teardown(LinkTeardown.PeerDisconnected)
                throw LinkClosedException(LinkTeardown.PeerDisconnected)
            }
            val delivered = withTimeoutOrNull(NOTIFY_ACK_TIMEOUT_MS) { notifyResults.receive() }
            if (delivered != true) {
                teardown(LinkTeardown.PeerDisconnected)
                throw LinkClosedException(LinkTeardown.PeerDisconnected)
            }
        }
    }

    private inner class GattPhoneLink : PhoneLink {
        override val maxWriteLen: Int get() = currentMaxWriteLen
        override val events: Flow<LinkEvent> = linkEvents.receiveAsFlow()
        override suspend fun send(chunk: ByteArray) = notifyOnce(chunk)
        override fun shutdown() = this@BleActor.shutdown()
    }

    companion object {
        /**
         * How long a `notify` waits for `onNotificationSent` before the
         * peer is presumed gone. A healthy link acks in well under 50 ms;
         * 2 s is generous headroom that still bounds a dead connection.
         * Phase 11 hardware testing measures the real distribution.
         */
        const val NOTIFY_ACK_TIMEOUT_MS = 2_000L
    }
}
