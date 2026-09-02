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
    // UNLIMITED, not BUFFERED: onInboundBytes trySends from a binder
    // thread that must neither block nor silently drop a chunk (a lost
    // chunk desynchronises the consumer's Framer). The real backpressure
    // is the InboundAssembler's 128 KiB cap on the consumer side; a
    // sustained flood beyond that ends the session there.
    private val linkEvents = Channel<LinkEvent>(Channel.UNLIMITED)
    private val notifyResults = Channel<Boolean>(Channel.CONFLATED)
    private val sendMutex = Mutex()
    private var currentMaxWriteLen = Frame.maxFramePayload(Frame.MIN_ATT_MTU)

    // attachServer() is called from BlePeripheral.start() on the caller's
    // thread, not necessarily @BleDispatcher; teardown() (which sets this)
    // always runs on @BleDispatcher. @Volatile so attachServer's guard
    // read is guaranteed to observe a teardown that already happened.
    @Volatile private var torn = false
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
     *
     * If teardown already happened — an event processed between
     * `openGattServer()` returning and this call landing, e.g. a stale
     * disconnect — the handle this call was just given would otherwise
     * never be closed and the watch never stopped, since a second
     * [teardown] call is a no-op (finding #4). Closing it here instead.
     */
    fun attachServer(handle: GattServerHandle) {
        if (torn) {
            handle.close()
            return
        }
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
     * The single teardown path — reached only from [process]'s handling
     * of [ConnectionStateMachine.Effect.TearDown] on the event loop. A
     * notify failure in [notifyOnce] posts [ConnectionStateMachine.Event.NotifyFailed]
     * rather than calling this directly, so [_state] only ever advances
     * here, together with [ConnectionStateMachine]'s own state (finding
     * #2: two independent writers previously let a buffered event
     * processed after a direct teardown revert [_state] to a live value).
     * Idempotent.
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
        // Unblocks a notifyOnce() concurrently suspended awaiting an ack
        // (finding #8) instead of leaving it to wait out the full
        // NOTIFY_ACK_TIMEOUT_MS after the link is already gone.
        notifyResults.close()
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
                onEvent(ConnectionStateMachine.Event.NotifyFailed)
                throw LinkClosedException(LinkTeardown.PeerDisconnected)
            }
            // receiveCatching, not receive: teardown() closes notifyResults
            // as part of the TORN transition, so a concurrent event-loop
            // teardown (e.g. CentralDisconnected mid-send) unblocks this
            // wait immediately instead of running out the full timeout
            // (finding #8). A closed channel here means teardown already
            // happened elsewhere; reuse its recorded reason rather than
            // firing a second, redundant NotifyFailed.
            val delivered = withTimeoutOrNull(NOTIFY_ACK_TIMEOUT_MS) {
                notifyResults.receiveCatching().getOrNull()
            }
            if (delivered != true) {
                if (torn) throw LinkClosedException(teardownReason ?: LinkTeardown.PeerDisconnected)
                onEvent(ConnectionStateMachine.Event.NotifyFailed)
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
