package com.ahlyxlabs.conveyance.transport

import com.ahlyxlabs.conveyance.transport.framing.Frame
import com.ahlyxlabs.conveyance.transport.link.LinkTeardown

/**
 * Pure model of one GATT-peripheral connection's lifecycle.
 *
 * Deliberately free of `android.bluetooth` types: the callback layer
 * (10.3b) translates `BluetoothGattServerCallback` / advertiser /
 * adapter-state events into [Event]s on the actor thread, applies the
 * returned [Effect]s, and never has to reason about ordering itself.
 * That keeps the part most likely to race — the transition table —
 * exhaustively unit-testable here.
 *
 * Not thread-safe: the owning actor confines it to a single dispatcher.
 */
class ConnectionStateMachine {

    enum class State {
        /** No central connected. */
        IDLE,

        /** Central connected; MTU not yet observed, not yet subscribed. */
        CONNECTED,

        /** Central connected and MTU observed; not yet subscribed. */
        MTU_KNOWN,

        /** Central connected and subscribed to `phone_to_pc_tx` — traffic can flow. */
        SUBSCRIBED,

        /** Torn down. Terminal; every further event is ignored. */
        TORN,
    }

    sealed interface Event {
        data object CentralConnected : Event
        data class MtuChanged(val mtu: Int) : Event
        data object Subscribed : Event
        data object Unsubscribed : Event
        data object CentralDisconnected : Event
        data object AdapterOff : Event
        data object ShutdownRequested : Event

        /**
         * A notify the actor sent was rejected or never acked (10.3b
         * remediation finding #2/#8). Kept distinct from
         * [CentralDisconnected] — same [LinkTeardown.PeerDisconnected]
         * reason and same unconditional teardown, but a separate origin
         * worth telling apart in logs/observability.
         */
        data object NotifyFailed : Event
    }

    sealed interface Effect {
        /** Report this as [com.ahlyxlabs.conveyance.transport.link.PhoneLink.maxWriteLen]. */
        data class SetMaxWriteLen(val bytes: Int) : Effect

        /** Subscribed and ready: expose the link as usable to 10.4. */
        data object LinkReady : Effect

        /** Tear the link down with this reason and stop advertising. */
        data class TearDown(val reason: LinkTeardown) : Effect
    }

    var state: State = State.IDLE
        private set

    /** Last MTU the central negotiated; 23 until the first exchange. */
    var negotiatedMtu: Int = Frame.MIN_ATT_MTU
        private set

    /** Current per-frame payload budget for split_message. */
    val maxWriteLen: Int get() = Frame.maxFramePayload(negotiatedMtu)

    /**
     * Apply one event; returns the effects the caller must carry out, in
     * order. Never throws — an out-of-order or duplicate event that has
     * no meaning in the current state produces no effects.
     */
    fun on(event: Event): List<Effect> {
        if (state == State.TORN) return emptyList()

        return when (event) {
            Event.CentralConnected -> {
                if (state == State.IDLE) state = State.CONNECTED
                emptyList()
            }

            is Event.MtuChanged -> {
                // Clamp as the sizing helper does; ignore a nonsensical value.
                if (event.mtu < Frame.MIN_ATT_MTU && negotiatedMtu != Frame.MIN_ATT_MTU) {
                    emptyList()
                } else {
                    negotiatedMtu = maxOf(event.mtu, Frame.MIN_ATT_MTU)
                    if (state == State.CONNECTED) state = State.MTU_KNOWN
                    listOf(Effect.SetMaxWriteLen(maxWriteLen))
                }
            }

            Event.Subscribed -> {
                if (state == State.CONNECTED || state == State.MTU_KNOWN) {
                    state = State.SUBSCRIBED
                    listOf(Effect.LinkReady)
                } else {
                    emptyList()
                }
            }

            Event.Unsubscribed -> {
                if (state == State.SUBSCRIBED) {
                    state = State.TORN
                    listOf(Effect.TearDown(LinkTeardown.SubscriptionLost))
                } else {
                    emptyList()
                }
            }

            Event.CentralDisconnected -> tearDown(LinkTeardown.PeerDisconnected)
            Event.AdapterOff -> tearDown(LinkTeardown.AdapterOff)
            Event.ShutdownRequested -> tearDown(LinkTeardown.LocalShutdown)
            Event.NotifyFailed -> tearDown(LinkTeardown.PeerDisconnected)
        }
    }

    private fun tearDown(reason: LinkTeardown): List<Effect> {
        state = State.TORN
        return listOf(Effect.TearDown(reason))
    }
}
