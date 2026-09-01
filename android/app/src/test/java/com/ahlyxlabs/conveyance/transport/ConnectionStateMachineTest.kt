package com.ahlyxlabs.conveyance.transport

import com.ahlyxlabs.conveyance.transport.ConnectionStateMachine.Effect
import com.ahlyxlabs.conveyance.transport.ConnectionStateMachine.Event
import com.ahlyxlabs.conveyance.transport.ConnectionStateMachine.State
import com.ahlyxlabs.conveyance.transport.framing.Frame
import com.ahlyxlabs.conveyance.transport.link.LinkTeardown
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ConnectionStateMachineTest {

    private val sm = ConnectionStateMachine()

    @Test
    fun happyPathToSubscribed() {
        assertEquals(State.IDLE, sm.state)
        assertEquals(emptyList<Effect>(), sm.on(Event.CentralConnected))
        assertEquals(State.CONNECTED, sm.state)

        assertEquals(listOf(Effect.SetMaxWriteLen(Frame.maxFramePayload(247))), sm.on(Event.MtuChanged(247)))
        assertEquals(State.MTU_KNOWN, sm.state)
        assertEquals(247, sm.negotiatedMtu)

        assertEquals(listOf(Effect.LinkReady), sm.on(Event.Subscribed))
        assertEquals(State.SUBSCRIBED, sm.state)
        assertEquals(Frame.maxFramePayload(247), sm.maxWriteLen)
    }

    @Test
    fun subscribeBeforeMtuIsAllowedAndMtuStillUpdatesLater() {
        sm.on(Event.CentralConnected)
        assertEquals(listOf(Effect.LinkReady), sm.on(Event.Subscribed))
        assertEquals(State.SUBSCRIBED, sm.state)
        assertEquals(Frame.MIN_ATT_MTU, sm.negotiatedMtu) // still the assumed minimum

        assertEquals(listOf(Effect.SetMaxWriteLen(Frame.maxFramePayload(185))), sm.on(Event.MtuChanged(185)))
        assertEquals(State.SUBSCRIBED, sm.state) // MTU change does not regress the state
    }

    @Test
    fun unsubscribeTearsDownWithSubscriptionLost() {
        sm.on(Event.CentralConnected)
        sm.on(Event.Subscribed)
        assertEquals(listOf(Effect.TearDown(LinkTeardown.SubscriptionLost)), sm.on(Event.Unsubscribed))
        assertEquals(State.TORN, sm.state)
    }

    @Test
    fun disconnectAdapterOffAndShutdownEachTearDownFromAnyLiveState() {
        for ((mkEvent, reason) in listOf(
            Event.CentralDisconnected to LinkTeardown.PeerDisconnected,
            Event.AdapterOff to LinkTeardown.AdapterOff,
            Event.ShutdownRequested to LinkTeardown.LocalShutdown,
        )) {
            val fresh = ConnectionStateMachine()
            fresh.on(Event.CentralConnected)
            fresh.on(Event.MtuChanged(100))
            assertEquals(listOf(Effect.TearDown(reason)), fresh.on(mkEvent))
            assertEquals(State.TORN, fresh.state)
        }
    }

    @Test
    fun everythingAfterTornIsIgnored() {
        sm.on(Event.CentralConnected)
        sm.on(Event.ShutdownRequested)
        assertEquals(State.TORN, sm.state)
        for (e in listOf(
            Event.CentralConnected,
            Event.MtuChanged(247),
            Event.Subscribed,
            Event.Unsubscribed,
            Event.CentralDisconnected,
            Event.AdapterOff,
            Event.ShutdownRequested,
        )) {
            assertEquals("after TORN: $e", emptyList<Effect>(), sm.on(e))
            assertEquals(State.TORN, sm.state)
        }
    }

    @Test
    fun strayEventsInIdleAreHarmless() {
        assertEquals(emptyList<Effect>(), sm.on(Event.Subscribed))
        assertEquals(emptyList<Effect>(), sm.on(Event.Unsubscribed))
        assertEquals(State.IDLE, sm.state)
        // A stray MTU while idle still records the value.
        assertTrue(sm.on(Event.MtuChanged(247)).contains(Effect.SetMaxWriteLen(Frame.maxFramePayload(247))))
    }
}
