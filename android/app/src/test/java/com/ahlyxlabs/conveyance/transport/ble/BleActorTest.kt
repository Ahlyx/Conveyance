package com.ahlyxlabs.conveyance.transport.ble

import com.ahlyxlabs.conveyance.transport.ConnectionStateMachine.Event
import com.ahlyxlabs.conveyance.transport.ConnectionStateMachine.State
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class BleActorTest {

    private val dispatcher = StandardTestDispatcher()
    private val fake = FakeGattServerHandle()

    private fun actor() = BleActor(dispatcher).also { it.attachServer(fake) }

    @Test
    fun connectMtuSubscribeDrivesStateToSubscribed() = runTest(dispatcher) {
        val a = actor()
        a.onEvent(Event.CentralConnected); runCurrent()
        assertEquals(State.CONNECTED, a.state.value)
        a.onEvent(Event.MtuChanged(247)); runCurrent()
        assertEquals(State.MTU_KNOWN, a.state.value)
        a.onEvent(Event.Subscribed); runCurrent()
        assertEquals(State.SUBSCRIBED, a.state.value)
        assertEquals(0, fake.closeCount)
    }

    @Test
    fun centralDisconnectTearsDownAndClosesTheServer() = runTest(dispatcher) {
        val a = actor()
        a.onEvent(Event.CentralConnected); runCurrent()
        a.onEvent(Event.CentralDisconnected); runCurrent()
        assertEquals(State.TORN, a.state.value)
        assertEquals(1, fake.closeCount)
    }

    @Test
    fun subscriptionLossTearsDown() = runTest(dispatcher) {
        val a = actor()
        a.onEvent(Event.CentralConnected); runCurrent()
        a.onEvent(Event.Subscribed); runCurrent()
        a.onEvent(Event.Unsubscribed); runCurrent()
        assertEquals(State.TORN, a.state.value)
        assertEquals(1, fake.closeCount)
    }

    @Test
    fun shutdownTearsDown() = runTest(dispatcher) {
        val a = actor()
        a.onEvent(Event.CentralConnected); runCurrent()
        a.shutdown(); runCurrent()
        assertEquals(State.TORN, a.state.value)
        assertEquals(1, fake.closeCount)
    }

    @Test
    fun eventsAfterTeardownAreInert() = runTest(dispatcher) {
        val a = actor()
        a.shutdown(); runCurrent()
        assertEquals(State.TORN, a.state.value)
        for (e in listOf(Event.CentralConnected, Event.MtuChanged(247), Event.Subscribed)) {
            a.onEvent(e); runCurrent()
            assertEquals(State.TORN, a.state.value)
        }
        assertEquals(1, fake.closeCount)
    }
}
