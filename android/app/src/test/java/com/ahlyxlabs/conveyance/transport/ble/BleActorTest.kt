package com.ahlyxlabs.conveyance.transport.ble

import com.ahlyxlabs.conveyance.transport.ConnectionStateMachine.Event
import com.ahlyxlabs.conveyance.transport.ConnectionStateMachine.State
import com.ahlyxlabs.conveyance.transport.framing.Frame
import com.ahlyxlabs.conveyance.transport.framing.InboundAssembler
import com.ahlyxlabs.conveyance.transport.framing.MessageSplitter
import com.ahlyxlabs.conveyance.transport.link.LinkClosedException
import com.ahlyxlabs.conveyance.transport.link.LinkEvent
import com.ahlyxlabs.conveyance.transport.link.LinkTeardown
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class BleActorTest {

    private val dispatcher = StandardTestDispatcher()
    private val fake = FakeGattServerHandle()
    private val fakeWatch = FakeAdapterWatch()

    private fun actor() = BleActor(dispatcher, fakeWatch).also { it.attachServer(fake) }

    private fun BleActor.driveToSubscribed(mtu: Int = 247) {
        onEvent(Event.CentralConnected)
        onEvent(Event.MtuChanged(mtu))
        onEvent(Event.Subscribed)
    }

    // -- state machine ----------------------------------------------------

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
        assertEquals(Frame.maxFramePayload(247), a.link!!.maxWriteLen)
    }

    @Test
    fun centralDisconnectTearsDownAndClosesTheServer() = runTest(dispatcher) {
        val a = actor()
        a.onEvent(Event.CentralConnected); runCurrent()
        a.onEvent(Event.CentralDisconnected); runCurrent()
        assertEquals(State.TORN, a.state.value)
        assertEquals(1, fake.closeCount)
        assertEquals(null, a.link)
    }

    @Test
    fun subscriptionLossTearsDown() = runTest(dispatcher) {
        val a = actor()
        a.driveToSubscribed(); runCurrent()
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
    fun adapterWatchStartsOnAttachAndStopsOnTeardown() = runTest(dispatcher) {
        val a = actor()
        assertTrue(fakeWatch.started)
        assertFalse(fakeWatch.stopped)
        a.shutdown(); runCurrent()
        assertTrue(fakeWatch.stopped)
    }

    @Test
    fun adapterOffFromWatchTearsDown() = runTest(dispatcher) {
        val a = actor()
        a.driveToSubscribed(); runCurrent()
        fakeWatch.triggerOff(); runCurrent()
        assertEquals(State.TORN, a.state.value)
        assertEquals(1, fake.closeCount)
        assertTrue(fakeWatch.stopped)
    }

    @Test
    fun eventsAfterTeardownAreInert() = runTest(dispatcher) {
        val a = actor()
        a.shutdown(); runCurrent()
        for (e in listOf(Event.CentralConnected, Event.MtuChanged(247), Event.Subscribed)) {
            a.onEvent(e); runCurrent()
            assertEquals(State.TORN, a.state.value)
        }
        assertEquals(1, fake.closeCount)
    }

    // -- outbound: one notification in flight ----------------------------

    @Test
    fun sendDeliversAFrameThenWaitsForOnNotificationSent() = runTest(dispatcher) {
        val a = actor()
        a.driveToSubscribed(); runCurrent()

        val frame = ByteArray(20) { it.toByte() }
        val job = launch { a.link!!.send(frame) }
        runCurrent()
        assertEquals(1, fake.notifications.size)
        assertArrayEquals(frame, fake.notifications[0])
        assertTrue("send must still be waiting for the ack", job.isActive)

        a.onNotificationResult(true)
        runCurrent()
        assertTrue(job.isCompleted)
    }

    @Test
    fun sendTimesOutIntoTeardownWhenNoAckArrives() = runTest(dispatcher) {
        val a = actor()
        a.driveToSubscribed(); runCurrent()

        var thrown: LinkTeardown? = null
        val job = launch {
            try {
                a.link!!.send(ByteArray(10))
                fail("expected LinkClosedException")
            } catch (e: LinkClosedException) {
                thrown = e.reason
            }
        }
        runCurrent()
        assertEquals(1, fake.notifications.size)

        advanceTimeBy(BleActor.NOTIFY_ACK_TIMEOUT_MS + 1)
        runCurrent()
        assertTrue(job.isCompleted)
        assertSame(LinkTeardown.PeerDisconnected, thrown)
        assertEquals(State.TORN, a.state.value)
        assertEquals(1, fake.closeCount)
    }

    @Test
    fun notifyRejectionTearsDownImmediately() = runTest(dispatcher) {
        val a = actor()
        a.driveToSubscribed(); runCurrent()
        fake.notifyReturns = false

        var thrown: LinkTeardown? = null
        val job = launch {
            try {
                a.link!!.send(ByteArray(8))
                fail("expected LinkClosedException")
            } catch (e: LinkClosedException) {
                thrown = e.reason
            }
        }
        runCurrent()
        assertTrue(job.isCompleted)
        assertSame(LinkTeardown.PeerDisconnected, thrown)
        assertEquals(State.TORN, a.state.value)
    }

    @Test
    fun sendAfterTeardownThrowsLinkClosed() = runTest(dispatcher) {
        val a = actor()
        a.driveToSubscribed(); runCurrent()
        val link = a.link!!
        a.shutdown(); runCurrent()

        var thrown: LinkTeardown? = null
        val job = launch {
            try {
                link.send(ByteArray(4)); fail("expected LinkClosedException")
            } catch (e: LinkClosedException) {
                thrown = e.reason
            }
        }
        runCurrent()
        assertTrue(job.isCompleted)
        assertSame(LinkTeardown.LocalShutdown, thrown)
    }

    // -- inbound + teardown stream -------------------------------------

    @Test
    fun inboundWriteBecomesAChunkAndTeardownEndsTheStream() = runTest(dispatcher) {
        val a = actor()
        a.driveToSubscribed(); runCurrent()

        val seen = mutableListOf<LinkEvent>()
        backgroundScope.launch { a.link!!.events.collect { seen += it } }

        a.onInboundBytes(byteArrayOf(1, 2, 3)); runCurrent()
        assertEquals(1, seen.size)
        assertArrayEquals(byteArrayOf(1, 2, 3), (seen[0] as LinkEvent.Chunk).bytes)

        a.shutdown(); runCurrent()
        val torn = seen.last() as LinkEvent.Torn
        assertSame(LinkTeardown.LocalShutdown, torn.reason)
    }

    @Test
    fun framesRoundTripThroughTheActorAndReassemble() = runTest(dispatcher) {
        val a = actor()
        a.driveToSubscribed(mtu = 23); runCurrent()
        val link = a.link!!

        val message = ByteArray(120) { (it % 251).toByte() }
        val (frames, _) = MessageSplitter.split(message, link.maxWriteLen, 0)
        assertTrue(frames.size > 1)

        for (f in frames) {
            val job = launch { link.send(f) }
            runCurrent()
            a.onNotificationResult(true)
            runCurrent()
            assertTrue(job.isCompleted)
        }
        assertEquals(frames.size, fake.notifications.size)

        val asm = InboundAssembler()
        val out = mutableListOf<ByteArray>()
        backgroundScope.launch {
            link.events.collect { if (it is LinkEvent.Chunk) out += asm.ingest(it.bytes) }
        }
        for (f in frames) { a.onInboundBytes(f); runCurrent() }
        assertEquals(1, out.size)
        assertArrayEquals(message, out[0])
    }
}
