package com.ahlyxlabs.conveyance.transport.link

import com.ahlyxlabs.conveyance.transport.framing.Frame
import com.ahlyxlabs.conveyance.transport.framing.InboundAssembler
import com.ahlyxlabs.conveyance.transport.framing.MessageSplitter
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class LoopbackLinkTest {

    /** Collect [PhoneLink.events] until the terminal Torn; return chunks + reason. */
    private suspend fun drain(link: PhoneLink): Pair<List<ByteArray>, LinkTeardown> {
        val chunks = ArrayList<ByteArray>()
        var reason: LinkTeardown? = null
        link.events.collect { ev ->
            when (ev) {
                is LinkEvent.Chunk -> chunks += ev.bytes
                is LinkEvent.Torn -> reason = ev.reason
            }
        }
        return chunks to reason!!
    }

    @Test
    fun chunksArriveInOrderOnTheOtherEndpoint() = runBlocking {
        val (a, b) = LoopbackLink.pair()
        val collector = async { drain(b) }

        a.send("one".toByteArray())
        a.send("two".toByteArray())
        a.send("three".toByteArray())
        a.shutdown()

        val (chunks, reason) = collector.await()
        assertEquals(listOf("one", "two", "three"), chunks.map { String(it) })
        assertSame(LinkTeardown.PeerDisconnected, reason) // b did not initiate
    }

    @Test
    fun initiatorSeesLocalShutdownPeerSeesPeerDisconnected() = runBlocking {
        val (a, b) = LoopbackLink.pair()
        val ca = async { drain(a) }
        val cb = async { drain(b) }
        a.shutdown()
        assertSame(LinkTeardown.LocalShutdown, ca.await().second)
        assertSame(LinkTeardown.PeerDisconnected, cb.await().second)
    }

    @Test
    fun sendAfterShutdownThrowsLinkClosed() {
        val (a, _) = LoopbackLink.pair()
        a.shutdown()
        val e = assertThrows(LinkClosedException::class.java) {
            runBlocking { a.send("x".toByteArray()) }
        }
        assertSame(LinkTeardown.LocalShutdown, e.reason)
    }

    @Test
    fun frameLargerThanOnePduIsRejected() {
        val (a, _) = LoopbackLink.pair(maxWriteLen = 8)
        // 8 payload + 6 header = 14 is the ceiling; 15 is a caller bug.
        runBlocking { a.send(ByteArray(14)) } // ok
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking { a.send(ByteArray(15)) }
        }
    }

    @Test
    fun failWithPropagatesReasonsToBothSides() = runBlocking {
        val (a, b) = LoopbackLink.pair()
        val ca = async { drain(a) }
        val cb = async { drain(b) }
        a.failWith(LinkTeardown.AdapterOff, peerReason = LinkTeardown.PeerDisconnected)
        assertSame(LinkTeardown.AdapterOff, ca.await().second)
        assertSame(LinkTeardown.PeerDisconnected, cb.await().second)
    }

    /**
     * The framing stack over the link, end to end: split at a 23-byte
     * MTU, send every frame, reassemble on the far endpoint — matches
     * Rust's `transport::test_suite::echo_through_full_stack`.
     */
    @Test
    fun fullStackEchoOverLoopback() = runBlocking {
        val (a, b) = LoopbackLink.pair(maxWriteLen = Frame.maxFramePayload(23))
        val message = ByteArray(500) { (it % 251).toByte() }
        val (frames, _) = MessageSplitter.split(message, a.maxWriteLen, 0)
        assertTrue(frames.size > 1)

        val done = CompletableDeferred<List<ByteArray>>()
        val job = launch {
            val asm = InboundAssembler()
            val msgs = ArrayList<ByteArray>()
            b.events.collect { ev ->
                when (ev) {
                    is LinkEvent.Chunk -> msgs += asm.ingest(ev.bytes)
                    is LinkEvent.Torn -> done.complete(msgs)
                }
            }
        }

        for (f in frames) a.send(f) // backpressure interleaves with the collector
        a.shutdown()

        val msgs = done.await()
        job.join()
        assertEquals(1, msgs.size)
        assertArrayEquals(message, msgs[0])
    }

    @Test
    fun midMessageTeardownDropsPartialReassemblyCleanly() = runBlocking {
        val (a, b) = LoopbackLink.pair(maxWriteLen = Frame.maxFramePayload(23))
        val (frames, _) = MessageSplitter.split(ByteArray(200) { 1 }, a.maxWriteLen, 0)

        val done = CompletableDeferred<Pair<Int, LinkTeardown>>()
        val job = launch {
            val asm = InboundAssembler()
            var completed = 0
            b.events.collect { ev ->
                when (ev) {
                    is LinkEvent.Chunk -> completed += asm.ingest(ev.bytes).size
                    is LinkEvent.Torn -> done.complete(completed to ev.reason)
                }
            }
        }

        a.send(frames.first()) // START only
        a.shutdown()

        val (completed, reason) = done.await()
        job.join()
        assertEquals(0, completed) // nothing half-delivered
        assertSame(LinkTeardown.PeerDisconnected, reason)
    }
}
