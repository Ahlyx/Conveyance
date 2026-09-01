package com.ahlyxlabs.conveyance.transport.framing

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** Host-JVM port of `conveyance_wire::framing` split/ack/sizing tests. */
class MessageSplitterTest {

    @Test
    fun smallMessageIsOneStartEndFrame() {
        val (frames, next) = MessageSplitter.split("ping".toByteArray(), 1000, 7)
        assertEquals(8, next)
        assertEquals(1, frames.size)
        val f = frames[0]
        assertArrayEquals(byteArrayOf(0x00, 0x04), f.copyOfRange(0, 2)) // len BE
        assertArrayEquals(byteArrayOf(0x00, 0x07), f.copyOfRange(2, 4)) // seq BE
        assertEquals((Frame.FLAG_START or Frame.FLAG_END).toByte(), f[4])
        assertEquals(0.toByte(), f[5])
        assertArrayEquals("ping".toByteArray(), f.copyOfRange(6, f.size))

        assertArrayEquals("ping".toByteArray(), Framer().ingest(f))
    }

    @Test
    fun largeMessageSplitsAndReassembles() {
        val message = ByteArray(10_000) { (it % 251).toByte() }
        val (frames, next) = MessageSplitter.split(message, 500, 0)
        assertEquals(20, frames.size)
        assertEquals(20, next)

        val framer = Framer()
        var assembled: ByteArray? = null
        for (f in frames) framer.ingest(f)?.let { assembled = it }
        assertArrayEquals(message, assembled)
    }

    @Test
    fun exactMultipleHasNoSpuriousEmptyTail() {
        val (frames, _) = MessageSplitter.split(ByteArray(1000) { 9 }, 500, 0)
        assertEquals(2, frames.size)
        assertEquals(Frame.FLAG_START.toByte(), frames[0][4])
        assertEquals(Frame.FLAG_END.toByte(), frames[1][4])
        assertArrayEquals(byteArrayOf(0x01, 0xF4.toByte()), frames[1].copyOfRange(0, 2)) // 500 BE

        val (empty, _) = MessageSplitter.split(ByteArray(0), 500, 0)
        assertEquals(1, empty.size)
        assertArrayEquals(ByteArray(0), Framer().ingest(empty[0]))
    }

    @Test
    fun seqWrapsU16WithoutError() {
        val (frames, next) = MessageSplitter.split("wrap".toByteArray(), 2, 0xFFFE)
        assertEquals(2, frames.size)
        assertEquals(0xFFFE, Frame.u16(frames[0][2], frames[0][3]))
        assertEquals(0xFFFF, Frame.u16(frames[1][2], frames[1][3]))
        assertEquals(0, next) // 0xFFFE + 2 wraps to 0

        val framer = Framer()
        framer.ingest(frames[0])
        assertArrayEquals("wrap".toByteArray(), framer.ingest(frames[1]))
    }

    @Test
    fun zeroSplitSizeIsRejected() {
        assertThrows(FramingException.InvalidSplitSize::class.java) {
            MessageSplitter.split("x".toByteArray(), 0, 0)
        }
    }

    @Test
    fun ackIsIgnoredAndDoesNotDisturbSequence() {
        val (frames, _) = MessageSplitter.split("hello world acked".toByteArray(), 6, 30)
        val framer = Framer()
        framer.ingest(frames[0]) // START seq 30
        assertNull(framer.ingest(Frame.encodeAck(30)))
        framer.ingest(frames[1])
        assertArrayEquals("hello world acked".toByteArray(), framer.ingest(frames[2]))
    }

    @Test
    fun maxFramePayloadMatchesSpecFormula() {
        assertEquals(14, Frame.maxFramePayload(0))
        assertEquals(14, Frame.maxFramePayload(22))
        assertEquals(14, Frame.maxFramePayload(23))
        assertEquals(176, Frame.maxFramePayload(185))
        assertEquals(238, Frame.maxFramePayload(247))
        assertEquals(508, Frame.maxFramePayload(517))
    }

    @Test
    fun everyEmittedFrameFitsOneAttPdu() {
        for (attMtu in intArrayOf(23, 24, 27, 100, 185, 247, 512, 517)) {
            val budget = Frame.maxFramePayload(attMtu)
            val pduLimit = maxOf(attMtu, Frame.MIN_ATT_MTU) - Frame.ATT_PDU_OVERHEAD
            for (msgLen in intArrayOf(0, 1, 13, 14, 15, budget, budget + 1, 3 * budget + 7, 5000)) {
                val msg = ByteArray(msgLen) { 0xAB.toByte() }
                val (frames, _) = MessageSplitter.split(msg, budget, 0)
                for (f in frames) {
                    assertTrue(
                        "attMtu=$attMtu msgLen=$msgLen frame=${f.size}",
                        f.size in Frame.HEADER_LEN..pduLimit,
                    )
                }
                val framer = Framer()
                var got: ByteArray? = null
                for (f in frames) framer.ingest(f)?.let { got = it }
                assertArrayEquals("attMtu=$attMtu msgLen=$msgLen", msg, got)
            }
        }
    }
}
