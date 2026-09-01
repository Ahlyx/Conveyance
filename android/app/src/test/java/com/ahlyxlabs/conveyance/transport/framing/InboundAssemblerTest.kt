package com.ahlyxlabs.conveyance.transport.framing

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** Host-JVM port of `conveyance_wire::assembler::InboundAssembler` tests. */
class InboundAssemblerTest {

    @Test
    fun aFrameSplitAcrossIngestsReassembles() {
        val msg = ByteArray(400) { 0x42 }
        val (frames, _) = MessageSplitter.split(msg, Frame.maxFramePayload(23), 0)
        val stream = frames.reduce { a, b -> a + b }

        val asm = InboundAssembler()
        val out = ArrayList<ByteArray>()
        for (b in stream) out += asm.ingest(byteArrayOf(b)) // one byte at a time
        assertEquals(1, out.size)
        assertArrayEquals(msg, out[0])
    }

    @Test
    fun uglyCutPointsAndTwoMessagesPerIngest() {
        val a = "first".toByteArray()
        val b = "second message a bit longer".toByteArray()
        val (fa, next) = MessageSplitter.split(a, 4, 0)
        val (fb, _) = MessageSplitter.split(b, 4, next)
        val stream = (fa + fb).reduce { x, y -> x + y }

        val whole = InboundAssembler().ingest(stream)
        assertEquals(2, whole.size)
        assertArrayEquals(a, whole[0])
        assertArrayEquals(b, whole[1])

        val asm = InboundAssembler()
        val out = ArrayList<ByteArray>()
        for (chunk in listOf(stream.copyOfRange(0, 3), stream.copyOfRange(3, 7), stream.copyOfRange(7, stream.size))) {
            out += asm.ingest(chunk)
        }
        assertEquals(2, out.size)
        assertArrayEquals(a, out[0])
        assertArrayEquals(b, out[1])
    }

    @Test
    fun interleavedAckIsIgnored() {
        val msg = "payload across three frames here".toByteArray()
        val (frames, _) = MessageSplitter.split(msg, 8, 30)
        assertTrue(frames.size >= 3)

        var stream = frames[0] + Frame.encodeAck(30)
        for (i in 1 until frames.size) stream += frames[i]

        assertArrayEquals(msg, InboundAssembler().ingest(stream).single())
    }

    @Test
    fun floodOverCapIsRejected() {
        val asm = InboundAssembler()
        val flood = ByteArray(Frame.DEFAULT_REASSEMBLY_CAP + 1)
        val e = assertThrows(FramingException.MessageTooLarge::class.java) { asm.ingest(flood) }
        assertEquals(Frame.DEFAULT_REASSEMBLY_CAP, e.cap)
    }

    @Test
    fun framingErrorsPropagateThroughTheStreamPath() {
        val (frames, _) = MessageSplitter.split(ByteArray(30) { 7 }, 8, 0)
        assertThrows(FramingException.StrayMiddleFrame::class.java) {
            InboundAssembler().ingest(frames[1])
        }
    }
}
