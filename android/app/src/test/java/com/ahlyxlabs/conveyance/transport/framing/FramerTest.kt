package com.ahlyxlabs.conveyance.transport.framing

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

/** Host-JVM port of `conveyance_wire::framing::Framer` tests. */
class FramerTest {

    @Test
    fun truncatedHeaderIsTyped() {
        for (n in 0 until Frame.HEADER_LEN) {
            assertThrows(
                "len $n",
                FramingException.FrameTruncated::class.java,
            ) { Framer().ingest(ByteArray(n) { 0xAA.toByte() }) }
        }
    }

    @Test
    fun declaredLengthMismatchIsTyped() {
        val bad = Frame.encode(0, Frame.FLAG_START or Frame.FLAG_END, "abc".toByteArray())
        bad[0] = 0xFF.toByte() // declares 0xFF03, only 3 follow
        val e = assertThrows(FramingException.FrameLengthMismatch::class.java) {
            Framer().ingest(bad)
        }
        assertEquals(65283, e.declared)
        assertEquals(3, e.actual)
    }

    @Test
    fun nonzeroReservedIsTyped() {
        val bad = Frame.encode(0, Frame.FLAG_START or Frame.FLAG_END, "x".toByteArray())
        bad[5] = 1
        assertThrows(FramingException.NonZeroReserved::class.java) { Framer().ingest(bad) }
    }

    @Test
    fun illegalFlagCombinationsAreTyped() {
        for (flags in intArrayOf(0b1000, 0b1001, 0b1010, 0b1100, 0b111, 0b110)) {
            val bad = Frame.encode(0, flags, ByteArray(0))
            val e = assertThrows(
                "flags $flags",
                FramingException.IllegalFlags::class.java,
            ) { Framer().ingest(bad) }
            assertEquals(flags, e.bits)
        }
    }

    @Test
    fun ackWithPayloadIsIllegal() {
        val bad = Frame.encode(5, Frame.FLAG_ACK, "z".toByteArray())
        assertThrows(FramingException.IllegalFlags::class.java) { Framer().ingest(bad) }
    }

    @Test
    fun sequenceGapWhenMiddleFrameDropped() {
        val (frames, _) = MessageSplitter.split(ByteArray(900) { 1 }, 300, 10) // seqs 10,11,12
        val framer = Framer()
        framer.ingest(frames[0])
        val e = assertThrows(FramingException.SequenceGap::class.java) { framer.ingest(frames[2]) }
        assertEquals(11, e.expected)
        assertEquals(12, e.got)
    }

    @Test
    fun strayMiddleFrameWithNoStart() {
        val (frames, _) = MessageSplitter.split(ByteArray(900) { 1 }, 300, 0)
        assertThrows(FramingException.StrayMiddleFrame::class.java) { Framer().ingest(frames[1]) }
    }

    @Test
    fun reorderingAcrossSingleFrameMessagesIsAGap() {
        val (a, _) = MessageSplitter.split("AAA".toByteArray(), 4, 5)
        val (b, _) = MessageSplitter.split("BBB".toByteArray(), 4, 7) // skips 6
        val framer = Framer()
        assertArrayEquals("AAA".toByteArray(), framer.ingest(a[0]))
        val e = assertThrows(FramingException.SequenceGap::class.java) { framer.ingest(b[0]) }
        assertEquals(6, e.expected)
        assertEquals(7, e.got)
    }

    @Test
    fun nestedStartRejected() {
        val (a, _) = MessageSplitter.split("first-message".toByteArray(), 4, 0)
        val (b, _) = MessageSplitter.split("second".toByteArray(), 4, 100)
        val framer = Framer()
        framer.ingest(a[0]) // START
        assertThrows(FramingException.NestedMessage::class.java) { framer.ingest(b[0]) }
    }

    @Test
    fun reassemblyCapYieldsMessageTooLargeWithSpecCode() {
        val (frames, _) = MessageSplitter.split(ByteArray(200) { 7 }, 50, 0)
        val framer = Framer(cap = 64)
        assertNull(framer.ingest(frames[0])) // 50 <= 64
        val e = assertThrows(FramingException.MessageTooLarge::class.java) { framer.ingest(frames[1]) }
        assertEquals(64, e.cap)
        assertEquals(100, e.size)
        assertEquals("conveyance/message_too_large", e.specCode)
    }

    /**
     * Deterministic seeded soak: adversarial mutations of valid frame
     * traffic. No exception type other than [FramingException] may
     * escape, and nothing may hang or OOM. Mirrors the Rust soak.
     */
    @Test
    fun mutationSoakProducesTypedErrorsNotCrashes() {
        var state = 0xC0FFEEL
        fun next(): Long {
            state = state * 6364136223846793005L + 1442695040888963407L
            return state ushr 16
        }

        val baseStreams = (0 until 8).map { n ->
            val body = ByteArray((n + 1) * 13) { (n * 31).toByte() }
            val (frames, _) = MessageSplitter.split(body, 7, n * 5)
            frames.reduce { acc, f -> acc + f } + Frame.encodeAck(n * 5)
        }

        repeat(50_000) {
            var bytes = baseStreams[(next() % baseStreams.size).toInt()].copyOf()
            val flips = 1 + (next() % 8).toInt()
            repeat(flips) {
                val idx = (next() % maxOf(1, bytes.size)).toInt()
                if (idx < bytes.size) bytes[idx] = (bytes[idx].toInt() xor (next() and 0xFF).toInt()).toByte()
            }
            if (next() and 1L == 1L && bytes.isNotEmpty()) {
                bytes = bytes.copyOf((next() % bytes.size).toInt())
            }
            try {
                Framer().ingest(bytes)
            } catch (_: FramingException) {
                // expected
            }
        }
    }
}
