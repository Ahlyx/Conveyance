package com.ahlyxlabs.conveyance.transport.framing

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Replays every vector in `framing_fixtures.json` — emitted by
 * `conveyance-wire` (the source of truth) — through this Kotlin port and
 * checks it byte for byte.
 *
 * If the Rust framing rules change, the fixture regenerates (its drift
 * gate is enforced in `cargo test` and `android.yml`) and this test
 * compares Kotlin against the new answer. If the Kotlin path diverges
 * from Rust for the same input, it fails here. Either way a Rust<->Kotlin
 * mismatch cannot ship silently — the same guarantee the crypto parity
 * suite gives for the primitives.
 *
 * Pure JVM: no emulator, no FFI.
 */
class FramingFixtureParityTest {

    private val doc: JSONObject = run {
        val stream = javaClass.getResourceAsStream("/framing_fixtures.json")
            ?: error("framing_fixtures.json missing from test resources")
        JSONObject(stream.bufferedReader().use { it.readText() })
    }

    @Test
    fun schemaVersionMatches() {
        assertEquals(1L, doc.getLong("schema_version"))
    }

    @Test
    fun constants() {
        val c = doc.getJSONObject("constants")
        assertEquals(c.getInt("header_len"), Frame.HEADER_LEN)
        assertEquals(c.getInt("flag_start"), Frame.FLAG_START)
        assertEquals(c.getInt("flag_end"), Frame.FLAG_END)
        assertEquals(c.getInt("flag_ack"), Frame.FLAG_ACK)
        assertEquals(c.getInt("reassembly_cap"), Frame.DEFAULT_REASSEMBLY_CAP)
        assertEquals(c.getInt("att_pdu_overhead"), Frame.ATT_PDU_OVERHEAD)
        assertEquals(c.getInt("min_att_mtu"), Frame.MIN_ATT_MTU)
    }

    @Test
    fun maxFramePayload() {
        forEachCase("max_frame_payload") { c ->
            assertEquals(
                "att_mtu=${c.getInt("att_mtu")}",
                c.getInt("max_payload"),
                Frame.maxFramePayload(c.getInt("att_mtu")),
            )
        }
    }

    @Test
    fun split() {
        forEachCase("split") { c ->
            val name = c.getString("name")
            val message = c.getString("message_hex").hex()
            val result = MessageSplitter.split(
                message,
                c.getInt("max_payload"),
                c.getInt("start_seq"),
            )
            assertEquals("$name: next_seq", c.getInt("expected_next_seq"), result.nextSeq)

            val expectedFrames = c.getJSONArray("frames_hex").strings()
            assertEquals("$name: frame count", expectedFrames.size, result.frames.size)
            expectedFrames.forEachIndexed { i, hex ->
                assertEquals("$name: frame $i", hex, result.frames[i].toHex())
            }

            // And they reassemble to the input.
            val framer = Framer()
            var got: ByteArray? = null
            for (f in result.frames) framer.ingest(f)?.let { got = it }
            assertArrayEquals("$name: round-trip", message, got)
        }
    }

    @Test
    fun ack() {
        forEachCase("ack") { c ->
            val frame = Frame.encodeAck(c.getInt("acked_seq"))
            assertEquals(c.getString("frame_hex"), frame.toHex())
            assertNull(Framer().ingest(frame))
        }
    }

    @Test
    fun reassembleOk() {
        forEachCase("reassemble_ok") { c ->
            val name = c.getString("name")
            val stream = c.getString("input_hex").hex()
            val offsets = c.getJSONArray("wire_chunk_offsets").ints()

            val asm = InboundAssembler()
            val got = ArrayList<ByteArray>()
            var prev = 0
            for (off in offsets) {
                got += asm.ingest(stream.copyOfRange(prev, off))
                prev = off
            }
            got += asm.ingest(stream.copyOfRange(prev, stream.size))

            val expected = c.getJSONArray("expected_messages_hex").strings()
            assertEquals("$name: message count", expected.size, got.size)
            expected.forEachIndexed { i, hex ->
                assertEquals("$name: message $i", hex, got[i].toHex())
            }
        }
    }

    @Test
    fun reassembleErr() {
        forEachCase("reassemble_err") { c ->
            val name = c.getString("name")
            val framer = Framer(cap = c.getInt("cap"))
            val frames = c.getJSONArray("input_frames_hex").strings().map { it.hex() }

            var thrown: FramingException? = null
            for (f in frames) {
                try {
                    framer.ingest(f)
                } catch (e: FramingException) {
                    thrown = e
                    break
                }
            }
            val err = c.getJSONObject("error")
            assertTrue("$name: expected a FramingException", thrown != null)
            assertFramingError(name, err, thrown!!)
        }
    }

    // -- helpers ---------------------------------------------------------

    private fun assertFramingError(name: String, err: JSONObject, e: FramingException) {
        when (err.getString("kind")) {
            "FrameTruncated" -> assertTrue("$name", e is FramingException.FrameTruncated)
            "NonZeroReserved" -> assertTrue("$name", e is FramingException.NonZeroReserved)
            "StrayMiddleFrame" -> assertTrue("$name", e is FramingException.StrayMiddleFrame)
            "NestedMessage" -> assertTrue("$name", e is FramingException.NestedMessage)
            "InvalidSplitSize" -> assertTrue("$name", e is FramingException.InvalidSplitSize)
            "FrameLengthMismatch" -> {
                e as FramingException.FrameLengthMismatch
                assertEquals("$name: declared", err.getInt("declared"), e.declared)
                assertEquals("$name: actual", err.getInt("actual"), e.actual)
            }
            "IllegalFlags" -> {
                e as FramingException.IllegalFlags
                assertEquals("$name: bits", err.getInt("bits"), e.bits)
            }
            "SequenceGap" -> {
                e as FramingException.SequenceGap
                assertEquals("$name: expected", err.getInt("expected"), e.expected)
                assertEquals("$name: got", err.getInt("got"), e.got)
            }
            "MessageTooLarge" -> {
                e as FramingException.MessageTooLarge
                assertEquals("$name: size", err.getInt("size"), e.size)
                assertEquals("$name: cap", err.getInt("cap"), e.cap)
                assertEquals("$name: spec_code", err.getString("spec_code"), e.specCode)
            }
            else -> error("$name: unknown error kind ${err.getString("kind")}")
        }
    }

    private fun forEachCase(group: String, body: (JSONObject) -> Unit) {
        doc.getJSONObject(group).getJSONArray("cases").objects().forEach(body)
    }

    private fun JSONArray.objects(): List<JSONObject> = (0 until length()).map { getJSONObject(it) }
    private fun JSONArray.strings(): List<String> = (0 until length()).map { getString(it) }
    private fun JSONArray.ints(): List<Int> = (0 until length()).map { getInt(it) }

    private fun String.hex(): ByteArray {
        require(length % 2 == 0)
        return ByteArray(length / 2) { substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xFF) }
}
