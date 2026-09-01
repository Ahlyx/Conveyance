package com.ahlyxlabs.conveyance.transport.framing

/**
 * Byte-stream reassembly for a sub-MTU transport, ported from
 * `conveyance_wire::assembler::InboundAssembler`.
 *
 * A GATT operation is bounded by the negotiated MTU, so one wire frame
 * may arrive split across several notifications — and frames chain into
 * messages. This buffers the raw byte stream, slices complete frames on
 * the `HEADER_LEN + declared` boundary, and feeds each to one persistent
 * [Framer] so every rule lives in exactly one place. One per direction;
 * discard it with the link on disconnect.
 *
 * The length prefix is checked against the cap *before* the buffer grows
 * toward it: a hostile `declared` never drives an allocation.
 */
class InboundAssembler {

    private val framer = Framer()
    private var buffer = ByteArray(0)

    /**
     * Feed inbound bytes; returns every application message that
     * completed on this call, in order. An incomplete frame is held for
     * the next call; an over-cap stream is [FramingException.MessageTooLarge].
     */
    fun ingest(bytes: ByteArray): List<ByteArray> {
        val cap = Frame.DEFAULT_REASSEMBLY_CAP

        buffer += bytes
        if (buffer.size > cap) throw FramingException.MessageTooLarge(buffer.size, cap)

        val messages = ArrayList<ByteArray>()
        while (true) {
            if (buffer.size < Frame.HEADER_LEN) return messages

            val declared = Frame.u16(buffer[0], buffer[1])
            if (declared > cap) throw FramingException.MessageTooLarge(declared, cap)

            val total = Frame.HEADER_LEN + declared
            if (buffer.size < total) return messages

            val frame = buffer.copyOfRange(0, total)
            buffer = buffer.copyOfRange(total, buffer.size)

            framer.ingest(frame)?.let { messages.add(it) }
        }
    }
}
