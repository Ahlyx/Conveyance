package com.ahlyxlabs.conveyance.transport.framing

/** Ordered wire frames plus the next free sequence number. */
data class SplitResult(val frames: List<ByteArray>, val nextSeq: Int)

/**
 * Splits one application message into wire frames, ported from
 * `conveyance_wire::framing::split_message`.
 *
 * `maxPayload` is the per-frame payload budget — callers derive it from
 * the negotiated MTU via [Frame.maxFramePayload]. A message that fits one
 * frame is a single `START | END`; larger ones are `START`, zero or more
 * middles, `END`. A zero-length message is one empty `START | END` frame.
 * Sequence numbers wrap at 2^16.
 */
object MessageSplitter {

    fun split(message: ByteArray, maxPayload: Int, startSeq: Int): SplitResult {
        if (maxPayload == 0) throw FramingException.InvalidSplitSize()

        // div_ceil, floored at 1 so an empty message still yields a frame.
        val count = maxOf(1, (message.size + maxPayload - 1) / maxPayload)
        val frames = ArrayList<ByteArray>(count)
        var offset = 0

        for (i in 0 until count) {
            val end = minOf(offset + maxPayload, message.size)
            val payload = message.copyOfRange(offset, end)
            offset = end

            val flags = when {
                i == 0 && count == 1 -> Frame.FLAG_START or Frame.FLAG_END
                i == 0 -> Frame.FLAG_START
                i == count - 1 -> Frame.FLAG_END
                else -> 0
            }
            frames.add(Frame.encode(Frame.wrappingAddU16(startSeq, i), flags, payload))
        }

        return SplitResult(frames, Frame.wrappingAddU16(startSeq, count))
    }
}
