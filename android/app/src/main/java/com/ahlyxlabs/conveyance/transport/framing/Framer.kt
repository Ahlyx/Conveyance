package com.ahlyxlabs.conveyance.transport.framing

import java.io.ByteArrayOutputStream

/**
 * Reassembly half-connection — one per direction. Ported byte-for-byte
 * from `conveyance_wire::framing::Framer`.
 *
 * Feed whole frames to [ingest]; it returns the completed application
 * message when an `END` frame lands, or null while a message is still in
 * flight. Reassembly is strict: frames arrive in sequence order, only
 * one message is mid-flight at a time, and the accumulated payload never
 * exceeds [cap]. Any violation throws a [FramingException] and the framer
 * must be discarded (the session ends).
 *
 * ACK frames parse, return null, and neither advance nor check the
 * sequence — v1 has no retransmission (see spec "Framing").
 */
class Framer(private val cap: Int = Frame.DEFAULT_REASSEMBLY_CAP) {

    private enum class Progress { IDLE, ASSEMBLING }

    private var progress = Progress.IDLE
    /** Next expected sequence number; null until the first data frame. */
    private var nextSeq: Int? = null
    private val buffer = ByteArrayOutputStream()

    fun ingest(frameBytes: ByteArray): ByteArray? {
        if (frameBytes.size < Frame.HEADER_LEN) throw FramingException.FrameTruncated()

        val declared = Frame.u16(frameBytes[0], frameBytes[1])
        val seq = Frame.u16(frameBytes[2], frameBytes[3])
        val flags = frameBytes[4].toInt() and 0xFF
        val reserved = frameBytes[5].toInt() and 0xFF
        val payload = frameBytes.copyOfRange(Frame.HEADER_LEN, frameBytes.size)

        if (reserved != 0) throw FramingException.NonZeroReserved()
        if (flags !in Frame.LEGAL_FLAGS) throw FramingException.IllegalFlags(flags)
        if (payload.size != declared) {
            throw FramingException.FrameLengthMismatch(declared, payload.size)
        }

        // ACKs reference history: they neither advance nor check seq.
        if (flags == Frame.FLAG_ACK) {
            if (payload.isNotEmpty()) throw FramingException.IllegalFlags(flags)
            return null
        }

        // Shape-versus-progress is diagnosed BEFORE sequence continuity:
        // a second START mid-message is that violation whatever seq it
        // claims; a middle frame while idle likewise.
        if (flags and Frame.FLAG_START != 0 && progress != Progress.IDLE) {
            throw FramingException.NestedMessage()
        }
        if (flags == 0 && progress == Progress.IDLE) {
            throw FramingException.StrayMiddleFrame()
        }

        val expected = nextSeq
        if (expected != null && seq != expected) {
            throw FramingException.SequenceGap(expected, seq)
        }
        nextSeq = Frame.wrappingAddU16(expected ?: seq, 1)

        return when (flags) {
            Frame.FLAG_START or Frame.FLAG_END -> payload
            Frame.FLAG_START -> {
                buffer.reset()
                buffer.write(payload)
                progress = Progress.ASSEMBLING
                checkCap()
                null
            }
            0 -> {
                buffer.write(payload)
                checkCap()
                null
            }
            Frame.FLAG_END -> {
                // A bare END means its START vanished — gap-class
                // corruption regardless of payload emptiness.
                if (progress == Progress.IDLE) {
                    throw FramingException.SequenceGap(Frame.wrappingAddU16(seq, 0xFFFF), seq)
                }
                buffer.write(payload)
                checkCap()
                progress = Progress.IDLE
                val done = buffer.toByteArray()
                buffer.reset()
                done
            }
            else -> error("flags validated against LEGAL_FLAGS")
        }
    }

    private fun checkCap() {
        if (buffer.size() > cap) throw FramingException.MessageTooLarge(buffer.size(), cap)
    }
}
