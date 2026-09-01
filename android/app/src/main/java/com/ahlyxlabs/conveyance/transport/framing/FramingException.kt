package com.ahlyxlabs.conveyance.transport.framing

/**
 * Every way a frame or a reassembly step can be rejected — the Kotlin
 * mirror of `conveyance_wire::FrameError`. Variant names and payload
 * fields match one-to-one; the `framing_fixtures.json` parity suite
 * asserts each case produces exactly the corresponding subclass.
 *
 * A framing violation is terminal: it ends the session
 * (`protocol_violation`). Only [MessageTooLarge] carries a client-facing
 * [specCode]; the rest are internal.
 */
sealed class FramingException(message: String) : Exception(message) {

    /** Spec error-model code where one exists, else null. */
    open val specCode: String? = null

    class FrameTruncated : FramingException("frame shorter than the 6-byte header")

    class FrameLengthMismatch(val declared: Int, val actual: Int) :
        FramingException("frame declares $declared payload bytes but $actual follow")

    class NonZeroReserved : FramingException("frame has reserved byte set to nonzero")

    class IllegalFlags(val bits: Int) :
        FramingException("illegal flag combination: 0b" + Integer.toBinaryString(bits))

    class StrayMiddleFrame :
        FramingException("middle frame received while not reassembling a message")

    class NestedMessage :
        FramingException("second START frame while a message is mid-reassembly")

    class SequenceGap(val expected: Int, val got: Int) :
        FramingException("sequence gap: expected $expected, got $got")

    class MessageTooLarge(val size: Int, val cap: Int) :
        FramingException("reassembly buffer limit exceeded ($size > $cap bytes)") {
        override val specCode: String = "conveyance/message_too_large"
    }

    class InvalidSplitSize :
        FramingException("split requested with zero-byte per-frame payload")
}
