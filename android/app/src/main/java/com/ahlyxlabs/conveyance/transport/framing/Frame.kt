package com.ahlyxlabs.conveyance.transport.framing

/**
 * Wire-frame constants and the low-level header codec, ported byte-for-
 * byte from `conveyance_wire::framing`. Spec: "Wire protocol" → "Framing".
 *
 * ```text
 * uint16 length;   // big-endian, length of payload
 * uint16 seq;      // per-connection monotonic, wraps at 2^16
 * uint8  flags;    // bit0 START, bit1 END, bit2 ACK
 * uint8  reserved; // zero
 * byte   payload[length]
 * ```
 */
object Frame {
    const val HEADER_LEN = 6

    const val FLAG_START = 0b001
    const val FLAG_END = 0b010
    const val FLAG_ACK = 0b100

    /** The only flag masks a receiver accepts. Anything else is illegal. */
    val LEGAL_FLAGS = intArrayOf(FLAG_START or FLAG_END, FLAG_START, FLAG_END, 0, FLAG_ACK)

    /** Spec: reassembly buffer per side MUST be capped, default 128 KiB. */
    const val DEFAULT_REASSEMBLY_CAP = 128 * 1024

    /** ATT opcode + attribute handle: the bytes a write/notify PDU spends before the value. */
    const val ATT_PDU_OVERHEAD = 3

    /** The BLE minimum ATT MTU; a sender that has not seen an MTU exchange assumes this. */
    const val MIN_ATT_MTU = 23

    /**
     * Largest frame *payload* that keeps a whole frame (this 6-byte
     * header + payload) inside one GATT operation at the negotiated ATT
     * MTU. Spec: `HEADER_LEN + payload <= att_mtu - 3`.
     *
     * An `attMtu` below [MIN_ATT_MTU] (including 0, reported before an
     * MTU exchange) is treated as 23, so the result is always >= 14 and
     * never zero — a valid [MessageSplitter.split] chunk size as-is.
     */
    fun maxFramePayload(attMtu: Int): Int =
        maxOf(attMtu, MIN_ATT_MTU) - ATT_PDU_OVERHEAD - HEADER_LEN

    /** Encode one frame. `payload.size` must fit in a u16. */
    fun encode(seq: Int, flags: Int, payload: ByteArray): ByteArray {
        require(payload.size <= 0xFFFF) { "frame payload exceeds u16 -- split must chunk" }
        val out = ByteArray(HEADER_LEN + payload.size)
        out[0] = ((payload.size ushr 8) and 0xFF).toByte()
        out[1] = (payload.size and 0xFF).toByte()
        out[2] = ((seq ushr 8) and 0xFF).toByte()
        out[3] = (seq and 0xFF).toByte()
        out[4] = (flags and 0xFF).toByte()
        out[5] = 0
        payload.copyInto(out, HEADER_LEN)
        return out
    }

    /** Build an ACK acknowledging [ackedSeq]: empty payload, no seq consumed. */
    fun encodeAck(ackedSeq: Int): ByteArray = encode(ackedSeq, FLAG_ACK, ByteArray(0))

    internal fun u16(hi: Byte, lo: Byte): Int =
        ((hi.toInt() and 0xFF) shl 8) or (lo.toInt() and 0xFF)

    /** u16 add with wraparound, matching Rust's `wrapping_add`. */
    internal fun wrappingAddU16(a: Int, b: Int): Int = (a + b) and 0xFFFF
}
