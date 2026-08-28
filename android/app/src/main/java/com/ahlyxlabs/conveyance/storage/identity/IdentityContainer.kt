package com.ahlyxlabs.conveyance.storage.identity

import java.nio.ByteBuffer

/**
 * The on-disk `identity.enc` byte layout. Self-contained: it carries both
 * the `conveyance_tier1`-wrapped content key and the sealed identity
 * blob, so unlock reads one file.
 *
 * ```
 * magic  "CVID"        4 bytes
 * version u8           1 byte   (currently 1)
 * wkLen   u16 BE       2 bytes  wrapped-content-key length
 * wrapped wkLen bytes           iv || AES-GCM(content_key) under conveyance_tier1
 * blob    rest                  create_sealed_identity output (its own version byte inside)
 * ```
 *
 * Pure format code — no Keystore, no crypto — so it is host-JVM testable.
 */
data class IdentityContainer(
    val wrappedContentKey: ByteArray,
    val sealedBlob: ByteArray,
) {
    fun encode(): ByteArray {
        require(wrappedContentKey.size in 1..0xFFFF) { "wrapped key length out of range" }
        require(sealedBlob.isNotEmpty()) { "sealed blob is empty" }
        return ByteBuffer.allocate(HEADER + wrappedContentKey.size + sealedBlob.size).apply {
            put(MAGIC)
            put(VERSION)
            putShort(wrappedContentKey.size.toShort())
            put(wrappedContentKey)
            put(sealedBlob)
        }.array()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is IdentityContainer) return false
        return wrappedContentKey.contentEquals(other.wrappedContentKey) &&
            sealedBlob.contentEquals(other.sealedBlob)
    }

    override fun hashCode(): Int =
        31 * wrappedContentKey.contentHashCode() + sealedBlob.contentHashCode()

    companion object {
        private val MAGIC = "CVID".toByteArray(Charsets.US_ASCII)
        const val VERSION: Byte = 1
        private const val HEADER = 4 + 1 + 2

        /** @throws IdentityCorruptException if the bytes are not a valid v1 container. */
        fun decode(bytes: ByteArray): IdentityContainer {
            if (bytes.size < HEADER) throw IdentityCorruptException("identity.enc truncated")
            val buf = ByteBuffer.wrap(bytes)
            val magic = ByteArray(4).also { buf.get(it) }
            if (!magic.contentEquals(MAGIC)) throw IdentityCorruptException("bad magic")
            val version = buf.get()
            if (version != VERSION) throw IdentityCorruptException("unsupported version $version")
            val wkLen = buf.short.toInt() and 0xFFFF
            if (wkLen == 0 || buf.remaining() <= wkLen) {
                throw IdentityCorruptException("identity.enc length fields inconsistent")
            }
            val wrapped = ByteArray(wkLen).also { buf.get(it) }
            val blob = ByteArray(buf.remaining()).also { buf.get(it) }
            return IdentityContainer(wrapped, blob)
        }
    }
}
