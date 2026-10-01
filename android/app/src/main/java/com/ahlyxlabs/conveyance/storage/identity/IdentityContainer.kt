package com.ahlyxlabs.conveyance.storage.identity

import java.nio.ByteBuffer

/** Versioned on-disk `identity.enc` envelope. */
data class IdentityContainer(
    /** Biometric: AES-GCM iv || ciphertext+tag. Passphrase: ciphertext+tag. */
    val wrappedContentKey: ByteArray,
    val sealedBlob: ByteArray,
    /** Null only for the legacy v1 biometric format. */
    val authMethod: Tier1AuthMethod? = null,
    /** Passphrase mode only; exactly 16 random bytes. */
    val salt: ByteArray? = null,
    /** Passphrase mode only; exactly 12 random bytes. */
    val nonce: ByteArray? = null,
    /** Random 16-byte identity-envelope generation, present in v2. */
    val generation: ByteArray? = null,
    val version: Byte = LEGACY_VERSION,
) {
    fun encode(): ByteArray {
        require(sealedBlob.isNotEmpty()) { "sealed blob is empty" }
        return when (version) {
            LEGACY_VERSION -> encodeLegacy()
            VERSION -> encodeV2()
            else -> throw IllegalArgumentException("unsupported identity container version $version")
        }
    }

    private fun encodeLegacy(): ByteArray {
        require(authMethod == null && salt == null && nonce == null && generation == null) {
            "legacy identity container cannot carry v2 fields"
        }
        require(wrappedContentKey.size in 1..0xFFFF) { "wrapped key length out of range" }
        return ByteBuffer.allocate(LEGACY_HEADER + wrappedContentKey.size + sealedBlob.size).apply {
            put(MAGIC)
            put(LEGACY_VERSION)
            putShort(wrappedContentKey.size.toShort())
            put(wrappedContentKey)
            put(sealedBlob)
        }.array()
    }

    private fun encodeV2(): ByteArray {
        val method = requireNotNull(authMethod) { "v2 identity container needs an auth method" }
        val id = requireNotNull(generation) { "v2 identity container needs a generation" }
        require(id.size == GENERATION_LEN) { "generation must be $GENERATION_LEN bytes" }
        val payload = when (method) {
            Tier1AuthMethod.BIOMETRIC -> {
                require(salt == null && nonce == null) { "biometric envelope cannot carry passphrase fields" }
                require(wrappedContentKey.size == AES_GCM_WRAPPED_KEY_LEN) { "invalid biometric envelope length" }
                wrappedContentKey
            }
            Tier1AuthMethod.PASSPHRASE -> {
                val kdfSalt = requireNotNull(salt) { "passphrase envelope needs a salt" }
                val aeadNonce = requireNotNull(nonce) { "passphrase envelope needs a nonce" }
                require(kdfSalt.size == SALT_LEN) { "salt must be $SALT_LEN bytes" }
                require(aeadNonce.size == NONCE_LEN) { "nonce must be $NONCE_LEN bytes" }
                require(wrappedContentKey.size == AEAD_WRAPPED_KEY_LEN) { "invalid passphrase envelope length" }
                kdfSalt + aeadNonce + wrappedContentKey
            }
        }
        require(payload.size <= 0xFFFF) { "auth envelope length out of range" }
        return ByteBuffer.allocate(V2_HEADER + payload.size + sealedBlob.size).apply {
            put(MAGIC)
            put(VERSION)
            put(method.wireTag)
            put(id)
            putShort(payload.size.toShort())
            put(payload)
            put(sealedBlob)
        }.array()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is IdentityContainer) return false
        return wrappedContentKey.contentEquals(other.wrappedContentKey) &&
            sealedBlob.contentEquals(other.sealedBlob) &&
            authMethod == other.authMethod &&
            salt.contentEqualsNullable(other.salt) &&
            nonce.contentEqualsNullable(other.nonce) &&
            generation.contentEqualsNullable(other.generation) &&
            version == other.version
    }

    override fun hashCode(): Int {
        var result = wrappedContentKey.contentHashCode()
        result = 31 * result + sealedBlob.contentHashCode()
        result = 31 * result + (authMethod?.hashCode() ?: 0)
        result = 31 * result + (salt?.contentHashCode() ?: 0)
        result = 31 * result + (nonce?.contentHashCode() ?: 0)
        result = 31 * result + (generation?.contentHashCode() ?: 0)
        result = 31 * result + version
        return result
    }

    companion object {
        private val MAGIC = "CVID".toByteArray(Charsets.US_ASCII)
        const val LEGACY_VERSION: Byte = 1
        const val VERSION: Byte = 2
        private const val GENERATION_LEN = 16
        private const val SALT_LEN = 16
        private const val NONCE_LEN = 12
        private const val LEGACY_HEADER = 4 + 1 + 2
        private const val V2_HEADER = 4 + 1 + 1 + GENERATION_LEN + 2
        private const val AES_GCM_WRAPPED_KEY_LEN = 32 + 16 + 12
        private const val AEAD_WRAPPED_KEY_LEN = 32 + 16

        /** @throws IdentityCorruptException if the bytes are not a valid supported container. */
        fun decode(bytes: ByteArray): IdentityContainer {
            if (bytes.size < 5) throw IdentityCorruptException("identity.enc truncated")
            val buf = ByteBuffer.wrap(bytes)
            val magic = ByteArray(4).also { buf.get(it) }
            if (!magic.contentEquals(MAGIC)) throw IdentityCorruptException("bad magic")
            return when (val version = buf.get()) {
                LEGACY_VERSION -> decodeLegacy(buf)
                VERSION -> decodeV2(buf)
                else -> throw IdentityCorruptException("unsupported version $version")
            }
        }

        private fun decodeLegacy(buf: ByteBuffer): IdentityContainer {
            if (buf.remaining() < 2) throw IdentityCorruptException("identity.enc truncated")
            val wrappedLen = buf.short.toInt() and 0xFFFF
            if (wrappedLen == 0 || buf.remaining() <= wrappedLen) {
                throw IdentityCorruptException("identity.enc length fields inconsistent")
            }
            val wrapped = ByteArray(wrappedLen).also { buf.get(it) }
            val blob = ByteArray(buf.remaining()).also { buf.get(it) }
            return IdentityContainer(
                wrappedContentKey = wrapped,
                sealedBlob = blob,
                version = LEGACY_VERSION,
            )
        }

        private fun decodeV2(buf: ByteBuffer): IdentityContainer {
            if (buf.remaining() < 1 + GENERATION_LEN + 2) {
                throw IdentityCorruptException("identity.enc v2 header truncated")
            }
            val method = Tier1AuthMethod.fromWireTag(buf.get())
            val generation = ByteArray(GENERATION_LEN).also { buf.get(it) }
            val payloadLen = buf.short.toInt() and 0xFFFF
            if (buf.remaining() <= payloadLen) {
                throw IdentityCorruptException("identity.enc v2 length fields inconsistent")
            }
            val payload = ByteArray(payloadLen).also { buf.get(it) }
            val blob = ByteArray(buf.remaining()).also { buf.get(it) }
            return when (method) {
                Tier1AuthMethod.BIOMETRIC -> {
                    if (payload.size != AES_GCM_WRAPPED_KEY_LEN) {
                        throw IdentityCorruptException("invalid biometric envelope length")
                    }
                    IdentityContainer(
                        wrappedContentKey = payload,
                        sealedBlob = blob,
                        authMethod = method,
                        generation = generation,
                        version = VERSION,
                    )
                }
                Tier1AuthMethod.PASSPHRASE -> {
                    if (payload.size != SALT_LEN + NONCE_LEN + AEAD_WRAPPED_KEY_LEN) {
                        throw IdentityCorruptException("invalid passphrase envelope length")
                    }
                    val p = ByteBuffer.wrap(payload)
                    val salt = ByteArray(SALT_LEN).also { p.get(it) }
                    val nonce = ByteArray(NONCE_LEN).also { p.get(it) }
                    val wrapped = ByteArray(p.remaining()).also { p.get(it) }
                    IdentityContainer(
                        wrappedContentKey = wrapped,
                        sealedBlob = blob,
                        authMethod = method,
                        salt = salt,
                        nonce = nonce,
                        generation = generation,
                        version = VERSION,
                    )
                }
            }
        }

        private fun ByteArray?.contentEqualsNullable(other: ByteArray?): Boolean =
            if (this == null) other == null else other != null && contentEquals(other)
    }
}
