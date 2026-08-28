package com.ahlyxlabs.conveyance.crypto

/**
 * Typed value wrappers for the crypto surface.
 *
 * They exist so consumers pass an `Ed25519SecretKey`, not a bare
 * `ByteArray` that could be any 32 bytes, and so secret-bearing values
 * redact themselves in logs and offer `destroy()`. None of the
 * UniFFI-generated `uniffi.conveyance_crypto_ffi.*` types appear in the
 * public API — this file (and [ConveyanceCrypto]) is the boundary.
 *
 * See [CryptoException] for what `destroy()` does and does not guarantee.
 */

/** A secret whose backing bytes are wiped on [destroy] (best effort — see [CryptoException]). */
sealed class Secret(bytes: ByteArray) {
    private val backing: ByteArray = bytes.copyOf()
    private var alive = true

    /** The raw bytes. Do not retain the returned reference past [destroy]. */
    fun bytes(): ByteArray {
        check(alive) { "secret has been destroyed" }
        return backing.copyOf()
    }

    /** Overwrite the backing array with zeros. Idempotent. */
    fun destroy() {
        backing.fill(0)
        alive = false
    }

    final override fun toString(): String = "${this::class.simpleName}(<redacted>)"
}

/** Ed25519 signing key: 32-byte scalar. */
class Ed25519SecretKey(bytes: ByteArray) : Secret(bytes) {
    init {
        require(bytes.size == 32) { "Ed25519 secret key must be 32 bytes, got ${bytes.size}" }
    }
}

/** X25519 static secret: 32-byte scalar. */
class X25519SecretKey(bytes: ByteArray) : Secret(bytes) {
    init {
        require(bytes.size == 32) { "X25519 secret key must be 32 bytes, got ${bytes.size}" }
    }
}

/** A 32-byte key-encryption / data-encryption key (e.g. an Argon2id DEK). */
class DerivedKey(bytes: ByteArray) : Secret(bytes) {
    init {
        require(bytes.size == 32) { "derived key must be 32 bytes, got ${bytes.size}" }
    }
}

/** A 32-byte ChaCha20-Poly1305 key. */
class AeadKey(bytes: ByteArray) : Secret(bytes) {
    init {
        require(bytes.size == 32) { "AEAD key must be 32 bytes, got ${bytes.size}" }
    }
}

/** A 32-byte Ed25519 public key. Not secret. */
@JvmInline
value class Ed25519PublicKey(val bytes: ByteArray) {
    init {
        require(bytes.size == 32) { "Ed25519 public key must be 32 bytes" }
    }
}

/** A 32-byte X25519 public key. Not secret. */
@JvmInline
value class X25519PublicKey(val bytes: ByteArray) {
    init {
        require(bytes.size == 32) { "X25519 public key must be 32 bytes" }
    }
}

/** A 64-byte Ed25519 compact signature. Not secret. */
@JvmInline
value class Ed25519Signature(val bytes: ByteArray) {
    init {
        require(bytes.size == 64) { "Ed25519 signature must be 64 bytes" }
    }
}

/** A 12-byte ChaCha20-Poly1305 nonce. Not secret; uniqueness is the caller's contract. */
@JvmInline
value class AeadNonce(val bytes: ByteArray) {
    init {
        require(bytes.size == 12) { "AEAD nonce must be 12 bytes" }
    }
}

/**
 * A validated BIP-39 recovery phrase. Its characters cannot be wiped (a
 * Kotlin `String` is immutable); the spec's answer to that is to never
 * store it. [toString] is redacted so it does not leak into a log.
 */
class RecoveryPhrase(private val phrase: String) {
    /** The 24 words, in order. */
    val words: List<String> get() = phrase.split(" ")

    /** The canonical space-separated form, for handing back to the bridge. */
    internal fun raw(): String = phrase

    override fun toString(): String = "RecoveryPhrase(<redacted>)"
}

/** Both long-term identity keypairs derived from a [RecoveryPhrase]. */
class IdentityKeys(
    val ed25519Secret: Ed25519SecretKey,
    val ed25519Public: Ed25519PublicKey,
    val x25519Secret: X25519SecretKey,
    val x25519Public: X25519PublicKey,
) {
    /** Wipe both secret scalars (best effort — see [CryptoException]). */
    fun destroy() {
        ed25519Secret.destroy()
        x25519Secret.destroy()
    }
}

/**
 * The domain-separation tag prepended to canonical JSON before signing.
 * The spec defines exactly these; more can be added as constants without
 * an API change.
 */
@JvmInline
value class SigningContext(val bytes: ByteArray) {
    companion object {
        /** `"conveyance-approve-v1"` — ApprovalResponse signatures. */
        val APPROVE = SigningContext("conveyance-approve-v1".toByteArray(Charsets.US_ASCII))

        /** `"conveyance-execute-v1"` — ExecuteResponse signatures. */
        val EXECUTE = SigningContext("conveyance-execute-v1".toByteArray(Charsets.US_ASCII))

        /**
         * `"conveyance-phone-log-v1"` — signed rows in an approval-log
         * export. Must equal `conveyance_core::storage::logdiff::PHONE_LOG_CONTEXT`;
         * the PC diff tool verifies against exactly this preimage.
         */
        val PHONE_LOG = SigningContext("conveyance-phone-log-v1".toByteArray(Charsets.US_ASCII))
    }
}

/** One loggable event — the fields that participate in the hash chain. */
data class LogEvent(
    /** 16-byte request correlation id. */
    val reqId: ByteArray,
    val eventType: String,
    /** Canonical JSON text of the event details. */
    val payloadJson: String,
    /** Unix seconds. */
    val timestamp: Long,
) {
    init {
        require(reqId.size == 16) { "req_id must be 16 bytes, got ${reqId.size}" }
    }

    // Content equality: this is a value, and tests compare them.
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is LogEvent) return false
        return reqId.contentEquals(other.reqId) &&
            eventType == other.eventType &&
            payloadJson == other.payloadJson &&
            timestamp == other.timestamp
    }

    override fun hashCode(): Int {
        var result = reqId.contentHashCode()
        result = 31 * result + eventType.hashCode()
        result = 31 * result + payloadJson.hashCode()
        result = 31 * result + timestamp.hashCode()
        return result
    }
}

/** A stored hash-chain row: event content plus the two chaining columns. */
data class ChainRow(
    val event: LogEvent,
    /** 32-byte SHA-256 of the previous row (32 zero bytes for the first). */
    val prevHash: ByteArray,
    /** 32-byte SHA-256 of this row. */
    val hash: ByteArray,
) {
    init {
        require(prevHash.size == 32) { "prev_hash must be 32 bytes" }
        require(hash.size == 32) { "hash must be 32 bytes" }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ChainRow) return false
        return event == other.event &&
            prevHash.contentEquals(other.prevHash) &&
            hash.contentEquals(other.hash)
    }

    override fun hashCode(): Int {
        var result = event.hashCode()
        result = 31 * result + prevHash.contentHashCode()
        result = 31 * result + hash.contentHashCode()
        return result
    }
}

/** The specific reason a hash-chain walk failed. */
sealed class ChainBreak {
    /** A row's content no longer matches its stored hash. */
    data class ContentTampered(val expectedHash: String, val storedHash: String) : ChainBreak()

    /** A row's `prev_hash` does not chain to the running head — a removal or reorder. */
    data class LinkBroken(val expectedPrev: String, val storedPrev: String) : ChainBreak()
}

/** Result of [ConveyanceCrypto.verifyChain]. */
sealed class ChainVerification {
    /** Every link and content hash checked out. */
    data class Intact(val verifiedRows: Long) : ChainVerification()

    /** The walk stopped at row [index]; [reason] carries the detail. */
    data class Broken(val index: Long, val reason: ChainBreak) : ChainVerification()
}
