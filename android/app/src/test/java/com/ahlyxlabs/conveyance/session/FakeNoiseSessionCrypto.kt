package com.ahlyxlabs.conveyance.session

import com.ahlyxlabs.conveyance.crypto.UnlockedIdentity
import com.ahlyxlabs.conveyance.crypto.X25519PublicKey

/**
 * A [NoiseSessionCrypto] that does no crypto: it lets the JVM `PhoneSession`
 * suite exercise lifecycle, timers, framing continuity and teardown without
 * the cross-compiled `.so`. Real Noise is covered by `PhoneSessionRealNoiseTest`
 * (instrumented) and the `Noise*ParityTest` suites.
 *
 * The transport transform is **XOR-with-counter**, not identity — a framing
 * bug that only bites on non-identity bytes, or one that reorders frames,
 * surfaces as a decrypt mismatch. Identity would hide both.
 */
class FakeNoiseSessionCrypto(
    private val completeAfterReads: Int = 1,
    private val failFirstRead: Boolean = false,
) : NoiseSessionCrypto {

    /** The session most recently handed out — for assertions (closed, failNextDecrypt). */
    var last: FakeNoiseSession? = null
        private set

    override fun initiate(
        identity: UnlockedIdentity,
        pcStaticPublic: X25519PublicKey,
    ): NoiseSession =
        FakeNoiseSession(isInitiator = true, completeAfterReads, failFirstRead).also { last = it }
}

/**
 * Models a KK party. As initiator: writes msg1, then completes after
 * [completeAfterReads] reads (KK is one read for the phone). As responder
 * (built directly by a test's "fake PC"): completes once it has read msg1
 * and written msg2.
 */
class FakeNoiseSession(
    val isInitiator: Boolean,
    private val completeAfterReads: Int = 1,
    failFirstRead: Boolean = false,
) : NoiseSession {

    private var writes = 0
    private var reads = 0
    private var complete = false
    private var pendingReadFailure = failFirstRead
    private var encSeq = 0
    private var decSeq = 0

    /** Set by a test to make the next [decrypt] throw [SessionException.SessionEnded]. */
    var failNextDecrypt = false

    var closed = false
        private set

    override fun needsWrite(): Boolean = when {
        complete -> false
        isInitiator -> writes == 0
        else -> reads >= 1 && writes == 0
    }

    override fun isHandshakeComplete(): Boolean = complete

    override fun writeHandshakeMessage(payload: ByteArray): ByteArray {
        check(!complete) { "handshake already complete" }
        writes++
        if (!isInitiator && reads >= 1) complete = true
        return HS_PREFIX + writes.toByte() + payload
    }

    override fun readHandshakeMessage(message: ByteArray): ByteArray {
        check(!complete) { "handshake already complete" }
        if (pendingReadFailure) {
            pendingReadFailure = false
            throw SessionException.HandshakeFailed()
        }
        reads++
        if (isInitiator && reads >= completeAfterReads) complete = true
        return ByteArray(0)
    }

    override fun encrypt(plaintext: ByteArray): ByteArray {
        check(complete) { "not in transport phase" }
        return xorCounter(plaintext, encSeq++)
    }

    override fun decrypt(ciphertext: ByteArray): ByteArray {
        check(complete) { "not in transport phase" }
        if (failNextDecrypt) {
            failNextDecrypt = false
            throw SessionException.SessionEnded()
        }
        return xorCounter(ciphertext, decSeq++)
    }

    override fun close() {
        closed = true
    }

    companion object {
        private val HS_PREFIX = "HS".toByteArray()

        /** XOR is its own inverse: two sessions whose counters advance in lockstep round-trip. */
        fun xorCounter(data: ByteArray, seq: Int): ByteArray =
            ByteArray(data.size) { i -> (data[i].toInt() xor ((seq + i + 1) and 0xFF)).toByte() }
    }
}

/** An [UnlockedIdentity] the fake crypto ignores — its scalars never matter here. */
class FakeUnlockedIdentity : UnlockedIdentity {
    var closed = false
        private set

    override fun ed25519PublicKey() = error("unused")
    override fun x25519PublicKey() = X25519PublicKey(ByteArray(32))
    override fun sign(message: ByteArray) = error("unused")
    override fun close() {
        closed = true
    }
}
