package com.ahlyxlabs.conveyance.transport.link

import kotlinx.coroutines.flow.Flow

/**
 * One live connection's data path — the Kotlin peer of Rust's
 * `conveyance_core::transport::Link`.
 *
 * The GATT peripheral (10.3b) implements it; the Noise session (10.4)
 * and the pairing ceremony (10.5) consume it. Nothing here knows about
 * sessions, Noise, or pairing — it moves raw framed bytes and reports
 * when it tears down.
 */
interface PhoneLink {

    /**
     * The per-frame **payload** budget — `Frame.maxFramePayload(
     * negotiatedMtu)` — to hand straight to [MessageSplitter.split]. A
     * whole frame is this plus the 6-byte header, which is exactly what
     * [send] accepts. It can grow after an MTU renegotiation, so read it
     * again before each split rather than caching it across a message.
     * Mirrors Rust `Link::max_write_len`.
     */
    val maxWriteLen: Int

    /**
     * Push one frame toward the peer. The frame — header plus up to
     * [maxWriteLen] payload bytes — must not exceed `maxWriteLen +
     * Frame.HEADER_LEN`; a larger chunk is a caller bug and throws
     * `IllegalArgumentException` (this layer never re-splits). Suspends
     * while the outbound path is full — legitimate backpressure; callers
     * await it rather than buffering without bound — and returns once the
     * frame is handed to the transport. Throws [LinkClosedException] if
     * the link has already torn down or tears down while suspended.
     * Mirrors Rust `Link::send`.
     */
    suspend fun send(chunk: ByteArray)

    /**
     * Inbound events in arrival order: one [LinkEvent.Chunk] per
     * notification / write the transport delivered, then exactly one
     * terminal [LinkEvent.Torn] when the link tears down, after which the
     * flow completes. A normal disconnect is a `Torn`, never an
     * exception. Collect once.
     */
    val events: Flow<LinkEvent>

    /**
     * Begin teardown. Idempotent. After this, [send] throws and [events]
     * emits [LinkEvent.Torn] (reason [LinkTeardown.LocalShutdown] if this
     * call initiated it) and completes. Mirrors Rust `Link::shutdown`.
     */
    fun shutdown()
}

/** An item from [PhoneLink.events]. */
sealed interface LinkEvent {
    /** One inbound chunk exactly as the transport delivered it. */
    class Chunk(val bytes: ByteArray) : LinkEvent

    /** The link has torn down; no further events follow. Terminal. */
    data class Torn(val reason: LinkTeardown) : LinkEvent
}

/** Thrown by [PhoneLink.send] once the link is gone. */
class LinkClosedException(val reason: LinkTeardown) :
    IllegalStateException("link closed: ${reason.message}")
