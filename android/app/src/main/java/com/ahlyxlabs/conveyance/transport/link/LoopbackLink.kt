package com.ahlyxlabs.conveyance.transport.link

import com.ahlyxlabs.conveyance.transport.framing.Frame
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ClosedReceiveChannelException
import kotlinx.coroutines.channels.ClosedSendChannelException
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow

/**
 * An in-memory cross-wired [PhoneLink] pair — the Kotlin peer of Rust's
 * `transport::mock`. A radio cannot loop back to itself, so this is how
 * the framing stack, and later the Noise session (10.4), get exercised
 * end to end without hardware.
 *
 * What one endpoint [send]s, the other receives as a [LinkEvent.Chunk],
 * in order, with real coroutine backpressure. Tearing down either
 * endpoint tears down both: the initiator sees [LinkTeardown.LocalShutdown],
 * its peer sees the reason the initiator supplied (default
 * [LinkTeardown.PeerDisconnected]).
 */
class LoopbackLink private constructor(
    override val maxWriteLen: Int,
    private val outbound: Channel<ByteArray>,
    private val inbound: Channel<ByteArray>,
    private val shared: Shared,
    private val self: Any,
) : PhoneLink {

    override suspend fun send(chunk: ByteArray) {
        shared.reasonFor(self)?.let { throw LinkClosedException(it) }
        require(chunk.size <= maxWriteLen + Frame.HEADER_LEN) {
            "frame ${chunk.size} exceeds one PDU (${maxWriteLen + Frame.HEADER_LEN})"
        }
        try {
            outbound.send(chunk)
        } catch (_: ClosedSendChannelException) {
            throw LinkClosedException(shared.reasonFor(self) ?: LinkTeardown.PeerDisconnected)
        }
    }

    override val events: Flow<LinkEvent> = flow {
        try {
            for (chunk in inbound) emit(LinkEvent.Chunk(chunk))
        } catch (_: ClosedReceiveChannelException) {
            // fall through to the terminal event
        }
        emit(LinkEvent.Torn(shared.reasonFor(self) ?: LinkTeardown.PeerDisconnected))
    }

    override fun shutdown() = shared.tearDown(self, LinkTeardown.LocalShutdown)

    /**
     * Test hook: simulate an external teardown (adapter off, subscription
     * lost, a framing violation) on this endpoint. The peer sees
     * [peerReason].
     */
    fun failWith(local: LinkTeardown, peerReason: LinkTeardown = LinkTeardown.PeerDisconnected) =
        shared.tearDown(self, local, peerReason)

    private class Shared(private val channels: List<Channel<ByteArray>>) {
        private val lock = Any()
        private var initiator: Any? = null
        private var initiatorReason: LinkTeardown? = null
        private var peerReason: LinkTeardown? = null

        fun tearDown(
            by: Any,
            local: LinkTeardown,
            peer: LinkTeardown = LinkTeardown.PeerDisconnected,
        ) {
            synchronized(lock) {
                if (initiator != null) return
                initiator = by
                initiatorReason = local
                peerReason = peer
            }
            channels.forEach { it.close() }
        }

        fun reasonFor(endpoint: Any): LinkTeardown? = synchronized(lock) {
            when {
                initiator == null -> null
                initiator === endpoint -> initiatorReason
                else -> peerReason
            }
        }
    }

    companion object {
        /** A connected pair. [maxWriteLen] defaults to a 247-MTU budget. */
        fun pair(maxWriteLen: Int = Frame.maxFramePayload(247)): Pair<LoopbackLink, LoopbackLink> {
            val a2b = Channel<ByteArray>(Channel.BUFFERED)
            val b2a = Channel<ByteArray>(Channel.BUFFERED)
            val shared = Shared(listOf(a2b, b2a))
            val a = Any()
            val b = Any()
            return LoopbackLink(maxWriteLen, a2b, b2a, shared, a) to
                LoopbackLink(maxWriteLen, b2a, a2b, shared, b)
        }
    }
}
