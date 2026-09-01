package com.ahlyxlabs.conveyance.transport.link

import com.ahlyxlabs.conveyance.transport.framing.FramingException

/**
 * Why a [PhoneLink] tore down. Every cause is terminal — the link is not
 * reused and there is no auto-reconnect (spec "Session end"). The Noise
 * session layer (10.4) maps these onto its own end reasons; this layer
 * only reports them.
 */
sealed class LinkTeardown(val message: String) {

    /** The BLE connection dropped (ACL loss, out of range, central closed it). */
    data object PeerDisconnected : LinkTeardown("peer disconnected")

    /** The Bluetooth adapter was turned off under the connection. */
    data object AdapterOff : LinkTeardown("bluetooth adapter turned off")

    /**
     * The central cleared the `phone_to_pc_tx` CCCD without dropping the
     * connection. Phone→PC traffic is undeliverable, so the spec treats
     * this as equivalent to disconnection.
     */
    data object SubscriptionLost : LinkTeardown("phone_to_pc_tx subscription lost")

    /** Local teardown: kill switch, session end, or an explicit shutdown() call. */
    data object LocalShutdown : LinkTeardown("local shutdown")

    /** A framing rule was violated mid-stream; the offending error is [cause]. */
    class ProtocolViolation(val cause: FramingException) :
        LinkTeardown("framing violation: ${cause.message}")
}
