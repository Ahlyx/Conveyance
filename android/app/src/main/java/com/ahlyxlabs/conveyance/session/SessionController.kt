package com.ahlyxlabs.conveyance.session

import com.ahlyxlabs.conveyance.crypto.UnlockedIdentity
import com.ahlyxlabs.conveyance.crypto.X25519PublicKey

/**
 * The seam 10.9's foreground service implements. **Not implemented in
 * 10.4b** — [PhoneSessionFactory] is the concrete seam that 10.4b ships and
 * tests drive directly; this interface just fixes the shape 10.9 and 10.10
 * build against.
 *
 * 10.9's implementation will:
 *
 *  1. start the BLE peripheral advertising (10.3b `BlePeripheral`);
 *  2. await its `PhoneLink` within [SESSION_START_TIMEOUT_MS];
 *  3. create the session with an `onEnded` callback that persists the
 *     session-end row with its [EndReason], notifies the user, and stops the
 *     BLE peripheral (aborted handshakes never invoke it);
 *  4. `phoneSession.start()` — which itself bounds the handshake with
 *     [HANDSHAKE_BUDGET_MS];
 *  5. expose [current] for the session-status UI (10.10) and the kill switch.
 *
 * A failed [startSession] leaves [current] null; a fresh call with the same
 * identity must proceed cleanly (spec 1631310).
 */
interface SessionController {

    /** The live session, or `null` when none is up. */
    val current: PhoneSession?

    /**
     * Bring a session up end-to-end: advertise, await the link, run the
     * handshake. Suspends until ACTIVE.
     *
     * @throws SessionException.HandshakeFailed on any handshake failure.
     */
    suspend fun startSession(
        identity: UnlockedIdentity,
        pcStaticPublic: X25519PublicKey,
    ): PhoneSession

    /** Tear the current session down for [reason]. Idempotent. */
    fun endSession(reason: EndReason)
}
