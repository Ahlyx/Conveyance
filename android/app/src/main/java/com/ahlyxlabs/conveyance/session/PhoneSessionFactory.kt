package com.ahlyxlabs.conveyance.session

import com.ahlyxlabs.conveyance.crypto.X25519PublicKey
import com.ahlyxlabs.conveyance.storage.identity.UnlockedPhoneSession
import com.ahlyxlabs.conveyance.storage.pairings.PairingEntity
import com.ahlyxlabs.conveyance.session.di.SessionDispatcher
import com.ahlyxlabs.conveyance.transport.link.PhoneLink
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.CoroutineDispatcher

/**
 * Builds a [PhoneSession] per connection. This is the concrete seam 10.4b
 * ships and tests use; [SessionController] (10.9) is layered on top.
 *
 * Holds no per-call state, so a [PhoneSession] whose handshake failed is
 * recovered simply by calling [create] again with the same identity — the
 * spec-1631310 "fresh start proceeds cleanly" guarantee.
 */
@Singleton
class PhoneSessionFactory @Inject constructor(
    @SessionDispatcher private val dispatcher: CoroutineDispatcher,
    private val noiseCrypto: NoiseSessionCrypto,
) {

    /**
     * @param unlockedSession the Tier 1 session holding the Rust-owned identity
     *   in Rust — see [NoiseSessionCrypto]).
     * @param pcStaticPublic the paired PC's long-term X25519 public key.
     * @param link the live connection, already SUBSCRIBED (10.3b).
     * @param params timing bounds; defaults to the spec defaults until 10.10
     *   provides a settings surface.
     * @param onEnded invoked once, on `@SessionDispatcher`, when the session
     *   reaches ENDED — with the reason. The 10.9 owner must use this event to
     *   persist the spec-mandated session-end row, notify the user, and stop
     *   the BLE peripheral. It is never invoked for an aborted handshake.
     */
    fun create(
        unlockedSession: UnlockedPhoneSession,
        pcStaticPublic: X25519PublicKey,
        link: PhoneLink,
        params: SessionParams = SessionParams.specDefaults(),
        onEnded: (EndReason) -> Unit,
    ): PhoneSession = PhoneSession(
        unlockedSession = unlockedSession,
        pcStaticPublic = pcStaticPublic,
        link = link,
        params = params,
        noiseCrypto = noiseCrypto,
        dispatcher = dispatcher,
        monotonicClock = AndroidSessionMonotonicClock,
        onEnded = onEnded,
    )

    /**
     * Production approval sessions are constructed from a persisted pairing.
     * Noise authenticates the paired X25519 static key; this same row supplies
     * the trusted PC Ed25519 identity and display name to approval handling.
     */
    fun createForPairing(
        unlockedSession: UnlockedPhoneSession,
        pairing: PairingEntity,
        link: PhoneLink,
        params: SessionParams = SessionParams.specDefaults(),
        onEnded: (EndReason) -> Unit,
    ): PhoneSession {
        require(pairing.pcIdPub.size == 32) { "paired PC identity key must be 32 bytes" }
        require(pairing.pcDhPub.size == 32) { "paired PC static key must be 32 bytes" }
        require(pairing.pcName.toByteArray(Charsets.UTF_8).size in 1..64) {
            "paired PC name must be 1 to 64 UTF-8 bytes"
        }
        val staticPublic = X25519PublicKey(pairing.pcDhPub.copyOf())
        return PhoneSession(
            unlockedSession = unlockedSession,
            pcStaticPublic = staticPublic,
            link = link,
            params = params,
            noiseCrypto = noiseCrypto,
            dispatcher = dispatcher,
            monotonicClock = AndroidSessionMonotonicClock,
            onEnded = onEnded,
            authenticatedPeer = AuthenticatedPeer(
                pcIdPub = pairing.pcIdPub,
                pcDhPub = pairing.pcDhPub,
                pcName = pairing.pcName,
            ),
        )
    }
}

/** Immutable public identity/name associated with the Noise-authenticated peer. */
class AuthenticatedPeer(
    pcIdPub: ByteArray,
    pcDhPub: ByteArray,
    val pcName: String,
) {
    private val idBytes = pcIdPub.copyOf()
    private val dhBytes = pcDhPub.copyOf()

    val pcIdPub: ByteArray get() = idBytes.copyOf()
    val pcDhPub: ByteArray get() = dhBytes.copyOf()
}
