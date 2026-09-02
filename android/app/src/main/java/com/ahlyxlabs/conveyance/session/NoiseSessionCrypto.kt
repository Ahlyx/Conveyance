package com.ahlyxlabs.conveyance.session

import com.ahlyxlabs.conveyance.crypto.UnlockedIdentity
import com.ahlyxlabs.conveyance.crypto.X25519PublicKey
import java.io.Closeable

/**
 * The phone's half of the `Noise_KK_25519_ChaChaPoly_BLAKE2s` session, as
 * a stable Kotlin API over the UniFFI bridge (`conveyance-noise` through
 * `conveyance-crypto-ffi`).
 *
 * Session keys never cross the boundary: [initiate] takes the identity
 * **handle** — the phone's X25519 static is read inside Rust from its
 * native `Zeroizing` buffer — and returns an opaque [NoiseSession]. Both
 * the phone (here) and the PC daemon drive the same `snow`, so the
 * handshake and transport bytes match; the instrumented parity suite
 * pins that.
 */
interface NoiseSessionCrypto {

    /**
     * Begin the phone's KK handshake as **initiator** (spec: the phone
     * initiates). [pcStaticPublic] is the paired PC's long-term X25519
     * public key, from the pairing store.
     *
     * @throws SessionException.HandshakeFailed if the key material is unusable.
     */
    fun initiate(identity: UnlockedIdentity, pcStaticPublic: X25519PublicKey): NoiseSession
}

/**
 * An opaque, Rust-owned Noise KK session. Drive the handshake with
 * [writeHandshakeMessage] / [readHandshakeMessage] until
 * [isHandshakeComplete], then [encrypt] / [decrypt]. [close] (or
 * `use { }`) drops the Rust object and wipes its `snow` state.
 *
 * Handshake payloads are empty in Conveyance (spec "Session start").
 * Not thread-safe on the Rust side either — a `Mutex` serializes access,
 * so concurrent calls are safe but pointless; drive it from one coroutine.
 */
interface NoiseSession : Closeable {

    /** True while the handshake is unfinished and it is this side's turn to write. */
    fun needsWrite(): Boolean

    /** True once the handshake completed and transport mode is active. */
    fun isHandshakeComplete(): Boolean

    /** @throws SessionException.HandshakeFailed, SessionException.WrongPhase */
    fun writeHandshakeMessage(payload: ByteArray = ByteArray(0)): ByteArray

    /** @throws SessionException.HandshakeFailed, SessionException.WrongPhase */
    fun readHandshakeMessage(message: ByteArray): ByteArray

    /** @throws SessionException.SessionEnded, SessionException.WrongPhase */
    fun encrypt(plaintext: ByteArray): ByteArray

    /**
     * Open one transport message. A MAC failure is
     * [SessionException.SessionEnded] — end the session.
     *
     * @throws SessionException.SessionEnded, SessionException.WrongPhase
     */
    fun decrypt(ciphertext: ByteArray): ByteArray
}
