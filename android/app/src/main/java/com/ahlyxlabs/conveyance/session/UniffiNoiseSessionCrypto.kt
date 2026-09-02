package com.ahlyxlabs.conveyance.session

import com.ahlyxlabs.conveyance.crypto.RustUnlockedIdentity
import com.ahlyxlabs.conveyance.crypto.UnlockedIdentity
import com.ahlyxlabs.conveyance.crypto.X25519PublicKey
import javax.inject.Inject
import uniffi.conveyance_crypto_ffi.NoiseFfiException
import uniffi.conveyance_crypto_ffi.NoiseSession as FfiNoiseSession
import uniffi.conveyance_crypto_ffi.noiseInitiate

/** [NoiseSessionCrypto] over the UniFFI bridge. Thin: unwrap, call, map. */
class UniffiNoiseSessionCrypto @Inject constructor() : NoiseSessionCrypto {

    override fun initiate(
        identity: UnlockedIdentity,
        pcStaticPublic: X25519PublicKey,
    ): NoiseSession {
        // The production identity is always Rust-backed; the raw FFI
        // handle is what noiseInitiate reads the X25519 static from.
        val ffiIdentity = (identity as? RustUnlockedIdentity)?.ffi
            ?: throw IllegalArgumentException("initiate() needs a Rust-backed UnlockedIdentity")
        return try {
            RustNoiseSession(noiseInitiate(ffiIdentity, pcStaticPublic.bytes))
        } catch (e: NoiseFfiException) {
            throw mapNoiseFfi(e)
        }
    }
}

/** Wraps the generated UniFFI object so callers never see `uniffi.*`. */
internal class RustNoiseSession(
    private val inner: FfiNoiseSession,
) : NoiseSession {

    override fun needsWrite(): Boolean = inner.needsWrite()

    override fun isHandshakeComplete(): Boolean = inner.isHandshakeComplete()

    override fun writeHandshakeMessage(payload: ByteArray): ByteArray =
        guarded { inner.writeHandshakeMessage(payload) }

    override fun readHandshakeMessage(message: ByteArray): ByteArray =
        guarded { inner.readHandshakeMessage(message) }

    override fun encrypt(plaintext: ByteArray): ByteArray =
        guarded { inner.encrypt(plaintext) }

    override fun decrypt(ciphertext: ByteArray): ByteArray =
        guarded { inner.decrypt(ciphertext) }

    /** Drops the Rust object; its `snow` state is wiped on drop. */
    override fun close() = inner.close()

    private inline fun guarded(block: () -> ByteArray): ByteArray =
        try {
            block()
        } catch (e: NoiseFfiException) {
            throw mapNoiseFfi(e)
        }
}

internal fun mapNoiseFfi(e: NoiseFfiException): SessionException = when (e) {
    is NoiseFfiException.HandshakeFailed -> SessionException.HandshakeFailed()
    is NoiseFfiException.SessionEnded -> SessionException.SessionEnded()
    is NoiseFfiException.NotHandshaking -> SessionException.WrongPhase("expected handshake phase")
    is NoiseFfiException.NotInTransport -> SessionException.WrongPhase("expected transport phase")
    is NoiseFfiException.BadKeyBytes -> SessionException.HandshakeFailed()
}
