package com.ahlyxlabs.conveyance.session

import uniffi.conveyance_crypto_ffi.NoiseFfiException
import uniffi.conveyance_crypto_ffi.noiseInitiateWithFixedEphemeral
import uniffi.conveyance_crypto_ffi.noiseRespond

/**
 * DEBUG-ONLY. Starts a Noise KK **initiator** with a caller-supplied
 * X25519 static *and* ephemeral, so the phone's handshake bytes are
 * deterministic and can be pinned against `noise_fixtures.json` by
 * `NoiseHandshakeParityTest`.
 *
 * Compiled only into the debug variant — whose `.so` carries
 * `conveyance-crypto-ffi/test-vectors`. A fixed ephemeral has no forward
 * secrecy; the Rust export it calls logs a loud WARN, and it cannot
 * exist in a release build (the feature is off there and
 * `conveyance-noise` refuses to compile it with `debug_assertions` off).
 */
object NoiseTestVectors {

    fun initiateWithFixedEphemeral(
        phoneStaticSecret: ByteArray,
        pcStaticPublic: ByteArray,
        ephemeral: ByteArray,
    ): NoiseSession =
        try {
            RustNoiseSession(
                noiseInitiateWithFixedEphemeral(phoneStaticSecret, pcStaticPublic, ephemeral),
            )
        } catch (e: NoiseFfiException) {
            throw mapNoiseFfi(e)
        }

    /**
     * A KK **responder** — the role the PC daemon plays. For an
     * instrumented two-party round-trip over an in-memory link; the
     * phone never takes this role in production. Random ephemeral.
     */
    fun respond(pcStaticSecret: ByteArray, phoneStaticPublic: ByteArray): NoiseSession =
        try {
            RustNoiseSession(noiseRespond(pcStaticSecret, phoneStaticPublic))
        } catch (e: NoiseFfiException) {
            throw mapNoiseFfi(e)
        }
}
