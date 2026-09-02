package com.ahlyxlabs.conveyance.session

import uniffi.conveyance_crypto_ffi.NoiseFfiException
import uniffi.conveyance_crypto_ffi.noiseInitiateWithFixedEphemeral

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
}
