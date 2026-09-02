package com.ahlyxlabs.conveyance.session

import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.conveyance_crypto_ffi.NoiseFfiException

/** Host-JVM: the UniFFI `NoiseFfiException` -> `SessionException` map. */
class SessionExceptionMappingTest {

    @Test
    fun everyNoiseFfiVariantMapsToASessionException() {
        assertTrue(mapNoiseFfi(NoiseFfiException.HandshakeFailed()) is SessionException.HandshakeFailed)
        assertTrue(mapNoiseFfi(NoiseFfiException.SessionEnded()) is SessionException.SessionEnded)
        assertTrue(mapNoiseFfi(NoiseFfiException.NotHandshaking()) is SessionException.WrongPhase)
        assertTrue(mapNoiseFfi(NoiseFfiException.NotInTransport()) is SessionException.WrongPhase)
        // Bad key bytes at the boundary is a caller bug that only shows up
        // as an unusable handshake — mapped generic, not leaked.
        assertTrue(mapNoiseFfi(NoiseFfiException.BadKeyBytes()) is SessionException.HandshakeFailed)
    }
}
