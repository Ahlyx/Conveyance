package com.ahlyxlabs.conveyance.session

/**
 * The session layer's error surface, in Kotlin terms.
 *
 * Callers catch these, never the UniFFI-generated `NoiseFfiException`.
 * [HandshakeFailed] and [SessionEnded] are deliberately coarse — the same
 * reason the Rust `NoiseError` is: a security product must not tell a
 * caller *which* internal check failed. Unlike the crypto layer these
 * throw rather than return `Result`, because the session's callers
 * (`PhoneSession`, later 10.7) already wrap the handshake and the
 * transport loop in try/catch and act on the category.
 */
sealed class SessionException(message: String) : Exception(message) {

    /** The Noise KK handshake failed — any cause. Fatal; abort to NO_SESSION. */
    class HandshakeFailed : SessionException("noise handshake failed")

    /**
     * A transport message failed to open, or the peers desynchronized.
     * Noise has no recovery from either; the caller ends the session.
     */
    class SessionEnded : SessionException("noise session ended")

    /** A [NoiseSession] method was called in the wrong phase — a caller bug. */
    class WrongPhase(detail: String) : SessionException(detail)

    /** The session is not ACTIVE — the phone-side cold-start guard (10.4b). */
    class NotActive : SessionException("no active session")
}
