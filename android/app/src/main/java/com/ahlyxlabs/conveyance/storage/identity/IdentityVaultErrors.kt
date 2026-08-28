package com.ahlyxlabs.conveyance.storage.identity

/**
 * The `conveyance_tier1` key was permanently invalidated (a biometric
 * enrollment change, per `setInvalidatedByBiometricEnrollment(true)`).
 * The sealed identity can no longer be opened on this device.
 *
 * Recovery: the user restores from their 24-word recovery phrase — which
 * re-derives the *same* identity keys — and then re-pairs each PC (the PC
 * cannot tell a legitimate restore from a stolen phrase, so it forces the
 * QR ceremony). See CONVEYANCE_SPEC.md "Recovery".
 */
class IdentityInvalidatedException(cause: Throwable? = null) :
    Exception("the identity key was invalidated; restore from the recovery phrase", cause)

/** `identity.enc` is missing, malformed, or will not decrypt. */
class IdentityCorruptException(message: String, cause: Throwable? = null) :
    Exception(message, cause)
