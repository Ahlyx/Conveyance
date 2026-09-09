package com.ahlyxlabs.conveyance.session

import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes

/**
 * Session timing parameters — a Kotlin port of
 * `conveyance_core::session::timers::SessionParams`.
 *
 * Bounds enforcement lives here, at construction. [validated] is the only
 * constructor callers can reach (the primary constructor is `private`), so a
 * future settings screen (10.10) physically cannot build parameters that
 * weaken the spec's minimums or exceed its maximums. Invalid input is
 * **rejected, never silently clamped**: a value the user believes says one
 * thing must not secretly do another. [OutOfBounds] names the offending
 * field so 10.10 can render a precise message.
 *
 * Values are [Duration]; call sites pass `.inWholeMilliseconds` to
 * coroutine `delay`.
 */
class SessionParams private constructor(
    val idleTimeout: Duration,
    val warnBefore: Duration,
    val hardCap: Duration,
) {

    companion object {
        /** Spec table "Timers": minimums and maximums, and the default warning lead. */
        val IDLE_MIN: Duration = 5.minutes
        val IDLE_MAX: Duration = 4.hours
        val CAP_MIN: Duration = 30.minutes
        val CAP_MAX: Duration = 24.hours
        val WARN_DEFAULT: Duration = 2.minutes

        /** Spec defaults: 30 min idle, 2 min warning, 4 h hard cap. */
        fun specDefaults(): SessionParams = SessionParams(30.minutes, WARN_DEFAULT, 4.hours)

        /**
         * The canonical constructor. Every externally supplied value passes
         * through here.
         *
         * @throws OutOfBounds if `idleTimeout` or `hardCap` is outside its
         *   `[MIN, MAX]` range, or if `warnBefore >= idleTimeout` (the
         *   warning must fit inside the idle window with room to matter).
         *   `hardCap < idleTimeout` is **permitted** — each value has
         *   independent bounds and the cap simply dominates (idle 4 h with
         *   cap 30 min means sessions always die at 30 min). Matches the
         *   daemon's recorded decision.
         */
        fun validated(
            idleTimeout: Duration,
            warnBefore: Duration,
            hardCap: Duration,
        ): SessionParams {
            requireInRange("idleTimeout", idleTimeout, IDLE_MIN, IDLE_MAX)
            requireInRange("hardCap", hardCap, CAP_MIN, CAP_MAX)
            if (warnBefore <= Duration.ZERO) {
                throw OutOfBounds("warnBefore", "must be positive", warnBefore)
            }
            if (warnBefore >= idleTimeout) {
                throw OutOfBounds(
                    "warnBefore",
                    "must be shorter than idleTimeout ($idleTimeout)",
                    warnBefore,
                )
            }
            return SessionParams(idleTimeout, warnBefore, hardCap)
        }

        private fun requireInRange(field: String, value: Duration, min: Duration, max: Duration) {
            if (value < min || value > max) {
                throw OutOfBounds(field, "must be within $min..$max", value)
            }
        }
    }

    /** A [validated] argument fell outside its permitted range. */
    class OutOfBounds(
        val field: String,
        requirement: String,
        val given: Duration,
    ) : IllegalArgumentException("session param '$field' $requirement (given $given)")
}
