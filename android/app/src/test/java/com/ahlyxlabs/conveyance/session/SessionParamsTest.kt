package com.ahlyxlabs.conveyance.session

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes

/**
 * Bounds parity with `conveyance_core::session::timers`: every edge that
 * `validated_accepts_*` / `validated_rejects_every_violated_bound` covers on
 * the Rust side, plus that [SessionParams.OutOfBounds] names the field.
 */
class SessionParamsTest {

    @Test
    fun specDefaultsMatchTheDaemon() {
        val p = SessionParams.specDefaults()
        assertEquals(30.minutes, p.idleTimeout)
        assertEquals(2.minutes, p.warnBefore)
        assertEquals(4.hours, p.hardCap)
    }

    @Test
    fun boundConstantsMatchTheDaemon() {
        assertEquals(5.minutes, SessionParams.IDLE_MIN)
        assertEquals(4.hours, SessionParams.IDLE_MAX)
        assertEquals(30.minutes, SessionParams.CAP_MIN)
        assertEquals(24.hours, SessionParams.CAP_MAX)
        assertEquals(2.minutes, SessionParams.WARN_DEFAULT)
    }

    @Test
    fun validatedAcceptsDefaultsAndInclusiveExtremes() {
        SessionParams.validated(30.minutes, 2.minutes, 4.hours)
        SessionParams.validated(SessionParams.IDLE_MIN, 1.minutes, SessionParams.CAP_MIN)
        SessionParams.validated(SessionParams.IDLE_MAX, 1.minutes, SessionParams.CAP_MAX)
    }

    @Test
    fun validatedKeepsExactlyWhatItWasGiven() {
        val p = SessionParams.validated(25.minutes, 90_000.milliseconds, 3.hours)
        assertEquals(25.minutes, p.idleTimeout)
        assertEquals(90_000.milliseconds, p.warnBefore)
        assertEquals(3.hours, p.hardCap)
    }

    @Test
    fun rejectsIdleBelowMinAndAboveMax() {
        assertField("idleTimeout") {
            SessionParams.validated(SessionParams.IDLE_MIN - 1.milliseconds, 1.minutes, SessionParams.CAP_MIN)
        }
        assertField("idleTimeout") {
            SessionParams.validated(SessionParams.IDLE_MAX + 1.milliseconds, 1.minutes, SessionParams.CAP_MAX)
        }
    }

    @Test
    fun rejectsCapBelowMinAndAboveMax() {
        assertField("hardCap") {
            SessionParams.validated(SessionParams.IDLE_MIN, 1.minutes, SessionParams.CAP_MIN - 1.milliseconds)
        }
        assertField("hardCap") {
            SessionParams.validated(SessionParams.IDLE_MIN, 1.minutes, SessionParams.CAP_MAX + 1.milliseconds)
        }
    }

    @Test
    fun rejectsWarnNotShorterThanIdle() {
        assertField("warnBefore") {
            SessionParams.validated(10.minutes, 10.minutes, 1.hours)
        }
        assertField("warnBefore") {
            SessionParams.validated(10.minutes, 11.minutes, 1.hours)
        }
    }

    @Test
    fun rejectsNonPositiveWarningLead() {
        assertField("warnBefore") {
            SessionParams.validated(10.minutes, 0.minutes, 1.hours)
        }
        assertField("warnBefore") {
            SessionParams.validated(10.minutes, -1.minutes, 1.hours)
        }
    }

    @Test
    fun capBelowIdleIsPermitted() {
        // Independent bounds; the cap dominates. Recorded deliberately, as
        // in timers.rs.
        val p = SessionParams.validated(4.hours, 2.minutes, 30.minutes)
        assertEquals(4.hours, p.idleTimeout)
        assertEquals(30.minutes, p.hardCap)
    }

    // The primary constructor is `private`: `SessionParams(a, b, c)` does not
    // resolve from this test (a different package would fail identically),
    // so `validated` / `specDefaults` are the only ways in. Compile-level
    // proof, not a runtime assertion.

    private fun assertField(expected: String, block: () -> Unit) {
        val e = assertThrows(SessionParams.OutOfBounds::class.java) { block() }
        assertEquals(expected, e.field)
    }
}
