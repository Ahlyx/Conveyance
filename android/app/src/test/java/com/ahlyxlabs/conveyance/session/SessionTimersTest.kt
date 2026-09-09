package com.ahlyxlabs.conveyance.session

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes

/**
 * Virtual-time parity with `timers.rs`'s `#[tokio::test(start_paused = true)]`
 * watchdog tests. `runTest` + `advanceTimeBy` + `runCurrent` is the Kotlin
 * equivalent of paused tokio time + `tokio::time::advance`. `advanceTimeBy(d)`
 * moves the clock without running the task scheduled at exactly `now + d`, so
 * every advance that should fire an event is followed by `runCurrent()`.
 *
 * Spec-scale params throughout (bounds forbid ms-scale, and virtual time does
 * not care about magnitude).
 */
@OptIn(ExperimentalCoroutinesApi::class)
class SessionTimersTest {

    private val params = SessionParams.validated(30.minutes, 2.minutes, 4.hours)

    @Test
    fun warningThenExpiryAtExactThresholds() = runTest {
        val timers = SessionTimers(params, backgroundScope)
        val events = mutableListOf<TimerEvent>()
        backgroundScope.launch { timers.events.collect { events += it } }
        timers.start()
        runCurrent()

        // Warning at idle_timeout - warn_before = 28 min.
        advanceTimeBy((28.minutes - 1.minutes).inWholeMilliseconds)
        runCurrent()
        assertEquals(emptyList<TimerEvent>(), events)
        advanceTimeBy(1.minutes.inWholeMilliseconds)
        runCurrent()
        assertEquals(listOf(TimerEvent.WarningDue), events)

        // Expiry at idle_timeout = 30 min; grace window still open at 29:59.
        advanceTimeBy((2.minutes - 1.minutes).inWholeMilliseconds)
        runCurrent()
        assertEquals(listOf(TimerEvent.WarningDue), events)
        advanceTimeBy(1.minutes.inWholeMilliseconds)
        runCurrent()
        assertEquals(listOf(TimerEvent.WarningDue, TimerEvent.IdleExpired), events)

        timers.cancel()
    }

    @Test
    fun activityResetsFullWindowAndRearmsWarning() = runTest {
        val timers = SessionTimers(params, backgroundScope)
        val events = mutableListOf<TimerEvent>()
        backgroundScope.launch { timers.events.collect { events += it } }
        timers.start()
        runCurrent()

        // Rescue right at the warning point.
        advanceTimeBy(28.minutes.inWholeMilliseconds)
        runCurrent()
        assertEquals(listOf(TimerEvent.WarningDue), events)
        timers.recordActivity()
        runCurrent()

        // Fresh full window: no expiry yet at rescue + 27:59...
        advanceTimeBy((28.minutes - 1.minutes).inWholeMilliseconds)
        runCurrent()
        assertEquals(listOf(TimerEvent.WarningDue), events)
        // ...warning again at rescue + 28 min...
        advanceTimeBy(1.minutes.inWholeMilliseconds)
        runCurrent()
        assertEquals(listOf(TimerEvent.WarningDue, TimerEvent.WarningDue), events)
        // ...expiry at rescue + 30 min.
        advanceTimeBy(2.minutes.inWholeMilliseconds)
        runCurrent()
        assertEquals(
            listOf(TimerEvent.WarningDue, TimerEvent.WarningDue, TimerEvent.IdleExpired),
            events,
        )

        timers.cancel()
    }

    @Test
    fun hardCapFiresThroughContinuousActivity() = runTest {
        val timers = SessionTimers(params, backgroundScope)
        val events = mutableListOf<TimerEvent>()
        backgroundScope.launch { timers.events.collect { events += it } }
        timers.start()
        runCurrent()

        // Poke every 15 min — denser than the 28-min warning offset, so idle
        // never fires. After 4 h the cap must fire anyway.
        repeat(20) {
            advanceTimeBy(15.minutes.inWholeMilliseconds)
            runCurrent()
            timers.recordActivity()
            runCurrent()
        }

        assertTrue("hard cap must fire", events.contains(TimerEvent.HardCapReached))
        assertTrue("idle must not fire under activity", !events.contains(TimerEvent.IdleExpired))

        timers.cancel()
    }

    @Test
    fun hardCapIsAbsoluteAndNotPostponedByActivity() = runTest {
        val timers = SessionTimers(params, backgroundScope)
        val events = mutableListOf<TimerEvent>()
        backgroundScope.launch { timers.events.collect { events += it } }
        timers.start()
        runCurrent()

        advanceTimeBy(3.hours.inWholeMilliseconds)
        runCurrent()
        timers.recordActivity()
        runCurrent()
        assertTrue(!events.contains(TimerEvent.HardCapReached))

        // Cap was fixed at start: it still fires at 4 h, not 4 h after the poke.
        advanceTimeBy((1.hours - 1.minutes).inWholeMilliseconds)
        runCurrent()
        assertTrue(!events.contains(TimerEvent.HardCapReached))
        advanceTimeBy(1.minutes.inWholeMilliseconds)
        runCurrent()
        assertTrue(events.contains(TimerEvent.HardCapReached))

        timers.cancel()
    }

    @Test
    fun cancelStopsAllEmissions() = runTest {
        val timers = SessionTimers(params, backgroundScope)
        val events = mutableListOf<TimerEvent>()
        backgroundScope.launch { timers.events.collect { events += it } }
        timers.start()
        runCurrent()
        timers.cancel()

        advanceTimeBy(5.hours.inWholeMilliseconds)
        runCurrent()
        assertEquals(emptyList<TimerEvent>(), events)
    }

    @Test
    fun queuedWarningFromOldIdleWindowIsDiscardedAfterActivity() = runTest {
        val timers = SessionTimers(params, backgroundScope)
        timers.start()
        runCurrent()

        // Let the old generation queue its warning before any collector exists.
        advanceTimeBy(28.minutes.inWholeMilliseconds)
        runCurrent()
        timers.recordActivity()

        val events = mutableListOf<TimerEvent>()
        backgroundScope.launch { timers.events.collect { events += it } }
        runCurrent()

        assertEquals("the reset invalidates an already-queued warning", emptyList<TimerEvent>(), events)
        timers.cancel()
    }

    @Test
    fun queuedExpiryFromOldIdleWindowIsDiscardedAfterActivity() = runTest {
        val timers = SessionTimers(params, backgroundScope)
        timers.start()
        runCurrent()

        // Queue both WarningDue and IdleExpired from the first idle window.
        advanceTimeBy(30.minutes.inWholeMilliseconds)
        runCurrent()
        timers.recordActivity()

        val events = mutableListOf<TimerEvent>()
        backgroundScope.launch { timers.events.collect { events += it } }
        runCurrent()

        assertEquals("the reset invalidates an already-queued expiry", emptyList<TimerEvent>(), events)
        timers.cancel()
    }

    @Test
    fun recordActivityBeforeStartIsANoop() = runTest {
        val timers = SessionTimers(params, backgroundScope)
        timers.recordActivity() // must not throw or launch anything
        runCurrent()
        timers.cancel()
    }
}
