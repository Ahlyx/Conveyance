package com.ahlyxlabs.conveyance.session

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch

/** What the watchdog reports to [PhoneSession]. Mirrors `timers::TimerEvent`. */
enum class TimerEvent {
    /** Move ACTIVE -> IDLE_WARNING (notify the user). */
    WarningDue,

    /** No activity arrived in the grace window: idle timeout. */
    IdleExpired,

    /** The absolute cap elapsed, regardless of everything. */
    HardCapReached,
}

/**
 * The session's timing watchdog — a Kotlin port of
 * `conveyance_core::session::timers::watchdog`.
 *
 * **Structural deviation from the daemon, semantically identical.** The
 * daemon runs one tokio task with a `select!` over three `sleep_until`
 * deadlines. Here it is three plain coroutines over `delay`, because that
 * is what `kotlinx-coroutines-test` virtualizes cleanly — a `select`-loop
 * port would need a monotonic-clock seam that does not line up with the
 * test scheduler. The guarantees are the same:
 *
 *  * **hard cap** — one `delay(hardCap)`, fixed at [start], never restarted;
 *    activity cannot postpone it. This is what defeats a compromised
 *    agent's keep-alive.
 *  * **idle window** — `delay(idle - warn)` then `WarningDue`, then
 *    `delay(warn)` then `IdleExpired`. The warning does NOT move the end
 *    time.
 *  * **activity** — cancels and relaunches the idle coroutine, so a rescued
 *    session gets a full fresh window *and* the warning re-arms.
 *
 * Confined to `@SessionDispatcher` by its owner: [start], [recordActivity]
 * and [cancel] are non-suspending and there is no lock. One instance per
 * session; [cancel] it with the session.
 */
class SessionTimers(
    private val params: SessionParams,
    private val scope: CoroutineScope,
) {

    private data class ScheduledEvent(
        val event: TimerEvent,
        val idleGeneration: Long?,
    )

    private val channel = Channel<ScheduledEvent>(Channel.BUFFERED)

    /**
     * Terminal-or-warning events in order. Collect once. Idle events from a
     * window invalidated by [recordActivity] are discarded even if they were
     * already queued before that activity was processed.
     */
    val events: Flow<TimerEvent> = channel.receiveAsFlow()
        .filter { scheduled ->
            !cancelled &&
                (scheduled.idleGeneration == null || scheduled.idleGeneration == idleGeneration)
        }
        .map { it.event }

    private var hardJob: Job? = null
    private var idleJob: Job? = null
    private var started = false
    private var cancelled = false
    private var idleGeneration = 0L

    /** Arm both deadlines. Call once. */
    fun start() {
        check(!started) { "SessionTimers.start() called twice" }
        started = true
        hardJob = scope.launch {
            delay(params.hardCap.inWholeMilliseconds)
            channel.trySend(ScheduledEvent(TimerEvent.HardCapReached, idleGeneration = null))
        }
        armIdleWindow()
    }

    private fun armIdleWindow() {
        val generation = ++idleGeneration
        idleJob = scope.launch {
            delay((params.idleTimeout - params.warnBefore).inWholeMilliseconds)
            channel.trySend(ScheduledEvent(TimerEvent.WarningDue, generation))
            delay(params.warnBefore.inWholeMilliseconds)
            channel.trySend(ScheduledEvent(TimerEvent.IdleExpired, generation))
        }
    }

    /**
     * Legitimate traffic arrived: restart the idle window from scratch
     * (warning re-armed). The hard cap is untouched — it is absolute.
     * No-op before [start] or after [cancel].
     */
    fun recordActivity() {
        if (!started || cancelled) return
        idleJob?.cancel()
        armIdleWindow()
    }

    /** Stop both deadlines and close [events]. Idempotent. */
    fun cancel() {
        if (cancelled) return
        cancelled = true
        idleGeneration++ // invalidate idle events already buffered in channel
        hardJob?.cancel()
        idleJob?.cancel()
        channel.close()
    }
}
