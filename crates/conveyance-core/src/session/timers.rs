//! Session timing parameters and the tokio timer watchdog.
//!
//! Bounds enforcement lives here, at construction. `SessionParams::validated`
//! is the only constructor external crates can reach (fields are
//! crate-private), so any future caller -- the daemon's config loader in
//! phase 7/9 above all -- physically cannot build parameters that weaken
//! the spec's minimums or exceed its maximums. Invalid input is rejected,
//! never silently clamped: a config the operator believes says one thing
//! must not secretly do another.
//!
//! The watchdog itself is a single tokio task owning three deadlines:
//!
//! * idle warning at `start + idle_timeout - warn_before`,
//! * idle expiry at `start + idle_timeout` (the warning does NOT move
//!   the end time; activity during the grace window restores a full
//!   fresh idle period),
//! * hard cap at `start + hard_cap`, which is absolute: activity never
//!   postpones it. This is what defeats compromised-agent keep-alive.

use std::time::Duration;

use thiserror::Error;
use tokio::sync::mpsc;

/// Spec table "Timers": defaults, minimums, maximums.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionParams {
    pub(crate) idle_timeout: Duration,
    pub(crate) warn_before: Duration,
    pub(crate) hard_cap: Duration,
}

#[derive(Debug, Error)]
#[error("session timer bounds violated")]
pub struct InvalidBounds;

impl SessionParams {
    pub const IDLE_MIN: Duration = Duration::from_secs(300); // 5 min
    pub const IDLE_MAX: Duration = Duration::from_secs(14_400); // 4 h
    pub const CAP_MIN: Duration = Duration::from_secs(1_800); // 30 min
    pub const CAP_MAX: Duration = Duration::from_secs(86_400); // 24 h
    pub const WARN_DEFAULT: Duration = Duration::from_secs(120); // 2 min

    /// Spec defaults: 30 min idle, 2 min warning, 4 h hard cap.
    pub fn spec_defaults() -> Self {
        Self {
            idle_timeout: Duration::from_secs(1_800),
            warn_before: Self::WARN_DEFAULT,
            hard_cap: Duration::from_secs(14_400),
        }
    }

    /// The canonical constructor. Every externally supplied value passes
    /// through here; the error is deliberately a single opaque variant
    /// for now (phase 7's config loader will add per-field detail where
    /// users need it).
    pub fn validated(
        idle_timeout: Duration,
        warn_before: Duration,
        hard_cap: Duration,
    ) -> Result<Self, InvalidBounds> {
        if !(Self::IDLE_MIN..=Self::IDLE_MAX).contains(&idle_timeout) {
            return Err(InvalidBounds);
        }
        if !(Self::CAP_MIN..=Self::CAP_MAX).contains(&hard_cap) {
            return Err(InvalidBounds);
        }
        // The warning must fit inside the idle window with room to be
        // meaningful; warn >= idle would fire it after expiry.
        if warn_before >= idle_timeout {
            return Err(InvalidBounds);
        }
        Ok(Self {
            idle_timeout,
            warn_before,
            hard_cap,
        })
    }

    /// Crate-internal constructor for tests and trusted constants.
    /// Deliberately not exported: bounds-checked values enter through
    /// [`validated`]; anything else is an in-crate, reviewed decision.
    #[cfg(test)]
    pub(crate) const fn raw(
        idle_timeout: Duration,
        warn_before: Duration,
        hard_cap: Duration,
    ) -> Self {
        Self {
            idle_timeout,
            warn_before,
            hard_cap,
        }
    }

    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    pub fn warn_before(&self) -> Duration {
        self.warn_before
    }

    pub fn hard_cap(&self) -> Duration {
        self.hard_cap
    }
}

/// What the watchdog reports to the session owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerEvent {
    /// Move ACTIVE -> IDLE_WARNING (notify the phone).
    WarningDue,
    /// No activity arrived in the grace window: idle timeout.
    IdleExpired,
    /// The absolute cap elapsed, regardless of everything.
    HardCapReached,
}

/// Runs until a terminal event. Feed `activity_tx` on every legitimate
/// interaction; consume `event_rx` and drive them through the state
/// machine. Dropping the returned task's handle aborts the watchdog --
/// callers (the Session) do exactly that on session end.
///
/// Must be spawned inside a tokio runtime.
pub(crate) async fn watchdog(
    params: SessionParams,
    mut activity_rx: mpsc::Receiver<()>,
    event_tx: mpsc::Sender<TimerEvent>,
) {
    use tokio::time::{Instant as TokioInstant, sleep_until};

    let start = TokioInstant::now();
    let hard_deadline = start + params.hard_cap;
    // First idle milestone: the warning point.
    let mut next_idle_deadline = start + params.idle_timeout - params.warn_before;
    let mut warned = false;

    loop {
        // Note: if two arms become ready at the same instant (possible
        // only when cap == an idle milestone exactly), tokio::select!
        // picks randomly among ready arms. Both terminal outcomes end
        // the session correctly; only the logged EndReason would differ.
        // No code may depend on tie ordering.
        tokio::select! {
            _ = sleep_until(hard_deadline) => {
                // Absolute. Activity cannot postpone this arm because the
                // deadline was fixed once, at start.
                let _ = event_tx.send(TimerEvent::HardCapReached).await;
                return;
            }
            _ = sleep_until(next_idle_deadline) => {
                if !warned {
                    warned = true;
                    // The warning fires early by exactly warn_before; the
                    // real end time stays put at start + idle_timeout.
                    next_idle_deadline += params.warn_before;
                    if event_tx.send(TimerEvent::WarningDue).await.is_err() {
                        return;
                    }
                } else {
                    let _ = event_tx.send(TimerEvent::IdleExpired).await;
                    return;
                }
            }
            activity = activity_rx.recv() => {
                match activity {
                    // Channel closed: owner went away; stop quietly.
                    None => return,
                    Some(()) => {
                        // Full reset: fresh idle window AND the warning
                        // re-arms (a rescued session gets warned again).
                        warned = false;
                        next_idle_deadline = TokioInstant::now() + params.idle_timeout - params.warn_before;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn validated_accepts_spec_defaults_and_extremes() {
        assert!(
            SessionParams::validated(ms(1_800_000), SessionParams::WARN_DEFAULT, ms(14_400_000))
                .is_ok()
        );

        // Exact minimums and maximums are inclusive.
        assert!(
            SessionParams::validated(SessionParams::IDLE_MIN, ms(60), SessionParams::CAP_MIN)
                .is_ok()
        );
        assert!(
            SessionParams::validated(SessionParams::IDLE_MAX, ms(60), SessionParams::CAP_MAX)
                .is_ok()
        );
    }

    #[test]
    fn validated_rejects_every_violated_bound() {
        let warn = ms(60);

        // Idle below minimum / above maximum.
        assert!(
            SessionParams::validated(
                SessionParams::IDLE_MIN - ms(1),
                warn,
                SessionParams::CAP_MIN
            )
            .is_err()
        );
        assert!(
            SessionParams::validated(
                SessionParams::IDLE_MAX + ms(1),
                warn,
                SessionParams::CAP_MAX
            )
            .is_err()
        );

        // Cap below minimum / above maximum.
        assert!(
            SessionParams::validated(
                SessionParams::IDLE_MIN,
                warn,
                SessionParams::CAP_MIN - ms(1)
            )
            .is_err()
        );
        assert!(
            SessionParams::validated(
                SessionParams::IDLE_MIN,
                warn,
                SessionParams::CAP_MAX + ms(1)
            )
            .is_err()
        );

        // Warn must precede idle expiry.
        assert!(SessionParams::validated(ms(600), ms(600), SessionParams::CAP_MIN).is_err());
        assert!(SessionParams::validated(ms(600), ms(700), SessionParams::CAP_MIN).is_err());

        // Recorded deliberately: cap < idle IS permitted (each value has
        // independent bounds). The cap simply dominates -- e.g. idle=4h
        // with cap=30min means sessions always die at 30min. If product
        // reasoning later wants cap >= idle enforced, it goes here.
    }

    #[test]
    fn fields_are_crate_private_so_external_code_cannot_bypass() {
        // Compile-level proof sketch: this compiles here (same crate);
        // from another crate, SessionParams { .. } literal construction
        // would fail to compile because the fields are pub(crate).
        let p = SessionParams::raw(ms(100), ms(20), ms(500));
        assert_eq!(p.idle_timeout, ms(100));
    }

    /// Watchdog timing, fully deterministic under paused tokio time.
    #[tokio::test(start_paused = true)]
    async fn warning_then_expiry_at_exact_thresholds() {
        let params = SessionParams::raw(ms(100), ms(40), ms(10_000));
        let (activity_tx, activity_rx) = mpsc::channel(8);
        let (event_tx, mut event_rx) = mpsc::channel(8);

        tokio::spawn(watchdog(params, activity_rx, event_tx));

        // Warning at start + 100 - 40 = 60ms.
        tokio::time::advance(ms(59)).await;
        assert!(event_rx.try_recv().is_err(), "no event before 60ms");
        tokio::time::advance(ms(1)).await;
        assert_eq!(event_rx.recv().await, Some(TimerEvent::WarningDue));

        // Expiry at start + 100ms.
        tokio::time::advance(ms(39)).await;
        assert!(event_rx.try_recv().is_err(), "grace window still open");
        tokio::time::advance(ms(1)).await;
        assert_eq!(event_rx.recv().await, Some(TimerEvent::IdleExpired));
        drop(activity_tx); // keep clippy quiet about unused sender
    }

    #[tokio::test(start_paused = true)]
    async fn activity_resets_full_window_and_rearms_warning() {
        let params = SessionParams::raw(ms(100), ms(40), ms(10_000));
        let (activity_tx, activity_rx) = mpsc::channel(8);
        let (event_tx, mut event_rx) = mpsc::channel(8);

        tokio::spawn(watchdog(params, activity_rx, event_tx));

        // Rescue right at the warning point.
        tokio::time::advance(ms(60)).await;
        assert_eq!(event_rx.recv().await, Some(TimerEvent::WarningDue));
        activity_tx.send(()).await.unwrap();

        // Fresh full window: warning again at +60ms from NOW, i.e. 120ms
        // total, expiry at 160ms total.
        tokio::time::advance(ms(119)).await;
        assert!(
            event_rx.try_recv().is_err(),
            "rescued session must not expire yet"
        );
        tokio::time::advance(ms(1)).await;
        assert_eq!(event_rx.recv().await, Some(TimerEvent::WarningDue));
        tokio::time::advance(ms(40)).await;
        assert_eq!(event_rx.recv().await, Some(TimerEvent::IdleExpired));
    }

    #[tokio::test(start_paused = true)]
    async fn hard_cap_fires_despite_continuous_activity() {
        let params = SessionParams::raw(ms(1_000), ms(100), ms(5_000));
        let (activity_tx, activity_rx) = mpsc::channel(1024);
        let (event_tx, mut event_rx) = mpsc::channel(8);

        tokio::spawn(watchdog(params, activity_rx, event_tx));

        // Pump activity every 100ms. Note this is denser than the
        // warning offset (idle-warn = 900ms), so no warning ever fires:
        // constant activity means constant freshness. That is correct --
        // the guarantee under test is purely "the cap fires anyway".
        for _ in 0..60 {
            tokio::time::advance(ms(100)).await;
            if activity_tx.send(()).await.is_err() {
                break; // watchdog gone: a terminal event happened
            }
            while let Ok(ev) = event_rx.try_recv() {
                match ev {
                    TimerEvent::HardCapReached => return,
                    TimerEvent::WarningDue => {}
                    TimerEvent::IdleExpired => panic!("idle expired despite constant activity"),
                }
            }
        }

        // Channel survived the whole loop without the cap surfacing?
        // Drain once more before declaring failure.
        while let Ok(ev) = event_rx.try_recv() {
            if ev == TimerEvent::HardCapReached {
                return;
            }
        }
        panic!("hard cap never fired despite continuous activity");
    }
}
