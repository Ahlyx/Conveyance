# Phase 10.3b Remediation — Exit Report

Fixes the 10 findings from the `/code-review ultra` pass over the Phase
10.3b BLE peripheral implementation, before starting Phase 10.4.

Base commit: `13da83c` (`docs: Phase 10.3 exit report...`). 6 commits,
`f4a781f..2a0604f`.

---

## Findings — evidence per finding

| # | Finding | Resolution | Evidence |
|---|---|---|---|
| **1** | `BlePeripheral.addService()` failure/exception silently swallowed | Fixed | `f4a781f`. Checked; a `false`/thrown result closes the server and reports the new `BleUnavailable.GattServiceUnavailable`. |
| **3** | `start()` returns `true` even after `onUnavailable` fired synchronously | Fixed | `f4a781f`. Tracked via a local flag; returns `false` when the synchronous-unavailable branch fired. `BlePeripheralInstrumentedTest.startReturnsFalseWhenUnavailableFiresBeforeItReturns` asserts the invariant against a real `BluetoothManager`. |
| **7** | `deviceSink`/`handle` construction-order race silently drops a connection's device | Fixed | `b4dc62f`. `RealGattServerHandle` now takes a deferred `server: () -> BluetoothGattServer?` supplier (the same shape already used for `handle` in the callback), so `handle` is built *before* `openGattServer()` — no assignment-order window left to race. `ConveyanceGattServerCallback.handle` simplified from a supplier to a plain value as a direct byproduct. New `ConveyanceGattServerCallbackTest` (zero prior coverage on this class). The race itself isn't independently unit-testable (no Mockito/Robolectric in this project); closed by construction, not by a timing test. |
| **2, 4, 8** | Two teardown paths (event-loop vs. direct from `notifyOnce()`) disagreed about post-teardown state | Fixed, as one consolidation | `b1945c6`. `teardown()` reachable only from `process()`; `notifyOnce()` posts the new `ConnectionStateMachine.Event.NotifyFailed` instead of tearing down directly. `teardown()` closes `notifyResults` so a concurrently in-flight `send()` unblocks immediately (#8) instead of running out `NOTIFY_ACK_TIMEOUT_MS`. `attachServer()` gains a `torn` guard, closing the handle instead of leaking it when teardown already happened first (#4). `torn` made `@Volatile` (`attachServer` runs on the caller's thread, not `@BleDispatcher`). Existing 13 `BleActorTest` cases run against the refactored actor **before** any new test was added, per instruction — all 13 passed unchanged; nothing needed updating. Three new regression tests, one per finding, each with the queue-interleaving worked out by hand in its comment: `bufferedEventAfterNotifyFailureDoesNotRevertState`, `attachServerAfterEarlyTeardownClosesTheHandleAndSkipsAdapterWatch`, `centralDisconnectDuringInFlightSendUnblocksImmediately`. |
| **5** | Stale disconnect callback tears down a session that never connected | Fixed — different root cause than proposed | `0fbfb04`. Pushback applied: `ConnectionStateMachine`'s unconditional teardown from any state is correct per spec and unchanged; `AdapterOff` has no staleness risk (one real broadcast, not a binder callback) and is also unchanged. The real gap was `ConveyanceGattServerCallback.onConnectionStateChange` forwarding any disconnect callback regardless of device identity. Now tracks `hasConnected`/`connectedDevice` (both `@Volatile` — runs on a binder thread) and ignores a disconnect that doesn't match. New test: a disconnect with no prior connect is a no-op. |
| **6** | `ConveyanceAdvertiser.stop()` during in-flight `start()` drops the "exactly one callback" contract | Fixed | `cc9325c`. `start()` records `pendingUnavailable`; `stop()` claims the outcome via the existing `consume()` chokepoint and invokes it with the new `BleUnavailable.Stopped` if it was still unclaimed, before actually stopping. `BlePeripheral.stop()`'s resulting re-entrancy (traced by hand, safe by construction) is documented on the method. New instrumented tests: `ConveyanceAdvertiserInstrumentedTest.stopImmediatelyAfterStartReportsStoppedRatherThanHanging`, `BlePeripheralInstrumentedTest.immediateStopAfterStartReportsStoppedNotSilence`. |
| **9** | `preparedWrite`/reliable BLE writes unhandled | Deferred to Phase 11 | `2a0604f`. Comment on `onCharacteristicWriteRequest`; bullet in `CONVEYANCE_PHASES.md`'s Phase 11 carry-over. btleplug and the emulator don't exercise this path. |
| **10** | `RealGattServerHandle` catches only `SecurityException` | Deferred to Phase 11 | `2a0604f`. Bullet in `CONVEYANCE_PHASES.md`'s Phase 11 carry-over — real hardware testing will show which `RuntimeException` classes actually appear. |

---

## Test totals

- **Android JVM (`testDebugUnitTest`):** 90 total, **7 new** since the
  10.3 exit report's 83 (3 `BleActorTest`, 4 `ConveyanceGattServerCallbackTest`),
  0 failures. `ConnectionStateMachineTest` extended in place (no new
  `@Test` methods) to cover `Event.NotifyFailed`.
- **Instrumented (`connectedDebugAndroidTest`, API-30 x86_64 emulator):**
  2 new tests in `BlePeripheralInstrumentedTest` (new file), 2 new in
  `ConveyanceAdvertiserInstrumentedTest`.
- **`lintDebug`:** green on every commit.
- **`android.yml`:** green on all 6 commits (`f4a781f`, `b4dc62f`,
  `0fbfb04`, `b1945c6`, `cc9325c`, `2a0604f`), each pushed and watched to
  completion before the next commit was made — including the
  `instrumented` step, so every new instrumented test above actually ran
  on the emulator, not just compiled.

---

## Deviations (all surfaced in-flight)

1. **#5's fix location differs from the review's framing.** The review
   grouped `CentralDisconnected` and `AdapterOff` together as both
   needing a fix; only `CentralDisconnected`'s translation layer
   (`ConveyanceGattServerCallback`) actually needed one. `ConnectionStateMachine`
   itself is unchanged — its unconditional teardown is correct per spec.
2. **`ConnectionStateMachine.Event.NotifyFailed` added** rather than
   reusing `Event.CentralDisconnected` for the notify-failure path —
   approved as the correct call in the plan review: same
   `LinkTeardown.PeerDisconnected` reason and effect, but a distinct
   origin worth telling apart in logs.
3. **`ConveyanceGattServerCallback.handle` signature simplified** from
   `() -> GattServerHandle?` to a plain `GattServerHandle` — approved as
   a deliberate byproduct of #7's fix, not a silent scope expansion.
4. **`ServerBox` (`BlePeripheral.kt`)** — a small private class added to
   give `RealGattServerHandle`'s `server` supplier real cross-thread
   visibility. `@Volatile` cannot annotate a local `var` in Kotlin (only
   a property with a backing field), so a plain local var was
   insufficient for the #7 fix as originally sketched in the plan.
5. **Local Android build environment was set up in this session**
   (JDK 17, Android SDK cmdline-tools + platform 35 + build-tools + NDK
   27, `cargo-ndk`, Rust Android targets) — none of this pre-existed;
   every `testDebugUnitTest`/`lintDebug` run reported in this report ran
   locally in-session, and every `connectedDebugAndroidTest` result came
   from watching the real `android.yml` GitHub Actions run per commit
   (this sandbox has no emulator/GUI set up for a local run).
6. **Two additional small items, self-identified, deliberately not
   fixed** (out of scope for this pass — not among the 10 findings):
   `BlePeripheral`'s `openGattServer()`-returns-null path still reports
   `BleUnavailable.AdapterOff` (imprecise; wants its own
   `GattServerUnopenable` reason eventually — user confirmed this is
   real), and `BleActor.server: GattServerHandle?` has the same
   cross-thread shape as `torn` but wasn't in the `@Volatile` audit's
   explicit scope. Tracked in a project memory
   (`ble-remediation-followups`) rather than fixed here.

---

## Deferred to Phase 11

Findings #9 and #10 — see `CONVEYANCE_PHASES.md`'s Phase 11 section,
second BLE carry-over bullet (added in `2a0604f`), for the detail.

---

Phase 10.3b remediation closed. Next: Phase 10.4 (Noise KK session,
reusing `snow` via UniFFI per the 10.1 precedent).
