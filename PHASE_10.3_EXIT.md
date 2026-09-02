# Phase 10.3 — Exit Report (BLE peripheral + GATT server + framing)

Phone-side BLE transport: the wire framing in Kotlin with cross-implementation
parity, the `conveyance-wire` leaf-crate extraction, and the Android
`BluetoothGattServer` + advertiser + permissions + teardown handling.

Split into **10.3a** (framing + transport seam, JVM-testable) and **10.3b**
(Android BLE plumbing, emulator/device-bound), with a review gate between.

Base commit: `974e7e3` (`docs(spec)`). 15 commits, `4ebff6a..0ebcbc0`.

---

## Spec amendments (landed first, `974e7e3`)

- **Framing sizing pinned:** `max_payload = negotiated_ATT_MTU − 3 − 6`; one
  frame fits one GATT operation. Receiver MUST reject a nonzero `reserved`
  byte. v1 neither emits nor requires ACKs (accept and ignore).
- **Session end:** loss of the `phone_to_pc_tx` subscription (CCCD cleared
  without an ACL drop) is equivalent to BLE disconnection — tear down, no
  auto-resubscribe.
- `CONVEYANCE_PHASES.md` §10.3 records the 10.3a / 10.3b split.

---

## Phase 10.3a — evidence per criterion

| Criterion | Evidence |
|---|---|
| **`conveyance-wire` extracted as a pure leaf crate** | `4ebff6a`. Deps: `thiserror`, `serde_json` (fixtures only, mirrors `conveyance-crypto`). `conveyance_core::wire::framing` is a re-export; every PC-side call site unchanged. `ProtocolError` drops 9 framing variants → `Frame(#[from] conveyance_wire::FrameError)`. `bcde642` moves `InboundAssembler` alongside `Framer`. Scope is the framing layer only — `wire::message`/`binding` are cyclically bound to `pairing`/`storage`/`transport` and stay in `conveyance-core`. |
| **Frame sizing fixed + test** | `9866f25`: `conveyance_wire::max_frame_payload(att_mtu)` is the single source of truth; `ble.rs` consumes it. `every_emitted_frame_fits_one_att_pdu` asserts across MTU 23–517 × msg 0–5000 that no frame exceeds `att_mtu − 3` on the wire and every case round-trips. `40975f8` follows: `Link::send`'s guard compared a whole frame against the payload budget (pre-existing conflation, mock's 512 hid it) — fixed in `mock.rs`+`ble.rs`, regression test `multi_frame_send_respects_max_write_len` added to the shared suite. |
| **Kotlin `Framer` / `MessageSplitter` / `InboundAssembler` port** | `c75dfaf`. `com.ahlyxlabs.conveyance.transport.framing`. `Framer` check order mirrors Rust exactly. `FramingException` sealed, variant-for-variant with `FrameError`, `MessageTooLarge.specCode = conveyance/message_too_large`. |
| **Ported unit suite + mutation soak** | `c75dfaf`: `FramerTest` (11), `MessageSplitterTest` (8), `InboundAssemblerTest` (5) — Rust cases ported one-for-one. 50 000-iteration seeded mutation soak: only `FramingException` escapes. |
| **`framing_fixtures.json` + emitter + both drift gates** | `8def627`: `conveyance_wire::fixtures::build_document()` computes every vector from the public API and asserts internally that splits round-trip and error inputs produce the exact `FrameError`. `examples/emit_framing_fixtures.rs` → `android/app/src/test/resources/framing_fixtures.json`. `tests/framing_fixture_drift.rs` gates `cargo test`. `cfe6178` adds the `android.yml` regen+diff step and `crates/conveyance-wire/**` trigger. |
| **JVM fixture-parity suite + CI floor** | `1cfb8e8`: `FramingFixtureParityTest` (7) replays constants / `max_frame_payload` / split / ack / `reassemble_ok` (whole + re-sliced at header/payload boundaries) / `reassemble_err` (every variant + fields). Real `org.json:json` test dep. `android.yml` "Verify JVM unit tests ran" step: floor 35, requires `FramingFixtureParityTest` + `FramerTest`. |
| **Pure `ConnectionStateMachine`** | `f9a50b3`: `transport/ConnectionStateMachine.kt`, zero `android.bluetooth` imports. `IDLE→CONNECTED→MTU_KNOWN→SUBSCRIBED→TORN`, effects `SetMaxWriteLen`/`LinkReady`/`TearDown`. Unsubscribe and adapter-off both tear down. `ConnectionStateMachineTest` (6). |
| **`PhoneLink` seam + `LoopbackLink` + full-stack echo** | `f9a50b3`: `PhoneLink` (payload-budget `maxWriteLen`, `suspend send(frame)` with backpressure + one-PDU guard + `LinkClosedException`, `events: Flow<LinkEvent>` ending in one terminal `Torn`, idempotent `shutdown()`). `LinkTeardown`: PeerDisconnected \| AdapterOff \| SubscriptionLost \| LocalShutdown \| ProtocolViolation. `LoopbackLink` (peer of Rust `transport::mock`), real coroutine backpressure, initiator/peer teardown reasons, `failWith()` hook. `LoopbackLinkTest` (7): ordering, reasons, one-PDU rejection, **full-stack echo** (split → send → `InboundAssembler` → reassemble), **mid-message teardown drops partial reassembly**. |

---

## Phase 10.3b — evidence per criterion

| Criterion | Evidence |
|---|---|
| **Permissions across the SDK-30 / 31 split + manifest** | `372e3ce`. `BlePermissions.requiredFor(sdkInt)` — empty ≤ 30, `{BLUETOOTH_ADVERTISE, BLUETOOTH_CONNECT}` on 31+, unit-tested both branches. No `BLUETOOTH_SCAN`, no location. Manifest: `uses-feature bluetooth_le required=true`, `BLUETOOTH`/`BLUETOOTH_ADMIN` `maxSdkVersion=30`, advertise + connect for 31+. `BlePermissionsInstrumentedTest` on the API-30 emulator. |
| **`@BleDispatcher` single-thread confinement seam** | `372e3ce`. `@BleDispatcher` qualifier + Singleton `Executors.newSingleThreadExecutor("conveyance-ble")`. `BleModule` (`0ebcbc0`) binds `AdapterWatch`. |
| **GATT server + two characteristics + CCCD, response discipline** | `7723145`. `ConveyanceGattProfile` pins the UUIDs (match `conveyance-core::transport::ids`) + pure `classifyDescriptorWrite` (CCCD `{01,00}`/`{02,00}` → subscribe, `{00,00}` → unsubscribe, else ignore) — unit-tested. `ConveyanceGattServerCallback`: descriptor writes get `sendResponse(GATT_SUCCESS)` **first**, then the CCCD change is interpreted. Instrumented: `openGattServer` + `addService` with the full profile. |
| **`BleActor` threading model** | `7723145` + `0ebcbc0`. Binder callbacks copy bytes and `trySend` onto channels; the `ConnectionStateMachine` and the notify gate run only on `@BleDispatcher`. `teardown()` is the single idempotent path: `_state`→TORN, stop watch, close server, emit `Torn`, close channels, cancel scope. `BleActorTest` (13) drives it with `StandardTestDispatcher`. |
| **BLE advertiser + graceful unsupported path** | `50b8e7c` + `a3849c0`. `ConveyanceAdvertiser` advertises the service UUID (connectable, no device name). `start()` invokes exactly one of `onStarted`/`onUnavailable`, within a 3 s watchdog: null advertiser, `startAdvertising` throw, and — the emulator case — **no framework callback at all** all map to `AdvertisingUnsupported`. `mapAdvertiseError` unit-tested. `ConveyanceAdvertiserInstrumentedTest` confirms the emulator reaches `onUnavailable(AdvertisingUnsupported)` via the watchdog. |
| **`GattPhoneLink` + MTU wiring + one notification in flight** | `0ebcbc0`. `BleActor` produces a `PhoneLink`; `maxWriteLen` tracks `maxFramePayload(negotiatedMtu)`. `notifyOnce`: Mutex-serialised, dispatcher-confined; per frame `server.notify` then await `onNotificationSent` via a conflated channel with a **2 s** timeout (`NOTIFY_ACK_TIMEOUT_MS`). `notify()` false or timeout → teardown + `LinkClosedException(PeerDisconnected)`. `RealGattServerHandle.notify` splits on `SDK_INT >= 33` (byte-array overload vs deprecated `setValue()+notify`, `@Suppress("DEPRECATION")` scoped to 30–32 only). `BleActorTest`: send/ack ordering, ack-timeout → teardown, notify-rejection → teardown, send-after-teardown, inbound `Chunk` + terminal `Torn`, multi-frame round-trip through the actor. |
| **Disconnect / adapter-off / subscription-loss teardown** | `CentralDisconnected` (`7723145`), notify failure/timeout (`0ebcbc0`), CCCD-clear `Unsubscribed` (`7723145`), and `AdapterOff` via `SystemAdapterWatch` — an `ACTION_STATE_CHANGED` receiver (`RECEIVER_NOT_EXPORTED`) registered in `attachServer`, unregistered in `teardown` (session-scoped, not app-global) (`0ebcbc0`). All converge on the one `TearDown` effect. `BleActorTest`: adapter-watch start/stop, adapter-off → TORN + server closed. |
| **Hilt assembly + advertising lifecycle seam** | `0ebcbc0`. `BlePeripheral` (`@Singleton`): `start(onUnavailable)` opens the GATT server, adds the pinned service, wires the actor, begins advertising; `stop()` stops advertising + shuts the actor down. Wired to no lifecycle — 10.9's foreground service calls `start`/`stop`, instrumented tests call them directly, 10.4 consumes `link`. |

---

## Test totals

- **Rust:** `conveyance-wire` 19 lib + 1 drift; `conveyance-core` 133 (+1 vs pre-10.3). `cargo test --workspace` green on Windows/Ubuntu/macOS; `ci.yml` green on every Rust-touching commit.
- **Android JVM (`testDebugUnitTest`):** 83 total, **66 new** across the `transport` / `transport.framing` / `transport.ble` suites, 0 failures. `lintDebug` green.
- **Instrumented (`connectedDebugAndroidTest`, API-30 x86_64 emulator):** `BlePermissionsInstrumentedTest`, `ConveyanceGattServerInstrumentedTest`, `ConveyanceAdvertiserInstrumentedTest` — GATT server opens + takes the profile; the advertiser reaches the unsupported path cleanly. `android.yml` green on `372e3ce`, `7723145`, `a3849c0`, `0ebcbc0`.

## Deviations (all surfaced in-flight)

1. `conveyance-wire` = framing layer only (not the whole `wire` module).
2. `InboundAssembler` relocated to `conveyance-wire` (`bcde642`, own commit).
3. `40975f8` — `Link::send` guard conflation fix (pre-existing latent bug).
4. `android.yml` JVM count-floor landed in `1cfb8e8` (with the suite it guards).
5. `50b8e7c`'s advertiser instrumented test failed CI (emulator radio never
   calls back); fixed with a start watchdog in `a3849c0` before proceeding.
6. 10.3b commits 4–6 landed consolidated (`0ebcbc0`) — the `BleActor.kt`
   changes span them and don't split into building intermediates.

---

## Deferred to Phase 11 (real radio)

The mock/loopback and the emulator cover everything CI can. These need
hardware and are carried into Phase 11:

- **Real advertise + PC daemon**: `conveyance-daemon`'s btleplug central
  scans, connects, discovers, subscribes; the phone's advertisement is
  actually seen.
- **Real MTU negotiation over ATT**: a multi-frame message across the real
  link, settling the frame-sizing formula against a real stack. Measure the
  handshake-at-MTU-23 latency (initial handshake may run before MTU
  negotiation completes).
- **`onNotificationSent` latency distribution** on a healthy link, to
  confirm `NOTIFY_ACK_TIMEOUT_MS = 2000` has the right headroom.
- **Physical mid-message disconnect** (walk out of range); **adapter toggled
  under a live connection**; **CCCD cleared by a real central** without a
  disconnect.
- **Advertiser on real hardware**: `onStartSuccess` path, and single- vs
  multi-advertisement capable chipsets.
- **Battery / foreground service** during a 30-min active session (with
  Phase 10.9).
- **nRF Connect** as an interim central for early bring-up before the daemon
  side is wired end to end.
