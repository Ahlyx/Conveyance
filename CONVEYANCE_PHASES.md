# Conveyance — Phased Implementation Plan

This document sits alongside `CONVEYANCE_SPEC.md` and breaks v1 into
implementable phases. Each phase has a scope, a deliverable, exit
criteria that must pass before moving on, and a ready-to-paste prompt
for the implementing agent.

Hand phases to the agent one at a time. Do not skip ahead. Do not
combine phases even if they look small — the exit criteria are what
prevents rot from accumulating.

Phases 0–9 are the Rust PC-side work. Phase 10 is the Android app, a
parallel track with its own sub-phases. Phase 11 is end-to-end
integration once both sides exist.

---

## How to use this document

For each phase:

1. Read the phase's scope and exit criteria yourself first. Make sure
   they match what you actually want. Amend if needed.
2. Paste the **Persistent context** block below, followed by the
   phase's prompt, into a fresh agent session. (One session per phase
   keeps context clean and makes it easy to re-run a phase if something
   goes wrong.)
3. Let the agent propose a plan first. Review, push back, adjust.
4. Let the agent implement.
5. Verify exit criteria before starting the next phase. If a criterion
   isn't met, that's the current phase's problem — don't defer.
6. Commit at the end of each phase with a message naming the phase.

If a phase is bigger than expected, split it. Don't let phases balloon.

---

## Persistent context (apply to every phase)

```
You are implementing Conveyance, a phone-approved capability broker for
MCP tool calls. The specification is in CONVEYANCE_SPEC.md — read it
in full before doing anything else on this phase. It is the source of
truth. When the spec conflicts with your instincts, the spec wins.

Rules that apply to every phase:

1. Cryptographic primitives named in the spec are FIXED. Do not
   substitute alternatives ("more modern," "faster," "more standard").
   The choices are Noise_KK_25519_ChaChaPoly_BLAKE2s for sessions,
   Ed25519 for signatures, X25519 for DH, ChaCha20-Poly1305 for AEAD,
   Argon2id for passphrase KDF, BIP-39 for recovery, SHA-256 for the
   hash chain, RFC 8785 JCS for canonical JSON. If you think one of
   these is wrong, stop and ask — do not silently change it.

2. Any item marked MUST or MUST NOT in the spec is non-negotiable.

3. For security-critical code (crypto primitives, handshake state
   machine, approval-execute binding, hash chain, keystore) write tests
   BEFORE implementation. For everything else, write tests alongside
   or after — your choice.

4. Do not invent protocols. Use the wire formats specified. Use the
   error codes specified. Use the state machines specified.

5. When you are uncertain about a detail not covered by the spec, ask
   rather than guess. Silent guessing on a security product is how
   holes get created.

6. Match the auditmcp writing style for code comments and
   documentation: explain WHY, not just WHAT. Acknowledge limitations
   precisely. No marketing prose. See github.com/Ahlyx/auditmcp for
   the reference voice.

7. At the start of each phase: read the relevant spec sections, list
   what you understand the scope to be, list any ambiguities, and
   propose an implementation plan. Wait for confirmation before writing
   code.

8. At the end of each phase: run all tests, run clippy and fmt, and
   report which exit criteria are met with evidence (test names, file
   paths, output).
```

---

## Phase 0 — Workspace & foundations

**Scope.** Cargo workspace with three crates, config parsing, error
types, platform paths, CI.

**Deliverable.** Empty binaries that build, config that loads, tests
that run, CI that passes.

**Exit criteria.**

- `cargo build --release` succeeds with zero warnings.
- `cargo clippy -- -D warnings` passes.
- `cargo fmt --check` passes.
- `cargo test` runs (may have no tests yet, that's fine).
- Config file can be loaded from platform-appropriate location.
- CI runs fmt, clippy, tests on Linux/macOS/Windows.

**Prompt.**

```
Phase 0 of Conveyance: workspace and foundations.

Scope:
- Create a Cargo workspace with three crates:
  * conveyance-core (shared library: types, config, errors, platform paths)
  * conveyance-daemon (binary: the daemon)
  * conveyance-shim (binary: the MCP shim)
- Define workspace-level dependencies with pinned versions.
- Implement config loading (TOML) with the shape shown in the spec's
  "Config format" section. Use `serde` and `toml`. Config is loaded
  from the platform-appropriate path per the spec's "Storage layout"
  section.
- Implement a `paths` module in conveyance-core that returns the
  correct config and data directories for Linux/macOS/Windows. Use
  the `dirs` or `directories` crate — pick one, don't roll your own.
- Define error types using `thiserror`. Include the named error codes
  from the spec's "Error model" section. Convertible to the JSON
  shape shown in the spec.
- Set up GitHub Actions CI matching auditmcp's shape: fmt, clippy
  (warnings denied), tests on Linux/macOS/Windows.

Do NOT implement any protocol logic, crypto, storage, or BLE. This
phase is scaffolding only.

Follow the persistent rules above. Propose your plan before writing
code.
```

---

## Phase 1 — Crypto core

**Scope.** All cryptographic primitives, isolated in conveyance-core.
No storage, no networking, no protocol yet — just the primitives with
tests.

**Deliverable.** `conveyance-core::crypto` module implementing identity
keys, signatures, canonical JSON, hash chain, BIP-39 derivation, and
Argon2id KDF. Fully tested.

**Exit criteria.**

- Ed25519 signing works, verifies known test vectors.
- X25519 DH works, verifies known test vectors.
- Canonical JSON (JCS) produces byte-identical output for the same
  input across platforms; test with RFC 8785 examples.
- Hash chain construction and verification: verify, verify with
  tampered row, verify with removed interior row all pass.
- BIP-39: generate a phrase, derive seed, derive identity keys.
  Deterministic. Matches BIP-39 test vectors for the wordlist and
  seed derivation.
- Argon2id derivation with spec parameters (m=65536, t=3, p=1)
  completes and is measured — log the timing so we know if it needs
  tuning on target hardware.
- 100% branch coverage on this module.

**Prompt.**

```
Phase 1 of Conveyance: crypto core.

Scope: implement everything in the spec's "Cryptographic primitives"
section, as a `crypto` module in conveyance-core. No storage yet, no
networking yet, no protocol yet.

Specific crates to use (do not substitute without discussion):
- ed25519-dalek for Ed25519
- x25519-dalek for X25519
- chacha20poly1305 for AEAD
- argon2 for Argon2id
- bip39 for BIP-39 wordlist and seed derivation
- hkdf + blake2 for HKDF-BLAKE2s
- sha2 for SHA-256
- serde_jcs or a JCS implementation you can verify against RFC 8785
- snow will be added in a later phase (Noise session) — not here

Test-first. For each primitive:
1. Write a test that uses known-good vectors (RFC 8785 for JCS, BIP-39
   test vectors, Ed25519 RFC test vectors).
2. Then implement the wrapper.
3. Confirm the test passes.

Also implement the hash chain constructor and verifier per the spec's
"Logging" section. Test: build a chain, verify it, alter a row, verify
fails; remove an interior row, verify fails.

Do NOT integrate with storage yet. This module should be pure
functions and value types.

Follow persistent rules. Propose your plan before writing code.
```

---

## Phase 2 — Encrypted storage

**Scope.** SQLite databases with migrations, OS-keychain-backed
encrypted identity storage, log writer.

**Deliverable.** `conveyance-core::storage` module. Identity can be
generated, encrypted at rest, and loaded. Log entries can be appended
and queried. Hash chain is enforced on append.

**Exit criteria.**

- Identity save/load roundtrip works on Linux, macOS, Windows.
- Refuses to start if OS keychain is unavailable (per spec).
- Pairings DB schema is created via migration.
- Executions log DB schema is created via migration.
- Log append computes and stores hash chain correctly.
- Log verify walks the chain and reports intact/tampered/reordered.
- Concurrent writes to the log serialize correctly (mirroring
  auditmcp's approach).
- Zero warnings, clippy clean, all tests pass.

**Prompt.**

```
Phase 2 of Conveyance: encrypted storage.

Scope:
- SQLite databases for pairings and the executions log, with
  migrations. Use `rusqlite` with the `bundled` feature (matches
  auditmcp — no system SQLite dependency). Schemas per the spec's
  "Logging" and "Storage layout" sections.
- OS keychain integration for encrypting identity at rest. Use the
  `keyring` crate. Per spec: refuse to start if keychain is
  unavailable; do NOT fall back to a passphrase silently.
- Encrypted identity storage: identity keys are encrypted with a DEK
  derived from a random key stored in the OS keychain. Serialization
  format is your choice but must be versioned.
- Log writer: appends entries with hash chain per the spec. Writes
  serialize on a shared DB (BEGIN IMMEDIATE, same pattern as
  auditmcp). Use the crypto module from phase 1 for the hash chain
  computation — do NOT re-implement.

Tests:
- Identity roundtrip on all three platforms (mock the keychain for
  CI; real keychain testing is manual).
- Log append + verify.
- Log append with concurrent writers.
- Log verify with tampered rows.
- Migration idempotency.

Do NOT implement BLE, sessions, pairing, or the daemon yet.

Follow persistent rules. Propose your plan before writing code.
```

---

## Phase 3 — Noise session wrapper & session state machine

**Scope.** Wrap `snow` for Noise_KK, implement the session state
machine, implement the idle and hard-cap timers.

**Deliverable.** Two in-process endpoints can establish a Noise KK
session, exchange messages, and end the session per the state machine.
No BLE yet — session runs over an in-memory channel for now.

**Exit criteria.**

- Noise KK handshake between two mock endpoints succeeds.
- Handshake with mismatched static keys fails.
- Transport messages after handshake are encrypted and authenticated.
- Session state machine transitions match the spec exactly.
- Idle timer fires at the configured threshold.
- Hard-cap timer fires regardless of activity.
- Session keys are zeroized on session end (verify with a
  `zeroize`-style pattern).
- `no_session` error is returned when the session state is anything
  other than ACTIVE.

**Prompt.**

```
Phase 3 of Conveyance: Noise KK session wrapper and session state
machine.

Scope:
- Use the `snow` crate for Noise. Pattern:
  Noise_KK_25519_ChaChaPoly_BLAKE2s (this exact spelling — snow uses
  this exact string).
- Wrap snow in a `Session` type that holds state per the spec's
  "Session lifecycle" section. States, transitions, and error codes
  come from the spec.
- Implement the idle timer and hard-cap timer using `tokio` (or the
  runtime we chose in phase 0). Minimums and maximums per the spec MUST
  be enforced and MUST NOT be bypassable through config.
- Session start requires: both sides know each other's static keys
  (loaded from storage; use phase-2 storage for this test), Noise
  handshake succeeds, both sides transition to ACTIVE.
- Cold-start enforcement: any operation requiring a session MUST
  return `conveyance/no_session` when state != ACTIVE. This is
  architectural — the code path must not exist to bypass this.

Testing:
- Use an in-memory transport (two async channels) — do NOT introduce
  BLE yet.
- Full handshake round-trip.
- Handshake with wrong static keys → fails cleanly.
- Timer expiry: idle and hard cap both trigger correct state
  transitions.
- Session end: keys zeroized (test by dropping and re-reading buffer
  patterns, or with a zeroize-verifying wrapper).
- Cold-start: attempt an operation when no session → correct error.

Do NOT implement BLE, pairing, the daemon, or the shim yet.

Follow persistent rules. Propose your plan before writing code.
```

---

## Phase 4 — Wire protocol & framing

**Scope.** CBOR message types, length-prefixed framing with chunking,
reassembly buffer, approval-execute binding logic.

**Deliverable.** All message types from the spec encode/decode
correctly. Framing handles messages larger than one MTU. Approval and
execute payloads bind correctly.

**Exit criteria.**

- Every message type in the spec has a round-trip test.
- Framing correctly splits and reassembles messages of arbitrary
  size up to the buffer cap.
- Malformed frames are rejected without panic.
- Approval-execute binding: matching payload approved, differing
  payload rejected with `approval_mismatch`.
- Fuzzing the parser (5-minute cargo-fuzz run minimum) produces no
  panics.

**Prompt.**

```
Phase 4 of Conveyance: wire protocol and framing.

Scope:
- Implement all message types from the spec's "Wire protocol" section
  as Rust types with serde CBOR serialization. Use `ciborium` for
  CBOR (widely used, actively maintained).
- Implement the framing layer per the spec: length-prefixed, sequenced,
  START/END/ACK flags, reassembly with a buffer cap.
- Reassembly buffer cap: 128 KiB per spec. Exceeding it terminates the
  session with `message_too_large`.
- Approval-execute binding: on ExecuteRequest, compare the fields to
  the previously approved ApprovalRequest by canonical JSON
  serialization. Any mismatch → `approval_mismatch`. Approved
  req_ids expire after 5 minutes.

Testing:
- Round-trip each message type.
- Framing round-trip: message smaller than MTU (one frame), message
  spanning multiple frames.
- Malformed frame injection: random bytes, truncated length prefix,
  invalid flag combinations — none may panic.
- Approval-execute binding: matching → passes, differing (any field)
  → rejected, expired req_id → rejected.
- Fuzz the parser with cargo-fuzz for at least 5 minutes; no panics.

Do NOT integrate with BLE, sessions, or daemon yet — this is a pure
protocol module. Use in-memory buffers for tests.

Follow persistent rules. Propose your plan before writing code.
```

---

## Phase 5 — BLE transport

**Scope.** BLE central role via btleplug, scanning, connecting, GATT
operations. Abstract transport trait so the wire protocol from phase 4
can run over either the mock (in-memory) or real BLE.

**Deliverable.** A `Transport` trait with two implementations: mock
(in-memory, for tests) and real (btleplug). The mock and real
implementations pass the same test suite for the operations they can
share.

**Exit criteria.**

- Transport trait defined; mock passes tests.
- Real BLE: can scan for a specific service UUID.
- Real BLE: can connect to an advertising peripheral on match.
- Real BLE: GATT operations (write, notify subscription) work against
  a test peripheral.
- Manual test: with a phone app stub advertising the service UUID,
  the daemon detects and connects.

**Prompt.**

```
Phase 5 of Conveyance: BLE transport.

Scope:
- Define a `Transport` trait with async methods: connect, write, read
  (notify), disconnect. Design it so the wire protocol from phase 4
  runs over any implementation.
- Implement a mock transport using in-memory channels for testing.
- Implement a real BLE transport using `btleplug` (cross-platform BLE
  central library, matches spec's PC-as-central role).
- Real transport scans for the Conveyance service UUID (which needs
  to be picked and pinned in the spec BEFORE this phase — see note
  below), connects on match, discovers the characteristics, subscribes
  to notifications on `phone_to_pc_tx`, writes to `pc_to_phone_tx`.
- Handle BLE disconnects cleanly — session teardown per spec.

Before starting: the service UUID and characteristic UUIDs are marked
TBD in the spec. Generate them now (uuidgen or equivalent) and update
the spec. This must happen once and be permanent.

Testing:
- Trait passes same test suite over both implementations for shared
  behavior (framing tests from phase 4 should just work).
- Real BLE: manual test against a stub advertising peripheral. A
  simple nRF Connect setup on any Android phone can advertise the
  service UUID for this test.
- Disconnect handling: mid-message disconnect surfaces as a
  transport error, not a panic.

Note: real BLE cannot be fully tested in CI without hardware. Mock
transport handles CI coverage. Real BLE is manually verified.

Follow persistent rules. Propose your plan before writing code.
```

---

## Phase 6 — Pairing ceremony

**Scope.** QR generation, pairing state machine, PairingConfirm/Ack
messages, nonce bloom filter, `conveyance pair` CLI command.

**Deliverable.** Pairing works end-to-end against a mock phone. Real
phone pairing waits until Phase 10 exists, but the daemon side is
complete.

**Exit criteria.**

- Full pairing succeeds against mock phone.
- Expired QR fails cleanly.
- Tampered PairingConfirm fails, nothing persisted.
- Replayed nonce (bloom filter hit) fails.
- Protocol version mismatch fails with an explicit error.
- Pairing state machine matches spec exactly.
- CLI: `conveyance pair` renders QR, waits, exits cleanly on success
  or timeout.

**Prompt.**

```
Phase 6 of Conveyance: pairing ceremony.

Scope:
- Implement the pairing state machine per the spec's "Pairing
  ceremony" section (PC side only — phone side comes in phase 10).
- QR generation: use the `qrcode` crate. Encode the CBOR object shown
  in the spec, error correction level H. Render to terminal (ASCII
  art) for the CLI, and optionally to a PNG file for cases where the
  terminal display is problematic.
- Pairing messages: PairingConfirm and PairingAck per the spec.
  Signature verification uses the crypto module from phase 1.
- Nonce bloom filter: use the `bloomfilter` crate with 48-hour
  retention. Bloom filter is persisted to disk (small file, rebuilt
  on daemon start).
- CLI command: `conveyance pair` — renders QR, drives the pairing
  state machine, blocks until success or timeout, exits with clear
  status.

Testing:
- Mock phone (Rust harness) that produces valid PairingConfirm.
- Full pairing to PAIRED state; verify both sides have each other's
  keys in storage.
- Expired QR: rejected.
- Invalid signature on PairingConfirm: rejected.
- Replayed nonce: rejected.
- Version mismatch: rejected with correct error.
- Timeout on user inaction: state machine returns to UNPAIRED
  cleanly.

Do NOT implement the phone side of pairing here — that's phase 10.
The mock phone in tests is a stand-in.

Follow persistent rules. Propose your plan before writing code.
```

---

## Phase 7 — Daemon binary & IPC

**Scope.** Long-running daemon binary. Local socket (Unix or named
pipe) for shim IPC. Session state management. Full request routing:
shim → daemon → phone (mock) → daemon → shim.

**Deliverable.** `conveyance daemon` runs, holds session state,
responds to IPC from a test client. Requests flow end to end (with
mock phone).

**Exit criteria.**

- Daemon starts, loads config, opens keychain, opens databases, binds
  local socket.
- Refuses to start if keychain unavailable or DBs unopenable.
- IPC protocol defined and stable.
- Session start/end flows work.
- `authenticated_request` flow works end-to-end against mock phone:
  IPC in → session check → phone approval → phone execute → response
  back → IPC out.
- Daemon shutdown is clean: sessions ended, in-flight requests
  marked, DBs flushed.
- Additional CLI: `conveyance status`, `conveyance session end`.

**Prompt.**

```
Phase 7 of Conveyance: daemon binary.

Scope:
- Implement the daemon as a long-running binary that integrates
  everything from phases 0-6.
- Local socket for shim IPC: use the `interprocess` crate for
  cross-platform Unix socket / named pipe abstraction.
- Define the daemon-shim IPC protocol — this is internal, not spec'd
  externally. Use bincode or serde CBOR. Message types: SessionStart,
  SessionEnd, AuthenticatedRequest, ListServices, CheckSession, plus
  responses.
- Session state lives in the daemon (per the spec's daemon+shim
  rationale). Multiple shims connected to one daemon share this
  state.
- Full request routing: shim sends AuthenticatedRequest over IPC →
  daemon checks session → daemon sends ApprovalRequest over Noise
  session to phone → phone responds with ApprovalResponse → daemon
  sends ExecuteRequest → phone responds with ExecuteResponse →
  daemon logs to executions.db → daemon returns result over IPC to
  shim.
- Additional CLI commands: `conveyance status` (prints daemon
  state), `conveyance session end` (ends active session).
- Clean shutdown: matches auditmcp's approach — SIGTERM/SIGINT
  handled, sessions ended, in-flight requests marked as timeout, DB
  writes flushed, up to 10s wait.

Testing:
- IPC roundtrip.
- Session start/end via IPC.
- Full request flow with mock phone: correct log entries on both
  sides, correct response propagation.
- Cold-start: IPC request with no session → correct error.
- Daemon crash mid-request: on restart, incomplete request is
  visible in log as deferred/timeout.
- Concurrent shims: two IPC clients see consistent session state.

Follow persistent rules. Propose your plan before writing code.
```

---

## Phase 8 — MCP shim binary

**Scope.** MCP JSON-RPC over stdio. Tool implementations. Structured
error propagation.

**Deliverable.** `conveyance mcp-shim` speaks MCP correctly. Real MCP
clients (Claude Code, etc.) can spawn it and invoke tools.

**Exit criteria.**

- MCP protocol handshake works (initialize, tools/list).
- All four v1 tools defined and callable per the spec.
- Errors propagate as structured JSON per the spec's error model.
- End-to-end: Claude Code (or another MCP client) invokes
  `authenticated_request`, request reaches daemon, phone approves and
  executes (mock), response returns through shim to client.

**Prompt.**

```
Phase 8 of Conveyance: MCP shim binary.

Scope:
- Implement the MCP shim binary. Speaks JSON-RPC over stdio per the
  MCP specification (which the spec assumes the implementer is
  familiar with — see modelcontextprotocol.io if not).
- On startup, connect to the daemon over the local socket from phase 7.
- Exit when stdin closes.
- Expose exactly these tools per the Conveyance spec:
  * authenticated_request(service, method, endpoint, params)
  * list_services()
  * check_session()
  * end_session()
- Nothing else. No key material tools. No "get secret" tool.
- Errors from the daemon are translated to the structured JSON error
  shape defined in the spec's "Error model" section, then returned
  through MCP as tool errors.

Testing:
- MCP protocol handshake against a test client.
- Tool schemas match the spec.
- Error propagation: daemon returns `phone_unreachable` → shim
  returns structured error with correct code and retryable flag.
- End-to-end: use Claude Code or the MCP inspector to invoke
  `authenticated_request`. Trace the full flow. Verify both logs
  contain the expected entries.

Follow persistent rules. Propose your plan before writing code.
```

---

## Phase 9 — Full CLI, config, log diff

**Scope.** Fill out remaining CLI commands, config validation, log
diff tool.

**Deliverable.** Complete CLI matches spec. Log diff tool reconciles
phone and PC logs and correctly flags mismatches.

**Exit criteria.**

- All CLI commands from the spec exist and work.
- `conveyance log query` supports all filters listed in the spec.
- `conveyance log verify` exit codes match spec (0/1/2).
- `conveyance log export --format jsonl` produces valid JSONL.
- `conveyance log diff <phone-export>` correctly identifies matched
  pairs, missing executions, executions without approvals, signature
  failures.
- Config validation catches invalid timers, unknown fields, etc.
  before startup.

**Prompt.**

```
Phase 9 of Conveyance: CLI, config, log diff.

Scope:
- Fill in the CLI commands not yet implemented: `conveyance unpair`,
  `conveyance log query`, `conveyance log verify`, `conveyance log
  export`, `conveyance log diff`.
- Match auditmcp's CLI ergonomics (see its README): filters use the
  same shape (--since with required unit, --tool, --status), exit
  codes for `verify` follow the same 0/1/2 pattern.
- Config validation: reject invalid session timers (below minimums or
  above maximums), unknown fields, malformed high-risk rules. Fail on
  startup, not lazily.
- Log diff tool: takes a phone export (JSONL) and the local
  executions.db, reconciles by req_id, produces a report with
  categories from the spec's "Diff tool" section.

Testing:
- CLI integration tests using assert_cmd or similar.
- Log diff against a known-good phone export: expected pairings and
  mismatches appear.
- Log diff detects: approval without execution (missing), execution
  without approval (SECURITY EVENT), invalid signature on phone
  entry, execution timestamped before approval.
- Config validation: each rejection condition triggers correctly.

Follow persistent rules. Propose your plan before writing code.
```

---

## Phase 10 — Android app (parallel track)

**Scope.** The entire phone side. Native Kotlin. Own multi-phase build.

**Sub-phases** (implement in order, similar structure to phases 1-9):

- **10.0** — Android project scaffolding, Kotlin, minimum SDK 30,
  Jetpack Compose, DI (Hilt), CI.
- **10.1** — Crypto core in Kotlin (or JNI wrapper around the Rust
  conveyance-core::crypto module — decision point, see below).
- **10.2** — Encrypted storage: Room with SQLCipher, Android Keystore
  integration, credential store, approval log.
- **10.3** — BLE peripheral + GATT server, framing (same wire
  protocol as PC side).
- **10.4** — Noise KK session (Kotlin implementation or JNI to Rust —
  same decision as 10.1).
- **10.5** — Pairing ceremony (phone side): QR scanner, PairingConfirm
  signing, storage of paired PC.
- **10.6** — Approval UI and Tier 1/2/3 authentication flows.
- **10.7** — Request executor: HTTP client that uses stored
  credentials, returns response through Noise session.
- **10.8** — Recovery phrase flows: first-run display (FLAG_SECURE),
  restore-from-phrase.
- **10.9** — Foreground service, battery management, notifications.
- **10.10** — App polish: settings, credential management UI,
  session status UI, kill switch.

**Decision point at 10.1:** implement crypto in Kotlin (with well-vetted
Kotlin/Java libraries like Tink, BouncyCastle for Argon2), or reuse the
Rust `conveyance-core::crypto` module via JNI/UniFFI. Rust reuse gives
one implementation to audit; Kotlin implementation avoids the JNI
build complexity. Recommendation: try UniFFI first (Mozilla-maintained,
generates Kotlin bindings from Rust automatically), fall back to
native Kotlin if the tooling causes friction. This decision affects
10.1, 10.4, and to a lesser extent 10.7.

**Prompt for Phase 10.0 (scaffolding — start here):**

```
Phase 10.0 of Conveyance: Android app scaffolding.

You are implementing the phone side of Conveyance. The spec is in
CONVEYANCE_SPEC.md — read the sections "Phone-side components" and
"Storage layout" carefully before starting.

Scope for this sub-phase:
- Create an Android project: native Kotlin, Jetpack Compose for UI,
  Hilt for DI, minimum SDK 30 (Android 11), target SDK the latest
  stable at build time.
- Package name: com.ahlyxlabs.conveyance (or your preference — update
  the spec if changed).
- Set up GitHub Actions CI: lint, unit tests.
- Empty app that launches to a splash screen and does nothing else.
- Do NOT implement crypto, storage, BLE, or any protocol logic in
  this sub-phase. Scaffolding only.

Follow persistent rules. Propose your plan before writing code.
```

Subsequent 10.x sub-phases follow the same shape — each with its own
prompt when you get to it. Don't try to plan all of Phase 10 in
advance beyond this outline; the specifics of, say, the BLE peripheral
implementation are easier to prompt for once 10.0-10.3 are done and
you can see how it's shaping up.

---

## Phase 11 — End-to-end integration

**Scope.** Real daemon + real Android app. Manual verification of full
flows. Log diff after real sessions.

**Deliverable.** A working v1 that a real user (you) can install on
your PC and phone, pair, and use to gate a real API call.

**Exit criteria.**

- Successful pairing: real Android phone with real PC daemon.
- Session start, request, approve, execute, response — all real.
- Real MCP client (Claude Code) can invoke `authenticated_request`
  and get a real HTTP response back from a real service (start with
  something innocuous like `GET https://httpbin.org/get` with a
  fake bearer token).
- Log diff after a mixed session produces the expected reconciliation
  report.
- End-to-end flow works on Linux + Android and Windows + Android.
- macOS + Android: works, may have quirks (spec calls out that macOS
  is CI-covered but not manually exercised in some cases — same
  applies here).
- Battery usage during a 30-min active session is measured on the
  phone and documented.

**Prompt.**

```
Phase 11 of Conveyance: end-to-end integration.

You now have a complete daemon (phases 0-9) and a complete Android
app (phase 10). This phase is bringing them together on real
hardware.

Scope:
- Manual pairing test: real Android phone with real daemon on your
  PC. QR displayed by daemon, scanned by phone, PairingConfirm
  signed and sent, both sides reach PAIRED.
- Manual session test: start session, make a real
  `authenticated_request` call through Claude Code, approve on
  phone, verify response returns correctly.
- Log diff test: run a mixed session (approvals, denials, an
  intentional timeout), export phone log, run diff, verify report is
  correct.
- Cross-platform: repeat pairing and session tests on Linux, macOS,
  Windows PC combinations with the same Android phone.
- Battery measurement: 30-min active session with periodic
  requests, measure phone battery drop, document.

Bugs found in this phase are the current phase's problem — fix them
here rather than deferring. When something surprises you, it means
some earlier assumption was wrong; find and update it (spec, code,
or tests).

Deliverable: a written report matching auditmcp's "How it has been
verified" section — what was tested on what platform, what was
verified vs. what was only compiled, what surprised you.

Follow persistent rules.
```

---

## After v1

Roadmap phases from the spec (SSH signing, iOS, multi-device, etc.)
each become their own multi-phase project of similar structure. Do not
start Phase 10 (iOS) or later until v1 has been used by real people
for real work for at least a month — real usage exposes design
mistakes that no amount of pre-planning catches.

---

## What to do if a phase goes sideways

- If the agent proposes deviating from the spec, stop it and either
  update the spec (deliberate change) or push back (spec wins).
- If an exit criterion can't be met, the phase isn't done. Don't
  advance. Diagnose why, and either fix or scope down.
- If a phase reveals that a decision from an earlier phase was wrong,
  fix it in the earlier phase's code and update the spec if the
  interface changed. Don't paper over it.
- If a phase turns out to be much bigger than expected, split it.
  Better to have 12 clean phases than 10 messy ones.
