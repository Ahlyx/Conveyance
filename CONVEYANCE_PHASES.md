# Conveyance — Phased Implementation Plan
  Better to have 12 clean phases than 10 messy ones.
- If a phase turns out to be much bigger than expected, split it.
## Phase 7 � Daemon binary & IPC

Split into two sub-phases (7.0, 7.1) during planning: the original
single phase composed six prior modules plus three new concerns (IPC,
long-running session ownership, request routing), which exceeded one
review gate.

### Phase 7.0 � Daemon skeleton, IPC & session lifecycle

**Scope.** Long-running daemon as a library function
(`conveyance-daemon::daemon::run(config)`); config resolution and
validation happen in the caller. Refuse-to-start chain in spec order
(config -> data dirs -> keychain identity -> databases -> socket bind),
each failure with an actionable message. Local-socket IPC server
(interprocess crate; Unix domain sockets / named pipes) with a framed
CBOR protocol: SessionStart, SessionEnd, CheckSession, Status plus
responses; authenticated-request routing arrives in 7.1. Session
lifecycle wired to phase 3 (responder-side Noise KK against a paired,
advertising phone). CLI: `conveyance daemon`, `conveyance status`,
`conveyance session start`, `conveyance session end`. Clean shutdown on
SIGTERM/SIGINT/Ctrl-C: session ended and zeroized, DBs checkpointed,
socket released, <=10 s drain.

**Exit criteria.**
- Daemon starts from config value; refuses to start (nonzero exit,
  actionable stderr) when keychain unavailable or a database cannot be
  opened.
- IPC roundtrip works over a real local socket in CI on all three
  platforms.
- Cold-start: any request while NO_SESSION returns
  `conveyance/no_session`.
- Session start/end via IPC reach ACTIVE / NO_SESSION against the mock
  phone; two concurrent IPC clients observe consistent state.
- Shutdown is clean and restartable (no stale socket lock).

### Phase 7.1 � Request routing & crash recovery

**Scope.** AuthenticatedRequest and ListServices routed over an active
session to the phone: ApprovalRequest -> signed ApprovalResponse ->
ExecuteRequest -> signed ExecuteResponse -> executions.db rows ->
IPC response. Signature verification on every phone message; denials
and timeouts propagate as spec error codes. Startup sweep marks
orphaned requests (`approval_request` without a terminal row) as
`request_timeout`, distinguishing `crashed_before_terminal` from live
timeouts in payload_json.

**Exit criteria.**
- Full authenticated_request flow against mock phone: correct log rows
  on both sides, response body propagates to the shim.
- Denied/expired approvals produce the right spec errors, no execution,
  log rows recorded.
- Crash mid-request: after restart the orphaned req_id is visible as
  request_timeout with crashed_before_terminal reason.
- Concurrent shims during one active request see consistent state.

  Better to have 12 clean phases than 10 messy ones.
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
- **10.2** — Encrypted storage. Split into **10.2a** (Android Keystore
  key provisioning + Rust-owned sealed identity + identity vault) and
  **10.2b** (Room + SQLCipher databases: credentials, approval log,
  pairings). See the dedicated blocks below.
- **10.3** — BLE peripheral + GATT server, framing (same wire
  protocol as PC side). Split into **10.3a** (Kotlin framing layer +
  cross-impl fixture parity + the `conveyance-wire` leaf-crate extract +
  the `PhoneLink` transport seam, all JVM-testable) and **10.3b** (the
  Android `BluetoothGattServer` + advertiser + permissions + disconnect
  handling, emulator/device-bound). **Closed** — see
  `PHASE_10.3_EXIT.md` for per-criterion evidence and the Phase 11
  hardware carry-over.
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

**Decision approach for 10.1:** UniFFI is the strongly-preferred path
because it eliminates duplicate implementations of security-critical code
(canonical JSON, HKDF-BLAKE2s, signing-payload construction) AND because
Phase 10.4 (Noise_KK) has no viable pure-Kotlin implementation — the
alternative to reusing snow via UniFFI is hand-rolling Noise_KK, which is
significantly more dangerous than hand-rolling any primitive. The
conveyance-core::crypto module should be extracted into a standalone
conveyance-crypto crate as a prerequisite regardless of path (the
pre-Phase-10 audit already flagged this scope drift). Then a time-boxed
spike (≤2 days) verifies UniFFI viability: cargo-ndk builds for
arm64-v8a and x86_64, one primitive round-trips through generated Kotlin
bindings against an RFC vector, both ABIs pass on emulator CI. If the
spike succeeds, proceed with UniFFI for the full 10.1 surface. If the
spike fails, do not silently fall back — report what failed and decide
deliberately whether to invest further in UniFFI or accept the
significant downstream cost of hand-rolling Noise in Kotlin.

### Phase 10.2 — Encrypted storage

Split into two sub-phases during planning, same reasoning as the Phase 7
split: the original single phase composed the Android Keystore key model,
a new Rust-owned key-handle type, an identity vault, and three separate
encrypted SQLite databases — more than one review gate. 10.2a is the
security-critical core (nothing plaintext-identity-bearing crosses the
FFI); 10.2b is the encrypted-database layer built on top of it.

The 10.1 `ConveyanceCrypto` interface is the seam: it has no production
consumers yet, so 10.2a is free to introduce a handle-based identity API
without touching call sites. `ConveyanceCrypto.deriveIdentity` (raw key
bytes) is retained solely as the cross-implementation verification path
for the fixture parity suite; it is not on the production unlock path.

#### Phase 10.2a — Keystore, sealed identity, identity vault

**Scope.** Android Keystore key provisioning with the spec-mandated Tier
1 flags. A Rust-owned `UnlockedIdentity` UniFFI object: identity Ed25519
and X25519 secret scalars are derived, sealed into `identity.enc`,
opened, and signed with entirely inside `conveyance-crypto`; Kotlin holds
only an opaque handle. An `IdentityVault` that creates the sealed
identity from a recovery phrase at first run and unlocks it under
BiometricPrompt. No databases, no BLE, no Noise, no pairing logic, no UI.

Two Keystore keys, on the right security axis:

- `conveyance_tier1` — AES-GCM-wraps the identity content key and each
  per-service credential DEK. `setUserAuthenticationRequired(true)`,
  `setUserAuthenticationParameters(0, BIOMETRIC_STRONG | DEVICE_CREDENTIAL)`
  (fresh auth every use), `setInvalidatedByBiometricEnrollment(true)`,
  `setUnlockedDeviceRequired(true)`, StrongBox when available. These are
  security requirements from the spec's "Phone-side components" section,
  not optional hardening.
- `conveyance_db` — AES-GCM-wraps the shared SQLCipher passphrase for the
  operational databases (10.2b). `setUserAuthenticationRequired(false)`
  deliberately: the approval log must accept writes throughout an active
  session without re-prompting. This key defends against offline
  extraction of storage obtained without a live session, not against a
  running compromised app (addressed by the Android sandbox and by
  biometric auth at session start).

**Exit criteria.**

- Keystore keys provision on the emulator; `KeyInfo` confirms
  `isUserAuthenticationRequired` and `isInvalidatedByBiometricEnrollment`
  are set on `conveyance_tier1`, and StrongBox is used when the device
  advertises it (software TEE fallback otherwise, no crash).
- Identity secret scalars never appear as a JVM value: verified by
  inspection of the FFI surface (no export returns them) and by the vault
  API shape (`unlock` returns an opaque handle).
- Round trip: `createFromPhrase` → persist `identity.enc` → `unlock`
  under a mocked/authorized crypto object → `sign` → signature verifies
  against the handle's public key via `ConveyanceCrypto`.
- Wrong content key → `DecryptionFailed`; truncated/version-mismatched
  blob → `DecryptionFailed`, no panic.
- `KeyPermanentlyInvalidatedException` handling path is exercised with a
  mocked cipher (recovery flow initiates); real enrollment-change
  triggering is deferred to Phase 11 hardware testing.
- `identity.enc` is versioned; a raw read of the file is not plaintext
  key material.
- Fixture parity suite still green (extended with a `sealed_identity`
  group); the drift gate still enforced in `cargo test` and CI.

#### Phase 10.2b — Encrypted databases

**Scope.** Three Room + SQLCipher databases. `credentials.enc`: per-row
secret encrypted with a per-service DEK (`conveyance_tier1`-wrapped),
sealed and opened one row at a time in Rust — never decrypted in bulk.
`approvals.db`: the hash-chained approval log (spec "Logging" schema
verbatim), append computing the chain via `ConveyanceCrypto.rowHash`,
`verify` via `ConveyanceCrypto.verifyChain`, JSONL export of signed rows
for `conveyance log diff`. `pairings.db`: schema and DAO only — no
ceremony producers yet (10.5). All three behind SQLCipher with the
shared `conveyance_db`-wrapped passphrase. Hilt wiring. No UI.

**Exit criteria.**

- Credential add / list (names only) / remove / open one round-trips on
  the emulator; a raw read of `credentials.enc` shows no plaintext secret
  or service DEK.
- Approval-log append builds a valid chain; `verify` reports intact for a
  clean chain, `ContentTampered` for an altered row, `LinkBroken` for a
  removed interior row.
- Concurrent appends serialize to a single valid chain (single-writer
  discipline, mirroring auditmcp).
- JSONL export produces one canonical-JSON object per row, signed with
  the phone identity; unsigned rows are never emitted.
- `pairings.db` schema is created via migration; DAO insert/query/delete
  round-trips.
- All three DB files are SQLCipher-encrypted at rest (raw bytes are not a
  readable SQLite header).
- Instrumented CI runs the new storage tests; `android.yml` asserts they
  executed.

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

**BLE items carried from Phase 10.3** (see `PHASE_10.3_EXIT.md`): real
advertise seen by the daemon's central; real MTU negotiation with a
multi-frame message over ATT; `onNotificationSent` latency vs the 2 s
`NOTIFY_ACK_TIMEOUT_MS`; physical mid-message disconnect, adapter toggle
under a live connection, CCCD cleared by a real central; advertiser
`onStartSuccess` on real hardware; nRF Connect as an interim central.

**BLE items carried from the 10.3b remediation pass** (findings #9, #10
— deferred, not fixed, per the remediation triage): `preparedWrite`
(Android's reliable/queued-write mechanism) is unhandled in
`ConveyanceGattServerCallback.onCharacteristicWriteRequest` — btleplug
and the emulator never exercise it, so it's unverified whether any real
central needs it. `RealGattServerHandle.notify`/`sendResponse`/`close`
catch only `SecurityException`; other `RuntimeException`s a real BLE
stack can throw (e.g. `IllegalStateException` from a dead Bluetooth
binder) propagate past `PhoneLink.send`'s documented
"only throws `LinkClosedException`" contract — real hardware testing
will show which exception classes actually appear before broadening the
catch is worth doing blind.

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