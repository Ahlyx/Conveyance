# Conveyance

A phone-approved capability broker for MCP tool calls. The user's phone
holds credentials and executes authenticated requests on behalf of an LLM
agent; the PC-side MCP server only relays requests and returns results.
Secrets never reside on the machine the agent runs on, and every action
requires a physical tap on a separate device.

The full design contract -- threat model, wire protocol, state machines,
fixed cryptographic choices -- is `CONVEYANCE_SPEC.md` in this repository.
`CONVEYANCE_PHASES.md` tracks the implementation sequence. Those two files
are the source of truth; this README describes what currently exists, not
what is planned as if it existed.

## How do I run it?

You need the [Rust toolchain](https://rustup.rs/) (stable 1.90 or newer;
the workspace is edition 2024 with a declared MSRV of 1.90).

```bash
git clone <this repo>
cd conveyance
cargo build --release
```

Both binaries land in `target/release/`. Neither does anything yet:

```bash
conveyance-daemon --version   # works; anything else exits with code 2
conveyance-shim --version     # same
```

The stubs exit nonzero on purpose: a daemon that exited 0 while doing
nothing would look healthy to scripts.

## What does it need?

- Rust stable >= 1.85 to build. No other runtime dependencies; CI covers
  Linux, macOS, and Windows.
- At run time (once implemented): config at the platform config directory
  (`%APPDATA%\conveyance\config.toml` on Windows, XDG equivalent elsewhere)
  and an available OS keychain. A missing config file is an error by
  design; nothing is auto-created behind your back.
- MIT licensed; see `LICENSE`.

## What state is it in?

Phases 0–4 complete; phases 5+ unstarted. Concretely:

**Working**

- **Cargo workspace** with three crates: `conveyance-core` (shared
  foundations), `conveyance-daemon` and `conveyance-shim` (stub binaries,
  `--version` only).
- **Crypto core** (`conveyance-core::crypto`, phase 1): Ed25519 signing
  (RFC 8032 vectors), X25519 DH (RFC 7748 vectors), ChaCha20-Poly1305 AEAD
  for stored blobs (RFC 8439 vector), Argon2id KDF at the spec's parameters
  (~85 ms per derivation on this dev machine — under the spec's 500 ms
  tuning threshold; run `cargo run --release --example kdf_timing` to
  measure yours), BIP-39 recovery → HKDF-BLAKE2s → identity keypairs
  (TREZOR vectors), RFC 8785 canonical JSON, and the hash-chain
  constructor/verifier from the Logging section. Secret types zeroize on
  drop and redact their `Debug`.
- **Canonical JSON is implemented in-tree, not via serde_jcs**: that crate
  inherits key ordering from serde_json's map flavor (code-point order,
  not the UTF-16 order RFC 8785 mandates) — a silent signature-portability
  bug for astral-plane keys. Per the spec amendment, floats in canonical
  input are rejected loudly rather than formatted.
- **HKDF-BLAKE2s is also in-tree**: RustCrypto's `hkdf`/`hmac` cannot wrap
  BLAKE2s (its digest core is Lazy-buffered). The implementation is generic
  over any 32-byte digest and validated against RFC 5869's SHA-256 vectors,
  including the zero-salt case Conveyance actually uses.
- **Encrypted storage** (`conveyance-core::storage`, phase 2):
  `executions.db` with the spec's hash-chained log schema — appends run
  BEGIN IMMEDIATE and read the chain head *inside* the transaction, proven
  fork-free by an 8-thread/8-connection contention test; verification
  delegates to the phase-1 chain module. `pairings.db` with CRUD and the
  derived `<phone-id>` handle (spec amendment). `identity.enc`: long-term
  keys sealed with ChaCha20-Poly1305 under a DEK derived via HKDF-BLAKE2s
  from a random KEK held in the OS keychain (`keyring` crate; Linux uses
  the pure-Rust zbus backend). Keychain-unreachable is a typed error that
  carries `conveyance/keychain_unavailable` for phase 7's refuse-to-start;
  there is deliberately no passphrase fallback. All storage tests use a
  mock provider; real-keychain behavior on Windows/macOS/Linux is compiled
  but not exercised by CI.
- **Sessions** (`conveyance-core::session`, phase 3): Noise_KK
  (`Noise_KK_25519_ChaChaPoly_BLAKE2s`, via snow) with the PC fixed as
  responder and the phone as initiator; a pure state machine implementing
  the spec's lifecycle diagram exhaustively (every legal and illegal
  transition pinned by tests); idle-warning/idle/hard-cap timers on tokio,
  verified at exact thresholds under paused time, with the hard cap proven
  to fire through continuous activity. `SessionParams::validated()` is the
  only constructor external code can reach — spec minimums/maximums are
  not bypassable through config (fail-closed rejection). Cold-start is
  structural: no method produces output without passing the ACTIVE check,
  so `conveyance/no_session` falls out automatically. Handshake failures
  collapse to the generic `handshake_failed` per the spec's no-leak rule.
- **Wire protocol** (`conveyance-core::wire`, phase 4): all ten message
  types from the spec as CBOR types (string-tagged envelope; `ReqId` is a
  16-byte CBOR byte string on the wire, lowercase hex in signature JSON —
  both contexts pinned by tests). Signatures cover
  `"context" || canonical_json(minus-signature)` with absent optional
  fields omitted entirely (spec amendment). Framing: 6-byte headers,
  START/END/ACK flags, strict sequence continuity, 128 KiB reassembly cap.
  Approval-execute binding enforces byte-for-byte payload equality after
  canonicalization, 5-minute expiry, and consume-on-use (spec amendment) —
  replays are distinguishable from unknown ids for logging. `params`/`body`
  values are validated into the canonical-JSON domain at construction;
  floats are rejected with a distinct error so MCP clients can recover.
- **Fuzzing**: coverage-guided libFuzzer targets under `fuzz/` (run via
  WSL2 Ubuntu locally; Linux CI later). Phase 4 verification ran both
  targets for 180 s each (~93 million executions combined) against the
  framing and CBOR parsers: zero crashes. A deterministic 70k-iteration
  mutation soak also runs in normal `cargo test` on every platform.
- **Config loading**, **platform paths**, **structured error model** as of
  phase 0.
- **CI** — fmt + clippy (`-D warnings`) once, tests across
  windows/ubuntu/macos.
- **Tests**: 140 passing. Branch coverage on the crypto module: 100%
  (measured with cargo-llvm-cov + nightly); every remaining uncovered line
  in the workspace is a test-guard panic arm, an environment-dependent
  config path outside that criterion, or a stub main.

**Not working / not started**

- Everything above this layer: BLE transport (phase 5), pairing ceremony
  (phase 6), the real daemon (phase 7), the real shim (phase 8), CLI and
  log diff (phase 9), Android app (phase 10). `sessions.log` waits for
  phase 7, when sessions exist.
- The two binaries are separate executables named after their crates. The
  unified `conveyance <subcommand>` command line from the spec arrives with
  the CLI phases; expect that consolidation then.
