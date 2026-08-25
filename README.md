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

Phases 0 and 1 complete; phases 2+ unstarted. Concretely:

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
- **Config loading**, **platform paths**, **structured error model** as of
  phase 0.
- **CI** — fmt + clippy (`-D warnings`) once, tests across
  windows/ubuntu/macos.
- **Tests**: 68 passing, including official vectors for every primitive
  that publishes them. Branch coverage on the crypto module: 100% (measured
  with cargo-llvm-cov + nightly; every remaining uncovered line in the
  workspace is a test-guard panic arm, an environment-dependent config path
  outside this phase's criterion, or a stub main).

**Not working / not started**

- Everything above this layer: encrypted storage (phase 2), Noise sessions
  (phase 3), wire protocol (phase 4), BLE (phase 5), pairing (phase 6),
  the real daemon (phase 7), the real shim (phase 8), CLI and log diff
  (phase 9), Android app (phase 10).
- The two binaries are separate executables named after their crates. The
  unified `conveyance <subcommand>` command line from the spec arrives with
  the CLI phases; expect that consolidation then.
