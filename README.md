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

Phase 0 complete; phases 1+ unstarted. Concretely:

**Working**

- **Cargo workspace** with three crates: `conveyance-core` (shared
  foundations), `conveyance-daemon` and `conveyance-shim` (stub binaries,
  `--version` only).
- **Config loading** (`conveyance-core::config`) — parses the spec's TOML
  shape including `[[high_risk]]` rules, applies spec defaults for session
  timers when sections are omitted. Parsing only: timer bound validation is
  phase 9, so an out-of-range value loads without complaint today.
- **Platform paths** (`conveyance-core::paths`) — config/data directories
  per the spec's storage layout table. On Windows the data directory is
  deliberately `%LOCALAPPDATA%`, not roaming, because logs and databases
  are machine-bound state.
- **Error model** (`conveyance-core::error`) — all eleven named error codes
  from the spec, each serializable into the spec's exact five-field JSON
  shape via `serde`. Handshake/peer-identity messages are fixed and generic
  per the spec's "MUST NOT leak which validation failed" rule.
- **CI** — fmt + clippy (`-D warnings`) once, tests across
  windows/ubuntu/macos.

**Not working / not started**

- Everything else: crypto (phase 1), encrypted storage (phase 2), Noise
  sessions (phase 3), wire protocol (phase 4), BLE (phase 5), pairing
  (phase 6), the real daemon (phase 7), the real shim (phase 8), CLI and
  log diff (phase 9), Android app (phase 10).
- The two binaries are separate executables named after their crates. The
  unified `conveyance <subcommand>` command line from the spec arrives with
  the CLI phases; expect that consolidation then.
