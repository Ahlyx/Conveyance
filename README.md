# Conveyance

A phone-approved capability broker for MCP tool calls. The agent on your PC
decides it needs an authenticated HTTP request; the request is relayed over
Bluetooth Low Energy to your phone; your phone shows you exactly what is about
to be sent and waits for a tap; only then does it execute the request using
credentials it holds itself and return the result to the PC. Credentials never
reside on the machine the agent runs on, and nothing authenticated happens
without a physical gesture on a separate device.

It is the hardware-wallet pattern applied to AI agents: the credential lives on
hardware the agent process cannot reach, and every use requires explicit human
action on that hardware. A compromised machine cannot exfiltrate what it never
had.

The full design contract — threat model, wire protocol, state machines, fixed
cryptographic choices — is [CONVEYANCE_SPEC.md](CONVEYANCE_SPEC.md), and
[CONVEYANCE_PHASES.md](CONVEYANCE_PHASES.md) breaks v1 into implementation
phases. Those two files are the source of truth. This README describes what
currently exists, not what is planned as if it existed.

## Why this exists

LLM agents increasingly need credentials to do useful work: API keys, OAuth
tokens, database passwords, signing keys. Every existing pattern for giving
those credentials to an agent has the same shape — the credential ends up
somewhere the agent process can read. Environment variables in an MCP config
file, a secret manager the process authenticates to, an OS keychain the process
has permission to query. A fully compromised host, or a prompt injection that
gains code execution, eventually reaches all of them.

The tools that gate access behind an OS-local prompt (biometric, admin auth)
raise the bar meaningfully, but they do not change the underlying fact: the
credential is retrievable from the same machine the agent runs on. Prompt
injection is precisely the attack that defeats anything the agent process can
itself invoke.

Hardware wallets solved this pattern for cryptocurrency keys by moving the
credential onto a separate device where using it requires a physical button
press. Conveyance applies the same model to agent tool calls: the phone holds
the credentials and executes requests itself, the PC relays requests and
receives results, and every execution requires a tap. An injection that
convinces the agent to exfiltrate secrets exfiltrates nothing, because the
agent never saw them.

## What state is it in?

PC-side v1 is complete: phases 0 through 9 of the implementation plan are done.
The Android app — phase 10 — has not been started. That split defines
everything else in this section.

### Working

- **Crypto core** (`conveyance-core::crypto`) — Ed25519 and X25519 against RFC
  vectors, ChaCha20-Poly1305 for stored blobs, Argon2id at the spec's
  parameters, BIP-39 recovery-phrase derivation against TREZOR test vectors,
  RFC 8785 canonical JSON, and HKDF-BLAKE2s. Canonical JSON and HKDF-BLAKE2s
  are implemented in-tree rather than via crates, for reasons worth knowing:
  `serde_jcs` inherits key ordering from serde_json's map flavor (code-point
  order instead of the UTF-16 code-unit order RFC 8785 mandates — a silent
  signature-portability bug for astral-plane keys), and RustCrypto's `hkdf`
  cannot wrap BLAKE2s at all. Secret types zeroize on drop.
  100% branch coverage measured on this module.
- **Encrypted storage** (`conveyance-core::storage`) — the hash-chained SQLite
  execution log with appends that serialize fork-free under multi-thread
  contention (`BEGIN IMMEDIATE`, chain head read inside the transaction), the
  pairings database with its derived phone-id handle, and long-term identity
  keys sealed under a DEK held in the OS keychain. There is deliberately no
  passphrase fallback when the keychain is unavailable: refuse-to-start beats
  silently weaker storage.
- **Sessions** (`conveyance-core::session`) — Noise_KK
  (`Noise_KK_25519_ChaChaPoly_BLAKE2s`, via snow) with the PC fixed as
  responder, the spec's session lifecycle implemented exhaustively (every legal
  and illegal transition pinned by tests), idle/hard-cap timers proven at exact
  thresholds under paused time, the hard cap shown to fire even under continuous
  activity, and session keys zeroized on end. Spec minimums on timers are not
  bypassable through config. Cold-start rejection is structural: no code path
  produces a result without passing the ACTIVE check.
- **Wire protocol** (`conveyance-core::wire`) — all ten message types as CBOR,
  length-prefixed framing with strict sequence continuity and a 128 KiB
  reassembly cap, and the approval-execute binding: the executed payload must
  match the approved payload byte-for-byte after canonicalization, approvals
  expire after five minutes, and each approval is consumed on first use. This
  binding defeats the TOCTOU attack where a compromised daemon shows the phone
  one payload and substitutes another for execution.
- **BLE transport** (`conveyance-core::transport`) — real BLE central role via
  btleplug behind the `ble` feature (default off; release builds enable it),
  plus an in-memory mock that carries the same test suite in CI. The real
  transport has been **radio-verified**: scanning, connecting, GATT writes, and
  notifications exercised over actual radio against an nRF Connect peripheral
  advertising the pinned service UUID — not merely compile-tested. That
  distinction matters here more than usual, because WinRT BLE stacks have
  quirks no unit test predicts.
- **Pairing ceremony** — QR display (error-correction level H, because the
  phone scans at an angle), signed PairingConfirm/Ack messages verified against
  the QR's own values, single-use nonces gated by a persisted bloom filter, and
  the full pairing state machine tested against a Rust mock phone. Live QR
  render and clean expiry manually verified.
- **Daemon** — refuse-to-start chain in spec order (config → data dirs →
  keychain identity → databases → socket bind), framed-CBOR IPC over Unix
  sockets / named pipes, session lifecycle ownership, request routing with
  Ed25519 signature verification on every message from the phone, and a
  crash-recovery sweep that marks orphaned requests at startup rather than
  leaving them invisible.
- **MCP shim** — JSON-RPC over stdio exposing exactly four tools
  (`authenticated_request`, `list_services`, `check_session`, `end_session`)
  and nothing else. No tool returns secret material; that constraint is
  architectural, not a policy setting. Errors propagate in the spec's
  structured JSON shape so the LLM can parse and react to them.
- **Full CLI** — `init`, `pair`, `daemon`, `status`, `session start/end`,
  `mcp-shim`, `unpair`, and `log query/verify/export/diff`. Config validation
  fails at startup, not lazily. The log diff tool reconciles phone-side
  approvals against PC-side executions by req_id and flags an execution without
  an approval as a security event, because under correct operation one should
  be impossible.
- **Tests and CI** — 248 tests across the workspace; libFuzzer targets on the
  framing and CBOR parsers ran ~93 million executions with zero crashes, plus a
  deterministic mutation soak that runs in every normal `cargo test`; CI runs
  fmt, clippy (warnings denied), and tests on Windows, Linux, and macOS.

### Not yet built

- **The Android app (phase 10)** — not started. It is the entire phone side:
  GATT peripheral role, Noise initiator, credential store, approval UI,
  Tier 1/2/3 authentication flows, recovery phrase handling.
- **Real-hardware pairing.** Pairing is verified against the mock phone only;
  pairing a physical phone waits for phase 10.
- iOS, SSH/git signing adapters, multi-device, multi-user policies — later
  roadmap phases (see Roadmap).

### Verification status, stated precisely

The BLE transport is radio-verified against nRF Connect; everything above it
(framing, sessions, pairing, routing) is verified against the mock transport
and mock phone, which share the real implementations' test suite. End-to-end
flows — MCP client → shim → daemon → scripted auto-approving phone → logs —
have been driven through real MCP clients, but always against the mock phone.
OS keychain integration is compiled but not exercised by CI on any platform;
real-keychain behavior is manual-test territory. macOS is covered by CI and
never manually exercised. The known limits of the hash chain itself (trailing
rows undetectable) are documented in the spec and apply unchanged from
auditmcp.

## How it works

An MCP client calls a tool → the shim relays it to the daemon over a local
socket → the daemon sends it over BLE inside a Noise-encrypted session → the
phone displays the request → the user taps approve → the phone executes the
HTTP request with its stored credentials → only the result travels back. The
PC holds pairing state, session state, and logs. The phone holds credentials
and approval authority. Neither side can do the other's job.

```
+--------------+  stdio JSON-RPC  +-----------+  local socket   +----------+
| MCP client   +----------------->+ mcp-shim  +---------------->+  daemon  |
| (Claude Code,|                  | (short-   |  framed CBOR    | pairing/ |
|  Cursor,...) |                  |  lived)   |                 | sessions |
+--------------+                  +-----------+                 | exec log |
                                                                +----+-----+
                                                                     | BLE
                                                                     | Noise_KK
                                                                     v
                                                                +----------+
                                                                |  phone   |
                                                                | creds,   |
                                                                | approval |
                                                                | UI, HTTP |
                                                                +----------+
```

The shim-and-daemon split exists for the same reason ssh-agent does: MCP
clients spawn a fresh subprocess per session, so anything held only by the shim
would be lost every launch. Pairing, sessions, and BLE state need continuity
across shim lifetimes.

One design choice worth stating up front because it looks redundant: the
application layer runs Noise_KK over the BLE link and does not trust BLE-layer
security at all. BLE pairing, LE Secure Connections, and GATT encryption are
not relied on for any security property, because the radio layer has a real
attack history — KNOB key-strength downgrade, the USENIX '20 pairing downgrades,
BLERP re-pairing — and Conveyance cannot fix or even detect weaknesses in stacks
it doesn't control. Every message that matters is authenticated-encrypted with
keys the BLE layer has no access to; enabling LE Secure Connections is defense
in depth, never load-bearing.

## How do I run it?

You need the [Rust toolchain](https://rustup.rs/) (stable; MSRV 1.90).

```bash
git clone https://github.com/Ahlyx/Conveyance
cd Conveyance
cargo build --release -p conveyance --features ble
```

The binary lands at `target/release/conveyance` (`conveyance.exe` on Windows).
Standalone `conveyance-daemon` and `conveyance-mcp-shim` binaries also build,
but the unified CLI is the intended interface.

First run needs an available OS keychain and a config file at the platform
config location (`%APPDATA%\conveyance\config.toml` on Windows, XDG equivalent
elsewhere). A missing keychain refuses startup rather than falling back, and a
missing config file is an error by design — nothing is auto-created behind
your back.

```bash
conveyance init identity      # generate the PC identity (explicit, never automatic)
conveyance pair               # render QR and wait for a phone
conveyance daemon             # run the daemon; blocks until Ctrl-C
conveyance status             # paired phones, session state, timer remaining
conveyance log verify         # walk the hash chain (exit 0/1/2)
conveyance log query --anomalous
```

To register the shim with Claude Code, add an entry to `.mcp.json` (Cursor and
other MCP clients take the equivalent shape):

```json
{
  "mcpServers": {
    "conveyance": {
      "command": "/absolute/path/to/conveyance",
      "args": ["mcp-shim"]
    }
  }
}
```

On Windows point `command` at `conveyance.exe`.

**Be clear about what this gets you today:** pairing requires scanning the QR
with the Conveyance phone app, which does not exist yet. Until phase 10 ships,
v1 is useful as a spec-and-substrate demonstration, not for day-to-day secret
gating. The complete flow can be exercised end-to-end through a real MCP client
against a scripted auto-approving phone — build with `--features mock-phone`
and run `conveyance daemon --mock-phone`; the flag refuses to start in builds
without the feature rather than pretending — but a real phone approving real
requests is future work, stated here rather than implied away.

## Threat model

[The spec's threat model section](CONVEYANCE_SPEC.md#threat-model) is
authoritative; this is the two-sentence version. The primary defense is that a
fully compromised PC — kernel malware, persistent implant, root — cannot
extract stored secrets, forge an approval, or cause an authenticated request to
execute without a physical tap, because secrets and approval authority live on
separate hardware and the approval-execute binding makes substitution detectable.
The primary non-defense is a fully compromised phone, which is game over for
the same reason it is for hardware wallets. The spec also enumerates what is
explicitly out of scope: traffic analysis, radio jamming, physical coercion,
legal compulsion, and nation-state adversaries with unpublished capabilities.

## Design notes

Security-critical modules — crypto, handshake state machine, approval binding,
hash chain, keystore — are written test-first with 100% branch coverage
required. Everything else earns whatever coverage judgment calls for.

Cryptographic choices are established primitives with strong deployment
precedents: Noise_KK and ChaCha20-Poly1305 (WireGuard's suite), X25519/Ed25519
(Signal's), Argon2id, BIP-39 recovery phrases (every Bitcoin hardware wallet),
SHA-256 hash chains. No novel cryptography; substituting any primitive requires
amending the spec first, not just the code.

Spec amendments are committed alongside the code that motivated them — the git
history shows this pattern repeatedly (consume-on-use approvals, HKDF salt
pinning, HANDSHAKING-abort semantics). When implementation revealed a design
gap, the design document changed with it, in the same commit, so the spec
cannot drift from reality silently.

Fail closed throughout: refuse-to-start beats degraded service, generic errors
where specific ones would leak which validation failed, minimums enforced
structurally rather than by convention.

Every deviation from plan is documented in-tree with reasoning — the canonical
JSON and HKDF implementations carry comments explaining why the off-the-shelf
crates were rejected, and those explanations are checked next to the code they
justify.

## Roadmap

[CONVEYANCE_PHASES.md](CONVEYANCE_PHASES.md) holds the phased breakdown with
exit criteria per phase. In short:

| Phases | Scope | Status |
|--------|-------|--------|
| 0–9 | PC side: crypto, storage, sessions, wire protocol, BLE, pairing, daemon, shim, CLI | Complete |
| 10.x | Android app (Kotlin): peripheral role, approval UI, credential store, recovery flows | Not started |
| 11 | Real-hardware end-to-end integration, cross-platform verification | Blocked on 10 |

After v1: signing adapters (SSH agent and git commit signing over the same
substrate — phone holds keys, phone signs on approval), then iOS, then
multi-device and multi-user/policy work. Later phases may be reordered or cut
based on real demand; the v1 substrate is what everything after depends on.
No dates are attached to any of this, deliberately.

## Contributing

[CONVEYANCE_SPEC.md](CONVEYANCE_SPEC.md) is the source of truth for design
decisions; when the spec conflicts with instinct, the spec wins. This is a
security project: changes to cryptographic primitives, wire formats, or state
machines require a spec amendment committed before (or alongside) the code that
implements them. Security-critical code lands test-first. Documentation should
explain why, acknowledge limitations precisely, and skip marketing prose —
matching the voice of [auditmcp](https://github.com/Ahlyx/auditmcp), the
companion project whose hash-chain format the logs intentionally share.

## License

MIT — see [LICENSE](LICENSE). Chosen for consistency with auditmcp and to
reduce friction for other projects building on the wire protocol.
