# Conveyance

A phone-approved capability broker for MCP tool calls. The user's phone holds
credentials and executes authenticated requests on behalf of an LLM agent; the
PC-side MCP server only relays the request and returns the result. Secrets
never reside on the machine the agent runs on, and every action requires a
physical tap on a separate device.

This document specifies v1 of Conveyance. It is prescriptive on cryptographic
choices, protocol formats, and state machines. It is architectural (not
prescriptive) on code organization, module boundaries, and error handling
patterns beyond the specific errors named below. An implementer should
treat the "MUST" and "MUST NOT" statements as non-negotiable, the named
primitives as fixed, and everything else as guidance.

---

## Why this exists

LLM agents increasingly need credentials to do useful work — API keys, OAuth
tokens, database passwords, signing keys. Every existing pattern for giving
those credentials to an agent has the same shape: the credential ends up in a
place the agent process can read. Environment variables in an MCP config
file, a secret manager the process authenticates to, a keychain the process
has permission to read — in all of these, a fully compromised host, or a
successful prompt injection that gets code execution, eventually reaches the
credential.

The category of tools that already exists (NoxKey, HashiCorp Vault Agent,
enterprise MCP gateways) improves on plaintext-in-config in one important
way: it gates access with an OS-local prompt (biometric, admin auth). This
raises the bar meaningfully. It does not change the fact that the
credential is retrievable from the same machine the agent runs on.

Conveyance takes the model that worked for cryptocurrency hardware wallets
and applies it to LLM agents: **the credential physically lives on a
different device**, and every use requires an explicit human gesture on
that device. A compromised host cannot extract what it never had. A prompt
injection that convinces the agent to exfiltrate secrets exfiltrates
nothing, because the agent process never saw them.

---

## Threat model

**Primary concern:** a prompt-injected, malicious, or otherwise compromised
agent process on the PC attempts to exfiltrate credentials, forge
authorizations, or take unintended destructive actions using the tool
surface Conveyance exposes.

**Secondary concern:** general accountability — a tamper-evident record of
what was approved, when, and what was executed as a result, on both sides
of the trust boundary.

**Explicitly out of scope:**

- A fully compromised phone. If the attacker controls the phone's OS,
  Conveyance offers no defense; this is the same limit hardware wallets
  operate under.
- Physical coercion of the user to approve requests.
- Legal compulsion. Biometric unlock has been ruled non-testimonial by
  several US courts; passphrase unlock generally has not. Conveyance MUST
  let the user choose which they use, but cannot resolve the underlying
  legal question.
- Traffic analysis. An attacker observing BLE traffic can learn that
  approvals are happening and their approximate size, even without
  decrypting them. Constant-rate padding is not specified.
- Radio-layer denial of service (jamming). Graceful failure only.
- Nation-state-level adversaries with active BLE downgrade capability and
  supply-chain reach. Conveyance defends against KNOB, BLERP, and pairing
  downgrade attacks by treating BLE as untrusted transport, but does not
  claim protection against attackers with novel unpublished capabilities.
- Multi-user or multi-tenant scenarios (v1 is strictly 1:1).

**Design property to preserve:** even given a fully compromised PC — kernel
malware, persistent implant, root code execution — the attacker cannot
extract stored secrets, cannot forge an approval, and cannot cause an
authenticated request to be executed without a physical tap on the paired
phone.

---

## Architecture overview

Conveyance is three components:

**The daemon** (`conveyance daemon`) runs persistently on the PC. It holds
pairing state, session state, the long-term PC identity keypair, and all
BLE connectivity to the phone. It exposes a local Unix domain socket (or
named pipe on Windows) for the MCP shim to connect to. It writes the
PC-side execution log.

**The MCP shim** (`conveyance mcp-shim`) is a short-lived process spawned
by MCP clients (Claude Code, Cursor, Claude Desktop). It speaks JSON-RPC
over stdio to the client and talks to the daemon over the local socket for
everything else. It carries no long-term state. Multiple shims connected
to one daemon are supported and share session state.

**The Android app** (`Conveyance` on the phone) runs when the user opens
it or when a notification wakes it. It advertises as a BLE peripheral,
holds the long-term phone identity keypair and stored credentials,
displays approval prompts, executes authenticated requests, and writes
the phone-side approval log.

```
+------------------+                 +----------------------+
|  MCP client      |  stdio JSON-RPC |  conveyance mcp-shim |
|  (Claude Code,   +---------------->+  (short-lived)       |
|   Cursor, etc.)  |                 |                      |
+------------------+                 +----+-----------------+
                                          | local socket
                                          | (unix / named pipe)
                                          v
                                     +----+-----------------+
                                     |  conveyance daemon   |
                                     |  (long-running)      |
                                     |                      |
                                     |  - pairing state     |
                                     |  - session state     |
                                     |  - PC identity key   |
                                     |  - execution log     |
                                     +----+-----------------+
                                          | BLE
                                          | (Noise_KK over
                                          |  GATT)
                                          v
                                     +----+-----------------+
                                     |  Conveyance (Android)|
                                     |                      |
                                     |  - phone identity key|
                                     |  - stored creds      |
                                     |  - approval UI       |
                                     |  - request executor  |
                                     |  - approval log      |
                                     +----------------------+
```

The daemon-and-shim split exists for the same reason ssh-agent and
gpg-agent do it: MCP clients spawn a fresh subprocess per session, so
anything held by the shim would be lost every launch. Pairing, sessions,
and BLE state need continuity across shim lifetimes.

---

## Cryptographic primitives

The following primitives are fixed. An implementer MUST NOT substitute
alternatives without a corresponding revision to this document. Rationale
is given so future revisions can be reasoned about.

| Purpose | Primitive | Reason |
|---------|-----------|--------|
| Session handshake | Noise Protocol Framework, pattern `Noise_KK_25519_ChaChaPoly_BLAKE2s` | Mutual authentication with both static keys known after pairing. Same DH/AEAD/hash suite as WireGuard, extensively deployed. |
| Session AEAD (post-handshake) | ChaCha20-Poly1305 (via Noise transport messages) | ARM-friendly without hardware AES; matches Noise cipher choice. |
| Long-term identity signatures | Ed25519 | Standard, fast, no parameter choices to get wrong. |
| Ephemeral key exchange in pairing | X25519 (as part of Noise) | Same curve as identity DH. |
| Stored-blob AEAD (at rest) | ChaCha20-Poly1305 | Consistency with wire AEAD. |
| Passphrase KDF | Argon2id, m=65536 (64 MiB), t=3, p=1; output length 32 bytes (feeds a ChaCha20-Poly1305 DEK); salt caller-supplied, 16 bytes | Memory-hard, resistant to GPU/ASIC attack. Tune upward on target hardware if a full derivation completes in under 500 ms. |
| Recovery-phrase derivation | BIP-39 wordlist (English), 256-bit entropy = 24 words → HKDF-BLAKE2s → seed → Ed25519 + X25519 keypairs (deterministic) | Standard, well-understood UX. Users have seen it in every hardware wallet. |
| HKDF-BLAKE2s parameters | Salt: omitted — treated as HashLen zero bytes per RFC 5869 §2.2. Info strings as listed in Recovery. L=32. | Cross-platform determinism requires both implementations to treat salt omission identically. |
| Hash chain (approval and execution logs) | SHA-256, `hash = SHA256(prev_hash \|\| canonical_json(entry))` | Matches auditmcp for interoperability of the diff tool. |
| Canonical JSON | RFC 8785 (JCS), with the value domain restricted to integers, strings, booleans, null, arrays, and objects. Float values in canonicalization input MUST be rejected with a clear error. | Deterministic serialization for hashing. The restriction exists because ECMAScript number formatting is a known cross-implementation divergence trap, and Conveyance's hashed content has no legitimate use for fractional numbers. Both sides MUST also sort object keys by UTF-16 code units (per RFC 8785 §3.2.3) rather than trusting any map's native iteration order. |

**BLE-layer security is treated as untrusted.** The daemon and app MUST NOT
rely on BLE pairing, LE Secure Connections, GATT encryption, or the
Whitelist for any security property. LE Secure Connections MAY be enabled
as defense in depth but MUST NOT be required for correctness. This is the
core mitigation against KNOB (arXiv 1904.03809), the BLE downgrade
attacks in USENIX Security '20, and the BLERP re-pairing family
(NDSS 2026). Every message that matters is authenticated-encrypted at
the application layer with keys BLE has no access to.

**What Conveyance MUST NOT do:**

- MUST NOT invent a new cryptographic protocol.
- MUST NOT AES-encrypt payloads directly ("just encrypt it") — all
  application-layer encryption goes through the Noise transport.
- MUST NOT sign a hash without recording, and displaying to the user, the
  human-readable preimage of what is being signed.
- MUST NOT store plaintext identity keys, plaintext credentials, or the
  recovery phrase.
- MUST NOT persist Noise session keys across sessions or across
  reconnections.

---

## Pairing ceremony

Pairing establishes long-term mutual authentication between one PC and one
phone. It happens once per PC-phone pair and requires a channel BLE cannot
tamper with. Conveyance uses a QR code shown on the PC and scanned by the
phone.

### QR contents

The QR encodes a CBOR object with the following fields:

```
{
  "v": 1,                              // protocol version
  "pc_id_pub": <32 bytes>,             // PC's long-term Ed25519 identity pubkey
  "pc_dh_pub": <32 bytes>,             // PC's long-term X25519 static pubkey
  "nonce": <32 bytes>,                 // random, single-use pairing nonce
  "expires": <unix seconds>,           // 60 seconds after QR display
  "pc_name": <string, ≤ 64 UTF-8>,     // hostname for phone-side display
  "ble_service_uuid": <16 bytes>       // custom service UUID daemon will scan for
}
```

Encoded as CBOR then base64url-encoded, then rendered as a QR code by the
daemon (using the `qrcode` crate or equivalent). QR error correction
level: H (30%), because the PC display may be at an angle.

### Sequence

1. User runs `conveyance pair` on the PC. Daemon generates a fresh
   `nonce`, computes `expires`, renders the QR, holds it on screen until
   dismissed or `expires` is reached.

2. User opens Conveyance on the phone, taps "Pair with PC", scans the QR.

3. Phone-side app validates: `v == 1`, `expires` is in the future,
   `pc_id_pub` and `pc_dh_pub` are valid curve points. Rejects otherwise.

4. Phone generates its own long-term Ed25519 identity keypair and X25519
   static keypair, if not already present.

5. Phone begins BLE advertising with `ble_service_uuid`.

6. Daemon, having generated the QR, is scanning for `ble_service_uuid`.
   Connects when advertisement seen.

7. Phone sends `PairingConfirm` message on the `phone_to_pc_tx` GATT
   characteristic:

   ```
   PairingConfirm {
     phone_id_pub:   <32 bytes>,      // Ed25519
     phone_dh_pub:   <32 bytes>,      // X25519
     signature:      <64 bytes>       // Ed25519 sig by phone_id_priv over
                                      //   ("conveyance-pair-v1"
                                      //    || pc_id_pub
                                      //    || nonce
                                      //    || phone_id_pub
                                      //    || phone_dh_pub)
   }
   ```

8. Daemon verifies the signature. If valid: daemon signs its own
   `PairingAck` symmetrically (Ed25519 over the same fields, its own key)
   and writes it to `pc_to_phone_tx`.

9. Phone verifies daemon's signature.

10. Both sides store the other's `id_pub` and `dh_pub` in their pairings
    database with the timestamp and (for daemon) `pc_name`.

11. Phone displays the 24-word recovery phrase for the user to write down.
    The phrase MUST be shown only once and MUST NOT be logged, screenshotted
    (via `FLAG_SECURE`), or transmitted anywhere. Phone advances only after
    the user confirms in-app that they have written it down.

12. Pairing complete. Both sides show a success state. QR is dismissed.

### Pairing state machine (PC side)

```
     UNPAIRED
        |
        | conveyance pair
        v
   QR_DISPLAYED  ---- (60s expires) ----> UNPAIRED
        |
        | BLE advertisement seen
        v
    CONNECTING   ---- (BLE failure) -----> QR_DISPLAYED
        |
        | GATT connected
        v
  AWAITING_CONFIRM  ---- (10s no msg) ---> UNPAIRED
        |
        | valid PairingConfirm received
        v
     ACK_SENT   ---- (write fails) -----> UNPAIRED
        |
        v
      PAIRED
```

Pairing MUST complete within 5 minutes of QR display or the whole
ceremony is aborted and restarted. Nonce is single-use even on failure.

### Rejection conditions (both sides)

- Signature invalid → abort, log locally, return generic pairing-failed
  error to UI. MUST NOT indicate which validation failed.
- Nonce already used → abort. Daemon retains a bloom filter of recent
  nonces (48-hour retention) to catch replay.
- QR expired → abort. Phone shows "code expired, ask PC to generate a new
  one."
- Protocol version mismatch → abort with a specific "incompatible
  versions" message; version numbers may be displayed to the user.

---

## Session lifecycle

A session is a Noise_KK transport channel between the paired phone and PC,
plus authorization state (idle timer, hard-cap timer, categorical
policy). Sessions are ephemeral; session keys MUST NOT be persisted.

### States

```
NO_SESSION  ------ user starts session (phone-side) ------> HANDSHAKING
                                                                |
                                                                | Noise KK
                                                                | complete
                                                                v
                                                             ACTIVE
                                                                |
                                        +---- idle > threshold -+
                                        |                       |
                                        v                       | hard cap
                                  IDLE_WARNING                  | reached
                                        |                       |
                          user activity |                       v
                                        +----> ACTIVE       ENDED
                                        |                       ^
                                idle timeout                    |
                                        |     explicit end,     |
                                        v     kill switch,      |
                                      ENDED <---BLE disconnect---+
```

Aborting out of HANDSHAKING -- handshake failure, peer disappearance,
or user cancellation before completion -- returns to NO_SESSION, not
ENDED. A session that never completed its handshake never existed;
ENDED implies a lifecycle that reached at least ACTIVE.

### Timers

| Timer | Default | Minimum | Maximum | Behavior on expiry |
|-------|---------|---------|---------|--------------------|
| Idle timeout | 30 min | 5 min | 4 hours | Transition to ENDED, notify user |
| Hard cap | 4 hours | 30 min | 24 hours | Transition to ENDED regardless of activity |
| Idle warning | Idle timeout - 2 min | n/a | n/a | Notification on phone; user may extend |

The hard cap MUST be enforced regardless of activity. This defeats
compromised-agent keep-alive attacks. Both timers are configurable in
`config.toml`; the minimums MUST be enforced by the daemon and MUST NOT
be user-bypassable through configuration.

### Session start

1. User opens phone app, taps "Start session with `<pc_name>`".
2. Phone authenticates the user according to the configured auth tier
   (passphrase or biometric — see below).
3. Phone begins BLE advertising.
4. Daemon (scanning) connects.
5. Both sides perform the Noise_KK handshake:
   - Initiator: phone. Responder: daemon.
   - Each side uses its own long-term X25519 static key and the peer's
     long-term X25519 static key learned during pairing.
   - Ephemeral keypairs generated fresh per session.
6. On successful handshake, both sides transition to ACTIVE.
7. Idle and hard-cap timers start.

Session start MUST fail closed if:

- No paired phone is available (return `PhoneNotPaired`).
- Phone is not reachable via BLE within a 30-second timeout
  (`PhoneUnreachable`).
- The Noise handshake fails for any reason (`HandshakeFailed`, generic —
  MUST NOT leak which validation failed).
- The peer static key does not match the paired-and-stored value
  (`PeerIdentityMismatch` — this is either an attack or a re-paired
  phone that hasn't re-paired with this PC).

### Cold-start behavior

When the daemon starts and no session is active, its state is
`NO_SESSION`. Any tool call arriving at the MCP shim while the daemon is
in `NO_SESSION` MUST be rejected with a structured error the LLM can
parse:

```
{
  "code": "conveyance/no_session",
  "message": "No active Conveyance session. User must start one on the paired phone.",
  "retryable": true,
  "retry_after_seconds": null
}
```

The shim MUST NOT attempt to auto-start sessions. The shim MUST NOT block
waiting for a session to appear. Enforcement is architectural: no code
path in the shim or the daemon produces a tool result without a valid
Noise transport message from an ACTIVE session.

### Session end

Sessions end via:

- Idle timeout expired
- Hard-cap expired
- BLE disconnection (both sides tear down immediately; MUST NOT auto-reconnect)
- User taps "End session" on the phone
- User invokes `conveyance session end` on the PC
- Kill switch (see below)

On end, the daemon MUST zeroize Noise session keys in memory. Both sides
log the session-end event to their respective databases with the reason.

### Kill switch

The phone app MUST provide a visible "End all sessions and disconnect"
button on its home screen. Tapping it ends the active session, drops any
pending approvals as denied, and (in v1) closes the BLE connection.
Users should feel safe using session mode aggressively; the kill switch
is what makes that safe.

---

## Wire protocol

### BLE topology

- Phone: GATT peripheral. Advertises the Conveyance service UUID
  (fixed, TBD, generated once for the project and pinned in the spec
  before v1 release).
- PC daemon: GATT central. Scans for the service UUID when a session is
  desired (i.e. after user has initiated on phone).
- One primary service, two characteristics, with UUIDs pinned below.
  These are permanent: once v1 ships, changing any of them breaks
  pairings in the wild.

  | Role | UUID |
  |------|------|
  | Conveyance service (advertised) | `709031fe-abea-437f-801e-dc6872723b1f` |
  | `pc_to_phone_tx` (write, no response) | `56d373b8-1dcf-4107-894b-b4888ff0db3f` |
  | `phone_to_pc_tx` (notify) | `b4b10ea8-450c-47bd-93d9-065bb67e1bc9` |

  All three are random version-4 UUIDs generated once at project start;
  nothing about them is derived from anything meaningful.

MTU is negotiated at connection time. The application-layer framing
handles any MTU ≥ 23 (the BLE minimum).

### Framing

Each application-layer message is length-prefixed and may be split across
multiple GATT operations if it exceeds the negotiated MTU minus overhead:

```
struct Frame {
  uint16 length;        // big-endian, length of `payload`
  uint16 seq;           // per-connection monotonic
  uint8  flags;         // bit 0: START, bit 1: END, bit 2: ACK
  uint8  reserved;      // zero
  byte   payload[length];
}
```

- A message fitting in one MTU: `START | END`, one frame.
- A larger message: `START` frame, zero or more middle frames, `END`
  frame. Receiver reassembles by `seq` and joins payloads.
- ACK frames carry no payload and confirm receipt of a message ID for
  request/response correlation at the transport layer.

Reassembly buffer per side MUST be capped (default 128 KiB); a single
message exceeding the cap causes the session to terminate with
`MessageTooLarge`.

### Message types (post-handshake)

Every message below is a Noise transport message. The plaintext inside is
CBOR-encoded. All messages carry a `req_id` (128-bit random) for
correlation.

```
ApprovalRequest {
  req_id:       <16 bytes>,
  op_type:      "authenticated_request" | "list_services" | "session_end",
  service:      <string>,           // e.g. "aws", "github"
  method:       <string>,           // e.g. "GET", "POST"
  endpoint:     <string>,           // e.g. "/v1/deploy"
  params:       <cbor value>,       // request parameters
  requested_by: <string>,           // MCP client hint if available
  timestamp:    <unix seconds>
}

ApprovalResponse {
  req_id:       <16 bytes>,
  decision:     "approved" | "denied" | "expired",
  reason:       <string, optional>, // e.g. "user_tap", "auto_deny_high_risk"
  signature:    <64 bytes>          // Ed25519 signature by phone_id_priv
                                     //   over ("conveyance-approve-v1"
                                     //         || canonical_json(this msg minus sig))
}

ExecuteRequest {
  req_id:       <16 bytes>,         // matches an approved ApprovalRequest
  op_type:      same as approved
  ...           same fields
}

ExecuteResponse {
  req_id:       <16 bytes>,
  status:       "ok" | "error" | "denied",
  http_status:  <uint16, optional>, // if applicable
  body:         <cbor value>,       // response body or error object
  executed_at:  <unix seconds>,
  signature:    <64 bytes>          // Ed25519 by phone_id_priv over
                                     //   ("conveyance-execute-v1"
                                     //         || canonical_json(this msg minus sig))
}

ListServicesRequest { req_id: <16 bytes> }
ListServicesResponse {
  req_id: <16 bytes>,
  services: [<string>, ...]         // no secret material, just names
}

Ping { req_id: <16 bytes>, timestamp: <unix seconds> }
Pong { req_id: <16 bytes>, timestamp: <unix seconds> }

SessionEnd { req_id: <16 bytes>, reason: <string> }
```

The Ed25519 signature over approval and execute responses is redundant
with the Noise authentication for confidentiality-and-integrity in
transit, but it makes each response a portable, verifiable artifact that
survives outside the session -- critical for the log-diff use case, and
for repudiation defense.

PairingConfirm and PairingAck messages travel through the same
WireMessage envelope as post-handshake messages, tagged
`pairing_confirm` and `pairing_ack` respectively. They differ from other
messages in three ways: (1) they are exchanged before any Noise session
exists, so they travel as plaintext CBOR over the framing layer directly
(not through a Noise transport); (2) their integrity depends entirely on
the embedded Ed25519 signatures rather than session authentication; (3)
their signature payload is raw byte concatenation of
"conveyance-pair-v1" and the field sequence specified in the pairing
ceremony section, not canonical JSON.

Signature payload construction rules: optional fields that are absent
MUST be omitted from the canonical JSON entirely, not rendered as JSON
null. This applies to `reason` in ApprovalResponse, `http_status` in
ExecuteResponse, and any future optional fields. Both Rust and Android
implementations MUST follow this rule identically; a null on one side
and an omission on the other produces non-verifying signatures.

### Approval-execute binding

An `ExecuteRequest` MUST reference a `req_id` that the phone has
previously approved and MUST match the previously approved fields byte
for byte after canonical JSON serialization. Any mismatch causes the
phone to deny execution with `ApprovalMismatch`. This defeats the
TOCTOU attack where a compromised daemon shows the phone one payload,
gets approval, then substitutes different bytes for execution.

The phone MUST retain approved-not-yet-executed `req_id`s for at most 5
minutes; older ones expire.

Approved `req_id`s are consumed on first successful validation. A second
ExecuteRequest referencing an already-consumed req_id MUST be rejected
with `approval_mismatch` and logged as a replay attempt. Approvals do
not survive their first execution; retries require re-approval.

---

## Authentication tiers

Three tiers. Which tier applies to which action is a runtime policy
decision configured in `config.toml`.

**Tier 1 — Session unlock.** Required once per session start. Unlocks the
phone's identity key material and stored credentials at rest. Method:
user's choice at first-run setup between:

- **Passphrase.** User-chosen. Argon2id-derived key encrypts the identity
  keystore. This is the option a user concerned about legal compulsion
  should pick.
- **Biometric.** Android BiometricPrompt, backed by Android Keystore with
  `setUserAuthenticationRequired(true)` and
  `setInvalidatedByBiometricEnrollment(true)`. Faster but not
  legally equivalent to a passphrase in most jurisdictions.

Users MAY switch methods later, but doing so requires re-authentication
with the current method.

**Tier 2 — Per-operation tap.** Default within an active session. A
single tap in the approval prompt is sufficient. No re-auth. Fast enough
that per-operation approval remains usable.

**Tier 3 — High-risk re-auth.** Certain operations always require a
fresh biometric or passphrase regardless of session state. Determined by
policy rules in `config.toml`, evaluated on the phone (not the daemon —
the daemon MUST NOT be trusted to classify risk correctly for its own
requests). Ships with these defaults:

- `method == "DELETE"` → Tier 3
- Any request to a destination not seen in the last 30 approvals
  (`novel_destination`) → Tier 3
- Explicit user-configured patterns (e.g. `service == "aws" && matches(endpoint, "*prod*")`) → Tier 3

Tier 3 policy MUST NOT be overridable by the daemon or the request
itself. The phone loads its own copy of the policy at session start and
uses that copy for the session's duration.

---

## Recovery

At pairing, the phone generates 256 bits of entropy from a CSPRNG, encodes
as a 24-word BIP-39 phrase, and displays it once to the user. The phrase
deterministically derives the phone's long-term Ed25519 and X25519
keypairs via HKDF-BLAKE2s with separate info strings:

```
seed              = BIP39-to-seed(phrase, passphrase="")
identity_ed25519  = HKDF-BLAKE2s(seed, info="conveyance-v1-identity-ed25519", L=32)
identity_x25519   = HKDF-BLAKE2s(seed, info="conveyance-v1-identity-x25519", L=32)
```

HKDF salt is omitted in all three uses above and therefore zero-filled
per RFC 5869 §2.2. This is deliberate and load-bearing: a second
implementation that substitutes an empty string, a null salt of different
length, or any domain-separated constant produces different keys with no
error anywhere.

Recovery on a new device: user installs Conveyance, chooses "Restore from
recovery phrase", enters 24 words. App validates the checksum (BIP-39
built-in), derives the identity keys, restores.

**Recovery restores identity, not pairings or credentials.**

- Identity keys are restored deterministically from the phrase.
- Stored credentials on the phone are NOT recoverable from the phrase.
  They live in the phone's encrypted credential store, which is bound to
  the specific device. The user must re-add credentials on the new
  device. This is deliberate: a bearer phrase that unlocks all your
  cloud credentials is a worse security property than "you have to
  re-add them."
- The PC still requires re-pairing with the restored phone. The
  restored identity key matches the old one, but the PC has no way to
  distinguish "user restored on a new phone" from "attacker stole the
  phrase," so it treats the new device as unknown. Re-pairing forces the
  QR ceremony, which requires physical access to the PC.

This layered recovery model — phrase restores identity, credentials
require re-entry, PC requires re-pairing — makes phrase compromise
survivable (attacker cannot immediately act) at the cost of a manual
recovery UX.

---

## Revocation

v1 revocation is manual and requires physical access to the PC.

```
conveyance unpair <phone-id>
```

Removes the phone from the paired database. The phone continues to
believe it is paired but cannot establish sessions.

`<phone-id>`: first 16 lowercase hex characters of SHA-256(phone_id_pub).
Shown by `conveyance status`; stable across DB rebuilds since it is
derived from the pubkey.

Revocation triggers:

- User loses phone → run `unpair` on PC → pair replacement phone.
- User suspects phone compromise → same.
- Recovery from lost recovery phrase → same, plus generating a new phrase
  by re-installing the app on the phone.

**No remote revocation is supported in v1.** Adding "revoke from the
phone" would require a second trusted device or a pre-shared revocation
token, both of which introduce their own attack surface. Deferred to v2
if user demand justifies it.

---

## Storage layout

### PC side

Config directory: platform-appropriate.

- Linux: `$XDG_CONFIG_HOME/conveyance/` (default `~/.config/conveyance/`)
- macOS: `~/Library/Application Support/conveyance/`
- Windows: `%APPDATA%\conveyance\`

Data directory (logs, databases): platform-appropriate.

- Linux: `$XDG_DATA_HOME/conveyance/` (default `~/.local/share/conveyance/`)
- macOS: same as config
- Windows: `%LOCALAPPDATA%\conveyance\`

Files:

- `config.toml` — user-editable configuration.
- `identity.enc` — long-term PC identity keypair, encrypted at rest using
  a key derived from the OS keychain (Windows DPAPI, macOS Keychain,
  Linux Secret Service via `libsecret`). If the OS keychain is
  unavailable, MUST refuse to start and print instructions — MUST NOT
  fall back to a passphrase without explicit config.
- `pairings.db` — SQLite. Paired phone identities and metadata.
- `executions.db` — SQLite. Hash-chained execution log (see Logging).
- `sessions.log` — plaintext text log of session starts/ends for
  debugging; contains no secret material.

### Phone side

All storage in the app's private internal storage. External storage MUST
NOT be used.

- `identity.enc` — long-term Ed25519 + X25519 keypairs, encrypted at
  rest. DEK stored in Android Keystore with user-authentication-required.
- `pairings.db` — SQLite. Paired PC identities, `pc_name`, first-paired
  timestamp, last-session timestamp.
- `credentials.enc` — SQLite. Stored service credentials. Each row's
  secret value is individually encrypted with a service-specific DEK
  derived from the Keystore-backed master key. Never decrypted in bulk.
- `approvals.db` — SQLite. Hash-chained approval log.
- `policy.toml` — Tier 3 rules. Loaded fresh at session start.

Recovery phrase is NEVER stored. Ever. Not even encrypted. The user is
the only backup.

---

## Logging

Both sides keep a hash-chained SQLite log of their respective concerns.
The two logs are independent — they do not share a schema, they cannot
tamper with each other — and can be reconciled after the fact by a diff
tool.

### Split authority

- **Phone log (`approvals.db`) is authoritative for approvals.**
  Contains every approval request received, every approval granted or
  denied, and the reason. Signed with `phone_id_priv`.
- **PC log (`executions.db`) is authoritative for executions.** Contains
  every execute request sent, every response received, whether the
  approval signature verified, and the HTTP status if applicable. Signed
  with `pc_id_priv`.

For any single operation there should be one approval row on the phone
and one execution row on the PC referencing the same `req_id`. Mismatches
are the interesting signal:

- Approval without matching execution → PC failed to execute (network,
  crash) OR PC never received the approval OR PC is silently discarding.
- Execution without matching approval → **alarm**. This should be
  impossible under correct operation; its presence indicates a bug or
  attack.

### Schema (both sides, aligned where possible)

```
CREATE TABLE entries (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  req_id        BLOB NOT NULL,           -- 16 bytes
  event_type    TEXT NOT NULL,           -- "approval_request", "approval_granted",
                                          -- "approval_denied", "execute_sent",
                                          -- "execute_result", "session_start", etc.
  payload_json  TEXT NOT NULL,           -- canonical JSON of event details
  timestamp     INTEGER NOT NULL,        -- unix seconds
  prev_hash     BLOB NOT NULL,           -- 32 bytes, SHA-256
  hash          BLOB NOT NULL UNIQUE     -- 32 bytes, SHA-256
);
CREATE INDEX idx_req_id ON entries(req_id);
CREATE INDEX idx_timestamp ON entries(timestamp);
```

Hash chaining is identical to auditmcp:
`hash = SHA256(prev_hash || canonical_json(entries_row_without_hash))`.
Genesis `prev_hash` is 32 zero bytes.

The `entries_row_without_hash` clause is scoped to event content only:
`{req_id, event_type, payload_json, timestamp}`. The `id` column is
DB-assigned metadata and MUST NOT be part of the hashed content. The
`prev_hash` column appears in the SHA-256 formula as the byte prefix
(see the formula), never inside the JSON. This scope matters: two
independently generated logs of the same events must produce the same
chain, which is what makes the diff tool's row-for-row comparison
possible.

### Diff tool

`conveyance log diff <phone-export.jsonl>` takes an exported phone log
(via a phone-side export flow, e.g. QR-chunked or file-share) and pairs
approvals with executions from the local `executions.db`. Reports:

- Approvals with matching executions (OK)
- Approvals without executions (missing, may be benign)
- Executions without approvals (SECURITY EVENT)
- Signature verification failures on either side
- Timestamp anomalies (execution before approval)

The diff tool MUST NOT modify either log. It MUST NOT accept unsigned
phone entries.

### Same limitations as auditmcp

The hash chain proves no interior row has been altered or removed. It
does NOT prove that no trailing rows have been truncated. Document this
under Known limitations, same wording style as auditmcp's readme.

---

## PC-side components

### CLI surface

```
conveyance daemon
    Run the daemon. Blocks. Reads config.toml. Exits nonzero on
    unrecoverable errors (keychain unavailable, DB unopenable, etc.).

conveyance mcp-shim
    Run the MCP server shim. Speaks JSON-RPC over stdio. Spawned by
    MCP clients. Connects to daemon over local socket. Exits when
    stdin closes.

conveyance pair
    Start pairing. Renders QR. Blocks until pairing completes, times
    out, or user cancels (Ctrl-C).

conveyance unpair <phone-id>
    Remove a paired phone by id (shown in `conveyance status`).
    Requires --yes for non-interactive use.

conveyance status
    Print daemon state: running/not-running, paired phones, active
    session (if any), timers remaining.

conveyance session end
    End the active session, if any.

conveyance log query [--since 2h] [--tool <name>] [--status <s>]
                      [--verbose] [--anomalous]
    Query the execution log. Matches auditmcp's query CLI shape.

conveyance log verify
    Walk the hash chain. Exit codes:
      0 - chain intact
      1 - chain verification failed (row altered/removed/reordered)
      2 - chain intact but derived indexes stale (repairable)

conveyance log export --format jsonl --output <file>
    Export the execution log for offline analysis or for diffing
    against a phone export.

conveyance log diff <phone-export.jsonl>
    Reconcile phone approvals with PC executions. See Logging.
```

### Config format

```toml
[daemon]
socket_path = "~/.local/share/conveyance/daemon.sock"  # linux/mac
# on windows: named_pipe = "\\\\.\\pipe\\conveyance-daemon"

[session]
idle_timeout_seconds  = 1800     # 30 min, min 300, max 14400
hard_cap_seconds      = 14400    # 4 hours, min 1800, max 86400
warn_before_seconds   = 120      # notify user 2 min before idle timeout

[ble]
# service UUID is baked in, not configurable

[logging]
executions_db = "~/.local/share/conveyance/executions.db"

[[high_risk]]
# rules layered on top of the phone's built-in defaults
match_service    = "aws"
match_endpoint   = "*prod*"
required_tier    = 3

[[high_risk]]
match_method     = "DELETE"
required_tier    = 3
```

### MCP tool surface (v1)

The shim exposes exactly these tools to MCP clients:

```
authenticated_request(service: str,
                       method: str,
                       endpoint: str,
                       params: object) -> object
    Request that the phone execute an HTTP request against `service`
    using stored credentials. Blocks until approved and executed, or
    denied, or the session ends. Returns the response body on success,
    or a structured error.

list_services() -> [str]
    Return the list of services for which the phone has stored
    credentials. Does not require session approval — only requires an
    active session.

check_session() -> object
    Return session state: active/inactive, seconds remaining on idle
    and hard-cap timers, paired phone id. Does not require session
    approval.

end_session() -> object
    End the active session. Idempotent; no-op if no session.
```

Nothing else. No key-material tools. No "list secrets." No "get
credential." The shim MUST NOT expose any tool that returns a secret
value to the caller.

---

## Phone-side components

Android app, native Kotlin. Minimum SDK 30 (Android 11). Target SDK
current-latest at build time.

### Required Android APIs

- BluetoothLE (`android.bluetooth.le`) for GATT server and advertising.
- Android Keystore (`android.security.keystore`) for identity key and
  credential DEK protection.
- BiometricPrompt (`androidx.biometric`) for biometric unlock.
- Room + SQLCipher (or SQLite with `androidx.security.crypto`) for
  encrypted databases.
- Foreground service for maintaining BLE advertising during an active
  session, with a persistent notification the user can tap to end.

### Screens

Minimal set for v1; UX polish deferred.

- **First run.** Welcome, generate identity, show recovery phrase (with
  `FLAG_SECURE`), require user confirmation of write-down.
- **Home.** Kill switch (prominent), list of paired PCs with last-session
  time, "Pair with PC" button, "Restore from recovery phrase" (only
  shown if no identity present).
- **Pair with PC.** Camera QR scanner.
- **Session active.** Live status: session started time, idle-timer
  countdown, hard-cap countdown, "End session now" button, list of
  recent approvals.
- **Approval prompt.** Sheet or dialog with: PC name, service, method,
  endpoint, params (structured), approve/deny buttons. Tier 3 prompts
  additionally require biometric or passphrase.
- **Credentials.** Add / list / remove stored credentials per service.
- **Settings.** Auth method choice, session timers (subject to daemon
  minimums), Tier 3 policy editor.

Recovery phrase is never accessible again from the app after first-run
confirmation. If the user needs it, they must have written it down.

### Foreground service and battery

Advertising and holding a BLE connection is battery-costly. The app MUST:

- Only advertise when a session is being started or is active.
- Present a persistent notification while advertising.
- Stop advertising and disconnect immediately on session end.
- Never advertise in the background outside of active-session state.

---

## Error model

All errors returned to the MCP client are structured JSON with these fields:

```
{
  "code":       <string>,      // machine-parseable, namespaced
  "message":    <string>,      // human-readable
  "retryable":  <bool>,
  "retry_after_seconds": <int|null>,
  "details":    <object|null>
}
```

Named error codes:

| Code | Meaning | Retryable |
|------|---------|-----------|
| `conveyance/no_session` | No active session | Yes, after user action |
| `conveyance/phone_unreachable` | Session not established within timeout | Yes |
| `conveyance/approval_denied` | User denied the request | No |
| `conveyance/approval_timeout` | User did not respond within 60 s | Yes |
| `conveyance/session_ended` | Session ended mid-request | Yes, after re-start |
| `conveyance/handshake_failed` | Noise handshake failed | No (fatal for pairing) |
| `conveyance/peer_identity_mismatch` | Phone key does not match paired identity | No |
| `conveyance/approval_mismatch` | Execute payload differs from approved payload | No — this is an attack signal |
| `conveyance/service_unknown` | No credentials for the requested service | No |
| `conveyance/message_too_large` | Reassembly buffer exceeded | No |
| `conveyance/keychain_unavailable` | OS keychain cannot be reached | No |

The error message MUST NOT leak information about which validation failed
for security-relevant errors (handshake, peer identity). Users learn the
category, not the specifics.

---

## Testing requirements

Before v1 is considered releasable, the following MUST be covered.

**Unit tests.**

- Noise KK handshake with matching identities: succeeds.
- Noise KK handshake with mismatched identities: fails (both directions).
- Ed25519 signature verification on approval messages: correct signatures
  verify, tampered fields fail.
- Canonical JSON serialization: same input produces identical bytes across
  platforms.
- BIP-39 phrase → seed → identity keys: deterministic, matches known
  BIP-39 test vectors.
- Argon2id passphrase derivation: correct parameters, minimum timing on
  target hardware.
- Hash chain: verify, verify with tampered row, verify with removed
  interior row.
- Session timer expiry (both idle and hard cap): fires at the right time,
  hard cap wins over activity.
- Approval-execute binding: matching payload approved, differing payload
  rejected.

**Integration tests.**

- Full pairing ceremony with a mock phone: PC and phone both reach
  PAIRED, both databases contain the peer's identity.
- Pairing with expired QR: fails cleanly.
- Pairing with tampered PairingConfirm: fails, nothing persisted.
- Session start after pairing: reaches ACTIVE.
- Session start with a phone whose identity does not match:
  `peer_identity_mismatch`.
- Full request flow: approve → execute → response, both logs contain
  matching rows, signatures verify.
- Denial flow: user denies, PC receives `approval_denied`, no execution.
- Idle timeout during a session: session ends, next request gets
  `no_session`.
- Hard cap during a session: session ends even if requests are flowing.
- BLE disconnect mid-session: both sides tear down.
- Malformed frame from BLE: session ends with `message_too_large` or
  parser error, does not crash.
- Approval-execute mismatch: `approval_mismatch` returned, execution
  does not happen, log entry recorded on both sides.

**End-to-end tests.**

- Full flow driven through Claude Code or another real MCP client
  against a mock phone (a Rust harness implementing the phone side).
- Full flow driven through a real Android phone against the daemon,
  manually verified.
- Log diff after a mixed session (approvals + executions + denials):
  produces the expected pairings, no false alarms.

**Fault injection.**

- Randomized frame corruption at BLE layer.
- Randomized message reordering (Noise transport should reject
  out-of-order).
- Randomized delays / partial writes.
- Simulated phone crash mid-approval.
- Simulated daemon crash mid-execute (recovery: next session starts
  clean, incomplete rows visible in log as `deferred` or equivalent).

Coverage target for security-critical modules (crypto, handshake,
approval binding, hash chain): 100% branch coverage. Coverage target
elsewhere: judgment.

---

## Roadmap

### v1 (this document)

MCP secrets broker. 1:1 pairing. Android + Linux/macOS/Windows PC.
Execute-side air-gap: phone executes HTTP requests, PC never sees
credentials. Passphrase or biometric session unlock. Recovery phrase.
Manual revocation.

### v2 — Signing adapters

SSH agent adapter (Unix-domain socket speaking the SSH agent protocol,
routes signing requests to phone). Git commit signing adapter (works via
`gpg.program` config with a wrapper). Same underlying substrate — phone
holds keys, phone signs on approval, PC never sees the key.

### v3 — iOS

Native Swift app. Same wire protocol. Same pairing ceremony. TestFlight
distribution initially.

### v4 — Multi-device

One phone controls multiple PCs. Per-PC session state on the phone.
Approval log distinguishes PCs. UI shows session state per PC.

### v5 — Multi-user / policies

Multiple phones can approve on behalf of the same PC with per-phone
role assignment. Policy language for approval rules beyond the current
Tier 3 patterns. This is where enterprise use cases become plausible and
where scope discipline in v1 pays off.

Later phases MAY be reordered or dropped based on real user demand. The
substrate — the trust primitives established in v1 — is what everything
after depends on.

---

## Explicit non-goals for v1

- Not a replacement for a secrets manager for services the user does not
  route through Conveyance. Conveyance is per-request approval for
  agent-driven access, not general credential storage.
- Not an enterprise product. No RBAC, no directory integration, no
  central policy server.
- Not a general BLE mesh. One phone, one PC per pairing.
- Not a substitute for OS-level security (disk encryption, screen lock,
  MDM). Conveyance runs on top of these, does not replace them.
- Not a defense against a phone the user does not physically control.

---

## Known limitations

**Trailing-row deletion in either log is undetectable.** Same inherent
limit as auditmcp: hash chaining proves interior integrity but cannot
detect truncation of the newest rows. Documented, not fixed. A future
external checkpoint/witness mechanism could address this and is out of
scope for v1.

**Traffic analysis is possible.** An attacker observing BLE traffic can
learn that approvals are happening and their approximate size.
Constant-rate padding is not implemented in v1.

**BLE range is not physical proximity.** Nominal 10 m becomes 100 m+
with amplifiers. Physical presence at pairing time is a strong
guarantee (the user is looking at the QR); physical presence during
sessions is a weaker one. Not a defense, an assumption the user should
be aware of.

**Approval fatigue.** Users allowed to run long sessions with per-op-tap
approval will eventually approve reflexively. Mitigated by hard cap,
Tier 3 for high-risk operations, categorical rules matching auditmcp's
anomaly detection. Not eliminable.

**One-shot recovery phrase display.** If the user does not write it down
during first-run, there is no second chance. This is deliberate — the
alternative is a phrase accessible in the app, which weakens the
security property.

**Battery cost on the phone.** BLE advertising and connection during
active sessions has non-trivial battery impact. Users running long
sessions will notice. Mitigations: hard cap keeps sessions short by
default; user can end sessions manually.

**Loss of both phone and recovery phrase is unrecoverable.** Same
property as any hardware wallet. Documented up front so users understand
the responsibility they are taking on.

---

## References

- Noise Protocol Framework: <https://noiseprotocol.org/noise.html>
- Noise pattern `KK`: mutual, both parties know each other's static keys.
- WireGuard whitepaper (as reference implementation of similar choices):
  <https://www.wireguard.com/papers/wireguard.pdf>
- RFC 8785 — JSON Canonicalization Scheme (JCS).
- BIP-39: <https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki>
- KNOB attack on BLE key entropy: arXiv 1904.03809.
- BLE pairing downgrade attacks: USENIX Security '20, Zhang et al.
- BLERP re-pairing attacks: NDSS 2026.
- auditmcp (companion project, threat model style reference):
  <https://github.com/Ahlyx/auditmcp>

---

## License

MIT. The license was chosen for consistency with auditmcp and to reduce
friction for other projects wanting to build on the wire protocol.
