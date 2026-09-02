//! Thin wrapper around `snow` for the fixed pattern
//! `Noise_KK_25519_ChaChaPoly_BLAKE2s`.
//!
//! Thinness is deliberate. This crate adds no crypto, no buffering, and
//! no interpretation of payloads; it maps the handshake's two roles onto
//! snow's builder, hands completed transports back, and collapses every
//! possible snow failure into [`NoiseError::HandshakeFailed`].
//!
//! That collapse is a spec requirement, not laziness: "HandshakeFailed,
//! generic -- MUST NOT leak which validation failed". A detailed error
//! ("remote static MAC mismatch") is reconnaissance for whoever caused
//! it. Details are available to a debugger at the snow layer if ever
//! genuinely needed; they never cross this boundary as strings.
//!
//! Handshake message payloads are empty; no prologue and no PSK are used
//! (spec "Session start"). Both the PC daemon (via `conveyance-core`) and
//! the Android app (via `conveyance-crypto-ffi`) drive *this* crate, so
//! the handshake bytes are identical on each side by construction.
//!
//! Extracted from `conveyance-core::session::noise` in phase 10.4 so the
//! Android side reaches the same `snow` through UniFFI;
//! `conveyance-core::session::noise` re-exports it and adds
//! `From<NoiseError> for ConveyanceError`, so the daemon is unchanged.
//!
//! SECURITY NOTE: zeroization of Noise cipher state is delegated to
//! snow's Drop implementation, which is not part of its stable API
//! contract. Everything Conveyance itself holds (static keys, scratch
//! buffers) is zeroized through our own types -- see `Session::end` on
//! the PC side and the Rust-owned `NoiseSession` handle on the phone.
//! If audit-grade proof of in-snow zeroization is ever demanded, the
//! honest options are forking snow to add assertions or implementing KK
//! over our own primitives; both are large decisions recorded here so
//! future-us does not re-research them.

// A predictable ephemeral (the `test-vectors` fixed-ephemeral seam) has
// no forward secrecy. Refuse to compile it into anything but a debug
// build — defense in depth behind the "default off" feature and the
// Gradle wiring that only enables it for the instrumented-test .so.
#[cfg(all(feature = "test-vectors", not(debug_assertions)))]
compile_error!(
    "the `test-vectors` feature (fixed Noise ephemeral) must never be built with \
     debug_assertions off — it is for the instrumented-test .so only"
);

use conveyance_crypto::Secret;
use thiserror::Error;

/// Cross-implementation handshake + transport test vectors. Needs the
/// fixed-ephemeral seam, so it is gated the same way.
#[cfg(any(test, feature = "test-vectors"))]
pub mod fixtures;

/// Every way this crate can fail. Deliberately two coarse variants: a
/// security product must not hand callers an oracle for *which* internal
/// check failed. The strings match the PC-side `ConveyanceError` codes so
/// `From<NoiseError> for ConveyanceError` in `conveyance-core` is 1:1.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum NoiseError {
    /// Any handshake failure — wrong static, corrupt bytes, wrong order.
    #[error("noise handshake failed")]
    HandshakeFailed,
    /// A transport-message failure: MAC mismatch or desynchronization.
    /// Noise has no recovery from either; the caller ends the session.
    #[error("noise session ended")]
    SessionEnded,
}

impl NoiseError {
    /// The spec error-model code. Kept here so the strings are pinned in
    /// the leaf crate; `conveyance-core` maps its `ConveyanceError` to the
    /// same values.
    pub fn code(&self) -> &'static str {
        match self {
            NoiseError::HandshakeFailed => "conveyance/handshake_failed",
            NoiseError::SessionEnded => "conveyance/session_ended",
        }
    }

    /// Spec error table: `handshake_failed` is fatal, `session_ended` is
    /// retryable after a fresh session start.
    pub fn retryable(&self) -> bool {
        matches!(self, NoiseError::SessionEnded)
    }
}

/// The exact spelling the spec fixes and snow expects.
const PATTERN: &str = "Noise_KK_25519_ChaChaPoly_BLAKE2s";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Sends message 1. The **phone's** production role — the session
    /// starts from the phone app (spec "Session start"); the phone side
    /// reaches this through `conveyance-crypto-ffi`'s `noise_initiate`.
    Initiator,
    /// Answers with message 2. The **PC daemon's** permanent production
    /// role. (Tests and the phone's `noise_respond` test seam also build
    /// a responder to drive both sides in one process.)
    Responder,
}

/// A handshake in progress. Driven by whichever half-duplex step comes
/// next (`needs_write`), then converted into a transport.
pub struct SessionHandshake {
    inner: snow::HandshakeState,
    role: Role,
}

impl SessionHandshake {
    pub fn new(
        role: Role,
        local_static: &Secret<32>,
        remote_static: &[u8; 32],
    ) -> Result<Self, NoiseError> {
        Self::build(role, local_static, remote_static, None)
    }

    /// **Test / fixture only.** A handshake with a caller-supplied
    /// ephemeral instead of a fresh random one.
    ///
    /// A fixed ephemeral makes the handshake bytes deterministic given
    /// fixed statics — which is exactly what the cross-implementation
    /// `noise_fixtures.json` vectors need to pin. It also destroys
    /// forward secrecy, so it is gated behind `test-vectors` (which
    /// itself refuses to build with `debug_assertions` off — see the
    /// crate-level `compile_error!`).
    #[cfg(any(test, feature = "test-vectors"))]
    pub fn with_fixed_ephemeral(
        role: Role,
        local_static: &Secret<32>,
        remote_static: &[u8; 32],
        ephemeral: &[u8; 32],
    ) -> Result<Self, NoiseError> {
        Self::build(role, local_static, remote_static, Some(ephemeral))
    }

    fn build(
        role: Role,
        local_static: &Secret<32>,
        remote_static: &[u8; 32],
        fixed_ephemeral: Option<&[u8; 32]>,
    ) -> Result<Self, NoiseError> {
        // KK means BOTH sides already know each other's statics (learned
        // during pairing). Setting remote_public_key on the responder too
        // is what makes a wrong-static peer fail its MAC check rather
        // than silently establishing a channel with an impostor.
        //
        // Snow's default (pure-Rust) crypto provider is used via feature
        // defaults; the primitives underneath are the same ones our
        // standalone crypto module pins. No prologue, no PSK (spec).
        let params = PATTERN.parse().map_err(handshake_failed)?;
        // snow 0.10's builder setters return Results (they validate key
        // lengths); every failure is pre-session setup, mapped generic.
        let mut builder = snow::Builder::new(params)
            .local_private_key(local_static.expose().as_slice())
            .map_err(handshake_failed)?
            .remote_public_key(remote_static)
            .map_err(handshake_failed)?;
        if let Some(eph) = fixed_ephemeral {
            builder = builder.fixed_ephemeral_key_for_testing_only(eph.as_slice());
        }

        let inner = match role {
            Role::Initiator => builder.build_initiator(),
            Role::Responder => builder.build_responder(),
        }
        .map_err(handshake_failed)?;

        Ok(Self { inner, role })
    }

    pub fn role(&self) -> Role {
        self.role
    }

    /// Whose move it is. KK has exactly two messages: initiator writes,
    /// responder reads/writes, initiator reads.
    pub fn needs_write(&self) -> bool {
        self.inner.is_my_turn()
    }

    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let mut out = vec![0u8; MAX_MESSAGE];
        let n = self
            .inner
            .write_message(payload, &mut out)
            .map_err(|_| NoiseError::HandshakeFailed)?;
        out.truncate(n);
        Ok(out)
    }

    pub fn read_message(&mut self, msg: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let mut buf = vec![0u8; MAX_MESSAGE];
        let n = self
            .inner
            .read_message(msg, &mut buf)
            // Any failure -- wrong static, corrupt bytes, wrong order --
            // is the same generic failure to the outside world.
            .map_err(|_| NoiseError::HandshakeFailed)?;
        buf.truncate(n);
        Ok(buf)
    }

    pub fn is_finished(&self) -> bool {
        self.inner.is_handshake_finished()
    }

    /// Complete the handshake. Consumes the handshake state: its keying
    /// material moves into the transport or is dropped, never copied out.
    pub fn into_transport(self) -> Result<SessionTransport, NoiseError> {
        let transport = self
            .inner
            .into_transport_mode()
            .map_err(|_| NoiseError::HandshakeFailed)?;
        Ok(SessionTransport { inner: transport })
    }
}

pub struct SessionTransport {
    inner: snow::TransportState,
}

impl SessionTransport {
    /// Seal one transport message. Returns a fresh buffer per call --
    /// callers own their bytes; we retain nothing. Write failures are
    /// unreachable in a healthy session (nonce exhaustion needs 2^64
    /// messages); they map to `SessionEnded`, which is what any such
    /// failure means operationally.
    pub fn send(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let mut out = vec![0u8; plaintext.len() + TAG_LEN];
        let n = self
            .inner
            .write_message(plaintext, &mut out)
            .map_err(|_| NoiseError::SessionEnded)?;
        out.truncate(n);
        Ok(out)
    }

    /// Open one transport message.
    ///
    /// A MAC failure here means the bytes were tampered with or the peer
    /// is desynchronized -- Noise has no recovery from either. From the
    /// client's perspective the effect is identical to any session end,
    /// so this returns `NoiseError::SessionEnded` (generic, leaks
    /// nothing); the CALLER records `EndReason::ProtocolViolation` in
    /// the log and tears the session down. Never continue after Err
    /// from this method.
    pub fn receive(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let mut buf = vec![0u8; ciphertext.len()];
        let plaintext = self.receive_into(ciphertext, &mut buf)?;
        Ok(plaintext.to_vec())
    }

    /// Same as [`receive`], but decrypting into a caller-provided buffer
    /// so the Session can route its retained (zeroized-on-end) scratch
    /// through here instead of allocating fresh memory per message.
    /// Returns the filled subslice of `buf`.
    pub fn receive_into<'b>(
        &mut self,
        ciphertext: &[u8],
        buf: &'b mut [u8],
    ) -> Result<&'b [u8], NoiseError> {
        let n = self
            .inner
            .read_message(ciphertext, buf)
            .map_err(|_| NoiseError::SessionEnded)?;
        Ok(&buf[..n])
    }
}

// snow rejects messages larger than 65535 bytes at the Noise protocol
// level; that ceiling is far above anything phase 3 passes through.
const MAX_MESSAGE: usize = 65_535;
const TAG_LEN: usize = 16;

fn handshake_failed(_: snow::Error) -> NoiseError {
    NoiseError::HandshakeFailed
}

#[cfg(test)]
mod tests {
    use super::*;
    use conveyance_crypto::dh::DhSecret;
    use conveyance_crypto::{EntropySource, OsEntropy, Secret};

    fn static_key() -> Secret<32> {
        let mut bytes = [0u8; 32];
        OsEntropy.fill(&mut bytes).unwrap();
        Secret::from_bytes(bytes)
    }

    fn peer_pub(secret: &Secret<32>) -> [u8; 32] {
        // Through our own DH wrapper: also proves the phase-1 module and
        // Noise agree on key derivation.
        DhSecret::from_bytes(*secret.expose())
            .public_key()
            .to_bytes()
    }

    #[test]
    fn pattern_string_resolves() {
        // If this fails, the spec-fixed pattern no longer parses -- stop
        // and reconcile with the spec before touching anything else.
        assert!(PATTERN.parse::<snow::params::NoiseParams>().is_ok());
    }

    #[test]
    fn full_handshake_reaches_transport_and_exchanges_authenticated_bytes() {
        let pc = static_key();
        let phone = static_key();

        let mut initiator = SessionHandshake::new(Role::Initiator, &phone, &peer_pub(&pc)).unwrap();
        let mut responder = SessionHandshake::new(Role::Responder, &pc, &peer_pub(&phone)).unwrap();

        // Message 1: initiator -> responder.
        assert!(initiator.needs_write());
        let m1 = initiator.write_message(b"").unwrap();
        let _echoed = responder.read_message(&m1).unwrap();

        // Message 2: responder -> initiator.
        assert!(responder.needs_write());
        let m2 = responder.write_message(b"").unwrap();
        let _echoed = initiator.read_message(&m2).unwrap();

        assert!(initiator.is_finished());
        assert!(responder.is_finished());

        let mut init_t = initiator.into_transport().unwrap();
        let mut resp_t = responder.into_transport().unwrap();

        let sealed = init_t.send(b"approve /v1/deploy?").unwrap();
        assert_ne!(
            sealed, b"approve /v1/deploy?",
            "ciphertext must differ from plaintext"
        );
        let opened = resp_t.receive(&sealed).unwrap();
        assert_eq!(opened, b"approve /v1/deploy?");
    }

    #[test]
    fn wrong_remote_static_fails_cleanly_in_both_configurations() {
        let pc = static_key();
        let phone = static_key();
        let impostor = static_key();

        // Case A: an impostor PHONE presents to the honest PC. The PC's
        // configured remote (what pairing taught it) is the real phone
        // key, so message 1 -- which carries the initiator's static
        // encrypted under keys involving DH(initiator_static,
        // expected_responder_static)... here the roles reverse -- cannot
        // verify. Detection lands at the responder's first read.
        let mut init = SessionHandshake::new(Role::Initiator, &phone, &peer_pub(&pc)).unwrap();
        let mut resp = SessionHandshake::new(Role::Responder, &pc, &peer_pub(&impostor)).unwrap();

        let m1 = init.write_message(b"").unwrap();
        match resp.read_message(&m1) {
            Err(NoiseError::HandshakeFailed) => {} // generic: exactly right
            other => panic!("expected generic HandshakeFailed, got {other:?}"),
        }

        // Case B: an impostor PC. The honest initiator addresses message 1
        // to the REAL PC static it learned during pairing; the impostor's
        // responder holds a different static, so it equally cannot open
        // message 1. KK pins both directions' statics into message 1's
        // keying -- there is no configuration where a wrong static
        // survives past the first read, whichever side is lying.
        let mut init2 =
            SessionHandshake::new(Role::Initiator, &phone, &peer_pub(&impostor)).unwrap();
        let mut resp2 = SessionHandshake::new(Role::Responder, &pc, &peer_pub(&phone)).unwrap();
        let m1b = init2.write_message(b"").unwrap();
        match resp2.read_message(&m1b) {
            Err(NoiseError::HandshakeFailed) => {}
            other => panic!("expected generic HandshakeFailed, got {other:?}"),
        }

        // And neither failure leaks anything beyond the generic code.
        let probe = NoiseError::HandshakeFailed;
        assert_eq!(probe.code(), "conveyance/handshake_failed");
    }

    #[test]
    fn tampered_ciphertext_is_rejected_not_garbled() {
        let pc = static_key();
        let phone = static_key();
        let mut i = SessionHandshake::new(Role::Initiator, &phone, &peer_pub(&pc)).unwrap();
        let mut r = SessionHandshake::new(Role::Responder, &pc, &peer_pub(&phone)).unwrap();

        let m1 = i.write_message(b"").unwrap();
        r.read_message(&m1).unwrap();
        let m2 = r.write_message(b"").unwrap();
        i.read_message(&m2).unwrap();

        let mut ti = i.into_transport().unwrap();
        let mut tr = r.into_transport().unwrap();

        let mut sealed = ti.send(b"data").unwrap();
        sealed[0] ^= 0x80;
        match tr.receive(&sealed) {
            // SessionEnded: see receive()'s contract -- the caller ends
            // the session with EndReason::ProtocolViolation.
            Err(NoiseError::SessionEnded) => {}
            other => panic!("tampered ciphertext must not decrypt, got {other:?}"),
        }
    }

    #[test]
    fn errors_never_leak_snow_internals() {
        // The generic mapping is load-bearing; assert its output shape.
        let e = handshake_failed(snow::Error::Decrypt);
        assert_eq!(e.code(), "conveyance/handshake_failed");
        assert!(!e.retryable());
    }
}
