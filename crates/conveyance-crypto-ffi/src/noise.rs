//! UniFFI bridge over `conveyance-noise` — the phone's half of the
//! `Noise_KK_25519_ChaChaPoly_BLAKE2s` session (phase 10.4).
//!
//! Kotlin never sees session keys, handshake secrets, or transport
//! symmetric state. [`noise_initiate`] takes the identity **handle**
//! ([`UnlockedIdentity`], whose X25519 static lives in native `Zeroizing`
//! memory) plus the PC's *public* static, and returns an opaque
//! [`NoiseSession`]. Handshake and transport methods move message bytes
//! only. Dropping the handle (Kotlin `close()` / `use { }`) wipes the
//! snow state through its `Drop`.
//!
//! The phone is always the KK **initiator** (spec "Session start"). One
//! object with a `Mutex`-guarded phase enum, because
//! `conveyance_noise::SessionHandshake` *consumes* itself into
//! `SessionTransport` and a UniFFI `&self` object can't express that.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use conveyance_crypto::Secret;
use conveyance_noise::{NoiseError, Role, SessionHandshake, SessionTransport};

use crate::sealed::UnlockedIdentity;

/// Failures the Noise bridge can report. Deliberately coarse for the same
/// reason `conveyance_noise::NoiseError` is: no oracle for *which* check
/// failed. The `Not*` variants are caller misuse (a method called in the
/// wrong phase) and are safe to name precisely.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum NoiseFfiError {
    #[error("noise handshake failed")]
    HandshakeFailed,
    #[error("noise session ended")]
    SessionEnded,
    #[error("method requires the handshake phase")]
    NotHandshaking,
    #[error("method requires the transport phase")]
    NotInTransport,
    #[error("a key argument has the wrong length")]
    BadKeyBytes,
}

fn map_noise_err(e: NoiseError) -> NoiseFfiError {
    match e {
        NoiseError::HandshakeFailed => NoiseFfiError::HandshakeFailed,
        NoiseError::SessionEnded => NoiseFfiError::SessionEnded,
    }
}

// snow's HandshakeState / TransportState are both large; boxing them
// would add an allocation and an indirection to every handshake step and
// every encrypt/decrypt for a one-per-session object. The PC daemon
// holds the same types unboxed.
#[allow(clippy::large_enum_variant)]
enum Phase {
    Handshaking(SessionHandshake),
    Transport(SessionTransport),
    /// Transient: held only across the in-place `Handshaking -> Transport`
    /// swap. A method that ever observes it returns `NotInTransport`.
    Spent,
}

/// An opaque Noise KK session. Kotlin drives it: [`write_handshake_message`]
/// / [`read_handshake_message`] to completion, then [`encrypt`] /
/// [`decrypt`].
#[derive(uniffi::Object)]
pub struct NoiseSession {
    phase: Mutex<Phase>,
}

impl NoiseSession {
    fn new(hs: SessionHandshake) -> Arc<Self> {
        Arc::new(Self {
            phase: Mutex::new(Phase::Handshaking(hs)),
        })
    }

    /// Recover from a poisoned lock rather than panic — a panic here
    /// aborts the process across the FFI ABI.
    fn lock(&self) -> MutexGuard<'_, Phase> {
        self.phase.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// If the handshake just finished, move to transport mode in place.
    fn maybe_promote(guard: &mut Phase) -> Result<(), NoiseFfiError> {
        // Check before replacing: an unfinished Handshaking must not be
        // swapped out for Spent.
        if !matches!(guard, Phase::Handshaking(hs) if hs.is_finished()) {
            return Ok(());
        }
        if let Phase::Handshaking(hs) = std::mem::replace(guard, Phase::Spent) {
            *guard = Phase::Transport(hs.into_transport().map_err(map_noise_err)?);
        }
        Ok(())
    }
}

#[uniffi::export]
impl NoiseSession {
    /// True while the handshake is unfinished and it is this side's turn
    /// to write. False once in transport mode.
    pub fn needs_write(&self) -> bool {
        matches!(&*self.lock(), Phase::Handshaking(hs) if hs.needs_write())
    }

    pub fn is_handshake_complete(&self) -> bool {
        matches!(&*self.lock(), Phase::Transport(_))
    }

    /// Write one handshake message. `payload` is empty in Conveyance.
    pub fn write_handshake_message(&self, payload: Vec<u8>) -> Result<Vec<u8>, NoiseFfiError> {
        let mut g = self.lock();
        let out = match &mut *g {
            Phase::Handshaking(hs) => hs.write_message(&payload).map_err(map_noise_err)?,
            _ => return Err(NoiseFfiError::NotHandshaking),
        };
        Self::maybe_promote(&mut g)?;
        Ok(out)
    }

    /// Read one handshake message. Returns its (empty) payload.
    pub fn read_handshake_message(&self, message: Vec<u8>) -> Result<Vec<u8>, NoiseFfiError> {
        let mut g = self.lock();
        let out = match &mut *g {
            Phase::Handshaking(hs) => hs.read_message(&message).map_err(map_noise_err)?,
            _ => return Err(NoiseFfiError::NotHandshaking),
        };
        Self::maybe_promote(&mut g)?;
        Ok(out)
    }

    /// Seal one transport message. `NotInTransport` before the handshake
    /// completes.
    pub fn encrypt(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, NoiseFfiError> {
        match &mut *self.lock() {
            Phase::Transport(t) => t.send(&plaintext).map_err(map_noise_err),
            _ => Err(NoiseFfiError::NotInTransport),
        }
    }

    /// Open one transport message. A MAC failure is `SessionEnded`
    /// (generic) — the caller ends the session.
    pub fn decrypt(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>, NoiseFfiError> {
        match &mut *self.lock() {
            Phase::Transport(t) => t.receive(&ciphertext).map_err(map_noise_err),
            _ => Err(NoiseFfiError::NotInTransport),
        }
    }
}

/// Start the phone's KK handshake as **initiator**.
///
/// The phone's X25519 static is read from `identity`'s native buffer and
/// never crosses back out. `pc_static_pub` is the PC's long-term X25519
/// public key from the stored pairing.
#[uniffi::export]
pub fn noise_initiate(
    identity: Arc<UnlockedIdentity>,
    pc_static_pub: Vec<u8>,
) -> Result<Arc<NoiseSession>, NoiseFfiError> {
    let pc_pub: [u8; 32] = crate::fixed(pc_static_pub).map_err(|_| NoiseFfiError::BadKeyBytes)?;
    let local = Secret::from_bytes(identity.x25519_static());
    let hs = SessionHandshake::new(Role::Initiator, &local, &pc_pub).map_err(map_noise_err)?;
    Ok(NoiseSession::new(hs))
}

/// **Test-vectors build only.** A handshake with a caller-supplied
/// X25519 static *and* ephemeral, so the phone's handshake bytes are
/// deterministic and can be pinned against the Rust reference in
/// `noise_fixtures.json`.
///
/// Gated behind `test-vectors` (default off; the Gradle wiring only
/// enables it for the instrumented-test `.so`, never release; and
/// `conveyance-noise` refuses to compile the feature with
/// `debug_assertions` off). A fixed ephemeral has no forward secrecy —
/// this must never run in production, so it also logs loudly.
#[cfg(feature = "test-vectors")]
#[uniffi::export]
pub fn noise_initiate_with_fixed_ephemeral(
    phone_x25519_secret: Vec<u8>,
    pc_static_pub: Vec<u8>,
    ephemeral: Vec<u8>,
) -> Result<Arc<NoiseSession>, NoiseFfiError> {
    eprintln!(
        "conveyance WARN: noise_initiate_with_fixed_ephemeral called — fixed ephemeral, \
         NO forward secrecy. This must only ever appear in a test-vectors build."
    );
    let secret: [u8; 32] =
        crate::fixed(phone_x25519_secret).map_err(|_| NoiseFfiError::BadKeyBytes)?;
    let pc_pub: [u8; 32] = crate::fixed(pc_static_pub).map_err(|_| NoiseFfiError::BadKeyBytes)?;
    let eph: [u8; 32] = crate::fixed(ephemeral).map_err(|_| NoiseFfiError::BadKeyBytes)?;
    let local = Secret::from_bytes(secret);
    let hs = SessionHandshake::with_fixed_ephemeral(Role::Initiator, &local, &pc_pub, &eph)
        .map_err(map_noise_err)?;
    Ok(NoiseSession::new(hs))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A responder built directly for the round-trip check (the phone
    // never takes this role in production).
    fn responder(pc_secret: [u8; 32], phone_pub: [u8; 32]) -> Arc<NoiseSession> {
        let local = Secret::from_bytes(pc_secret);
        NoiseSession::new(SessionHandshake::new(Role::Responder, &local, &phone_pub).unwrap())
    }

    fn dh_pub(secret: &[u8; 32]) -> [u8; 32] {
        conveyance_crypto::dh::DhSecret::from_bytes(*secret)
            .public_key()
            .to_bytes()
    }

    #[test]
    fn full_handshake_then_transport_both_ways() {
        let phone_s = [7u8; 32];
        let pc_s = [9u8; 32];

        // Phone = initiator, via the production entry with a raw secret
        // (the test builds an UnlockedIdentity-free handshake directly).
        let init = NoiseSession::new(
            SessionHandshake::new(
                Role::Initiator,
                &Secret::from_bytes(phone_s),
                &dh_pub(&pc_s),
            )
            .unwrap(),
        );
        let resp = responder(pc_s, dh_pub(&phone_s));

        assert!(init.needs_write());
        let m1 = init.write_handshake_message(vec![]).unwrap();
        assert!(resp.read_handshake_message(m1).unwrap().is_empty());
        let m2 = resp.write_handshake_message(vec![]).unwrap();
        assert!(init.read_handshake_message(m2).unwrap().is_empty());

        assert!(init.is_handshake_complete());
        assert!(resp.is_handshake_complete());

        let ct = init.encrypt(b"hello pc".to_vec()).unwrap();
        assert_eq!(resp.decrypt(ct).unwrap(), b"hello pc");
        let ct = resp.encrypt(b"hello phone".to_vec()).unwrap();
        assert_eq!(init.decrypt(ct).unwrap(), b"hello phone");
    }

    #[test]
    fn methods_in_the_wrong_phase_are_typed_errors() {
        let s = NoiseSession::new(
            SessionHandshake::new(
                Role::Initiator,
                &Secret::from_bytes([1u8; 32]),
                &dh_pub(&[2u8; 32]),
            )
            .unwrap(),
        );
        assert!(matches!(
            s.encrypt(vec![1]),
            Err(NoiseFfiError::NotInTransport)
        ));
        assert!(matches!(
            s.decrypt(vec![1]),
            Err(NoiseFfiError::NotInTransport)
        ));
    }

    #[test]
    fn wrong_pc_static_fails_handshake_generic() {
        let phone_s = [7u8; 32];
        let pc_s = [9u8; 32];
        let impostor = [3u8; 32];

        let init = NoiseSession::new(
            SessionHandshake::new(
                Role::Initiator,
                &Secret::from_bytes(phone_s),
                &dh_pub(&impostor),
            )
            .unwrap(),
        );
        let resp = responder(pc_s, dh_pub(&phone_s));
        let m1 = init.write_handshake_message(vec![]).unwrap();
        assert!(matches!(
            resp.read_handshake_message(m1),
            Err(NoiseFfiError::HandshakeFailed)
        ));
    }

    #[test]
    fn tampered_ciphertext_is_session_ended() {
        let phone_s = [7u8; 32];
        let pc_s = [9u8; 32];
        let init = NoiseSession::new(
            SessionHandshake::new(
                Role::Initiator,
                &Secret::from_bytes(phone_s),
                &dh_pub(&pc_s),
            )
            .unwrap(),
        );
        let resp = responder(pc_s, dh_pub(&phone_s));
        let m1 = init.write_handshake_message(vec![]).unwrap();
        resp.read_handshake_message(m1).unwrap();
        let m2 = resp.write_handshake_message(vec![]).unwrap();
        init.read_handshake_message(m2).unwrap();

        let mut ct = init.encrypt(b"data".to_vec()).unwrap();
        ct[0] ^= 0x80;
        assert!(matches!(resp.decrypt(ct), Err(NoiseFfiError::SessionEnded)));
    }
}
