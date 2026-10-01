//! The pairing ceremony driver: walks the state machine over a real
//! (or mock) transport until PAIRED, or back to UNPAIRED with an error.
//!
//! Single QR per invocation (phase-6 decision): one nonce, one budget,
//! one confirm window. Rejections burn the nonce -- "single-use even on
//! failure" -- which is why the replay gate records the nonce IMMEDIATELY
//! on receipt, before any validation: by the time we know whether the
//! confirm was valid, the nonce must already be consumed either way.
//!
//! Validation order is therefore: replay-gate FIRST (it mutates state),
//! then signature. Both failures collapse to the same generic error
//! toward the user; the local log distinguishes them.

use std::time::Duration;

use crate::crypto::EntropySource;
use crate::time::unix_now;
use crate::transport::{InboundAssembler, Link};

use crate::crypto::sign::IdentitySecretKey;
use crate::storage::pairings::PairingsDb;
use crate::transport::Transport;
use crate::wire::framing::split_message;
use crate::wire::message::{WireMessage, encode};

use super::PairingError;
use super::machine::{self, Event, PairingState};
use super::messages::{PairingAck, decode_confirm_message};
use super::nonce::NonceGuard;
use super::qr::PairingQr;

#[derive(Clone, Copy, Debug)]
pub struct CeremonyLimits {
    pub qr_ttl: Duration,
    pub confirm_timeout: Duration,
    pub total_budget: Duration,
}

impl CeremonyLimits {
    pub const fn spec() -> Self {
        Self {
            qr_ttl: Duration::from_secs(60),
            confirm_timeout: Duration::from_secs(10),
            total_budget: Duration::from_secs(300),
        }
    }

    #[cfg(test)]
    pub const fn raw(qr_ttl: u64, confirm_timeout: u64, total_budget: u64) -> Self {
        Self {
            qr_ttl: Duration::from_secs(qr_ttl),
            confirm_timeout: Duration::from_secs(confirm_timeout),
            total_budget: Duration::from_secs(total_budget),
        }
    }
}

pub struct CeremonyContext<'a> {
    /// PC identity signing key (Acks) and its Ed25519 public half (QR).
    pub pc_id_secret: &'a IdentitySecretKey,
    /// PC X25519 static PUBLIC half, from the same storage the session
    /// handshake will use later. Supplied rather than derived so the
    /// caller cannot accidentally pair two different halves.
    pub pc_dh_pub: [u8; 32],
    pub pc_name: String,
    pub service_uuid_bytes: [u8; 16],
    pub store: &'a PairingsDb,
    pub nonces: &'a mut NonceGuard,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PairedPeer {
    pub phone_id_pub: [u8; 32],
    pub phone_dh_pub: [u8; 32],
}

/// Run the full ceremony. Shows ONE QR via `display`, waits within the
/// QR window for the phone to advertise and connect, takes ONE confirm,
/// answers with the Ack, persists the peer. Any rejection returns Err
/// with the nonce burned; rerun `conveyance pair` for a fresh code.
///
/// `entropy` sources the single-use pairing nonce -- production passes
/// [`crate::crypto::OsEntropy`]; tests inject a deterministic source so
/// the replay gate can be exercised without a driver copy.
pub async fn run_pairing<T, D, E>(
    transport: &mut T,
    ctx: &mut CeremonyContext<'_>,
    limits: CeremonyLimits,
    entropy: &E,
    mut display: D,
) -> Result<PairedPeer, PairingError>
where
    T: Transport,
    T::Link: Link + Send,
    D: FnMut(&PairingQr),
    E: EntropySource,
{
    // ---- QR_DISPLAYED ---------------------------------------------------
    let started = tokio::time::Instant::now();
    let qr_deadline = started + limits.qr_ttl;

    let mut nonce = [0u8; 32];
    entropy.fill(&mut nonce)?;
    let pc_id_pub = ctx.pc_id_secret.public_key().to_bytes();

    let qr = PairingQr::new(
        unix_now(),
        pc_id_pub,
        ctx.pc_dh_pub,
        nonce,
        &ctx.pc_name,
        ctx.service_uuid_bytes,
    )?;
    display(&qr);
    let mut state = machine::step(PairingState::Unpaired, Event::BeginPairing)
        .expect("driver only begins from Unpaired");

    // ---- CONNECTING (loop inside the QR window; BLE failures retry) ----
    let mut link = loop {
        if tokio::time::Instant::now() >= qr_deadline {
            return Err(PairingError::QrExpired);
        }
        let wait = qr_deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(
            wait.min(Duration::from_millis(250)),
            transport.connect(wait),
        )
        .await
        {
            Err(_) => continue,     // sweep tick; keep scanning until expiry
            Ok(Err(_)) => continue, // BLE hiccup: still QR_DISPLAYED
            Ok(Ok(link)) => break link,
        }
    };
    state = machine::step(state, Event::AdvertisementSeen)
        .expect("advertisement seen while QR_DISPLAYED");
    state = machine::step(state, Event::GattConnected).expect("link up while CONNECTING");

    // ---- AWAITING_CONFIRM ----------------------------------------------
    // Every exit drives the machine first -- including failures, whose
    // destination is UNPAIRED with the nonce burned (single-use even on
    // failure). The macro keeps each arm honest about that pairing of
    // transition + error.
    macro_rules! fail_via {
        ($event:expr, $err:expr) => {{
            state = machine::step(state, $event).expect("driver only emits legal failure events");
            debug_assert_eq!(state, PairingState::Unpaired);
            return Err($err);
        }};
    }

    let inbound = match receive_pairing_confirm(&mut link, limits.confirm_timeout).await {
        Ok(message) => message,
        Err(ConfirmReceiveError::TimedOut) => {
            fail_via!(Event::ConfirmTimeout, PairingError::ConfirmTimedOut)
        }
        Err(ConfirmReceiveError::Invalid) => {
            fail_via!(Event::InvalidConfirm, PairingError::GenericFailed)
        }
        Err(ConfirmReceiveError::InvalidAfterMessage) => {
            // A complete application message was received, so consume the
            // QR nonce even if trailing data or transport teardown makes
            // the one-shot exchange invalid.
            if ctx.nonces.record_and_check(&nonce) {
                eprintln!("pairing rejected: replayed pairing nonce");
                fail_via!(Event::InvalidConfirm, PairingError::ReplayedNonce);
            }
            fail_via!(Event::InvalidConfirm, PairingError::GenericFailed)
        }
    };

    // Replay gate FIRST: a completed application message consumes the QR
    // nonce even if it is malformed, unexpected, or has an invalid signer.
    if ctx.nonces.record_and_check(&nonce) {
        eprintln!("pairing rejected: replayed pairing nonce");
        fail_via!(Event::InvalidConfirm, PairingError::ReplayedNonce);
    }

    // A single pairing Link carries exactly one confirm. The receive path
    // rejects any additional complete message before this point.
    let confirm = match decode_confirm_message(&inbound) {
        Ok(confirm) => confirm,
        Err(_) => fail_via!(Event::InvalidConfirm, PairingError::GenericFailed),
    };

    // Signature second. Wrong-key/tampered/impostor all collapse here --
    // generic toward users per the spec's MUST-NOT-indicate rule. The
    // nonce is already consumed above; no further burn needed.
    let phone_public =
        match crate::crypto::sign::IdentityPublicKey::from_bytes(&confirm.phone_id_pub) {
            Ok(pk) => pk,
            Err(_) => fail_via!(Event::InvalidConfirm, PairingError::GenericFailed),
        };
    if confirm.verify(&phone_public, &pc_id_pub, &nonce).is_err() {
        fail_via!(Event::InvalidConfirm, PairingError::GenericFailed);
    }

    // ---- ACK_SENT -------------------------------------------------------
    state = machine::step(state, Event::ValidConfirmReceived)
        .expect("valid confirm while AWAITING_CONFIRM");

    let ack = PairingAck::sign(
        ctx.pc_id_secret,
        &nonce,
        &pc_id_pub,
        &confirm.phone_id_pub,
        &confirm.phone_dh_pub,
    );
    let ack_bytes = encode(&WireMessage::PairingAck(ack))?;
    // Pairing owns a fresh Link and sends one application message, so its
    // outbound sequence starts at zero. A later Noise session opens a new
    // Link and starts its own framing state.
    let (frames, _next_tx_seq) = match split_message(&ack_bytes, link.max_write_len(), 0) {
        Ok(split) => split,
        Err(_) => {
            state = machine::step(state, Event::AckWriteFailed)
                .expect("ack framing failure while ACK_SENT");
            debug_assert_eq!(state, PairingState::Unpaired);
            return Err(PairingError::GenericFailed);
        }
    };
    for frame in frames {
        if let Err(e) = link.send(&frame).await {
            state =
                machine::step(state, Event::AckWriteFailed).expect("ack failure while ACK_SENT");
            debug_assert_eq!(state, PairingState::Unpaired);
            return Err(PairingError::Transport(e.to_string()));
        }
    }

    // ---- PAIRED ----------------------------------------------------------
    state = machine::step(state, Event::AckWrittenOk).expect("ack ok while ACK_SENT");
    debug_assert_eq!(state, PairingState::Paired);

    let record = ctx
        .store
        .record(confirm.phone_id_pub, confirm.phone_dh_pub, unix_now())?;

    Ok(PairedPeer {
        phone_id_pub: record.id_pub,
        phone_dh_pub: record.dh_pub,
    })
}

#[derive(Debug)]
enum ConfirmReceiveError {
    TimedOut,
    Invalid,
    InvalidAfterMessage,
}

/// Receive and reassemble the phone's one pairing application message.
/// The single timeout wraps the entire loop, so trickling valid partial
/// frames cannot restart the confirm window. After the first complete
/// message, inspect a bounded number of already-queued chunks to reject
/// extra messages or trailing partial framing without delaying the Ack.
async fn receive_pairing_confirm<L: Link>(
    link: &mut L,
    timeout: Duration,
) -> Result<Vec<u8>, ConfirmReceiveError> {
    const MAX_QUEUED_CHUNKS_TO_DRAIN: usize = 64;

    let mut assembler = InboundAssembler::new();
    let receive = async {
        let mut confirm = None;
        let mut drained_chunks = 0;
        loop {
            let chunk = if confirm.is_some() {
                match link
                    .try_recv()
                    .map_err(|_| ConfirmReceiveError::InvalidAfterMessage)?
                {
                    Some(chunk) => {
                        drained_chunks += 1;
                        if drained_chunks > MAX_QUEUED_CHUNKS_TO_DRAIN {
                            return Err(ConfirmReceiveError::InvalidAfterMessage);
                        }
                        chunk
                    }
                    None if assembler.is_idle() => {
                        return confirm.take().ok_or(ConfirmReceiveError::Invalid);
                    }
                    None => return Err(ConfirmReceiveError::InvalidAfterMessage),
                }
            } else {
                link.recv()
                    .await
                    .map_err(|_| ConfirmReceiveError::Invalid)?
            };
            let messages = assembler.ingest(&chunk).map_err(|_| {
                if confirm.is_some() {
                    ConfirmReceiveError::InvalidAfterMessage
                } else {
                    ConfirmReceiveError::Invalid
                }
            })?;
            match (confirm.is_some(), messages.as_slice()) {
                (false, []) | (true, []) => {}
                (false, [message]) => confirm = Some(message.clone()),
                // A second application message, whether coalesced into
                // the completing chunk or queued separately, violates the
                // one-shot pairing protocol.
                (false, _) | (true, _) => {
                    return Err(ConfirmReceiveError::InvalidAfterMessage);
                }
            }
        }
    };
    tokio::time::timeout(timeout, receive)
        .await
        .map_err(|_| ConfirmReceiveError::TimedOut)?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::OsEntropy;
    use crate::crypto::dh::DhSecret;
    use crate::crypto::sign::IdentityPublicKey;
    use crate::crypto::test_support::{CounterEntropy, FixedEntropy};
    use crate::pairing::messages::PairingConfirm;
    use crate::session::{PeerIdentity, Role, SessionHandshake, SessionParams};
    use crate::storage::identity::StoredIdentity;
    use crate::storage::pairings::PairingsDb;
    use crate::test_support::MockKeyProvider;
    use crate::transport::mock::MockTransport;
    use crate::transport::{InboundAssembler, TransportError};
    use crate::wire::framing::split_message;
    use tokio::sync::mpsc;

    #[derive(Clone)]
    struct PhoneKeys {
        id_secret: IdentitySecretKey,
        id_pub: [u8; 32],
        dh_secret: DhSecret,
        dh_pub: [u8; 32],
    }

    fn phone_keys() -> PhoneKeys {
        let id_secret = IdentitySecretKey::generate(&CounterEntropy).unwrap();
        let dh_secret = DhSecret::generate(&OsEntropy).unwrap();
        let id_pub = id_secret.public_key().to_bytes();
        let dh_pub = dh_secret.public_key().to_bytes();
        PhoneKeys {
            id_secret,
            id_pub,
            dh_secret,
            dh_pub,
        }
    }

    struct PhoneObservation {
        pc_id_pub: [u8; 32],
        pc_dh_pub: [u8; 32],
        confirm_frames: usize,
        ack_frames: usize,
    }

    #[derive(Clone, Copy)]
    enum Mode {
        Valid,
        WrongSigner,
        TamperedDh,
        StaleContext,
    }

    /// Mock phone: parse the displayed QR, sign+send Confirm per mode,
    /// verify the Ack, and report what it stored about the PC.
    fn spawn_phone(
        mut link: <MockTransport as Transport>::Link,
        keys: PhoneKeys,
        mut qr_rx: mpsc::Receiver<String>,
        mode: Mode,
    ) -> tokio::task::JoinHandle<Option<PhoneObservation>> {
        tokio::spawn(async move {
            let text = match qr_rx.recv().await {
                Some(t) => t,
                None => return None,
            };
            let qr = PairingQr::parse(&text, unix_now()).ok()?;

            let (pc_pub, nonce) = match mode {
                Mode::StaleContext => ([0x99u8; 32], [0x77u8; 32]),
                _ => (qr.pc_id_pub, qr.nonce),
            };
            let mut confirm =
                PairingConfirm::sign(&keys.id_secret, &pc_pub, &nonce, &keys.id_pub, &keys.dh_pub);
            if matches!(mode, Mode::TamperedDh) {
                confirm.phone_dh_pub[0] ^= 0xFF;
            }
            if matches!(mode, Mode::WrongSigner) {
                let stranger = IdentitySecretKey::generate(&CounterEntropy).unwrap();
                confirm = PairingConfirm::sign(
                    &stranger,
                    &qr.pc_id_pub,
                    &qr.nonce,
                    &keys.id_pub,
                    &keys.dh_pub,
                );
            }

            let raw_confirm = crate::pairing::messages::encode_confirm_message(&confirm).ok()?;
            let (confirm_frames, _) = split_message(&raw_confirm, link.max_write_len(), 0).ok()?;
            let confirm_frame_count = confirm_frames.len();
            for frame in confirm_frames {
                link.send(&frame).await.ok()?;
            }

            let mut assembler = InboundAssembler::new();
            let mut ack_frame_count = 0;
            let raw_ack = loop {
                let chunk = link.recv().await.ok()?;
                ack_frame_count += 1;
                let messages = assembler.ingest(&chunk).ok()?;
                if messages.len() > 1 {
                    return None;
                }
                if let Some(message) = messages.into_iter().next() {
                    break message;
                }
            };
            let ack = crate::pairing::messages::decode_ack_message(&raw_ack).ok()?;
            if ack.nonce != qr.nonce
                || ack.pc_id_pub != qr.pc_id_pub
                || ack.phone_id_pub != keys.id_pub
                || ack.phone_dh_pub != keys.dh_pub
            {
                return None;
            }
            let pc_public = IdentityPublicKey::from_bytes(&qr.pc_id_pub).ok()?;
            ack.verify(&pc_public).ok()?;
            Some(PhoneObservation {
                pc_id_pub: qr.pc_id_pub,
                pc_dh_pub: qr.pc_dh_pub,
                confirm_frames: confirm_frame_count,
                ack_frames: ack_frame_count,
            })
        })
    }

    fn valid_confirm_for(qr: &PairingQr, keys: &PhoneKeys) -> PairingConfirm {
        PairingConfirm::sign(
            &keys.id_secret,
            &qr.pc_id_pub,
            &qr.nonce,
            &keys.id_pub,
            &keys.dh_pub,
        )
    }

    /// Destructured fixture fields. Tests destructure ONCE so that
    /// `ta`, `nonces`, and `qr_tx` can be borrowed independently without
    /// whole-struct borrow conflicts.
    struct FixtureParts {
        store: PairingsDb,
        nonces: NonceGuard,
        signer: IdentitySecretKey,
        pc_dh_pub: [u8; 32],
        qr_tx: mpsc::Sender<String>,
        qr_rx: Option<mpsc::Receiver<String>>,
        ta: MockTransport,
        tb: MockTransport,
        _dir: tempfile::TempDir,
    }

    fn fixture() -> FixtureParts {
        fixture_with_max_write(24)
    }

    fn fixture_with_max_write(max_write: usize) -> FixtureParts {
        let dir = tempfile::tempdir().unwrap();
        let store = PairingsDb::open(&dir.path().join("pairings.db")).unwrap();
        let nonces = NonceGuard::open(&dir.path().join("nonces.bin"));
        let signer = IdentitySecretKey::generate(&CounterEntropy).unwrap();
        let pc_dh_pub = DhSecret::generate(&OsEntropy)
            .unwrap()
            .public_key()
            .to_bytes();
        let (qr_tx, qr_rx) = mpsc::channel(4);
        let (ta, tb) = MockTransport::pair_with(256, max_write);
        FixtureParts {
            store,
            nonces,
            signer,
            pc_dh_pub,
            qr_tx,
            qr_rx: Some(qr_rx),
            ta,
            tb,
            _dir: dir,
        }
    }

    fn display_to(qr_tx: &mpsc::Sender<String>) -> impl FnMut(&PairingQr) + '_ {
        move |qr| {
            // try_send, never blocking_send: this closure runs ON the
            // async runtime, where blocking would panic. Capacity 4 with
            // one parked consumer means the slot is always free; a
            // failure here is a loud wiring bug, not a retry case.
            let payload = qr.encode().unwrap();
            qr_tx
                .try_send(payload)
                .expect("qr channel must be idle between ceremonies");
        }
    }

    #[tokio::test]
    async fn full_pairing_reaches_paired_and_both_sides_store_peer() {
        let FixtureParts {
            _dir,
            store,
            mut nonces,
            signer,
            pc_dh_pub,
            qr_tx,
            mut qr_rx,
            mut ta,
            mut tb,
        } = fixture();

        let phone_link = tb.connect(Duration::ZERO).await.unwrap();
        drop(tb);
        let handle = spawn_phone(phone_link, phone_keys(), qr_rx.take().unwrap(), Mode::Valid);

        let mut ctx = CeremonyContext {
            pc_id_secret: &signer,
            pc_dh_pub,
            pc_name: "dev-pc".into(),
            service_uuid_bytes: crate::transport::ids::service_uuid_bytes(),
            store: &store,
            nonces: &mut nonces,
        };
        let peer = run_pairing(
            &mut ta,
            &mut ctx,
            CeremonyLimits::raw(60, 10, 300),
            &OsEntropy,
            display_to(&qr_tx),
        )
        .await
        .expect("valid pairing must reach PAIRED");

        assert_eq!(peer.phone_id_pub.len(), 32);

        let stored = store.list().unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].id_pub, peer.phone_id_pub);
        assert_eq!(stored[0].dh_pub, peer.phone_dh_pub);
        assert_eq!(
            stored[0].phone_id,
            crate::storage::pairings::phone_id_for(&peer.phone_id_pub)
        );

        let phone = handle
            .await
            .unwrap()
            .expect("phone verified and stored PC identity");
        assert_eq!(phone.pc_id_pub, signer.public_key().to_bytes());
        assert_eq!(phone.pc_dh_pub, pc_dh_pub);
        assert!(phone.confirm_frames > 1, "Confirm must use multiple frames");
        assert!(phone.ack_frames > 1, "Ack must use multiple frames");
    }

    #[tokio::test]
    async fn pairing_qr_static_key_continues_into_noise_kk() {
        let dir = tempfile::tempdir().unwrap();
        let identity_path = dir.path().join("identity.enc");
        let key_provider = MockKeyProvider::default();
        let generated = StoredIdentity::generate(&OsEntropy).unwrap();
        generated
            .save(&identity_path, &key_provider, &CounterEntropy)
            .unwrap();
        let pc_identity = StoredIdentity::load(&identity_path, &key_provider).unwrap();
        let pc_dh_pub = pc_identity.x25519_public_key();
        let pc_signer = pc_identity.identity_key();

        let pairings = PairingsDb::open(&dir.path().join("pairings.db")).unwrap();
        let mut nonces = NonceGuard::open(&dir.path().join("nonces.bin"));
        let (qr_tx, qr_rx) = mpsc::channel(4);
        let (mut pc_transport, mut phone_transport) = MockTransport::pair_with(256, 24);
        let phone_link = phone_transport.connect(Duration::ZERO).await.unwrap();
        drop(phone_transport);
        let phone_keys = phone_keys();
        let phone_keys_for_ceremony = phone_keys.clone();
        let phone_task = spawn_phone(phone_link, phone_keys_for_ceremony, qr_rx, Mode::Valid);

        let mut context = CeremonyContext {
            pc_id_secret: &pc_signer,
            pc_dh_pub,
            pc_name: "dev-pc".into(),
            service_uuid_bytes: crate::transport::ids::service_uuid_bytes(),
            store: &pairings,
            nonces: &mut nonces,
        };
        let paired = run_pairing(
            &mut pc_transport,
            &mut context,
            CeremonyLimits::raw(60, 10, 300),
            &OsEntropy,
            display_to(&qr_tx),
        )
        .await
        .expect("valid framed pairing completes");
        let phone_view = phone_task
            .await
            .unwrap()
            .expect("phone verified and stored the Ack");

        assert_eq!(phone_view.pc_dh_pub, pc_identity.x25519_public_key());
        assert_ne!(phone_view.pc_dh_pub, *pc_identity.x25519_secret.expose());
        let stored_phone = pairings.list().unwrap().pop().unwrap();
        assert_eq!(stored_phone.id_pub, paired.phone_id_pub);
        assert_eq!(stored_phone.dh_pub, paired.phone_dh_pub);

        // The phone pins the QR value as its Noise remote static. The PC
        // responder uses the matching secret loaded from encrypted storage.
        let phone_identity = PeerIdentity {
            local_static: crate::crypto::Secret::from_bytes(phone_keys.dh_secret.to_bytes()),
            remote_static: phone_view.pc_dh_pub,
        };
        let pc_session_identity = PeerIdentity {
            local_static: crate::crypto::Secret::from_bytes(*pc_identity.x25519_secret.expose()),
            remote_static: stored_phone.dh_pub,
        };
        let mut phone_handshake =
            SessionHandshake::begin(Role::Initiator, &phone_identity).unwrap();
        let mut pc_handshake =
            SessionHandshake::begin(Role::Responder, &pc_session_identity).unwrap();
        let first = phone_handshake.write_message(b"").unwrap();
        pc_handshake.read_message(&first).unwrap();
        let second = pc_handshake.write_message(b"").unwrap();
        phone_handshake.read_message(&second).unwrap();

        let params = SessionParams::spec_defaults();
        let mut phone_session = phone_handshake.establish(params).unwrap();
        let mut pc_session = pc_handshake.establish(params).unwrap();
        let sealed = phone_session.send(b"paired static key continuity").unwrap();
        assert_eq!(
            pc_session.receive(&sealed).unwrap(),
            b"paired static key continuity"
        );
    }

    #[tokio::test]
    async fn wrong_signer_rejected_nothing_persisted() {
        let FixtureParts {
            _dir,
            store,
            mut nonces,
            signer,
            pc_dh_pub,
            qr_tx,
            mut qr_rx,
            mut ta,
            mut tb,
        } = fixture();

        let phone_link = tb.connect(Duration::ZERO).await.unwrap();
        drop(tb);
        let handle = spawn_phone(
            phone_link,
            phone_keys(),
            qr_rx.take().unwrap(),
            Mode::WrongSigner,
        );

        let mut ctx = CeremonyContext {
            pc_id_secret: &signer,
            pc_dh_pub,
            pc_name: "dev-pc".into(),
            service_uuid_bytes: crate::transport::ids::service_uuid_bytes(),
            store: &store,
            nonces: &mut nonces,
        };
        let result = run_pairing(
            &mut ta,
            &mut ctx,
            CeremonyLimits::raw(60, 10, 300),
            &OsEntropy,
            display_to(&qr_tx),
        )
        .await;

        assert!(matches!(result, Err(PairingError::GenericFailed)));
        assert_eq!(store.count().unwrap(), 0, "nothing persisted on rejection");
        let _ = handle.await.unwrap();
    }

    #[tokio::test]
    async fn tampered_dh_field_rejected_cleanly() {
        let FixtureParts {
            _dir,
            store,
            mut nonces,
            signer,
            pc_dh_pub,
            qr_tx,
            mut qr_rx,
            mut ta,
            mut tb,
        } = fixture();

        let phone_link = tb.connect(Duration::ZERO).await.unwrap();
        drop(tb);
        let handle = spawn_phone(
            phone_link,
            phone_keys(),
            qr_rx.take().unwrap(),
            Mode::TamperedDh,
        );

        let mut ctx = CeremonyContext {
            pc_id_secret: &signer,
            pc_dh_pub,
            pc_name: "dev-pc".into(),
            service_uuid_bytes: crate::transport::ids::service_uuid_bytes(),
            store: &store,
            nonces: &mut nonces,
        };
        let result = run_pairing(
            &mut ta,
            &mut ctx,
            CeremonyLimits::raw(60, 10, 300),
            &OsEntropy,
            display_to(&qr_tx),
        )
        .await;
        assert!(matches!(result, Err(PairingError::GenericFailed)));
        assert_eq!(store.count().unwrap(), 0);
        let _ = handle.await.unwrap();
    }

    #[tokio::test]
    async fn stale_context_confirm_rejected_as_generic() {
        let FixtureParts {
            _dir,
            store,
            mut nonces,
            signer,
            pc_dh_pub,
            qr_tx,
            mut qr_rx,
            mut ta,
            mut tb,
        } = fixture();

        let phone_link = tb.connect(Duration::ZERO).await.unwrap();
        drop(tb);
        let handle = spawn_phone(
            phone_link,
            phone_keys(),
            qr_rx.take().unwrap(),
            Mode::StaleContext,
        );

        let mut ctx = CeremonyContext {
            pc_id_secret: &signer,
            pc_dh_pub,
            pc_name: "dev-pc".into(),
            service_uuid_bytes: crate::transport::ids::service_uuid_bytes(),
            store: &store,
            nonces: &mut nonces,
        };
        let result = run_pairing(
            &mut ta,
            &mut ctx,
            CeremonyLimits::raw(60, 10, 300),
            &OsEntropy,
            display_to(&qr_tx),
        )
        .await;
        assert!(matches!(result, Err(PairingError::GenericFailed)));
        assert_eq!(store.count().unwrap(), 0);
        let _ = handle.await.unwrap();
    }

    #[tokio::test]
    async fn malformed_frame_fails_closed_without_persisting() {
        let FixtureParts {
            _dir,
            store,
            mut nonces,
            signer,
            pc_dh_pub,
            mut ta,
            mut tb,
            ..
        } = fixture();
        let mut phone_link = tb.connect(Duration::ZERO).await.unwrap();
        drop(tb);

        let malformed = crate::wire::framing::encode_frame(
            0,
            crate::wire::framing::FLAG_START | 0b1000,
            b"bad",
        );
        phone_link.send(&malformed).await.unwrap();

        let mut ctx = CeremonyContext {
            pc_id_secret: &signer,
            pc_dh_pub,
            pc_name: "dev-pc".into(),
            service_uuid_bytes: crate::transport::ids::service_uuid_bytes(),
            store: &store,
            nonces: &mut nonces,
        };
        let result = run_pairing(
            &mut ta,
            &mut ctx,
            CeremonyLimits::raw(60, 10, 300),
            &OsEntropy,
            |_| {},
        )
        .await;

        assert!(matches!(result, Err(PairingError::GenericFailed)));
        assert_eq!(store.count().unwrap(), 0);
    }

    #[tokio::test]
    async fn truncated_confirm_then_disconnect_fails_closed_without_persisting() {
        let FixtureParts {
            _dir,
            store,
            mut nonces,
            signer,
            pc_dh_pub,
            qr_tx,
            mut qr_rx,
            mut ta,
            mut tb,
        } = fixture();
        let mut phone_link = tb.connect(Duration::ZERO).await.unwrap();
        drop(tb);
        let mut qr_rx = qr_rx.take().unwrap();
        let keys = phone_keys();
        let phone = tokio::spawn(async move {
            let text = qr_rx.recv().await?;
            let qr = PairingQr::parse(&text, unix_now()).ok()?;
            let confirm = valid_confirm_for(&qr, &keys);
            let bytes = crate::pairing::messages::encode_confirm_message(&confirm).ok()?;
            let (frames, _) = split_message(&bytes, phone_link.max_write_len(), 0).ok()?;
            assert!(frames.len() > 1);
            phone_link.send(&frames[0]).await.ok()?;
            phone_link.shutdown();
            Some(())
        });

        let mut ctx = CeremonyContext {
            pc_id_secret: &signer,
            pc_dh_pub,
            pc_name: "dev-pc".into(),
            service_uuid_bytes: crate::transport::ids::service_uuid_bytes(),
            store: &store,
            nonces: &mut nonces,
        };
        let result = run_pairing(
            &mut ta,
            &mut ctx,
            CeremonyLimits::raw(60, 10, 300),
            &OsEntropy,
            display_to(&qr_tx),
        )
        .await;

        assert!(matches!(result, Err(PairingError::GenericFailed)));
        assert_eq!(store.count().unwrap(), 0);
        assert_eq!(phone.await.unwrap(), Some(()));
    }

    #[tokio::test]
    async fn confirm_timeout_covers_the_entire_trickled_framed_message() {
        let FixtureParts {
            _dir,
            store,
            mut nonces,
            signer,
            pc_dh_pub,
            qr_tx,
            mut qr_rx,
            mut ta,
            mut tb,
        } = fixture_with_max_write(14);
        let mut phone_link = tb.connect(Duration::ZERO).await.unwrap();
        drop(tb);
        let mut qr_rx = qr_rx.take().unwrap();
        let keys = phone_keys();
        let phone = tokio::spawn(async move {
            let text = qr_rx.recv().await?;
            let qr = PairingQr::parse(&text, unix_now()).ok()?;
            let confirm = valid_confirm_for(&qr, &keys);
            let bytes = crate::pairing::messages::encode_confirm_message(&confirm).ok()?;
            let (frames, _) = split_message(&bytes, phone_link.max_write_len(), 0).ok()?;
            assert!(
                frames.len() >= 8,
                "confirm must span enough frames to trickle"
            );
            for (index, frame) in frames.iter().enumerate() {
                if index > 0 {
                    tokio::time::sleep(Duration::from_millis(30)).await;
                }
                if phone_link.send(frame).await.is_err() {
                    break;
                }
            }
            Some(())
        });

        let mut ctx = CeremonyContext {
            pc_id_secret: &signer,
            pc_dh_pub,
            pc_name: "dev-pc".into(),
            service_uuid_bytes: crate::transport::ids::service_uuid_bytes(),
            store: &store,
            nonces: &mut nonces,
        };
        let result = run_pairing(
            &mut ta,
            &mut ctx,
            CeremonyLimits {
                qr_ttl: Duration::from_secs(60),
                confirm_timeout: Duration::from_millis(125),
                total_budget: Duration::from_secs(300),
            },
            &OsEntropy,
            display_to(&qr_tx),
        )
        .await;

        assert!(
            matches!(result, Err(PairingError::ConfirmTimedOut)),
            "expected whole-operation timeout, got {result:?}"
        );
        assert_eq!(store.count().unwrap(), 0);
        let _ = phone.await.unwrap();
    }

    #[tokio::test]
    async fn queued_extra_application_message_is_rejected_and_nonce_is_burned() {
        let FixtureParts {
            _dir,
            store,
            mut nonces,
            signer,
            pc_dh_pub,
            qr_tx,
            mut qr_rx,
            mut ta,
            mut tb,
        } = fixture_with_max_write(512);
        let mut phone_link = tb.connect(Duration::ZERO).await.unwrap();
        drop(tb);
        let mut qr_rx = qr_rx.take().unwrap();
        let keys = phone_keys();
        let forced_nonce = [0x6D; 32];
        let phone = tokio::spawn(async move {
            let text = qr_rx.recv().await?;
            let qr = PairingQr::parse(&text, unix_now()).ok()?;
            let confirm = valid_confirm_for(&qr, &keys);
            let confirm_bytes = crate::pairing::messages::encode_confirm_message(&confirm).ok()?;
            let (confirm_frames, next_seq) =
                split_message(&confirm_bytes, phone_link.max_write_len(), 0).ok()?;
            let extra_bytes = encode(&WireMessage::Ping(crate::wire::message::Ping {
                req_id: crate::wire::message::ReqId([0x91; 16]),
                timestamp: 1_700_000_000,
            }))
            .ok()?;
            let (extra_frames, _) =
                split_message(&extra_bytes, phone_link.max_write_len(), next_seq).ok()?;

            // Send one frame per Link chunk, like Android's BLE notifier.
            // The PC must inspect chunks already queued when Confirm ends
            // so a second application message cannot slip through.
            for frame in confirm_frames.into_iter().chain(extra_frames) {
                phone_link.send(&frame).await.ok()?;
            }
            Some(())
        });

        let mut ctx = CeremonyContext {
            pc_id_secret: &signer,
            pc_dh_pub,
            pc_name: "dev-pc".into(),
            service_uuid_bytes: crate::transport::ids::service_uuid_bytes(),
            store: &store,
            nonces: &mut nonces,
        };
        let result = run_pairing(
            &mut ta,
            &mut ctx,
            CeremonyLimits::raw(60, 10, 300),
            &FixedEntropy(forced_nonce.to_vec()),
            display_to(&qr_tx),
        )
        .await;

        assert!(matches!(result, Err(PairingError::GenericFailed)));
        assert_eq!(store.count().unwrap(), 0);
        assert!(
            nonces.contains(&forced_nonce),
            "complete invalid batch burns nonce"
        );
        assert_eq!(phone.await.unwrap(), Some(()));
    }

    #[tokio::test]
    async fn pairing_decoder_rejects_trailing_cbor_and_burns_nonce() {
        let FixtureParts {
            _dir,
            store,
            mut nonces,
            signer,
            pc_dh_pub,
            qr_tx,
            mut qr_rx,
            mut ta,
            mut tb,
        } = fixture();
        let mut phone_link = tb.connect(Duration::ZERO).await.unwrap();
        drop(tb);
        let mut qr_rx = qr_rx.take().unwrap();
        let keys = phone_keys();
        let forced_nonce = [0x7E; 32];
        let phone = tokio::spawn(async move {
            let text = qr_rx.recv().await?;
            let qr = PairingQr::parse(&text, unix_now()).ok()?;
            let confirm = valid_confirm_for(&qr, &keys);
            let mut bytes = crate::pairing::messages::encode_confirm_message(&confirm).ok()?;
            bytes.push(0);
            let (frames, _) = split_message(&bytes, phone_link.max_write_len(), 0).ok()?;
            for frame in frames {
                phone_link.send(&frame).await.ok()?;
            }
            Some(())
        });

        let mut ctx = CeremonyContext {
            pc_id_secret: &signer,
            pc_dh_pub,
            pc_name: "dev-pc".into(),
            service_uuid_bytes: crate::transport::ids::service_uuid_bytes(),
            store: &store,
            nonces: &mut nonces,
        };
        let result = run_pairing(
            &mut ta,
            &mut ctx,
            CeremonyLimits::raw(60, 10, 300),
            &FixedEntropy(forced_nonce.to_vec()),
            display_to(&qr_tx),
        )
        .await;

        assert!(matches!(result, Err(PairingError::GenericFailed)));
        assert_eq!(store.count().unwrap(), 0);
        assert!(nonces.contains(&forced_nonce));
        assert_eq!(phone.await.unwrap(), Some(()));
    }

    #[tokio::test]
    async fn silent_phone_times_out_cleanly() {
        let FixtureParts {
            _dir,
            store,
            mut nonces,
            signer,
            pc_dh_pub,
            qr_tx: _,
            qr_rx: _,
            mut ta,
            mut tb,
        } = fixture();

        let _link = tb.connect(Duration::ZERO).await.unwrap();
        drop(tb);

        let mut ctx = CeremonyContext {
            pc_id_secret: &signer,
            pc_dh_pub,
            pc_name: "dev-pc".into(),
            service_uuid_bytes: crate::transport::ids::service_uuid_bytes(),
            store: &store,
            nonces: &mut nonces,
        };
        let result = run_pairing(
            &mut ta,
            &mut ctx,
            CeremonyLimits::raw(60, 1, 300),
            &OsEntropy,
            |_| {},
        )
        .await;
        assert!(matches!(result, Err(PairingError::ConfirmTimedOut)));
        assert_eq!(store.count().unwrap(), 0);
    }

    /// A transport that never advertises: proves clean QrExpired.
    struct NeverTransport;

    impl Transport for NeverTransport {
        type Link = crate::transport::mock::MockLink;

        async fn connect(&mut self, _t: Duration) -> Result<Self::Link, TransportError> {
            std::future::pending().await
        }
    }

    #[tokio::test(start_paused = true)]
    async fn qr_expiry_without_advertiser_is_clean() {
        let FixtureParts {
            _dir,
            store,
            mut nonces,
            signer,
            pc_dh_pub,
            qr_tx: _,
            qr_rx: _,
            ta: _,
            tb: _,
        } = fixture();
        let mut transport = NeverTransport;

        let mut ctx = CeremonyContext {
            pc_id_secret: &signer,
            pc_dh_pub,
            pc_name: "dev-pc".into(),
            service_uuid_bytes: crate::transport::ids::service_uuid_bytes(),
            store: &store,
            nonces: &mut nonces,
        };
        let result = run_pairing(
            &mut transport,
            &mut ctx,
            CeremonyLimits::raw(2, 1, 300),
            &OsEntropy,
            |_| {},
        )
        .await;
        assert!(matches!(result, Err(PairingError::QrExpired)));
        assert_eq!(store.count().unwrap(), 0);
    }

    #[tokio::test]
    async fn replayed_nonce_is_caught_by_the_gate() {
        let FixtureParts {
            _dir,
            store,
            mut nonces,
            signer,
            pc_dh_pub,
            qr_tx,
            mut qr_rx,
            mut ta,
            mut tb,
        } = fixture();

        // Fixed entropy makes run_pairing mint this exact nonce, which an
        // earlier ceremony already consumed -- so the replay gate trips.
        // No driver copy needed: the real run_pairing runs, seam and all.
        let forced_nonce = [0x42u8; 32];
        assert!(!nonces.record_and_check(&forced_nonce));

        let phone_link = tb.connect(Duration::ZERO).await.unwrap();
        drop(tb);
        let handle = spawn_phone(phone_link, phone_keys(), qr_rx.take().unwrap(), Mode::Valid);

        let mut ctx = CeremonyContext {
            pc_id_secret: &signer,
            pc_dh_pub,
            pc_name: "dev-pc".into(),
            service_uuid_bytes: crate::transport::ids::service_uuid_bytes(),
            store: &store,
            nonces: &mut nonces,
        };
        let result = run_pairing(
            &mut ta,
            &mut ctx,
            CeremonyLimits::raw(60, 10, 300),
            &FixedEntropy(forced_nonce.to_vec()),
            display_to(&qr_tx),
        )
        .await;

        assert!(matches!(result, Err(PairingError::ReplayedNonce)));
        assert_eq!(store.count().unwrap(), 0);
        let _ = handle.await.unwrap();
    }
}
