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
use crate::transport::Link;

use crate::crypto::sign::IdentitySecretKey;
use crate::storage::pairings::PairingsDb;
use crate::transport::Transport;
use crate::wire::message::{WireMessage, decode, encode};

use super::PairingError;
use super::machine::{self, Event, PairingState};
use super::messages::PairingAck;
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

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Run the full ceremony. Shows ONE QR via `display`, waits within the
/// QR window for the phone to advertise and connect, takes ONE confirm,
/// answers with the Ack, persists the peer. Any rejection returns Err
/// with the nonce burned; rerun `conveyance pair` for a fresh code.
pub async fn run_pairing<T, D>(
    transport: &mut T,
    ctx: &mut CeremonyContext<'_>,
    limits: CeremonyLimits,
    mut display: D,
) -> Result<PairedPeer, PairingError>
where
    T: Transport,
    T::Link: Link + Send,
    D: FnMut(&PairingQr),
{
    // ---- QR_DISPLAYED ---------------------------------------------------
    let started = tokio::time::Instant::now();
    let qr_deadline = started + limits.qr_ttl;

    let mut nonce = [0u8; 32];
    crate::crypto::OsEntropy.fill(&mut nonce)?;
    let pc_id_pub = ctx.pc_id_secret.public_key().to_bytes();

    let qr = PairingQr::new(
        now_unix(),
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

    let inbound = match tokio::time::timeout(limits.confirm_timeout, Box::pin(link.recv())).await {
        Err(_) => fail_via!(Event::ConfirmTimeout, PairingError::ConfirmTimedOut),
        Ok(Err(_)) => {
            // Transport died before any confirm existed. Nothing was ever
            // received, so there is no replay to record; the nonce dies
            // with this QR regardless.
            return Err(PairingError::GenericFailed);
        }
        Ok(Ok(chunk)) => chunk,
    };

    let confirm = match decode(&inbound) {
        Ok(WireMessage::PairingConfirm(c)) => c,
        _ => fail_via!(Event::InvalidConfirm, PairingError::GenericFailed),
    };

    // Replay gate FIRST: consumes the nonce whatever happens next.
    if ctx.nonces.record_and_check(&nonce) {
        eprintln!("pairing rejected: replayed pairing nonce");
        fail_via!(Event::InvalidConfirm, PairingError::ReplayedNonce);
    }

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
    if let Err(e) = link.send(&encode(&WireMessage::PairingAck(ack))?).await {
        state = machine::step(state, Event::AckWriteFailed).expect("ack failure while ACK_SENT");
        debug_assert_eq!(state, PairingState::Unpaired);
        return Err(PairingError::Transport(e.to_string()));
    }

    // ---- PAIRED ----------------------------------------------------------
    state = machine::step(state, Event::AckWrittenOk).expect("ack ok while ACK_SENT");
    debug_assert_eq!(state, PairingState::Paired);

    let record = ctx
        .store
        .record(confirm.phone_id_pub, confirm.phone_dh_pub, now_unix())?;

    Ok(PairedPeer {
        phone_id_pub: record.id_pub,
        phone_dh_pub: record.dh_pub,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::OsEntropy;
    use crate::crypto::dh::DhSecret;
    use crate::crypto::sign::IdentityPublicKey;
    use crate::crypto::test_support::CounterEntropy;
    use crate::pairing::messages::PairingConfirm;
    use crate::storage::pairings::PairingsDb;
    use crate::transport::TransportError;
    use crate::transport::mock::MockTransport;
    use tokio::sync::mpsc;

    #[derive(Clone)]
    struct PhoneKeys {
        id_secret: IdentitySecretKey,
        id_pub: [u8; 32],
        dh_pub: [u8; 32],
    }

    fn phone_keys() -> PhoneKeys {
        let id_secret = IdentitySecretKey::generate(&CounterEntropy).unwrap();
        let dh = DhSecret::generate(&OsEntropy).unwrap();
        let id_pub = id_secret.public_key().to_bytes();
        let dh_pub = dh.public_key().to_bytes();
        PhoneKeys {
            id_secret,
            id_pub,
            dh_pub,
        }
    }

    #[derive(Clone, Copy)]
    enum Mode {
        Valid,
        WrongSigner,
        TamperedDh,
        StaleContext,
    }

    type StoredPeer = ([u8; 32], [u8; 32]);

    /// Mock phone: parse the displayed QR, sign+send Confirm per mode,
    /// verify the Ack, and report what it stored about the PC.
    fn spawn_phone(
        mut link: <MockTransport as Transport>::Link,
        keys: PhoneKeys,
        mut qr_rx: mpsc::Receiver<String>,
        mode: Mode,
    ) -> tokio::task::JoinHandle<Option<StoredPeer>> {
        tokio::spawn(async move {
            let text = match qr_rx.recv().await {
                Some(t) => t,
                None => return None,
            };
            let qr = PairingQr::parse(&text, now_unix()).ok()?;

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

            let raw_confirm = encode(&WireMessage::PairingConfirm(confirm)).ok()?;
            link.send(&raw_confirm).await.ok()?;

            let raw_ack = link.recv().await.ok()?;
            match decode(&raw_ack).ok()? {
                WireMessage::PairingAck(ack) => {
                    let pc_public = IdentityPublicKey::from_bytes(&ack.pc_id_pub).ok()?;
                    ack.verify(&pc_public).ok()?;
                    Some((ack.pc_id_pub, qr.pc_dh_pub))
                }
                _ => None,
            }
        })
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
        let dir = tempfile::tempdir().unwrap();
        let store = PairingsDb::open(&dir.path().join("pairings.db")).unwrap();
        let nonces = NonceGuard::open(&dir.path().join("nonces.bin"));
        let signer = IdentitySecretKey::generate(&CounterEntropy).unwrap();
        let pc_dh_pub = DhSecret::generate(&OsEntropy)
            .unwrap()
            .public_key()
            .to_bytes();
        let (qr_tx, qr_rx) = mpsc::channel(4);
        let (ta, tb) = MockTransport::pair();
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

        let (pc_id, pc_dh) = handle.await.unwrap().expect("phone stored PC identity");
        assert_eq!(pc_id, signer.public_key().to_bytes());
        assert_eq!(pc_dh, pc_dh_pub);
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
            display_to(&qr_tx),
        )
        .await;
        assert!(matches!(result, Err(PairingError::GenericFailed)));
        assert_eq!(store.count().unwrap(), 0);
        let _ = handle.await.unwrap();
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
        let result = run_pairing(&mut ta, &mut ctx, CeremonyLimits::raw(60, 1, 300), |_| {}).await;
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
            |_| {},
        )
        .await;
        assert!(matches!(result, Err(PairingError::QrExpired)));
        assert_eq!(store.count().unwrap(), 0);
    }

    /// Test-only driver with a FORCED nonce: fresh entropy never
    /// collides, so replay needs this seam. Duplicates the small driver
    /// prologue deliberately -- production stays seam-free.
    async fn run_forced_nonce<D>(
        transport: &mut MockTransport,
        ctx: &mut CeremonyContext<'_>,
        limits: CeremonyLimits,
        forced_nonce: [u8; 32],
        mut display: D,
    ) -> Result<PairedPeer, PairingError>
    where
        D: FnMut(&PairingQr),
    {
        let qr_deadline = tokio::time::Instant::now() + limits.qr_ttl;
        let pc_id_pub = ctx.pc_id_secret.public_key().to_bytes();
        let qr = PairingQr::new(
            now_unix(),
            pc_id_pub,
            ctx.pc_dh_pub,
            forced_nonce,
            &ctx.pc_name,
            ctx.service_uuid_bytes,
        )?;
        display(&qr);

        let mut link = loop {
            if tokio::time::Instant::now() >= qr_deadline {
                return Err(PairingError::QrExpired);
            }
            let wait = qr_deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(wait.min(Duration::from_millis(50)), transport.connect(wait))
                .await
            {
                Err(_) => continue,
                Ok(Err(_)) => continue,
                Ok(Ok(link)) => break link,
            }
        };

        let inbound =
            match tokio::time::timeout(limits.confirm_timeout, Box::pin(link.recv())).await {
                Err(_) => return Err(PairingError::ConfirmTimedOut),
                Ok(Ok(chunk)) => chunk,
                Ok(Err(_)) => return Err(PairingError::GenericFailed),
            };
        let confirm = match decode(&inbound) {
            Ok(WireMessage::PairingConfirm(c)) => c,
            _ => return Err(PairingError::GenericFailed),
        };
        if ctx.nonces.record_and_check(&forced_nonce) {
            return Err(PairingError::ReplayedNonce);
        }
        let phone_public = match IdentityPublicKey::from_bytes(&confirm.phone_id_pub) {
            Ok(pk) => pk,
            Err(_) => return Err(PairingError::GenericFailed),
        };
        if confirm
            .verify(&phone_public, &pc_id_pub, &forced_nonce)
            .is_err()
        {
            return Err(PairingError::GenericFailed);
        }
        let ack = PairingAck::sign(
            ctx.pc_id_secret,
            &forced_nonce,
            &pc_id_pub,
            &confirm.phone_id_pub,
            &confirm.phone_dh_pub,
        );
        link.send(&encode(&WireMessage::PairingAck(ack))?)
            .await
            .map_err(|e| PairingError::Transport(e.to_string()))?;
        let record = ctx
            .store
            .record(confirm.phone_id_pub, confirm.phone_dh_pub, now_unix())?;
        Ok(PairedPeer {
            phone_id_pub: record.id_pub,
            phone_dh_pub: record.dh_pub,
        })
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

        let forced_nonce = [0x42u8; 32];
        // An earlier ceremony already consumed this nonce.
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
        let result = run_forced_nonce(
            &mut ta,
            &mut ctx,
            CeremonyLimits::raw(60, 10, 300),
            forced_nonce,
            |qr| {
                let payload = qr.encode().unwrap();
                qr_tx
                    .try_send(payload)
                    .expect("qr channel must be idle here");
            },
        )
        .await;

        assert!(matches!(result, Err(PairingError::ReplayedNonce)));
        assert_eq!(store.count().unwrap(), 0);
        let _ = handle.await.unwrap();
    }
}
