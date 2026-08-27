//! Scripted mock phone for end-to-end testing WITHOUT radio hardware.
//!
//! Compiled only under the `mock-phone` cargo feature and activated
//! only by an explicit flag at startup. This is what lets a REAL MCP
//! client (mcp-inspector, Claude Code) drive a REAL daemon binary plus
//! this phone through the complete approval/execution flow on a laptop.
//!
//! Behavior is deliberately boring and deterministic:
//!
//! * Pairs itself into `pairings.db` (`record_pairing`) so no BLE
//!   ceremony is needed;
//! * Answers every ApprovalRequest with a signed APPROVAL;
//! * Executes every ExecuteRequest "successfully" (echoes the request,
//!   HTTP 200, signature included);
//! * Answers list_services with a fixed set; pings with pongs.
//!
//! Every protocol exchange is appended as JSONL to the file named by
//! CONVEYANCE_MOCK_PHONE_LOG (if set) AND mirrored to stderr, so E2E
//! verification can assert against the phone side of the story just
//! like the real approvals.db would allow after phase 10.
//!
//! Deliberately distinct from the daemon's in-process test harness
//! (`test_support::mock_phone_task` in lib.rs): this one is
//! always-approve and never waits on a scripted channel, because a real
//! MCP client sits on the other end. The harness one scripts denials,
//! timeouts, and forged signatures for unit tests. The shared
//! happy-path handling is small enough that keeping the two apart is
//! cheaper than one cfg-branched serve loop.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use conveyance_core::crypto::dh::DhSecret;
use conveyance_core::crypto::sign::IdentitySecretKey;
use conveyance_core::crypto::{OsEntropy, Secret};
use conveyance_core::session::{PeerIdentity, Role, Session as CoreSession, SessionHandshake};
use conveyance_core::storage::StorageError;
use conveyance_core::storage::pairings::PairingsDb;
use conveyance_core::time::unix_now;
use conveyance_core::transport::mock::{MockLink, MockTransport};
use conveyance_core::transport::{InboundAssembler, Transport};
use conveyance_core::wire::framing;
use conveyance_core::wire::message::{
    self as wire, ApprovalResponse, Decision, ExecuteResponse, Status,
};

use crate::phone::{PhoneDialer, PhoneLink};

/// The in-memory keychain stub, re-exported so E2E tooling that only
/// depends on this module keeps one import. The implementation lives in
/// `conveyance_core::test_support`.
pub use conveyance_core::test_support::MockKeyProvider;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One scripted phone. Fixed identity generated at construction so the
/// pairing row matches every session this process ever dials.
pub struct MockPhone {
    signer: IdentitySecretKey,
    dh: DhSecret,
    /// The PC's X25519 static, learned "at pairing time" -- KK requires
    /// each side to hold the peer's static.
    pc_dh_pub: [u8; 32],
    log_file: Option<PathBuf>,
}

impl MockPhone {
    /// Build with the PC's DH static; without it no KK handshake can
    /// run, which is exactly the pairing-time dependency the ceremony
    /// would satisfy.
    pub fn new(pc_dh_pub: [u8; 32]) -> Self {
        Self {
            signer: IdentitySecretKey::generate(&OsEntropy).unwrap(),
            dh: DhSecret::generate(&OsEntropy).unwrap(),
            pc_dh_pub,
            log_file: std::env::var("CONVEYANCE_MOCK_PHONE_LOG")
                .ok()
                .map(PathBuf::from),
        }
    }

    /// Insert/refresh this phone's pairing row. Idempotent upsert --
    /// the same write the ceremony performs on success.
    pub fn record_pairing(&self, store: &PairingsDb) -> Result<(), StorageError> {
        store.record(
            self.signer.public_key().to_bytes(),
            self.dh.public_key().to_bytes(),
            unix_now(),
        )?;
        Ok(())
    }

    /// The pairing handle this phone is known by (same derivation as
    /// `pairings.phone_id_for`, applied to this phone's identity key).
    pub fn phone_id(&self) -> String {
        conveyance_core::storage::pairings::phone_id_for(&self.signer.public_key().to_bytes())
    }

    /// Dialer for daemon assembly. Arc-shared so every dial serves the
    /// same identity and transcript.
    pub fn dialer(self: &Arc<Self>) -> impl PhoneDialer + 'static {
        MockPhoneDialer {
            phone: Arc::clone(self),
        }
    }

    fn note_transcript(&self, event: &str, detail: serde_json::Value) {
        let line =
            serde_json::json!({ "ts": unix_now(), "event": event, "detail": detail }).to_string();
        if let Some(path) = &self.log_file {
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            {
                let _ = writeln!(f, "{line}");
            }
        }
        eprintln!("MOCK-PHONE {line}");
    }
}

/// Dialer half handed to daemon assembly: mints a fresh cross-wired
/// transport pair per dial and spawns this phone's serve loop opposite
/// the daemon link.
pub struct MockPhoneDialer {
    phone: Arc<MockPhone>,
}

impl PhoneDialer for MockPhoneDialer {
    fn dial(
        &mut self,
        _timeout: Duration,
    ) -> BoxFuture<'_, Result<Box<dyn PhoneLink>, conveyance_core::transport::TransportError>> {
        let phone = Arc::clone(&self.phone);
        Box::pin(async move {
            let (mut t_daemon, mut t_phone) = MockTransport::pair();
            let daemon_link = t_daemon.connect(Duration::ZERO).await?;
            let phone_link = t_phone.connect(Duration::ZERO).await?;

            tokio::spawn(mock_phone_serve(Arc::clone(&phone), phone_link));
            Ok(Box::new(daemon_link) as Box<dyn PhoneLink>)
        })
    }
}

/// The phone's whole life per connection: KK handshake as INITIATOR
/// (its permanent role per spec), then scripted protocol service until
/// the transport dies.
async fn mock_phone_serve(phone: Arc<MockPhone>, mut link: MockLink) {
    let peer = PeerIdentity {
        local_static: Secret::from_bytes(phone.dh.to_bytes()),
        remote_static: phone.pc_dh_pub,
    };
    let mut hs = match SessionHandshake::begin(Role::Initiator, &peer) {
        Ok(hs) => hs,
        Err(_) => return,
    };

    // One IO half for the whole connection: framing sequence numbers
    // must continue across handshake -> transport.
    let mut io = PhoneIo::new(&mut link);

    let m1 = match hs.write_message(b"") {
        Ok(m) => m,
        Err(_) => return,
    };
    if io.send_app(&m1).await.is_err() {
        return;
    }
    let Some(m2) = io.recv_app().await else {
        return;
    };
    if hs.read_message(&m2).is_err() {
        return;
    }
    let mut session = match hs.establish(conveyance_core::session::SessionParams::spec_defaults()) {
        Ok(s) => s,
        Err(_) => return,
    };
    phone.note_transcript("session_established", serde_json::json!({}));

    loop {
        let Some(cipher) = io.recv_app().await else {
            phone.note_transcript("transport_closed", serde_json::json!({}));
            break;
        };
        // Decrypt BEFORE decoding: frames carry Noise ciphertext.
        let Ok(plain) = session.receive(&cipher) else {
            phone.note_transcript("decrypt_failed", serde_json::json!({}));
            break;
        };
        let decoded: Option<wire::WireMessage> = ciborium::de::from_reader(&mut &plain[..]).ok();
        let Some(message) = decoded else {
            phone.note_transcript("undecodable_plaintext", serde_json::json!({}));
            break;
        };

        match message {
            wire::WireMessage::Ping(p) => {
                let pong = wire::WireMessage::Pong(wire::Pong {
                    req_id: p.req_id,
                    timestamp: p.timestamp,
                });
                if let Ok(bytes) = wire::encode(&pong)
                    && io.send_encrypted(&mut session, &bytes).await.is_err()
                {
                    break;
                }
            }
            wire::WireMessage::ApprovalRequest(req) => {
                phone.note_transcript(
                    "approval_request",
                    serde_json::json!({
                        "service": req.service,
                        "method": req.method,
                        "endpoint": req.endpoint,
                        "params": req.params,
                        "requested_by": req.requested_by,
                    }),
                );
                let rsp = ApprovalResponse::approved_or_denied(
                    req.req_id,
                    Decision::Approved,
                    None,
                    &phone.signer,
                );
                phone.note_transcript("approval_granted", serde_json::json!({}));
                if let Ok(bytes) = wire::encode(&wire::WireMessage::ApprovalResponse(rsp))
                    && io.send_encrypted(&mut session, &bytes).await.is_err()
                {
                    break;
                }
            }
            wire::WireMessage::ExecuteRequest(req) => {
                phone.note_transcript(
                    "execute_request",
                    serde_json::json!({
                        "service": req.service,
                        "method": req.method,
                        "endpoint": req.endpoint,
                    }),
                );
                let body = serde_json::json!({
                    "echo": {
                        "service": req.service,
                        "method": req.method,
                        "endpoint": req.endpoint,
                        "params": req.params,
                    },
                    "phone": "mock",
                });
                let rsp =
                    match ExecuteResponse::new(req.req_id, Status::Ok, Some(200), body, unix_now())
                    {
                        Ok(unsigned) => unsigned.sign(&phone.signer),
                        Err(_) => break,
                    };
                phone.note_transcript(
                    "execute_result",
                    serde_json::json!({ "status": "ok", "http_status": 200 }),
                );
                if let Ok(bytes) = wire::encode(&wire::WireMessage::ExecuteResponse(rsp))
                    && io.send_encrypted(&mut session, &bytes).await.is_err()
                {
                    break;
                }
            }
            wire::WireMessage::ListServicesRequest(req) => {
                phone.note_transcript("list_services_request", serde_json::json!({}));
                let rsp = wire::WireMessage::ListServicesResponse(wire::ListServicesResponse {
                    req_id: req.req_id,
                    services: vec!["github".into(), "aws".into()],
                });
                phone.note_transcript(
                    "list_services_response",
                    serde_json::json!({ "services": ["github", "aws"] }),
                );
                if let Ok(bytes) = wire::encode(&rsp)
                    && io.send_encrypted(&mut session, &bytes).await.is_err()
                {
                    break;
                }
            }
            other => {
                phone.note_transcript(
                    "unsolicited_message",
                    serde_json::json!({ "kind": format!("{other:?}") }),
                );
            }
        }
    }
}

/// Framed app-message IO over a MockLink for the phone side. Kept
/// local to this module: the shape is trivial and the alternative is
/// exporting test plumbing from production surfaces.
struct PhoneIo<'a> {
    link: &'a mut MockLink,
    assembler: InboundAssembler,
    tx_seq: u16,
}

impl<'a> PhoneIo<'a> {
    fn new(link: &'a mut MockLink) -> Self {
        Self {
            link,
            assembler: InboundAssembler::new(),
            tx_seq: 0,
        }
    }

    async fn send_app(&mut self, bytes: &[u8]) -> Result<(), ()> {
        let max = self.link.max_write_len();
        let (frames, next) = framing::split_message(bytes, max, self.tx_seq).map_err(|_| ())?;
        self.tx_seq = next;
        for f in frames {
            self.link.send(&f).await.map_err(|_| ())?;
        }
        Ok(())
    }

    async fn recv_app(&mut self) -> Option<Vec<u8>> {
        loop {
            match self.link.recv().await {
                Err(_) => return None,
                Ok(chunk) => match self.assembler.ingest(&chunk) {
                    Ok(msgs) if !msgs.is_empty() => return msgs.into_iter().next(),
                    Ok(_) => continue,
                    Err(_) => return None,
                },
            }
        }
    }

    async fn send_encrypted(
        &mut self,
        session: &mut CoreSession,
        plaintext: &[u8],
    ) -> Result<(), ()> {
        let cipher = session.send(plaintext).map_err(|_| ())?;
        self.send_app(&cipher).await
    }
}
