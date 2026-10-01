//! Rust-backed phone approval protocol bridge.
//!
//! Kotlin receives only validated display data and opaque request/session
//! handles. CBOR interpretation, canonical binding, response preimages,
//! and signing remain in Rust; identity private keys never cross UniFFI.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use conveyance_protocol::binding::ApprovedRequestTracker;
use conveyance_protocol::crypto::canonical_json::to_canonical_string;
use conveyance_protocol::message::{
    ApprovalRequest, ApprovalResponse, Decision, ExecuteRequest, ListServicesResponse, Pong, ReqId,
    WireMessage, decode as decode_wire, decode_approval_request, decode_execute_request, encode,
};
use conveyance_protocol::policy::{ApprovedDestination, PhoneApprovalPolicy, Tier3Reason};

use crate::sealed::UnlockedIdentity;

/// UI-safe failures. Detailed parser/cryptographic causes stay native.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ApprovalFfiError {
    #[error("approval request is invalid")]
    InvalidRequest,
    #[error("approval decision is invalid")]
    InvalidDecision,
    #[error("request already reached a terminal decision")]
    DuplicateDecision,
    #[error("request ID was already received on this session")]
    DuplicateRequest,
    #[error("request belongs to a different authenticated session")]
    WrongSession,
    #[error("approval response could not be signed")]
    SigningFailed,
    #[error("execute request does not match a live approval")]
    BindingRejected,
    #[error("phone approval policy is invalid")]
    PolicyInvalid,
}

#[derive(uniffi::Record)]
pub struct ApprovalHistoryDestination {
    pub service: String,
    pub endpoint: String,
}

#[derive(uniffi::Record)]
pub struct ApprovalTierDecision {
    pub tier: u8,
    pub reasons: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ApprovalInboundKind {
    ApprovalRequest,
    SessionEnd,
    Ping,
    ListServicesRequest,
    Unexpected,
}

enum ApprovalInboundPayload {
    Request(Arc<ValidatedApprovalRequest>),
    SessionEnd,
    Ping(ReqId),
    ListServices(ReqId),
    Unexpected,
}

/// Strictly decoded application message scoped to its authenticated session.
#[derive(uniffi::Object)]
pub struct DecodedApprovalInbound {
    owner: Arc<ApprovalSessionScope>,
    payload: ApprovalInboundPayload,
}

#[uniffi::export]
impl DecodedApprovalInbound {
    pub fn kind(&self) -> ApprovalInboundKind {
        match &self.payload {
            ApprovalInboundPayload::Request(_) => ApprovalInboundKind::ApprovalRequest,
            ApprovalInboundPayload::SessionEnd => ApprovalInboundKind::SessionEnd,
            ApprovalInboundPayload::Ping(_) => ApprovalInboundKind::Ping,
            ApprovalInboundPayload::ListServices(_) => ApprovalInboundKind::ListServicesRequest,
            ApprovalInboundPayload::Unexpected => ApprovalInboundKind::Unexpected,
        }
    }

    pub fn approval_request(&self) -> Option<Arc<ValidatedApprovalRequest>> {
        match &self.payload {
            ApprovalInboundPayload::Request(request) => Some(request.clone()),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum ApprovalDecision {
    Approved,
    Denied,
    Expired,
}

impl From<ApprovalDecision> for Decision {
    fn from(value: ApprovalDecision) -> Self {
        match value {
            ApprovalDecision::Approved => Self::Approved,
            ApprovalDecision::Denied => Self::Denied,
            ApprovalDecision::Expired => Self::Expired,
        }
    }
}

/// Kotlin-visible values copied only from Rust-validated protocol data.
#[derive(uniffi::Record)]
pub struct ApprovalRequestSummary {
    pub req_id: String,
    pub op_type: String,
    pub service: String,
    pub method: String,
    pub endpoint: String,
    /// Canonical JSON for structured inspection. It is rendered from the
    /// same validated request retained in the opaque handle.
    pub params_json: String,
    /// Canonical binding JSON from this exact validated Rust request.
    pub canonical_request_json: String,
    pub requested_by: Option<String>,
    pub timestamp: i64,
}

/// Opaque validated request. It cannot be constructed from Kotlin fields.
#[derive(uniffi::Object)]
pub struct ValidatedApprovalRequest {
    request: ApprovalRequest,
    owner: Arc<ApprovalSessionScope>,
}

struct ApprovalSessionScope;

#[uniffi::export]
impl ValidatedApprovalRequest {
    pub fn summary(&self) -> Result<ApprovalRequestSummary, ApprovalFfiError> {
        let params_json = to_canonical_string(&self.request.params)
            .map_err(|_| ApprovalFfiError::InvalidRequest)?;
        let canonical_request_json = self
            .request
            .canonical_binding_json()
            .map_err(|_| ApprovalFfiError::InvalidRequest)?;
        Ok(ApprovalRequestSummary {
            req_id: self.request.req_id.hex(),
            op_type: "authenticated_request".into(),
            service: self.request.service.clone(),
            method: self.request.method.clone(),
            endpoint: self.request.endpoint.clone(),
            params_json,
            canonical_request_json,
            requested_by: self.request.requested_by.clone(),
            timestamp: self.request.timestamp,
        })
    }

    /// Canonical audit payload derived from the exact Rust request retained
    /// by this opaque handle. Kotlin does not reconstruct protocol fields.
    pub fn terminal_log_payload(
        &self,
        decision: ApprovalDecision,
        reason: Option<String>,
        required_tier: u8,
        tier3_reasons: Vec<String>,
    ) -> Result<String, ApprovalFfiError> {
        if !(2..=3).contains(&required_tier) {
            return Err(ApprovalFfiError::InvalidDecision);
        }
        let binding = self
            .request
            .canonical_binding_json()
            .map_err(|_| ApprovalFfiError::InvalidRequest)?;
        let mut payload: serde_json::Value =
            serde_json::from_str(&binding).map_err(|_| ApprovalFfiError::InvalidRequest)?;
        let object = payload
            .as_object_mut()
            .ok_or(ApprovalFfiError::InvalidRequest)?;
        let decision_text = match decision {
            ApprovalDecision::Approved => "approved",
            ApprovalDecision::Denied => "denied",
            ApprovalDecision::Expired => "expired",
        };
        object.insert("decision".into(), decision_text.into());
        object.insert("required_tier".into(), required_tier.into());
        object.insert(
            "tier3_reasons".into(),
            serde_json::Value::Array(tier3_reasons.into_iter().map(Into::into).collect()),
        );
        match reason {
            Some(reason) => {
                object.insert("reason".into(), reason.into());
            }
            None => {
                object.remove("reason");
            }
        }
        to_canonical_string(&payload).map_err(|_| ApprovalFfiError::InvalidRequest)
    }
}

struct ApprovalInner {
    tracker: ApprovedRequestTracker,
    received_ids: HashSet<String>,
    terminal_ids: HashSet<String>,
    policy: PhoneApprovalPolicy,
}

/// One instance belongs to one live authenticated PhoneSession. Dropping
/// it discards all in-memory ExecuteRequest authorization artifacts.
#[derive(uniffi::Object)]
pub struct ApprovalProtocol {
    scope: Arc<ApprovalSessionScope>,
    inner: Mutex<ApprovalInner>,
}

impl ApprovalProtocol {
    fn lock(&self) -> MutexGuard<'_, ApprovalInner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn evaluate_tier_inner(
        &self,
        request: &ApprovalRequest,
        recent_approvals: Vec<ApprovalHistoryDestination>,
    ) -> ApprovalTierDecision {
        let history: Vec<_> = recent_approvals
            .into_iter()
            .map(|entry| ApprovedDestination {
                service: entry.service,
                endpoint: entry.endpoint,
            })
            .collect();
        let decision = self.lock().policy.evaluate(request, &history);
        ApprovalTierDecision {
            tier: decision.tier,
            reasons: decision
                .reasons
                .into_iter()
                .map(|reason| match reason {
                    Tier3Reason::DeleteMethod => "delete_method".to_owned(),
                    Tier3Reason::NovelDestination => "novel_destination".to_owned(),
                    Tier3Reason::ConfiguredRule => "configured_rule".to_owned(),
                })
                .collect(),
        }
    }

    fn register_request(
        &self,
        request: ApprovalRequest,
    ) -> Result<Arc<ValidatedApprovalRequest>, ApprovalFfiError> {
        let mut inner = self.lock();
        if !inner.received_ids.insert(request.req_id.hex()) {
            return Err(ApprovalFfiError::DuplicateRequest);
        }
        Ok(Arc::new(ValidatedApprovalRequest {
            request,
            owner: self.scope.clone(),
        }))
    }
}

#[uniffi::export]
impl ApprovalProtocol {
    /// The number of most recent successful approvals used for novelty policy.
    /// Exporting this keeps the Android log query aligned with shared Rust policy.
    pub fn destination_history_limit(&self) -> u32 {
        conveyance_protocol::policy::DESTINATION_HISTORY_LIMIT as u32
    }

    #[uniffi::constructor]
    pub fn new(policy_toml: String) -> Result<Arc<Self>, ApprovalFfiError> {
        let policy = PhoneApprovalPolicy::parse(&policy_toml)
            .map_err(|_| ApprovalFfiError::PolicyInvalid)?;
        Ok(Arc::new(Self {
            scope: Arc::new(ApprovalSessionScope),
            inner: Mutex::new(ApprovalInner {
                tracker: ApprovedRequestTracker::new(),
                received_ids: HashSet::new(),
                terminal_ids: HashSet::new(),
                policy,
            }),
        }))
    }

    /// Strictly decode and validate one authenticated_request ApprovalRequest.
    /// Other wire messages and op_type values fail closed.
    pub fn decode_request(
        &self,
        plaintext: Vec<u8>,
    ) -> Result<Arc<ValidatedApprovalRequest>, ApprovalFfiError> {
        let request =
            decode_approval_request(&plaintext).map_err(|_| ApprovalFfiError::InvalidRequest)?;
        self.register_request(request)
    }

    /// Decode authenticated application plaintext exactly once. Approval
    /// requests are fully validated and reserved before Kotlin can display
    /// them. SessionEnd and Ping are explicit protocol controls; all other
    /// valid message kinds are returned as Unexpected for fail-closed dispatch.
    pub fn decode_inbound(
        &self,
        plaintext: Vec<u8>,
    ) -> Result<Arc<DecodedApprovalInbound>, ApprovalFfiError> {
        let message = decode_wire(&plaintext).map_err(|_| ApprovalFfiError::InvalidRequest)?;
        let payload = match message {
            WireMessage::ApprovalRequest(request) => {
                request
                    .validate()
                    .map_err(|_| ApprovalFfiError::InvalidRequest)?;
                if request.op_type != conveyance_protocol::message::OpType::AuthenticatedRequest {
                    return Err(ApprovalFfiError::InvalidRequest);
                }
                ApprovalInboundPayload::Request(self.register_request(request)?)
            }
            WireMessage::SessionEnd(_) => ApprovalInboundPayload::SessionEnd,
            WireMessage::Ping(ping) => ApprovalInboundPayload::Ping(ping.req_id),
            WireMessage::ListServicesRequest(request) => {
                ApprovalInboundPayload::ListServices(request.req_id)
            }
            _ => ApprovalInboundPayload::Unexpected,
        };
        Ok(Arc::new(DecodedApprovalInbound {
            owner: self.scope.clone(),
            payload,
        }))
    }

    /// Build the exact shared wire Pong for a decoded Ping from this session.
    pub fn encode_pong(
        &self,
        inbound: Arc<DecodedApprovalInbound>,
    ) -> Result<Vec<u8>, ApprovalFfiError> {
        if !Arc::ptr_eq(&inbound.owner, &self.scope) {
            return Err(ApprovalFfiError::WrongSession);
        }
        let req_id = match &inbound.payload {
            ApprovalInboundPayload::Ping(req_id) => *req_id,
            _ => return Err(ApprovalFfiError::InvalidRequest),
        };
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ApprovalFfiError::InvalidRequest)?
            .as_secs()
            .try_into()
            .map_err(|_| ApprovalFfiError::InvalidRequest)?;
        encode(&WireMessage::Pong(Pong { req_id, timestamp }))
            .map_err(|_| ApprovalFfiError::InvalidRequest)
    }

    /// Encode the protocol's non-approval service-name response for a
    /// request decoded on this authenticated session.
    pub fn encode_list_services_response(
        &self,
        inbound: Arc<DecodedApprovalInbound>,
        services: Vec<String>,
    ) -> Result<Vec<u8>, ApprovalFfiError> {
        if !Arc::ptr_eq(&inbound.owner, &self.scope) {
            return Err(ApprovalFfiError::WrongSession);
        }
        let req_id = match &inbound.payload {
            ApprovalInboundPayload::ListServices(req_id) => *req_id,
            _ => return Err(ApprovalFfiError::InvalidRequest),
        };
        encode(&WireMessage::ListServicesResponse(ListServicesResponse {
            req_id,
            services,
        }))
        .map_err(|_| ApprovalFfiError::InvalidRequest)
    }

    /// Classify a Rust-validated request using this protocol/session's
    /// immutable phone policy and the last successful approvals supplied
    /// newest first by the phone's authoritative approval log.
    pub fn evaluate_tier(
        &self,
        request: Arc<ValidatedApprovalRequest>,
        recent_approvals: Vec<ApprovalHistoryDestination>,
    ) -> Result<ApprovalTierDecision, ApprovalFfiError> {
        if !Arc::ptr_eq(&request.owner, &self.scope) {
            return Err(ApprovalFfiError::WrongSession);
        }
        Ok(self.evaluate_tier_inner(&request.request, recent_approvals))
    }

    /// Sign and encode one terminal response through the opaque identity.
    /// The caller invokes this only after session/deadline/policy/auth and
    /// explicit-user-action checks have succeeded. Approved requests are
    /// retained in the same shared tracker that later validates execution.
    pub fn signed_response(
        &self,
        request: Arc<ValidatedApprovalRequest>,
        decision: ApprovalDecision,
        reason: Option<String>,
        identity: Arc<UnlockedIdentity>,
    ) -> Result<Vec<u8>, ApprovalFfiError> {
        if !Arc::ptr_eq(&request.owner, &self.scope) {
            return Err(ApprovalFfiError::WrongSession);
        }
        let decision: Decision = decision.into();
        let request_id = request.request.req_id.hex();
        let mut inner = self.lock();
        if inner.terminal_ids.contains(&request_id) {
            return Err(ApprovalFfiError::DuplicateDecision);
        }

        // Force the exact binding representation to validate before any
        // signature is produced. The tracker recomputes from this same
        // shared Rust type when it retains the artifact.
        if decision == Decision::Approved {
            request
                .request
                .canonical_binding_json()
                .map_err(|_| ApprovalFfiError::InvalidRequest)?;
        }

        let unsigned = ApprovalResponse::unsigned(request.request.req_id, decision, reason);
        let payload = unsigned
            .signature_payload()
            .map_err(|_| ApprovalFfiError::SigningFailed)?;
        // Validate wire encoding and size before the identity signs.
        encode(&WireMessage::ApprovalResponse(unsigned.clone()))
            .map_err(|_| ApprovalFfiError::SigningFailed)?;

        // Reserve the request ID while holding the mutex so duplicate or
        // concurrent calls can never produce two terminal signatures.
        inner.terminal_ids.insert(request_id.clone());
        let signature: [u8; 64] = identity
            .sign(payload)
            .try_into()
            .map_err(|_| ApprovalFfiError::SigningFailed)?;
        let response = unsigned.with_signature(signature);

        if decision == Decision::Approved {
            inner
                .tracker
                .record_approval(&request.request, &response)
                .map_err(|_| ApprovalFfiError::InvalidRequest)?;
        }

        let encoded = encode(&WireMessage::ApprovalResponse(response))
            .map_err(|_| ApprovalFfiError::SigningFailed)?;
        Ok(encoded)
    }

    /// Validate and consume an ExecuteRequest binding. This method is a
    /// protocol parity seam only; it performs no credential access or I/O.
    pub fn validate_execute_binding(&self, plaintext: Vec<u8>) -> Result<(), ApprovalFfiError> {
        let execute: ExecuteRequest =
            decode_execute_request(&plaintext).map_err(|_| ApprovalFfiError::BindingRejected)?;
        self.lock()
            .tracker
            .validate_execute(&execute)
            .map_err(|_| ApprovalFfiError::BindingRejected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use conveyance_protocol::crypto::sign::IdentityPublicKey;
    use conveyance_protocol::message::{ApprovalRequest, OpType, ReqId, decode};

    const RECOVERY: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn identity() -> Arc<UnlockedIdentity> {
        let sealed =
            crate::sealed::create_sealed_identity(RECOVERY.into(), vec![0x42; 32]).unwrap();
        crate::sealed::open_sealed_identity(sealed.blob, vec![0x42; 32]).unwrap()
    }

    fn request_bytes_at(endpoint: &str) -> Vec<u8> {
        let request = ApprovalRequest::new(
            ReqId([0x35; 16]),
            OpType::AuthenticatedRequest,
            "github".into(),
            "POST".into(),
            endpoint.into(),
            serde_json::json!({"env":"prod", "count":2}),
            Some("cli".into()),
            1_700_000_000,
        )
        .unwrap();
        conveyance_protocol::message::encode(&WireMessage::ApprovalRequest(request)).unwrap()
    }

    fn request_bytes() -> Vec<u8> {
        request_bytes_at("/v1/deploy")
    }

    #[test]
    fn summary_is_derived_from_validated_rust_request() {
        let protocol = ApprovalProtocol::new(String::new()).unwrap();
        let request = protocol.decode_request(request_bytes()).unwrap();
        let summary = request.summary().unwrap();
        assert_eq!(summary.req_id, "35".repeat(16));
        assert_eq!(summary.service, "github");
        assert_eq!(summary.method, "POST");
        assert_eq!(summary.endpoint, "/v1/deploy");
        assert_eq!(summary.params_json, r#"{"count":2,"env":"prod"}"#);
        assert_eq!(
            summary.canonical_request_json,
            r#"{"endpoint":"/v1/deploy","method":"POST","op_type":"authenticated_request","params":{"count":2,"env":"prod"},"req_id":"35353535353535353535353535353535","requested_by":"cli","service":"github","timestamp":1700000000}"#
        );
    }

    #[test]
    fn ffi_signature_verifies_and_approved_binding_is_exact_and_one_shot() {
        let protocol = ApprovalProtocol::new(String::new()).unwrap();
        let id = identity();
        let request = protocol.decode_request(request_bytes()).unwrap();
        let wire = protocol
            .signed_response(
                request.clone(),
                ApprovalDecision::Approved,
                None,
                id.clone(),
            )
            .unwrap();
        let WireMessage::ApprovalResponse(response) = decode(&wire).unwrap() else {
            panic!("wrong response")
        };
        let public: [u8; 32] = id.ed25519_public().try_into().unwrap();
        response
            .verify_signature(&IdentityPublicKey::from_bytes(&public).unwrap())
            .unwrap();

        let execute = ExecuteRequest::new(
            ReqId([0x35; 16]),
            OpType::AuthenticatedRequest,
            "github".into(),
            "POST".into(),
            "/v1/deploy".into(),
            serde_json::json!({"env":"prod", "count":2}),
            Some("cli".into()),
            1_700_000_000,
        )
        .unwrap();
        let execute_bytes =
            conveyance_protocol::message::encode(&WireMessage::ExecuteRequest(execute.clone()))
                .unwrap();
        protocol
            .validate_execute_binding(execute_bytes.clone())
            .unwrap();
        assert!(matches!(
            protocol.validate_execute_binding(execute_bytes),
            Err(ApprovalFfiError::BindingRejected)
        ));

        let substituted = ExecuteRequest::new(
            execute.req_id,
            execute.op_type,
            execute.service,
            execute.method,
            "/v1/other".into(),
            execute.params,
            execute.requested_by,
            execute.timestamp,
        )
        .unwrap();
        let bytes = conveyance_protocol::message::encode(&WireMessage::ExecuteRequest(substituted))
            .unwrap();
        assert!(matches!(
            protocol.validate_execute_binding(bytes),
            Err(ApprovalFfiError::BindingRejected)
        ));
    }

    #[test]
    fn denial_and_expiration_are_signed_but_never_create_binding() {
        for decision in [ApprovalDecision::Denied, ApprovalDecision::Expired] {
            let protocol = ApprovalProtocol::new(String::new()).unwrap();
            let id = identity();
            let request_bytes = request_bytes();
            let request = protocol.decode_request(request_bytes.clone()).unwrap();
            let bytes = protocol
                .signed_response(request, decision, None, id)
                .unwrap();
            assert!(matches!(
                decode(&bytes).unwrap(),
                WireMessage::ApprovalResponse(_)
            ));
            let execute = ExecuteRequest::new(
                ReqId([0x35; 16]),
                OpType::AuthenticatedRequest,
                "github".into(),
                "POST".into(),
                "/v1/deploy".into(),
                serde_json::json!({"env":"prod", "count":2}),
                Some("cli".into()),
                1_700_000_000,
            )
            .unwrap();
            let execute_bytes =
                conveyance_protocol::message::encode(&WireMessage::ExecuteRequest(execute))
                    .unwrap();
            assert!(matches!(
                protocol.validate_execute_binding(execute_bytes),
                Err(ApprovalFfiError::BindingRejected)
            ));
        }
    }

    #[test]
    fn same_req_id_with_mutated_fields_cannot_get_a_second_decision() {
        let protocol = ApprovalProtocol::new(String::new()).unwrap();
        let id = identity();
        let first = protocol.decode_request(request_bytes()).unwrap();
        protocol
            .signed_response(first, ApprovalDecision::Denied, None, id.clone())
            .unwrap();
        assert!(matches!(
            protocol.decode_request(request_bytes_at("/v1/other")),
            Err(ApprovalFfiError::DuplicateRequest)
        ));
    }

    #[test]
    fn duplicate_req_id_is_rejected_before_either_request_is_presented() {
        let protocol = ApprovalProtocol::new(String::new()).unwrap();
        protocol.decode_request(request_bytes()).unwrap();
        assert!(matches!(
            protocol.decode_request(request_bytes()),
            Err(ApprovalFfiError::DuplicateRequest)
        ));
    }

    #[test]
    fn one_request_handle_can_produce_only_one_terminal_response() {
        let protocol = ApprovalProtocol::new(String::new()).unwrap();
        let id = identity();
        let request = protocol.decode_request(request_bytes()).unwrap();
        protocol
            .signed_response(request.clone(), ApprovalDecision::Denied, None, id.clone())
            .unwrap();
        assert!(matches!(
            protocol.signed_response(request, ApprovalDecision::Approved, None, id),
            Err(ApprovalFfiError::DuplicateDecision)
        ));
    }

    #[test]
    fn phone_tier_policy_uses_its_immutable_rules_and_exact_history() {
        let protocol = ApprovalProtocol::new(
            "[[high_risk]]\nmatch_service='github'\nmatch_endpoint='*prod*'\nrequired_tier=3"
                .into(),
        )
        .unwrap();
        let req = protocol
            .decode_request(request_bytes_at("/prod/deploy"))
            .unwrap();
        let novel = protocol.evaluate_tier(req.clone(), vec![]).unwrap();
        assert_eq!(novel.tier, 3);
        assert_eq!(novel.reasons, vec!["novel_destination", "configured_rule"]);

        let known = protocol
            .evaluate_tier(
                req,
                vec![ApprovalHistoryDestination {
                    service: "github".into(),
                    endpoint: "/prod/deploy".into(),
                }],
            )
            .unwrap();
        assert_eq!(known.tier, 3);
        assert_eq!(known.reasons, vec!["configured_rule"]);
    }

    #[test]
    fn invalid_phone_policy_cannot_create_an_approval_protocol() {
        assert!(matches!(
            ApprovalProtocol::new("[[high_risk]]\nrequired_tier=3".into()),
            Err(ApprovalFfiError::PolicyInvalid)
        ));
    }

    #[test]
    fn validated_request_handle_cannot_cross_authenticated_sessions() {
        let first = ApprovalProtocol::new(String::new()).unwrap();
        let second = ApprovalProtocol::new(String::new()).unwrap();
        let request = first.decode_request(request_bytes()).unwrap();
        let id = identity();
        assert!(matches!(
            second.signed_response(request.clone(), ApprovalDecision::Approved, None, id,),
            Err(ApprovalFfiError::WrongSession)
        ));
        assert!(matches!(
            second.evaluate_tier(request, vec![]),
            Err(ApprovalFfiError::WrongSession)
        ));
    }

    #[test]
    fn inbound_dispatch_recognizes_session_end_ping_and_rejects_unexpected_to_caller() {
        let protocol = ApprovalProtocol::new(String::new()).unwrap();
        let ping = WireMessage::Ping(conveyance_protocol::message::Ping {
            req_id: ReqId([0x11; 16]),
            timestamp: 1_700_000_000,
        });
        let ping = protocol
            .decode_inbound(conveyance_protocol::message::encode(&ping).unwrap())
            .unwrap();
        assert_eq!(ping.kind(), ApprovalInboundKind::Ping);
        assert!(ping.approval_request().is_none());
        let pong = protocol.encode_pong(ping).unwrap();
        let WireMessage::Pong(pong) = decode_wire(&pong).unwrap() else {
            panic!("Ping must produce a shared-wire Pong")
        };
        assert_eq!(pong.req_id, ReqId([0x11; 16]));

        let end = WireMessage::SessionEnd(conveyance_protocol::message::SessionEnd {
            req_id: ReqId([0x12; 16]),
            reason: "complete".into(),
        });
        let end = protocol
            .decode_inbound(conveyance_protocol::message::encode(&end).unwrap())
            .unwrap();
        assert_eq!(end.kind(), ApprovalInboundKind::SessionEnd);

        let list =
            WireMessage::ListServicesRequest(conveyance_protocol::message::ListServicesRequest {
                req_id: ReqId([0x13; 16]),
            });
        let list = protocol
            .decode_inbound(conveyance_protocol::message::encode(&list).unwrap())
            .unwrap();
        assert_eq!(list.kind(), ApprovalInboundKind::ListServicesRequest);
        let list_response = protocol
            .encode_list_services_response(list, vec!["github".into()])
            .unwrap();
        assert!(matches!(
            decode_wire(&list_response).unwrap(),
            WireMessage::ListServicesResponse(response)
                if response.req_id == ReqId([0x13; 16]) && response.services == ["github"]
        ));
    }

    #[test]
    fn inbound_approval_reserves_request_id_before_summary_or_ui() {
        let protocol = ApprovalProtocol::new(String::new()).unwrap();
        let request = protocol.decode_inbound(request_bytes()).unwrap();
        assert_eq!(request.kind(), ApprovalInboundKind::ApprovalRequest);
        assert_eq!(
            request
                .approval_request()
                .unwrap()
                .summary()
                .unwrap()
                .service,
            "github"
        );
        assert!(matches!(
            protocol.decode_inbound(request_bytes()),
            Err(ApprovalFfiError::DuplicateRequest)
        ));
    }

    #[test]
    fn terminal_log_payload_is_canonical_and_preserves_request_binding_fields() {
        let protocol = ApprovalProtocol::new(String::new()).unwrap();
        let request = protocol.decode_request(request_bytes()).unwrap();
        let log = request
            .terminal_log_payload(
                ApprovalDecision::Expired,
                Some("approval_timeout".into()),
                3,
                vec!["novel_destination".into()],
            )
            .unwrap();
        assert_eq!(
            log,
            r#"{"decision":"expired","endpoint":"/v1/deploy","method":"POST","op_type":"authenticated_request","params":{"count":2,"env":"prod"},"reason":"approval_timeout","req_id":"35353535353535353535353535353535","requested_by":"cli","required_tier":3,"service":"github","tier3_reasons":["novel_destination"],"timestamp":1700000000}"#
        );
    }
}
