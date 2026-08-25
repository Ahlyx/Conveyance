//! Message types from the spec's "Wire protocol" section.
//!
//! Wire encoding is CBOR (via ciborium); the envelope is a string-tagged
//! enum so decoded traffic is self-describing in a debugger and Android's
//! dispatch is one obvious `when`. Signature payloads are canonical JSON
//! (RFC 8785 subset, per the spec amendment): the message minus its
//! `signature` field, prefixed with a context tag.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::ProtocolError;
use crate::crypto::canonical_json::canonicalize;
use crate::crypto::sign::{IdentityPublicKey, IdentitySecretKey};

// ---------------------------------------------------------------------------
// ReqId
// ---------------------------------------------------------------------------

/// A 128-bit request correlation id.
///
/// Serialization is context-dependent: 16-byte CBOR byte string on the
/// wire (efficient), lowercase hex inside canonical JSON for signatures
/// (matches hashchain convention). Android must implement both. The split
/// rides on serde's `is_human_readable()`, which JSON reports as true and
/// binary formats as false -- a standard serde mechanism, not an accident
/// to be "simplified" later.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ReqId(pub [u8; 16]);

impl ReqId {
    pub fn generate<E: crate::crypto::EntropySource>(entropy: &E) -> Result<Self, ProtocolError> {
        let mut bytes = [0u8; 16];
        entropy.fill(&mut bytes)?;
        Ok(Self(bytes))
    }

    pub fn hex(&self) -> String {
        let mut s = String::with_capacity(32);
        for b in self.0 {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

impl Serialize for ReqId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.hex())
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for ReqId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = ReqId;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "a 128-bit req_id (hex string or 16-byte buffer)")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<ReqId, E> {
                let raw = hex_decode(v).ok_or_else(|| E::custom("req_id hex malformed"))?;
                <[u8; 16]>::try_from(raw)
                    .map(ReqId)
                    .map_err(|_| E::custom("req_id must be 16 bytes"))
            }

            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<ReqId, E> {
                <[u8; 16]>::try_from(v)
                    .map(ReqId)
                    .map_err(|_| E::custom("req_id must be 16 bytes"))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("validated above"))
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// Enumerated field values (closed sets; unknown values fail decode)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpType {
    #[serde(rename = "authenticated_request")]
    AuthenticatedRequest,
    #[serde(rename = "list_services")]
    ListServices,
    #[serde(rename = "session_end")]
    SessionEnd,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    #[serde(rename = "approved")]
    Approved,
    #[serde(rename = "denied")]
    Denied,
    #[serde(rename = "expired")]
    Expired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status {
    #[serde(rename = "ok")]
    Ok,
    #[serde(rename = "error")]
    Error,
    #[serde(rename = "denied")]
    Denied,
}

// ---------------------------------------------------------------------------
// Messages. Field names are the wire keys AND the canonical-JSON keys used
// in signatures; renaming here changes interop, not just style.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub req_id: ReqId,
    pub op_type: OpType,
    pub service: String,
    pub method: String,
    pub endpoint: String,
    /// Request parameters. Restricted to the canonical-JSON domain at
    /// construction ([`ensure_canonical_domain`]) because this exact value
    /// must survive byte-for-byte into ExecuteRequest comparisons.
    pub params: serde_json::Value,
    /// MCP client hint, when the caller supplied one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_by: Option<String>,
    /// Unix seconds.
    pub timestamp: i64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ApprovalResponse {
    pub req_id: ReqId,
    pub decision: Decision,
    /// SPEC RULE (amended): absent means ABSENT in signature JSON, never
    /// null. skip_serializing_if enforces the Rust side of that contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Ed25519 over "conveyance-approve-v1" || canonical_json(minus sig).
    #[serde(with = "signature_serde")]
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExecuteRequest {
    pub req_id: ReqId,
    /// Must equal the approved request's fields byte-for-byte after
    /// canonical JSON serialization (binding.rs enforces).
    pub op_type: OpType,
    pub service: String,
    pub method: String,
    pub endpoint: String,
    pub params: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_by: Option<String>,
    pub timestamp: i64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExecuteResponse {
    pub req_id: ReqId,
    pub status: Status,
    /// SPEC RULE (amended): absent means ABSENT in signature JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    /// Response body or error object; canonical-JSON domain enforced at
    /// construction like `params`.
    pub body: serde_json::Value,
    /// Unix seconds.
    pub executed_at: i64,
    /// Ed25519 over "conveyance-execute-v1" || canonical_json(minus sig).
    #[serde(with = "signature_serde")]
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ListServicesRequest {
    pub req_id: ReqId,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ListServicesResponse {
    pub req_id: ReqId,
    /// Names only; no secret material by spec mandate.
    pub services: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Ping {
    pub req_id: ReqId,
    pub timestamp: i64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Pong {
    pub req_id: ReqId,
    pub timestamp: i64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SessionEnd {
    pub req_id: ReqId,
    pub reason: String,
}

/// The carrier. One tag per message kind; the tag strings are wire
/// surface area (Android dispatches on them), so renames are breaking.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WireMessage {
    ApprovalRequest(ApprovalRequest),
    ApprovalResponse(ApprovalResponse),
    ExecuteRequest(ExecuteRequest),
    ExecuteResponse(ExecuteResponse),
    ListServicesRequest(ListServicesRequest),
    ListServicesResponse(ListServicesResponse),
    Ping(Ping),
    Pong(Pong),
    SessionEnd(SessionEnd),
}

// ---------------------------------------------------------------------------
// Construction with domain validation
// ---------------------------------------------------------------------------

/// Reject any value outside the canonical-JSON domain BEFORE it can enter
/// a signed or compared structure. Floats are the practical case; raw
/// bytes cannot appear in serde_json::Value at all.
pub(crate) fn ensure_canonical_domain(
    value: &serde_json::Value,
    field: &'static str,
) -> Result<(), ProtocolError> {
    match value {
        serde_json::Value::Number(n) => {
            if n.is_f64() {
                Err(ProtocolError::UnsupportedValueType { field })
            } else {
                Ok(())
            }
        }
        serde_json::Value::Array(items) => items
            .iter()
            .try_for_each(|v| ensure_canonical_domain(v, field)),
        serde_json::Value::Object(map) => map
            .values()
            .try_for_each(|v| ensure_canonical_domain(v, field)),
        _ => Ok(()),
    }
}

macro_rules! validate_params_field {
    ($fn_name:ident, $struct_ty:ident, { $($arg:ident : $ty:ty),+ }, $field_expr:expr) => {
        impl $struct_ty {
            #[allow(clippy::too_many_arguments)]
            pub fn $fn_name(
                $($arg: $ty,)+
            ) -> Result<Self, ProtocolError> {
                ensure_canonical_domain(&$field_expr, stringify!(params))?;
                Ok(Self { $($arg,)+ })
            }
        }
    };
}

validate_params_field!(
    new,
    ApprovalRequest,
    {
        req_id: ReqId,
        op_type: OpType,
        service: String,
        method: String,
        endpoint: String,
        params: serde_json::Value,
        requested_by: Option<String>,
        timestamp: i64
    },
    params
);

validate_params_field!(
    new,
    ExecuteRequest,
    {
        req_id: ReqId,
        op_type: OpType,
        service: String,
        method: String,
        endpoint: String,
        params: serde_json::Value,
        requested_by: Option<String>,
        timestamp: i64
    },
    params
);

impl ExecuteResponse {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        req_id: ReqId,
        status: Status,
        http_status: Option<u16>,
        body: serde_json::Value,
        executed_at: i64,
    ) -> Result<Unsigned<Self>, ProtocolError> {
        ensure_canonical_domain(&body, "body")?;
        Ok(Unsigned(Self {
            req_id,
            status,
            http_status,
            body,
            executed_at,
            // Placeholder overwritten by signing below.
            signature: [0u8; 64],
        }))
    }
}

// ---------------------------------------------------------------------------
// Signing / verifying
// ---------------------------------------------------------------------------

pub const APPROVE_CONTEXT: &[u8] = b"conveyance-approve-v1";
pub const EXECUTE_CONTEXT: &[u8] = b"conveyance-execute-v1";

/// Marker for a response that has not been signed yet.
pub struct Unsigned<T>(T);

impl Unsigned<ExecuteResponse> {
    pub fn sign(self, key: &IdentitySecretKey) -> ExecuteResponse {
        let payload = signing_payload(EXECUTE_CONTEXT, &self.0)
            .expect("own struct serializes to canonical JSON");
        let signature = key.sign(&payload);
        ExecuteResponse {
            signature,
            ..self.0
        }
    }
}

impl ApprovalResponse {
    /// Build + sign in one step.
    pub fn approved_or_denied(
        req_id: ReqId,
        decision: Decision,
        reason: Option<String>,
        key: &IdentitySecretKey,
    ) -> Self {
        let unsigned = Self {
            req_id,
            decision,
            reason,
            signature: [0u8; 64],
        };
        let payload = signing_payload(APPROVE_CONTEXT, &unsigned)
            .expect("own struct serializes to canonical JSON");
        let signature = key.sign(&payload);
        Self {
            signature,
            ..unsigned
        }
    }

    pub fn verify_signature(&self, phone_public: &IdentityPublicKey) -> Result<(), ProtocolError> {
        let payload = signing_payload(APPROVE_CONTEXT, self)?;
        phone_public
            .verify(&payload, &self.signature)
            .map_err(|_| ProtocolError::SignatureInvalid)
    }
}

impl ExecuteResponse {
    pub fn verify_signature(&self, phone_public: &IdentityPublicKey) -> Result<(), ProtocolError> {
        let payload = signing_payload(EXECUTE_CONTEXT, self)?;
        phone_public
            .verify(&payload, &self.signature)
            .map_err(|_| ProtocolError::SignatureInvalid)
    }
}

/// `"context" || canonical_json(message_minus_signature)`.
///
/// The signature FIELD is removed from the produced JSON entirely (spec
/// amendment): optional fields absent are omitted, never null, and the
/// signature itself must not appear in what it covers.
fn signing_payload<T: Serialize>(context: &[u8], msg: &T) -> Result<Vec<u8>, ProtocolError> {
    let mut value = serde_json::to_value(msg).map_err(|e| ProtocolError::Cbor(e.to_string()))?;
    let removed = value.as_object_mut().and_then(|m| m.remove("signature"));
    debug_assert!(
        removed.is_some(),
        "signed messages must carry a signature field"
    );
    let canonical = canonicalize(&value)?;
    let mut out = Vec::with_capacity(context.len() + canonical.len());
    out.extend_from_slice(context);
    out.extend_from_slice(canonical.as_bytes());
    Ok(out)
}

/// 64-byte signature arrays: bytes on CBOR, hex on JSON (same dual-context
/// rule as ReqId).
mod signature_serde {
    use super::*;

    pub fn serialize<S: Serializer>(sig: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            let mut strg = String::with_capacity(128);
            for b in sig {
                strg.push_str(&format!("{b:02x}"));
            }
            s.serialize_str(&strg)
        } else {
            s.serialize_bytes(sig)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = [u8; 64];
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "a 64-byte Ed25519 signature (hex or raw)")
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<[u8; 64], E> {
                let raw: Vec<u8> = (0..v.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&v[i..i + 2], 16))
                    .collect::<Result<_, _>>()
                    .map_err(|_| E::custom("signature hex malformed"))?;
                <[u8; 64]>::try_from(raw).map_err(|_| E::custom("signature must be 64 bytes"))
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<[u8; 64], E> {
                <[u8; 64]>::try_from(v).map_err(|_| E::custom("signature must be 64 bytes"))
            }
        }
        d.deserialize_any(V)
    }
}

// ---------------------------------------------------------------------------
// Codec entry points
// ---------------------------------------------------------------------------

pub fn encode(msg: &WireMessage) -> Result<Vec<u8>, ProtocolError> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(msg, &mut out).map_err(|e| ProtocolError::Cbor(e.to_string()))?;
    Ok(out)
}

pub fn decode(bytes: &[u8]) -> Result<WireMessage, ProtocolError> {
    ciborium::de::from_reader(&mut &bytes[..]).map_err(|e| {
        // Closed enums (OpType, Decision, Status) must fail loudly and
        // distinctly -- silently mapping an unknown future value onto a
        // default would be exactly the wrong behavior for a security
        // protocol.
        let text = e.to_string();
        if text.contains("unknown variant") || text.contains("unknown field") {
            ProtocolError::UnknownEnumValue
        } else {
            ProtocolError::Cbor(text)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::test_support::CounterEntropy;

    fn sample_req_id(seed: u8) -> ReqId {
        ReqId([seed; 16])
    }

    fn sample_request(seed: u8) -> ApprovalRequest {
        ApprovalRequest::new(
            sample_req_id(seed),
            OpType::AuthenticatedRequest,
            "github".into(),
            "POST".into(),
            "/v1/deploy".into(),
            serde_json::json!({"env": "prod", "replicas": 3}),
            Some("claude-code".into()),
            1_700_000_000,
        )
        .unwrap()
    }

    #[test]
    fn every_message_type_round_trips_through_cbor() {
        let req_id = sample_req_id(1);
        let msgs: Vec<WireMessage> = vec![
            WireMessage::ApprovalRequest(sample_request(1)),
            WireMessage::ApprovalResponse(ApprovalResponse::approved_or_denied(
                req_id,
                Decision::Approved,
                Some("user_tap".into()),
                &IdentitySecretKey::generate(&CounterEntropy).unwrap(),
            )),
            WireMessage::ExecuteRequest(
                ExecuteRequest::new(
                    req_id,
                    OpType::AuthenticatedRequest,
                    "github".into(),
                    "POST".into(),
                    "/v1/deploy".into(),
                    serde_json::json!({"env": "prod"}),
                    None,
                    1_700_000_000,
                )
                .unwrap(),
            ),
            WireMessage::ExecuteResponse(
                ExecuteResponse::new(
                    req_id,
                    Status::Ok,
                    Some(200),
                    serde_json::json!({"sha": "abc123"}),
                    1_700_000_001,
                )
                .unwrap()
                .sign(&IdentitySecretKey::generate(&CounterEntropy).unwrap()),
            ),
            WireMessage::ListServicesRequest(ListServicesRequest { req_id }),
            WireMessage::ListServicesResponse(ListServicesResponse {
                req_id,
                services: vec!["github".into(), "aws".into()],
            }),
            WireMessage::Ping(Ping {
                req_id,
                timestamp: 5,
            }),
            WireMessage::Pong(Pong {
                req_id,
                timestamp: 5,
            }),
            WireMessage::SessionEnd(SessionEnd {
                req_id,
                reason: "idle_timeout".into(),
            }),
        ];

        for msg in &msgs {
            let bytes = encode(msg).unwrap();
            let back = decode(&bytes).unwrap();
            assert_eq!(&back, msg);
        }
    }

    #[test]
    fn envelope_tags_are_present_and_snake_cased() {
        let bytes = encode(&WireMessage::Ping(Ping {
            req_id: sample_req_id(2),
            timestamp: 1,
        }))
        .unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("ping"), "tag missing from {text}");

        let bytes = encode(&WireMessage::ListServicesRequest(ListServicesRequest {
            req_id: sample_req_id(2),
        }))
        .unwrap();
        assert!(String::from_utf8_lossy(&bytes).contains("list_services_request"));
    }

    #[test]
    fn req_id_is_bytes_on_cbor_and_hex_in_json() {
        let id = ReqId([0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);

        let json = serde_json::to_value(id).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String("deadbeef000102030405060708090a0b".into())
        );

        // Through the CBOR path it must come back from raw bytes: encode a
        // Ping via ciborium and confirm the hex string does NOT appear in
        // the encoded form (it would if we'd leaked the human-readable arm).
        let bytes = encode(&WireMessage::Ping(Ping {
            req_id: id,
            timestamp: 0,
        }))
        .unwrap();
        assert!(
            !bytes.windows(2).any(|w| w == b"de"),
            "hex leaked into CBOR"
        );

        let back = decode(&bytes).unwrap();
        match back {
            WireMessage::Ping(p) => assert_eq!(p.req_id, id),
            other => panic!("wrong variant {other:?}"),
        }
    }

    #[test]
    fn float_params_are_rejected_with_the_distinct_variant() {
        let err = ApprovalRequest::new(
            sample_req_id(3),
            OpType::AuthenticatedRequest,
            "aws".into(),
            "GET".into(),
            "/x".into(),
            serde_json::json!({"confidence": 0.95}),
            None,
            1,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ProtocolError::UnsupportedValueType { field: "params" }
        ));

        // Nested floats count too.
        let err = ApprovalRequest::new(
            sample_req_id(3),
            OpType::AuthenticatedRequest,
            "aws".into(),
            "GET".into(),
            "/x".into(),
            serde_json::json!({"a": {"b": [1, 2.5]}}),
            None,
            1,
        )
        .unwrap_err();
        assert!(matches!(err, ProtocolError::UnsupportedValueType { .. }));
    }

    #[test]
    fn integer_params_pass_and_survive_round_trip() {
        let m = ApprovalRequest::new(
            sample_req_id(4),
            OpType::ListServices,
            "aws".into(),
            "GET".into(),
            "/x".into(),
            serde_json::json!({"limit": 50, "deep": {"flag": true, "n": null}}),
            None,
            7,
        )
        .unwrap();
        let back = decode(&encode(&WireMessage::ApprovalRequest(m.clone())).unwrap()).unwrap();
        assert_eq!(back, WireMessage::ApprovalRequest(m));
    }

    /// THE omission-rule pin: absent `reason` produces NO key in the
    /// signature payload; present `reason` produces the key. If either
    /// half regresses to null-rendering, signatures diverge from Android
    /// silently -- this test is where that dies loudly.
    #[test]
    fn optional_fields_are_omitted_not_nulled_in_signature_payloads() {
        let key = IdentitySecretKey::generate(&CounterEntropy).unwrap();
        let id = sample_req_id(5);

        let without_reason =
            ApprovalResponse::approved_or_denied(id, Decision::Approved, None, &key);
        let payload = signing_payload(APPROVE_CONTEXT, &without_reason).unwrap();
        let json_text = std::str::from_utf8(&payload[APPROVE_CONTEXT.len()..]).unwrap();
        assert!(!json_text.contains("reason"), "{json_text}");
        assert!(!json_text.contains("null"), "{json_text}");
        assert!(json_text.contains("\"req_id\""), "{json_text}");
        assert!(json_text.contains("\"decision\""), "{json_text}");

        let with_reason = ApprovalResponse::approved_or_denied(
            id,
            Decision::Denied,
            Some("user_tap".into()),
            &key,
        );
        let payload = signing_payload(APPROVE_CONTEXT, &with_reason).unwrap();
        let json_text = std::str::from_utf8(&payload[APPROVE_CONTEXT.len()..]).unwrap();
        assert!(json_text.contains("\"reason\":\"user_tap\""), "{json_text}");

        // Same for http_status on execute responses.
        let unsigned_absent =
            ExecuteResponse::new(id, Status::Error, None, serde_json::json!("boom"), 9).unwrap();
        let payload = signing_payload(EXECUTE_CONTEXT, &unsigned_absent.0).unwrap();
        let json_text = std::str::from_utf8(&payload[EXECUTE_CONTEXT.len()..]).unwrap();
        assert!(!json_text.contains("http_status"), "{json_text}");
    }

    #[test]
    fn approval_signature_verifies_and_detects_tampering() {
        let key = IdentitySecretKey::generate(&CounterEntropy).unwrap();
        let public = key.public_key();

        let resp =
            ApprovalResponse::approved_or_denied(sample_req_id(6), Decision::Approved, None, &key);
        resp.verify_signature(&public).unwrap();

        // Tampered reason field breaks verification.
        let mut tampered = resp.clone();
        tampered.reason = Some("forged".into());
        assert!(matches!(
            tampered.verify_signature(&public),
            Err(ProtocolError::SignatureInvalid)
        ));

        // Tampered decision likewise.
        let mut tampered = resp.clone();
        tampered.decision = Decision::Denied;
        assert!(matches!(
            tampered.verify_signature(&public),
            Err(ProtocolError::SignatureInvalid)
        ));

        // Wrong verifier key too.
        let stranger = IdentitySecretKey::generate(&CounterEntropy).unwrap();
        assert!(matches!(
            resp.verify_signature(&stranger.public_key()),
            Err(ProtocolError::SignatureInvalid)
        ));
    }

    #[test]
    fn execute_response_signature_cycle() {
        let key = IdentitySecretKey::generate(&CounterEntropy).unwrap();
        let public = key.public_key();

        let resp = ExecuteResponse::new(
            sample_req_id(7),
            Status::Ok,
            Some(200),
            serde_json::json!({"ok": 1}),
            42,
        )
        .unwrap()
        .sign(&key);

        resp.verify_signature(&public).unwrap();

        let mut bad = resp.clone();
        bad.executed_at += 1;
        assert!(matches!(
            bad.verify_signature(&public),
            Err(ProtocolError::SignatureInvalid)
        ));
    }

    #[test]
    fn unknown_enum_values_fail_decode_closed() {
        use ciborium::value::Value;

        // Hand-build an approval_request envelope whose decision is a
        // value the protocol has never defined. Decode must reject it as
        // a distinct error, not coerce it into something wrong.
        let map = vec![
            (
                Value::Text("type".into()),
                Value::Text("approval_response".into()),
            ),
            (Value::Text("req_id".into()), Value::Text("ab".repeat(16))),
            (
                Value::Text("decision".into()),
                Value::Text("maybe_sure".into()),
            ),
            (Value::Text("signature".into()), Value::Bytes(vec![7u8; 64])),
        ];
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&Value::Map(map), &mut bytes).unwrap();

        match decode(&bytes) {
            Err(ProtocolError::UnknownEnumValue) => {}
            other => panic!("expected UnknownEnumValue for bogus decision, got {other:?}"),
        }
    }
}
