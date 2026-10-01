//! Emit byte-for-byte Android FFI approval protocol fixtures.

use std::path::PathBuf;

use conveyance_crypto_ffi::approval::{ApprovalDecision, ApprovalProtocol};
use conveyance_crypto_ffi::sealed::{create_sealed_identity, open_sealed_identity};
use conveyance_protocol::message::{ApprovalRequest, OpType, ReqId, WireMessage, encode};

const RECOVERY: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from("android/app/src/androidTest/assets/approval_fixtures.json")
        });
    let content_key = vec![0x42; 32];
    let sealed = create_sealed_identity(RECOVERY.to_owned(), content_key.clone())?;
    let identity = open_sealed_identity(sealed.blob, content_key)?;
    let request = ApprovalRequest::new(
        ReqId([0x35; 16]),
        OpType::AuthenticatedRequest,
        "github".into(),
        "POST".into(),
        "/v1/deploy".into(),
        serde_json::json!({"env": "prod", "count": 2}),
        Some("cli".into()),
        1_700_000_000,
    )?;
    let request_bytes = encode(&WireMessage::ApprovalRequest(request))?;

    let mut decisions = serde_json::Map::new();
    for (name, decision) in [
        ("approved", ApprovalDecision::Approved),
        ("denied", ApprovalDecision::Denied),
        ("expired", ApprovalDecision::Expired),
    ] {
        let protocol = ApprovalProtocol::new(String::new())?;
        let handle = protocol.decode_request(request_bytes.clone())?;
        let response = protocol.signed_response(handle, decision, None, identity.clone())?;
        decisions.insert(name.to_owned(), serde_json::Value::String(hex(&response)));
    }

    let fixtures = serde_json::json!({
        "schema_version": 1,
        "recovery_phrase": RECOVERY,
        "content_key_hex": hex(&[0x42; 32]),
        "identity_ed25519_public_hex": hex(&identity.ed25519_public()),
        "request_cbor_hex": hex(&request_bytes),
        "request": {
            "req_id": "35".repeat(16),
            "op_type": "authenticated_request",
            "service": "github",
            "method": "POST",
            "endpoint": "/v1/deploy",
            "params_json": "{\"count\":2,\"env\":\"prod\"}",
            "requested_by": "cli",
            "timestamp": 1_700_000_000_i64
        },
        "response_cbor_hex": decisions,
    });

    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(
        output,
        format!("{}\n", serde_json::to_string_pretty(&fixtures)?),
    )?;
    Ok(())
}
