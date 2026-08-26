//! Integration tests: the shim's line handler driven against a REAL
//! daemon (mock-phone feature) so every assertion crosses the full
//! IPC + Noise + log stack, not a mock of it.

use conveyance_core::crypto::dh::DhSecret;
use conveyance_core::session::SessionParams;
use conveyance_core::storage::identity::StoredIdentity;
use conveyance_daemon::ipc::IpcRequest;
use conveyance_daemon::mockphone::{MockKeyProvider, MockPhone};
use conveyance_daemon::{DaemonConfig, DaemonDeps};
use serde_json::{Value, json};
use std::sync::Arc;

use crate::handle_line;

/// Assemble and serve a real daemon with the scripted mock phone on a
/// unique socket name, pointed at a temp data dir. Mirrors exactly what
/// the `--mock-phone` binary mode does.
async fn spawn_mock_daemon(tag: &str) -> (tempfile::TempDir, DaemonConfig) {
    let dir = tempfile::tempdir().unwrap();
    let keys = MockKeyProvider::default();

    let pc_identity = StoredIdentity::generate(&conveyance_core::crypto::OsEntropy).unwrap();
    let config = DaemonConfig {
        socket: format!("conveyance-shim-test-{}-{tag}", std::process::id()),
        pairings_db: dir.path().join("pairings.db"),
        executions_db: dir.path().join("executions.db"),
        identity_file: dir.path().join("identity.enc"),
        session_params: SessionParams::validated(
            SessionParams::IDLE_MIN,
            std::time::Duration::from_secs(60),
            SessionParams::CAP_MIN,
        )
        .unwrap(),
    };

    pc_identity
        .save(
            &config.identity_file,
            &keys,
            &conveyance_core::crypto::OsEntropy,
        )
        .unwrap();

    let stores = conveyance_daemon::refuse_to_start_with(&config, &keys).unwrap();

    // The phone needs the PC's DH static for KK -- same pairing-time
    // dependency the ceremony satisfies.
    let pc_dh_pub = DhSecret::from_bytes(*stores.identity.x25519_secret.expose())
        .public_key()
        .to_bytes();
    let phone = Arc::new(MockPhone::new(pc_dh_pub));
    phone.record_pairing(stores.store.as_ref()).unwrap();

    let deps = DaemonDeps::new(Box::new(phone.dialer()));
    let state = conveyance_daemon::assemble_state(&config, stores, deps);
    let shutdown = conveyance_daemon::server::start_ipc_server(&config, state)
        .await
        .unwrap();
    // Keep the sender alive for the test's duration.
    std::mem::forget(shutdown);

    (dir, config)
}

/// Drive one JSON-RPC request through the shim's line handler.
async fn call(line: &str, socket: &str) -> Option<Value> {
    crate::handle_line(line, socket)
        .await
        .map(|resp| serde_json::from_str(&resp).unwrap())
}

#[tokio::test]
async fn handshake_and_tool_discovery_over_real_daemon() {
    let (_dir, config) = spawn_mock_daemon("handshake").await;
    let sock = config.socket.clone();

    // initialize -> protocol echo + serverInfo.
    let init = json!({
        "jsonrpc": "2.0", "id": 1,
        "method": "initialize",
        "params": { "protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": { "name": "test", "version": "0" } }
    });
    let resp = call(&init.to_string(), &sock).await.unwrap();
    assert_eq!(resp["result"]["protocolVersion"], json!("2025-06-18"));
    assert_eq!(
        resp["result"]["serverInfo"]["name"],
        json!("conveyance-shim")
    );

    // notifications/initialized -> silence.
    assert!(
        handle_line(
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            &sock
        )
        .await
        .is_none()
    );

    // tools/list -> EXACTLY the four spec'd tools, nothing else.
    let list = call(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#, &sock)
        .await
        .unwrap();
    let tools = list["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        vec![
            "authenticated_request",
            "list_services",
            "check_session",
            "end_session"
        ],
        "tool surface must match the spec exactly"
    );
    for t in tools {
        assert_eq!(
            t["inputSchema"]["type"],
            json!("object"),
            "{} needs object schema",
            t["name"]
        );
    }

    // Unknown method -> -32601 with verbatim id.
    let unknown = call(
        r#"{"jsonrpc":"2.0","id":3,"method":"read_secret_file"}"#,
        &sock,
    )
    .await
    .unwrap();
    assert_eq!(unknown["error"]["code"], json!(-32601));
    assert_eq!(unknown["id"], json!(3));
}

#[tokio::test]
async fn cold_start_check_session_surfaces_no_session_error() {
    let (_dir, config) = spawn_mock_daemon("coldstart").await;
    let sock = config.socket.clone();

    let resp = call(
        r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"check_session","arguments":{}}}"#,
        &sock,
    )
    .await
    .unwrap();
    assert_eq!(resp["result"]["isError"], json!(true));
    let payload: Value =
        serde_json::from_str(resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    // Five-field shape from the spec's error model, nulls PRESENT.
    assert_eq!(payload["code"], json!("conveyance/no_session"));
    assert_eq!(payload["retryable"], json!(true));
    assert_eq!(payload["retry_after_seconds"], Value::Null);
    assert_eq!(payload["details"], Value::Null);
    assert_eq!(
        payload.as_object().unwrap().len(),
        5,
        "field-set drift breaks the error contract"
    );
}

#[tokio::test]
async fn argument_validation_is_a_protocol_error() {
    let (_dir, config) = spawn_mock_daemon("badargs").await;
    let sock = config.socket.clone();

    // Missing required args -> -32602 (not a tool error).
    let resp = call(
        r#"{"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"authenticated_request","arguments":{"service":"github"}}}"#,
        &sock,
    )
    .await
    .unwrap();
    assert_eq!(resp["error"]["code"], json!(-32602));

    // Unknown tool name -> -32602 as well.
    let resp = call(
        r#"{"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"get_credential","arguments":{}}}"#,
        &sock,
    )
    .await
    .unwrap();
    assert_eq!(resp["error"]["code"], json!(-32602));
}

#[tokio::test]
async fn daemon_unreachable_maps_to_structured_internal_error() {
    // A socket nobody serves.
    let resp = call(
        r#"{"jsonrpc":"2.0","id":30,"method":"tools/call","params":{"name":"list_services","arguments":{}}}"#,
        "conveyance-no-daemon-here",
    )
    .await
    .unwrap();
    assert_eq!(resp["result"]["isError"], json!(true));
    let payload: Value =
        serde_json::from_str(resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(payload["code"], json!("conveyance/internal"));
    assert_eq!(
        payload["retryable"],
        json!(true),
        "not-running is retryable after starting the daemon"
    );
    assert!(
        payload["message"]
            .as_str()
            .unwrap()
            .contains("daemon is not running")
    );
}

#[tokio::test]
async fn end_session_is_idempotent_and_reports_inactive() {
    let (_dir, config) = spawn_mock_daemon("endsession").await;
    let sock = config.socket.clone();

    for _ in 0..2 {
        let resp = call(
            r#"{"jsonrpc":"2.0","id":40,"method":"tools/call","params":{"name":"end_session","arguments":{}}}"#,
            &sock,
        )
        .await
        .unwrap();
        assert_eq!(resp["result"]["isError"], json!(false));
        let payload: Value =
            serde_json::from_str(resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(payload["session"], json!("inactive"));
    }
}

#[tokio::test]
async fn full_authenticated_request_through_shim_to_phone() {
    let (_dir, config) = spawn_mock_daemon("fullflow").await;
    let sock = config.socket.clone();

    // Start the session via IPC directly (the shim cannot start
    // sessions -- that is the point).
    conveyance_daemon::ipc::single_request(&sock, IpcRequest::SessionStart)
        .await
        .unwrap();

    let req = json!({
        "jsonrpc": "2.0", "id": 50,
        "method": "tools/call",
        "params": {
            "name": "authenticated_request",
            "arguments": {
                "service": "github",
                "method": "POST",
                "endpoint": "/v1/deploy",
                "params": { "env": "prod" }
            }
        }
    });
    let resp = call(&req.to_string(), &sock).await.unwrap();
    assert_eq!(resp["result"]["isError"], json!(false), "{resp}");
    let body: Value =
        serde_json::from_str(resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(body["echo"]["service"], json!("github"));
    assert_eq!(body["echo"]["params"]["env"], json!("prod"));
}
