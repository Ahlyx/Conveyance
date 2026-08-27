//! JSON-RPC 2.0 / MCP protocol types for the stdio transport.
//!
//! Hand-rolled rather than pulled from an SDK on purpose: the shim
//! speaks exactly five methods over newline-delimited JSON, and owning
//! this file means the whole protocol surface is auditable in one
//! screenful. Compliance is arbitrated by real clients (mcp-inspector,
//! Claude Code), not by a dependency tree.
//!
//! Stdio framing per the MCP spec: one JSON-RPC message per line,
//! UTF-8, `\n` delimited. Nothing that is not a protocol message may
//! ever be written to stdout -- diagnostics go to stderr.

use serde_json::Value;

/// Protocol versions this shim can speak. A client requesting any of
/// these gets it echoed back; anything else gets the newest supported
/// version, which per the MCP spec tells the client to re-initialize.
pub const SUPPORTED_PROTOCOL_VERSIONS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];

/// The version we advertise when the client requests nothing we know.
pub const FALLBACK_PROTOCOL_VERSION: &str = "2025-06-18";

// ---- inbound ------------------------------------------------------------------

/// One parsed inbound line. `id` is preserved verbatim (number, string,
/// or null) because clients correlate on exact equality.
#[derive(Debug)]
pub struct InboundRequest {
    pub id: Option<Value>,
    pub method: String,
    pub params: Option<Value>,
}

/// Classification of an inbound line, deciding whether (and what) we
/// answer.
#[derive(Debug)]
pub enum Inbound {
    /// Has an `id`: demands a response (or a JSON-RPC error).
    Request(InboundRequest),
    /// No `id`: never answered, by JSON-RPC definition. The method name
    /// is validated (a nameless line is still an error) but not retained
    /// -- the shim ignores every notification it receives.
    Notification,
}

/// Parse one stdin line. Errors carry the JSON-RPC error code to reply
/// with (`id` unknown => null).
pub fn parse_line(line: &str) -> Result<Inbound, (i64, String)> {
    if line.trim().is_empty() {
        // Tolerate stray blank lines instead of erroring on them.
        return Err((-32700, String::new())); // handled specially: silent skip
    }

    let value: Value =
        serde_json::from_str(line).map_err(|e| (-32700, format!("parse error: {e}")))?;

    let obj = match value.as_object() {
        Some(o) => o,
        None => return Err((-32600, "request must be a JSON object".into())),
    };

    // jsonrpc field is required by spec; accept "2.0" only. Being strict
    // here catches clients speaking some other RPC dialect early.
    match obj.get("jsonrpc").and_then(Value::as_str) {
        Some("2.0") => {}
        _ => return Err((-32600, "missing or invalid jsonrpc field".into())),
    }

    // Presence is validated even for notifications: a line with no
    // method is malformed regardless of whether it wants an answer.
    let method = match obj.get("method").and_then(Value::as_str) {
        Some(m) => m.to_string(),
        None => return Err((-32600, "missing method field".into())),
    };

    let has_id = obj.get("id").is_some();
    let id = obj.get("id").cloned();

    if !has_id {
        return Ok(Inbound::Notification);
    }
    // A null id is treated as a notification per JSON-RPC semantics;
    // MCP clients do not send them.
    if matches!(id, Some(Value::Null)) {
        return Ok(Inbound::Notification);
    }

    Ok(Inbound::Request(InboundRequest {
        id,
        method,
        params: obj.get("params").cloned(),
    }))
}

// ---- outbound -----------------------------------------------------------------

/// A successful response payload body (the `result` value).
pub fn result_response(id: &Option<Value>, result: Value) -> String {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id.clone().unwrap_or(Value::Null),
        "result": result,
    });
    body.to_string()
}

/// A JSON-RPC protocol-level error (bad method, parse failure). Tool
/// failures do NOT use this shape -- they are `result` payloads with
/// `isError: true`, per MCP's tool-error model.
pub fn error_response(id: &Option<Value>, code: i64, message: &str) -> String {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id.clone().unwrap_or(Value::Null),
        "error": { "code": code, "message": message },
    });
    body.to_string()
}

// ---- initialize ---------------------------------------------------------------

/// Version negotiation: echo a supported request, else fall back to our
/// newest. See SUPPORTED_PROTOCOL_VERSIONS.
fn negotiate_version(params: Option<&Value>) -> String {
    let requested = params
        .and_then(|p| p.get("protocolVersion"))
        .and_then(Value::as_str);
    match requested {
        Some(v) if SUPPORTED_PROTOCOL_VERSIONS.contains(&v) => v.to_string(),
        _ => FALLBACK_PROTOCOL_VERSION.to_string(),
    }
}

/// Build the initialize result. Capabilities advertise tools only --
/// that is the entire surface this server has.
pub fn initialize_result(params: Option<&Value>) -> Value {
    serde_json::json!({
        "protocolVersion": negotiate_version(params),
        "capabilities": {
            "tools": { "listChanged": false }
        },
        "serverInfo": {
            "name": env!("CARGO_PKG_NAME"),
            "version": env!("CARGO_PKG_VERSION"),
            "title": "Conveyance",
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_request_with_numeric_id() {
        let line = r#"{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{}}"#;
        match parse_line(line).unwrap() {
            Inbound::Request(r) => {
                assert_eq!(r.id, Some(json!(7)));
                assert_eq!(r.method, "tools/list");
            }
            other => panic!("expected request, got {other:?}"),
        }
    }

    #[test]
    fn string_ids_are_preserved_verbatim() {
        let line = r#"{"jsonrpc":"2.0","id":"abc-1","method":"ping"}"#;
        match parse_line(line).unwrap() {
            Inbound::Request(r) => assert_eq!(r.id, Some(json!("abc-1"))),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn notifications_have_no_id_and_are_classified() {
        let line = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        assert!(matches!(parse_line(line).unwrap(), Inbound::Notification));
    }

    #[test]
    fn nameless_notification_is_still_rejected() {
        let (code, _) = parse_line(r#"{"jsonrpc":"2.0"}"#).unwrap_err();
        assert_eq!(code, -32600);
    }

    #[test]
    fn null_id_is_a_notification_not_a_request() {
        let line = r#"{"jsonrpc":"2.0","id":null,"method":"x"}"#;
        assert!(matches!(parse_line(line).unwrap(), Inbound::Notification));
    }

    #[test]
    fn malformed_json_is_parse_error() {
        let (code, _) = parse_line("{not json").unwrap_err();
        assert_eq!(code, -32700);
    }

    #[test]
    fn wrong_jsonrpc_version_is_invalid_request() {
        let (code, _) = parse_line(r#"{"jsonrpc":"1.0","id":1,"method":"x"}"#).unwrap_err();
        assert_eq!(code, -32600);
    }

    #[test]
    fn missing_method_is_invalid_request() {
        let (code, _) = parse_line(r#"{"jsonrpc":"2.0","id":1}"#).unwrap_err();
        assert_eq!(code, -32600);
    }

    #[test]
    fn blank_lines_are_silently_skippable() {
        let (code, msg) = parse_line("   \n").unwrap_err();
        assert_eq!(code, -32700);
        assert!(msg.is_empty(), "empty message marks the silent-skip case");
    }

    #[test]
    fn negotiation_echoes_supported_versions() {
        for v in SUPPORTED_PROTOCOL_VERSIONS {
            let params = json!({ "protocolVersion": v });
            let out = initialize_result(Some(&params));
            assert_eq!(out["protocolVersion"], json!(v));
        }
    }

    #[test]
    fn negotiation_falls_back_on_unknown_or_absent() {
        let params = json!({ "protocolVersion": "1999-01-01" });
        assert_eq!(
            initialize_result(Some(&params))["protocolVersion"],
            json!(FALLBACK_PROTOCOL_VERSION)
        );
        assert_eq!(
            initialize_result(None)["protocolVersion"],
            json!(FALLBACK_PROTOCOL_VERSION)
        );
    }

    #[test]
    fn response_shapes_carry_verbatim_id() {
        let id = Some(json!("id-9"));
        let r = result_response(&id, json!({"ok": true}));
        assert!(r.contains("\"id\":\"id-9\""));
        let e = error_response(&id, -32601, "nope");
        assert!(e.contains("-32601"));
    }
}
