//! The four spec'd tools: schemas, dispatch to the daemon, and the
//! error translation table.
//!
//! Tool failures are NOT JSON-RPC errors -- MCP's model is that a
//! tool call returns `isError: true` with content the model can read.
//! The text payload is the spec's exact five-field error shape
//! (`code`, `message`, `retryable`, `retry_after_seconds` (null),
//! `details` (null)) so downstream parsing matches every other
//! Conveyance surface byte-for-byte.
//!
//! Deliberate pass-through posture: the shim adds no policy of its
//! own. Cold-start enforcement already lives in the daemon; a
//! check_session while NO_SESSION surfaces the daemon's structured
//! conveyance/no_session error verbatim. The shim MUST NOT auto-start
//! sessions, and there is no code path here that could.

use serde_json::Value;

use conveyance_daemon::ipc::{IpcError, IpcRequest, IpcResponse};

/// One tool definition for tools/list.
struct ToolDef {
    name: &'static str,
    description: &'static str,
    schema: Value,
}

/// The four tool definitions. A function rather than a const: schemas
/// are runtime-built JSON values.
fn tool_defs() -> Vec<ToolDef> {
    vec![
        ToolDef {
            name: "authenticated_request",
            description: "Request that the paired phone execute an HTTP request against `service` \
using its stored credentials. Blocks until approved and executed on the \
phone, or denied, or the session ends. Returns the response body on \
success, or a structured error.",
            schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "service": { "type": "string", "description": "Service name, e.g. \"github\", \"aws\"" },
                    "method": { "type": "string", "description": "HTTP method, e.g. \"GET\", \"POST\"" },
                    "endpoint": { "type": "string", "description": "Endpoint path, e.g. \"/v1/deploy\"" },
                    "params": {
                        "type": "object",
                        "description": "Request parameters sent to the phone",
                        "default": {}
                    }
                },
                "required": ["service", "method", "endpoint"],
                "additionalProperties": false
            }),
        },
        ToolDef {
            name: "list_services",
            description: "List the services for which the phone has stored credentials. Requires an \
active session but no per-call approval.",
            schema: serde_json::json!({
                "type": "object", "properties": {}, "additionalProperties": false
            }),
        },
        ToolDef {
            name: "check_session",
            description: "Return session state: active/inactive and seconds remaining on the idle \
and hard-cap timers. Errors with conveyance/no_session when no session is active.",
            schema: serde_json::json!({
                "type": "object", "properties": {}, "additionalProperties": false
            }),
        },
        ToolDef {
            name: "end_session",
            description: "End the active Conveyance session. Idempotent; a no-op when no session \
is active.",
            schema: serde_json::json!({
                "type": "object", "properties": {}, "additionalProperties": false
            }),
        },
    ]
}

/// tools/list result. Exactly four tools, forever: anything else is a
/// spec violation with security implications (no key-material tools).
pub fn tools_list_result() -> Value {
    let tools: Vec<Value> = tool_defs()
        .into_iter()
        .map(|t| {
            serde_json::json!({
                "name": t.name,
                "description": t.description,
                "inputSchema": t.schema,
            })
        })
        .collect();
    serde_json::json!({ "tools": tools })
}

/// Validate `tools/call` arguments and translate to an IPC request.
/// Argument problems are protocol-level (-32602), not tool errors.
fn build_ipc_request(name: &str, args: Option<&Value>) -> Result<IpcRequest, String> {
    let empty_args = serde_json::json!({});
    let args = match args {
        Some(v) if v.is_object() => v,
        Some(_) => return Err("tool arguments must be an object".into()),
        None => &empty_args,
    };

    match name {
        "authenticated_request" => {
            let get = |key: &str| -> Result<String, String> {
                args.get(key)
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .ok_or(format!("missing required string argument '{key}'"))
            };
            Ok(IpcRequest::AuthenticatedRequest {
                service: get("service")?,
                method: get("method")?,
                endpoint: get("endpoint")?,
                params: args
                    .get("params")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!({})),
                // Not part of the MCP surface: clients cannot spoof a
                // caller hint beyond what the daemon itself observed.
                requested_by: None,
            })
        }
        "list_services" => Ok(IpcRequest::ListServices),
        "check_session" => Ok(IpcRequest::CheckSession),
        "end_session" => Ok(IpcRequest::SessionEnd),
        other => Err(format!("unknown tool '{other}'")),
    }
}

/// Map a daemon IPC response onto an MCP tools/call result value.
/// Daemon errors become isError:true tool results carrying the exact
/// five-field shape from the spec's error model.
pub fn call_result_for(resp: IpcResponse) -> Value {
    let result_json = match resp {
        IpcResponse::Body(body) => body,
        IpcResponse::Services(names) => {
            serde_json::Value::Array(names.into_iter().map(serde_json::Value::String).collect())
        }
        IpcResponse::SessionActive {
            idle_seconds_remaining,
            hard_cap_seconds_remaining,
        } => serde_json::json!({
            "session": "active",
            "idle_seconds_remaining": idle_seconds_remaining,
            "hard_cap_seconds_remaining": hard_cap_seconds_remaining,
        }),
        IpcResponse::SessionEnded => serde_json::json!({ "session": "inactive" }),
        IpcResponse::SessionStarted | IpcResponse::Ok => serde_json::json!({ "ok": true }),
        IpcResponse::Error {
            code,
            message,
            retryable,
        } => {
            let err = serde_json::json!({
                "code": code,
                "message": message,
                "retryable": retryable,
                // Both nulls are PRESENT by spec mandate: field-set
                // stability is part of the error contract.
                "retry_after_seconds": Value::Null,
                "details": Value::Null,
            });
            return tool_error(err);
        }
        IpcResponse::Status {
            version,
            uptime_seconds,
            session_active,
            paired_phones,
        } => {
            // Status is reachable via check_session? No -- it is not a
            // tool. Kept unreachable defensively rather than panicking.
            let _ = (version, uptime_seconds, session_active, paired_phones);
            serde_json::json!({ "ok": true })
        }
    };
    tool_success(result_json)
}

fn tool_success(value: Value) -> Value {
    serde_json::json!({
        "content": [{ "type": "text", "text": value.to_string() }],
        "isError": false,
    })
}

fn tool_error(five_field_error: Value) -> Value {
    serde_json::json!({
        "content": [{ "type": "text", "text": five_field_error.to_string() }],
        "isError": true,
    })
}

/// Translate an IPC transport failure into the same five-field shape.
pub fn ipc_error_result(err: &IpcError) -> Value {
    let (code, retryable, hint) = match err {
        IpcError::NotRunning { .. } => (
            "conveyance/internal",
            true,
            "daemon is not running or its socket changed; start it with `conveyance daemon`",
        ),
        _ => ("conveyance/internal", false, "unexpected IPC failure"),
    };
    let message = format!("{err}\nhint: {hint}");
    tool_error(serde_json::json!({
        "code": code,
        "message": message,
        "retryable": retryable,
        "retry_after_seconds": Value::Null,
        "details": Value::Null,
    }))
}

/// Execute one tools/call end-to-end: validate arguments, talk to the
/// daemon, map the answer. `socket` is the daemon's IPC identity.
pub async fn dispatch_call(
    socket: &str,
    name: &str,
    args: Option<&Value>,
) -> Result<Value, String> {
    let ipc_req = build_ipc_request(name, args)?;

    match conveyance_daemon::ipc::single_request(socket, ipc_req).await {
        Ok(resp) => Ok(call_result_for(resp)),
        Err(e) => Ok(ipc_error_result(&e)),
    }
}
