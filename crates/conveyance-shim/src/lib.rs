//! The Conveyance MCP shim: speaks MCP (JSON-RPC over stdio) on behalf
//! of an external client, translating tool calls into daemon IPC.
//!
//! Security posture, all spec-mandated and structural:
//!
//! * Exactly four tools are exposed. There is no code path that reads
//!   key material or credentials -- not hidden, not gated: absent.
//! * The shim never starts sessions. Cold-start enforcement lives in
//!   the daemon; this layer only relays its structured verdicts.
//! * stdout carries protocol messages and nothing else. Diagnostics go
//!   to stderr -- a stray println here corrupts a client session, so
//!   the discipline is architectural (no macro that writes to stdout is
//!   reachable from the serve loop).

pub mod rpc;
pub mod tools;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// One served line's outcome. `Some(text)` is a protocol message to
/// write back; `None` means silence (notification, blank line).
async fn handle_line(line: &str, socket: &str) -> Option<String> {
    match rpc::parse_line(line) {
        // Blank lines happen when a terminal wraps stdin; skipping them
        // beats killing the session over whitespace.
        Err((-32700, empty)) if empty.is_empty() => None,

        Err((code, message)) => Some(rpc::error_response(&None, code, &message)),

        Ok(rpc::Inbound::Notification) => {
            // notifications/initialized and friends: acknowledged by
            // the absence of a response, per JSON-RPC.
            None
        }

        Ok(rpc::Inbound::Request(req)) => {
            let result = match req.method.as_str() {
                "initialize" => rpc::initialize_result(req.params.as_ref()),
                "ping" => serde_json::json!({}),
                "tools/list" => tools::tools_list_result(),
                "tools/call" => {
                    let name = req
                        .params
                        .as_ref()
                        .and_then(|p| p.get("name"))
                        .and_then(serde_json::Value::as_str);
                    let args = req.params.as_ref().and_then(|p| p.get("arguments"));
                    // Argument problems are protocol errors (-32602);
                    // everything the daemon answers becomes a tool
                    // result (possibly isError).
                    match name {
                        Some(name) => match tools::dispatch_call(socket, name, args).await {
                            Ok(v) => v,
                            Err(msg) => {
                                return Some(rpc::error_response(&req.id, -32602, &msg));
                            }
                        },
                        None => {
                            return Some(rpc::error_response(
                                &req.id,
                                -32602,
                                "missing params.name",
                            ));
                        }
                    }
                }
                other => {
                    return Some(rpc::error_response(
                        &req.id,
                        -32601,
                        &format!("method '{other}' not found"),
                    ));
                }
            };
            Some(rpc::result_response(&req.id, result))
        }
    }
}

/// Serve MCP over stdio until stdin closes, then exit cleanly. This is
/// the shim's whole life; `socket` is the daemon IPC identity.
pub async fn run(socket: &str) -> Result<(), String> {
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut stdout = tokio::io::stdout();

    let mut buf = Vec::with_capacity(4096);
    loop {
        buf.clear();
        let n = reader
            .read_until(b'\n', &mut buf)
            .await
            .map_err(|e| format!("stdin read failed: {e}"))?;
        if n == 0 {
            // stdin closed: the client is gone. Exit 0 quietly.
            return Ok(());
        }

        let line = String::from_utf8_lossy(&buf[..n]);
        if let Some(response) = handle_line(line.trim_end_matches(['\n', '\r']), socket).await {
            let mut out = response;
            out.push('\n');
            stdout
                .write_all(out.as_bytes())
                .await
                .map_err(|e| format!("stdout write failed: {e}"))?;
            stdout
                .flush()
                .await
                .map_err(|e| format!("stdout flush failed: {e}"))?;
        }
    }
}

#[cfg(test)]
mod tests;
