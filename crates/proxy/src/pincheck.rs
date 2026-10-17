//! F3: runtime hook connecting PinStore to proxy traffic.
//!
//! Detects MCP `tools/list` JSON-RPC traffic, verifies tool-definition
//! hashes against the pin store, and produces the JSON-RPC error body used
//! to block a response whose tool definitions drifted.

use std::sync::Arc;

use bytes::Bytes;
use parking_lot::Mutex;
use serde_json::Value;

use forculus_audit::event::{
    AuditEvent, Channel, ErrorInfo, EventOutcome, EventType, RequestInfo, SessionInfo,
};
use forculus_audit::logger::AuditLogger;

use crate::pins::{PinStore, PinVerdict, ToolDef};

/// True if the request body is a JSON-RPC call to `tools/list`.
pub fn is_tools_list_request(req_body: &[u8]) -> bool {
    serde_json::from_slice::<Value>(req_body)
        .ok()
        .and_then(|v| {
            v.get("method")
                .and_then(|m| m.as_str())
                .map(|m| m == "tools/list")
        })
        .unwrap_or(false)
}

/// Extract the JSON-RPC id from a request body, for error responses.
pub fn request_id(req_body: &[u8]) -> Option<Value> {
    serde_json::from_slice::<Value>(req_body)
        .ok()
        .and_then(|v| v.get("id").cloned())
}

/// Extract tool definitions from a successful `tools/list` response body.
/// Returns None for anything that is not a tools/list result.
pub fn parse_tools_list(resp_body: &[u8]) -> Option<Vec<ToolDef>> {
    let v = serde_json::from_slice::<Value>(resp_body).ok()?;
    let tools = v.get("result")?.get("tools")?.as_array()?;
    let defs: Vec<ToolDef> = tools
        .iter()
        .filter_map(|t| {
            Some(ToolDef {
                name: t.get("name")?.as_str()?.to_string(),
                description: t
                    .get("description")
                    .and_then(|d| d.as_str())
                    .unwrap_or_default()
                    .to_string(),
                input_schema: t
                    .get("inputSchema")
                    .or_else(|| t.get("input_schema"))
                    .cloned()
                    .unwrap_or(Value::Null),
            })
        })
        .collect();
    if defs.is_empty() { None } else { Some(defs) }
}

/// Verify tool definitions against the pin store.
///
/// On `Changed`, emits a `ToolPinViolation` audit event and returns Err with
/// a human-readable message; on `Pinned`/`NewServer`, returns Ok and the
/// caller forwards the upstream response unchanged.
pub fn verify_tools_list(
    pin_store: &Arc<Mutex<PinStore>>,
    channel: Channel,
    host: &str,
    tools: &[ToolDef],
    audit_logger: Option<&AuditLogger>,
    session: Option<&SessionInfo>,
    tool: &str,
    action: &str,
    target: &str,
    duration_us: u64,
) -> Result<(), String> {
    let mut store = pin_store.lock();
    let verdict = store.verify(host, tools);
    match verdict {
        PinVerdict::Pinned | PinVerdict::NewServer => Ok(()),
        PinVerdict::Changed(names) => {
            let message = format!(
                "tool definition hash mismatch on server {}: {}",
                host,
                names.join(", ")
            );
            if let Some(logger) = audit_logger {
                let mut builder = AuditEvent::builder(EventType::ToolPinViolation, channel)
                    .outcome(EventOutcome::Denied)
                    .request(RequestInfo {
                        tool: tool.to_string(),
                        action: action.to_string(),
                        resource: None,
                        target: target.to_string(),
                    })
                    .error(ErrorInfo {
                        category: "tool_pin_violation".to_string(),
                        message: message.clone(),
                    })
                    .duration_us(duration_us);
                if let Some(si) = session {
                    builder = builder.session(si.clone());
                }
                logger.log(builder.build());
            }
            Err(message)
        }
    }
}

/// JSON-RPC error body returned to the client instead of a blocked
/// `tools/list` response.
pub fn pin_violation_error_body(request_id: Option<&Value>, message: &str) -> Bytes {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": -32001,
            "message": format!("Forculus: {}", message),
        }
    });
    Bytes::from(body.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_tools_list_request() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
        assert!(is_tools_list_request(body));
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}"#;
        assert!(!is_tools_list_request(body));
        assert!(!is_tools_list_request(b"not json"));
    }

    #[test]
    fn extracts_request_id() {
        let body = br#"{"jsonrpc":"2.0","id":42,"method":"tools/list"}"#;
        assert_eq!(request_id(body), Some(serde_json::json!(42)));
        assert_eq!(request_id(b"nope"), None);
    }

    #[test]
    fn parses_tools_list_response() {
        let body = br#"{"jsonrpc":"2.0","id":1,"result":{"tools":[
            {"name":"t1","description":"d","inputSchema":{"type":"object"}},
            {"name":"t2","description":"d2","input_schema":{"type":"object"}}
        ]}}"#;
        let defs = parse_tools_list(body).unwrap();
        assert_eq!(defs.len(), 2);
        assert_eq!(defs[0].name, "t1");
        assert!(parse_tools_list(br#"{"jsonrpc":"2.0","id":1,"error":{"code":1}}"#).is_none());
        assert!(parse_tools_list(b"nope").is_none());
    }

    #[test]
    fn violation_body_shape() {
        let id = serde_json::json!(7);
        let body = pin_violation_error_body(Some(&id), "boom");
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"]["code"], -32001);
        assert_eq!(v["id"], 7);
        assert!(v["error"]["message"].as_str().unwrap().contains("boom"));
    }
}
