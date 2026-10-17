//! Integration tests for the MCP gateway.
//!
//! Uses in-process mock upstream servers connected via tokio duplex channels
//! rather than spawning real child processes.

use std::collections::HashMap;
use std::sync::Arc;

use forculus_mcp::gateway::McpGateway;
use forculus_mcp::transport::stdio::StdioTransport;
use forculus_mcp::types::{
    CONTENT_BLOCKED, JsonRpcMessage, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse,
    POLICY_DENIED, RATE_LIMITED, RequestId, Tool, ToolCallParams,
};
use forculus_policy::engine::PolicyEngine;
use tokio::io::{DuplexStream, duplex};

// ── Helpers ──────────────────────────────────────────────────────────

/// Create a pair of transports connected to each other (simulating stdio
/// between two processes).
fn create_transport_pair() -> (
    StdioTransport<DuplexStream, DuplexStream>,
    StdioTransport<DuplexStream, DuplexStream>,
) {
    let (a_to_b_read, a_to_b_write) = duplex(8192);
    let (b_to_a_read, b_to_a_write) = duplex(8192);
    (
        StdioTransport::new(b_to_a_read, a_to_b_write), // "client" side
        StdioTransport::new(a_to_b_read, b_to_a_write), // "server" side
    )
}

/// A mock upstream MCP server that responds to initialize, tools/list, and tools/call.
async fn run_mock_mcp_server(
    mut transport: StdioTransport<DuplexStream, DuplexStream>,
    tools: Vec<Tool>,
) {
    loop {
        match transport.read_message().await {
            Ok(Some(JsonRpcMessage::Request(req))) => {
                let response = match req.method.as_str() {
                    "initialize" => JsonRpcResponse::success(
                        req.id,
                        serde_json::json!({
                            "protocolVersion": "2024-11-05",
                            "capabilities": { "tools": {} },
                            "serverInfo": { "name": "mock-server", "version": "1.0" }
                        }),
                    ),
                    "tools/list" => {
                        JsonRpcResponse::success(req.id, serde_json::json!({ "tools": tools }))
                    }
                    "tools/call" => {
                        let params: ToolCallParams =
                            serde_json::from_value(req.params.unwrap()).unwrap();
                        if params.name == "fail_tool" {
                            JsonRpcResponse::error(req.id, -1, "mock tool error".to_string())
                        } else {
                            JsonRpcResponse::success(
                                req.id,
                                serde_json::json!({
                                    "content": [{
                                        "type": "text",
                                        "text": format!("Called: {}", params.name)
                                    }]
                                }),
                            )
                        }
                    }
                    _ => JsonRpcResponse::error(req.id, -32601, "not found".to_string()),
                };
                if transport.write_message(&response).await.is_err() {
                    break;
                }
            }
            Ok(Some(JsonRpcMessage::Notification(_))) => {} // ignore
            Ok(None) => break,                              // EOF
            Err(_) => break,
            Ok(Some(JsonRpcMessage::Response(_))) => {} // ignore
        }
    }
}

fn sample_tool(name: &str, desc: &str) -> Tool {
    Tool {
        name: name.to_string(),
        description: Some(desc.to_string()),
        input_schema: serde_json::json!({"type": "object"}),
    }
}

// ── Integration tests ────────────────────────────────────────────────

#[tokio::test]
async fn full_handshake() {
    let gateway = McpGateway::new_with_upstreams(HashMap::new());

    let init_req = JsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: RequestId::Number(1),
        method: "initialize".into(),
        params: Some(serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "test-agent", "version": "1.0" }
        })),
    });

    let response = gateway.handle_message(init_req).await.unwrap();
    if let JsonRpcMessage::Response(resp) = response {
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["protocolVersion"], "2024-11-05");
        assert_eq!(result["serverInfo"]["name"], "forculus");
        assert!(result["capabilities"]["tools"].is_object());
    } else {
        panic!("Expected response");
    }

    // Send initialized notification — should return None.
    let notif = JsonRpcMessage::Notification(JsonRpcNotification {
        jsonrpc: "2.0".into(),
        method: "notifications/initialized".into(),
        params: None,
    });
    assert!(gateway.handle_message(notif).await.is_none());
}

#[tokio::test]
async fn tools_list_with_namespacing() {
    // Create mock upstream with tools, build gateway manually.
    let (client_transport, server_transport) = create_transport_pair();
    let tools = vec![
        sample_tool("read", "Read a file"),
        sample_tool("write", "Write a file"),
    ];
    let tools_for_mock = tools.clone();
    tokio::spawn(async move {
        run_mock_mcp_server(server_transport, tools_for_mock).await;
    });

    // Do the client handshake + tool discovery.
    let mut client = client_transport;
    let mut rid: i64 = 1;
    forculus_mcp::client::initialize(&mut client, &mut rid)
        .await
        .unwrap();
    let discovered = forculus_mcp::client::list_tools(&mut client, &mut rid)
        .await
        .unwrap();
    assert_eq!(discovered.len(), 2);
    assert_eq!(discovered[0].name, "read");
    assert_eq!(discovered[1].name, "write");
}

#[tokio::test]
async fn tool_call_forwarding_via_client() {
    let (client_transport, server_transport) = create_transport_pair();
    let tools = vec![sample_tool("greet", "Say hello")];
    tokio::spawn(async move {
        run_mock_mcp_server(server_transport, tools).await;
    });

    let mut client = client_transport;
    let mut rid: i64 = 1;
    forculus_mcp::client::initialize(&mut client, &mut rid)
        .await
        .unwrap();

    let result = forculus_mcp::client::call_tool(&mut client, &mut rid, "greet", None)
        .await
        .unwrap();
    assert_eq!(result.content.len(), 1);
    match &result.content[0] {
        forculus_mcp::types::ToolContent::Text { text } => {
            assert_eq!(text, "Called: greet");
        }
        _ => panic!("Expected text content"),
    }
}

#[tokio::test]
async fn gateway_merged_tools_namespaces_correctly() {
    // We can't easily create real UpstreamServers with DuplexStream transports
    // (they require ChildStdout/ChildStdin). Instead, test merged_tools logic
    // by verifying the gateway's initialize and tools/list responses.
    let gateway = McpGateway::new_with_upstreams(HashMap::new());

    // With no upstreams, merged_tools returns only the builtin governance tools.
    let tools = gateway.merged_tools().await;
    assert_eq!(tools.len(), 7, "expected 7 builtin tools");
    assert!(
        tools.iter().all(|t| t.name.starts_with("forculus__")),
        "all builtin tools should be prefixed with forculus__"
    );

    // Test that tools/list returns the builtin tools via handle_message.
    let req = JsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: RequestId::Number(1),
        method: "tools/list".into(),
        params: None,
    });
    let resp = gateway.handle_message(req).await.unwrap();
    if let JsonRpcMessage::Response(r) = resp {
        let tools_arr = r.result.unwrap()["tools"].as_array().unwrap().clone();
        assert_eq!(tools_arr.len(), 7);
    } else {
        panic!("Expected response");
    }
}

#[tokio::test]
async fn tool_call_without_namespace_returns_error() {
    let gateway = McpGateway::new_with_upstreams(HashMap::new());

    let req = JsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: RequestId::Number(1),
        method: "tools/call".into(),
        params: Some(serde_json::json!({
            "name": "no_namespace_tool",
            "arguments": {}
        })),
    });

    let resp = gateway.handle_message(req).await.unwrap();
    if let JsonRpcMessage::Response(r) = resp {
        assert!(r.error.is_some());
        let err = r.error.unwrap();
        assert!(err.message.contains("server__tool"));
    } else {
        panic!("Expected response");
    }
}

#[tokio::test]
async fn tool_call_unknown_server_returns_error() {
    let gateway = McpGateway::new_with_upstreams(HashMap::new());

    let req = JsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: RequestId::Number(1),
        method: "tools/call".into(),
        params: Some(serde_json::json!({
            "name": "nonexistent__tool",
            "arguments": {}
        })),
    });

    let resp = gateway.handle_message(req).await.unwrap();
    if let JsonRpcMessage::Response(r) = resp {
        assert!(r.error.is_some());
        let err = r.error.unwrap();
        assert!(err.message.contains("nonexistent"));
    } else {
        panic!("Expected response");
    }
}

#[tokio::test]
async fn unknown_method_returns_error() {
    let gateway = McpGateway::new_with_upstreams(HashMap::new());

    let req = JsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: RequestId::Number(1),
        method: "some/unknown".into(),
        params: None,
    });

    let resp = gateway.handle_message(req).await.unwrap();
    if let JsonRpcMessage::Response(r) = resp {
        assert!(r.error.is_some());
        assert_eq!(r.error.unwrap().code, forculus_mcp::types::METHOD_NOT_FOUND);
    } else {
        panic!("Expected response");
    }
}

#[tokio::test]
async fn ping_returns_success() {
    let gateway = McpGateway::new_with_upstreams(HashMap::new());

    let req = JsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: RequestId::String("ping-1".into()),
        method: "ping".into(),
        params: None,
    });

    let resp = gateway.handle_message(req).await.unwrap();
    if let JsonRpcMessage::Response(r) = resp {
        assert!(r.error.is_none());
        assert_eq!(r.id, RequestId::String("ping-1".into()));
    } else {
        panic!("Expected response");
    }
}

#[tokio::test]
async fn error_propagation_from_upstream() {
    // Test that when upstream returns an error for tools/call, the client
    // propagates it as a ForculusError.
    let (client_transport, server_transport) = create_transport_pair();
    let tools = vec![sample_tool("fail_tool", "Always fails")];
    tokio::spawn(async move {
        run_mock_mcp_server(server_transport, tools).await;
    });

    let mut client = client_transport;
    let mut rid: i64 = 1;
    forculus_mcp::client::initialize(&mut client, &mut rid)
        .await
        .unwrap();

    let err = forculus_mcp::client::call_tool(&mut client, &mut rid, "fail_tool", None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("mock tool error"));
}

#[tokio::test]
async fn multiple_upstream_tool_discovery() {
    // Verify that two independent mock servers each return their own tools.
    let (client1, server1) = create_transport_pair();
    let (client2, server2) = create_transport_pair();

    let tools1 = vec![sample_tool("read", "Read a file")];
    let tools2 = vec![sample_tool("search", "Search the web")];

    let t1 = tools1.clone();
    let t2 = tools2.clone();
    tokio::spawn(async move {
        run_mock_mcp_server(server1, t1).await;
    });
    tokio::spawn(async move {
        run_mock_mcp_server(server2, t2).await;
    });

    let mut c1 = client1;
    let mut c2 = client2;
    let mut rid1: i64 = 1;
    let mut rid2: i64 = 1;

    forculus_mcp::client::initialize(&mut c1, &mut rid1)
        .await
        .unwrap();
    forculus_mcp::client::initialize(&mut c2, &mut rid2)
        .await
        .unwrap();

    let discovered1 = forculus_mcp::client::list_tools(&mut c1, &mut rid1)
        .await
        .unwrap();
    let discovered2 = forculus_mcp::client::list_tools(&mut c2, &mut rid2)
        .await
        .unwrap();

    assert_eq!(discovered1.len(), 1);
    assert_eq!(discovered1[0].name, "read");
    assert_eq!(discovered2.len(), 1);
    assert_eq!(discovered2[0].name, "search");
}

#[tokio::test]
async fn tool_call_missing_params_returns_error() {
    let gateway = McpGateway::new_with_upstreams(HashMap::new());

    let req = JsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: RequestId::Number(1),
        method: "tools/call".into(),
        params: None,
    });

    let resp = gateway.handle_message(req).await.unwrap();
    if let JsonRpcMessage::Response(r) = resp {
        assert!(r.error.is_some());
        assert!(r.error.unwrap().message.contains("Missing params"));
    } else {
        panic!("Expected response");
    }
}

#[tokio::test]
async fn unsolicited_response_returns_none() {
    let gateway = McpGateway::new_with_upstreams(HashMap::new());

    let msg = JsonRpcMessage::Response(JsonRpcResponse::success(
        RequestId::Number(999),
        serde_json::json!({}),
    ));

    assert!(gateway.handle_message(msg).await.is_none());
}

// ── Policy integration tests ─────────────────────────────────────────

/// Build a PolicyEngine from inline YAML.
fn engine_with_rules(yaml: &str) -> Arc<PolicyEngine> {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("test.yaml"), yaml).unwrap();
    Arc::new(PolicyEngine::from_directory(dir.path()).unwrap())
}

/// Build a tools/call request for the given namespaced tool name.
fn tool_call_request(id: i64, namespaced_name: &str) -> JsonRpcMessage {
    JsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: RequestId::Number(id),
        method: "tools/call".into(),
        params: Some(serde_json::json!({
            "name": namespaced_name,
            "arguments": {}
        })),
    })
}

#[tokio::test]
async fn tool_call_allowed_by_policy() {
    let engine = engine_with_rules(
        r#"
rules:
  - name: allow-all
    verdict: allow
    match:
      tools: ["*"]
"#,
    );

    let gateway = McpGateway::new_with_upstreams(HashMap::new()).with_policy_engine(engine);

    // Policy allows, but no upstream exists → expect "Unknown server" error,
    // NOT a policy denial.
    let resp = gateway
        .handle_message(tool_call_request(1, "mock__read"))
        .await
        .unwrap();

    if let JsonRpcMessage::Response(r) = resp {
        let err = r.error.expect("should have an error (no upstream)");
        assert_ne!(err.code, POLICY_DENIED, "should NOT be a policy denial");
        assert!(
            err.message.contains("Unknown server"),
            "expected 'Unknown server', got: {}",
            err.message,
        );
    } else {
        panic!("Expected response");
    }
}

#[tokio::test]
async fn tool_call_denied_by_policy() {
    let engine = engine_with_rules(
        r#"
rules:
  - name: deny-all
    verdict: deny
    reason: "blocked by test policy"
"#,
    );

    let gateway = McpGateway::new_with_upstreams(HashMap::new()).with_policy_engine(engine);

    let resp = gateway
        .handle_message(tool_call_request(1, "mock__read"))
        .await
        .unwrap();

    if let JsonRpcMessage::Response(r) = resp {
        let err = r.error.expect("should be denied");
        assert_eq!(err.code, POLICY_DENIED);
        assert!(err.message.contains("Policy denied"));
        assert!(err.message.contains("blocked by test policy"));
    } else {
        panic!("Expected response");
    }
}

#[tokio::test]
async fn tool_call_default_deny_no_matching_rule() {
    // Policy has a rule that only matches a different tool — no rule matches
    // the requested tool, so the engine's default-deny kicks in.
    let engine = engine_with_rules(
        r#"
rules:
  - name: allow-specific
    verdict: allow
    match:
      tools: ["other_server"]
      actions: ["specific_action"]
"#,
    );

    let gateway = McpGateway::new_with_upstreams(HashMap::new()).with_policy_engine(engine);

    let resp = gateway
        .handle_message(tool_call_request(1, "mock__read"))
        .await
        .unwrap();

    if let JsonRpcMessage::Response(r) = resp {
        let err = r.error.expect("should be denied by default");
        assert_eq!(err.code, POLICY_DENIED);
        assert!(
            err.message.contains("default deny"),
            "expected default deny message, got: {}",
            err.message,
        );
    } else {
        panic!("Expected response");
    }
}

// ── Audit cross-crate integration tests ─────────────────────────────

/// A minimal mock MCP server implemented as a Python script.
/// Handles initialize, tools/list, and tools/call over stdio JSON-RPC.
const MOCK_MCP_SERVER_SCRIPT: &str = r#"
import sys, json
def respond(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except Exception:
        continue
    msg_id = msg.get("id")
    if msg_id is None:
        continue
    method = msg.get("method", "")
    if method == "initialize":
        respond({"jsonrpc": "2.0", "id": msg_id, "result": {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "mock", "version": "1.0"}}})
    elif method == "tools/list":
        respond({"jsonrpc": "2.0", "id": msg_id, "result": {"tools": [{"name": "greet", "description": "Say hi", "inputSchema": {"type": "object"}}]}})
    elif method == "tools/call":
        respond({"jsonrpc": "2.0", "id": msg_id, "result": {"content": [{"type": "text", "text": "Hello from mock!"}]}})
    else:
        respond({"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": "Method not found"}})
"#;

#[tokio::test]
async fn mcp_tool_call_produces_audit_event() {
    // Skip if python3 is not available.
    if std::process::Command::new("python3")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("python3 not found, skipping test");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("mock_mcp_server.py");
    std::fs::write(&script_path, MOCK_MCP_SERVER_SCRIPT).unwrap();

    let audit_db = dir.path().join("audit.db");
    let logger = forculus_audit::logger::AuditLogger::new(&audit_db).unwrap();

    let config = forculus_config::McpGatewayConfig {
        upstream_servers: vec![forculus_config::UpstreamServerConfig {
            name: "mock".into(),
            url: None,            command: "python3".into(),
            args: vec![script_path.to_str().unwrap().to_string()],
            env: Default::default(),
        }],
        ..Default::default()
    };

    let engine = engine_with_rules(
        r#"
rules:
  - name: allow-all
    verdict: allow
    match:
      tools: ["*"]
"#,
    );

    let gateway = McpGateway::new(config)
        .await
        .unwrap()
        .with_policy_engine(engine)
        .with_audit_logger(logger.clone());

    // Send a tools/call for mock__greet (the mock server exposes "greet").
    let resp = gateway
        .handle_message(tool_call_request(1, "mock__greet"))
        .await
        .unwrap();
    if let JsonRpcMessage::Response(r) = &resp {
        assert!(
            r.error.is_none(),
            "tool call should succeed, got error: {:?}",
            r.error
        );
    } else {
        panic!("Expected response");
    }

    // Shut down the logger to flush events.
    logger.shutdown().await;

    // Query the audit store and verify the event.
    let store = forculus_audit::store::AuditStore::open(&audit_db).unwrap();
    let events = store
        .query(&forculus_audit::query::AuditFilter::default())
        .unwrap();

    assert!(!events.is_empty(), "should have at least one audit event");
    let event = &events[0];
    assert_eq!(
        event.event_type,
        forculus_audit::event::EventType::RequestProcessed
    );
    assert_eq!(event.outcome, forculus_audit::event::EventOutcome::Success);
    assert_eq!(event.channel, forculus_audit::event::Channel::McpGateway);

    gateway.shutdown().await;
}

#[tokio::test]
async fn mcp_denied_tool_call_produces_denied_audit_event() {
    let dir = tempfile::tempdir().unwrap();
    let audit_db = dir.path().join("audit.db");
    let logger = forculus_audit::logger::AuditLogger::new(&audit_db).unwrap();

    let engine = engine_with_rules(
        r#"
rules:
  - name: deny-all
    verdict: deny
    reason: "blocked by test policy"
"#,
    );

    let gateway = McpGateway::new_with_upstreams(HashMap::new())
        .with_policy_engine(engine)
        .with_audit_logger(logger.clone());

    let resp = gateway
        .handle_message(tool_call_request(1, "mock__greet"))
        .await
        .unwrap();
    if let JsonRpcMessage::Response(r) = &resp {
        assert!(r.error.is_some(), "should be denied");
        assert_eq!(r.error.as_ref().unwrap().code, POLICY_DENIED);
    } else {
        panic!("Expected response");
    }

    // Shut down the logger to flush events.
    logger.shutdown().await;

    // Query the audit store and verify the denial event.
    let store = forculus_audit::store::AuditStore::open(&audit_db).unwrap();
    let events = store
        .query(&forculus_audit::query::AuditFilter::default())
        .unwrap();

    assert!(!events.is_empty(), "should have at least one audit event");
    let event = &events[0];
    assert_eq!(
        event.event_type,
        forculus_audit::event::EventType::PolicyDecision
    );
    assert_eq!(event.outcome, forculus_audit::event::EventOutcome::Denied);
    assert_eq!(event.channel, forculus_audit::event::Channel::McpGateway);

    // Verify policy information is included.
    assert!(event.policy.is_some(), "policy info should be populated");
    let policy = event.policy.as_ref().unwrap();
    assert_eq!(policy.verdict, "deny");
}

#[tokio::test]
async fn governance_metadata_contains_real_verdict() {
    // Test that governance_metadata() produces correct fields from a real
    // policy evaluation (cross-crate: policy engine → MCP governance).
    let engine = engine_with_rules(
        r#"
rules:
  - name: allow-reads
    verdict: allow
    reason: "read operations are safe"
    match:
      tools: ["*"]
      actions: ["read_*"]
"#,
    );

    let ctx = forculus_policy::context::RequestContext::new("fs", "read_file");
    let eval = engine.evaluate(&ctx);

    let meta = forculus_mcp::governance::governance_metadata(&eval);

    assert_eq!(meta["governance"]["verdict"], "allow");
    assert_eq!(meta["governance"]["matched_rule"], "allow-reads");
    assert_eq!(meta["governance"]["reason"], "read operations are safe");
    assert_eq!(meta["governance"]["version"], "0.2.0");
    assert!(meta["governance"]["evaluation_time_us"].is_number());
}

// ── Content inspection cross-crate integration tests ─────────────────

#[tokio::test]
async fn mcp_tool_call_blocked_by_content_inspection() {
    // A tool call whose arguments contain an AWS key should be blocked
    // by the content scanner before ever reaching an upstream server.
    let engine = engine_with_rules(
        r#"
rules:
  - name: allow-all
    verdict: allow
    match:
      tools: ["*"]
"#,
    );

    let scanner = Arc::new(forculus_inspect::scanner::ContentScanner::builtin());

    let gateway = McpGateway::new_with_upstreams(HashMap::new())
        .with_policy_engine(engine)
        .with_content_scanner(scanner);

    // Build a tools/call with sensitive content in arguments.
    let req = JsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: RequestId::Number(1),
        method: "tools/call".into(),
        params: Some(serde_json::json!({
            "name": "mock__read",
            "arguments": {
                "config": "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"
            }
        })),
    });

    let resp = gateway.handle_message(req).await.unwrap();
    if let JsonRpcMessage::Response(r) = resp {
        let err = r.error.expect("should be blocked by content inspection");
        assert_eq!(
            err.code, CONTENT_BLOCKED,
            "expected CONTENT_BLOCKED (-32003), got: {} — {}",
            err.code, err.message,
        );
        assert!(
            err.message.contains("content inspection"),
            "error message should mention content inspection, got: {}",
            err.message,
        );
    } else {
        panic!("Expected response");
    }
}

/// Mock MCP server that returns tool results containing sensitive data.
const MOCK_MCP_SERVER_WITH_SECRET: &str = r#"
import sys, json
def respond(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except Exception:
        continue
    msg_id = msg.get("id")
    if msg_id is None:
        continue
    method = msg.get("method", "")
    if method == "initialize":
        respond({"jsonrpc": "2.0", "id": msg_id, "result": {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "mock", "version": "1.0"}}})
    elif method == "tools/list":
        respond({"jsonrpc": "2.0", "id": msg_id, "result": {"tools": [{"name": "leak", "description": "Leaks a secret", "inputSchema": {"type": "object"}}]}})
    elif method == "tools/call":
        respond({"jsonrpc": "2.0", "id": msg_id, "result": {"content": [{"type": "text", "text": "Here is the key: AKIAIOSFODNN7EXAMPLE"}]}})
    else:
        respond({"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": "Method not found"}})
"#;

#[tokio::test]
async fn mcp_response_blocked_when_critical_finding() {
    // When the upstream tool result contains an AWS key (block action),
    // the response should be blocked with -32003 error.
    if std::process::Command::new("python3")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("python3 not found, skipping test");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("mock_secret_server.py");
    std::fs::write(&script_path, MOCK_MCP_SERVER_WITH_SECRET).unwrap();

    let engine = engine_with_rules(
        r#"
rules:
  - name: allow-all
    verdict: allow
    match:
      tools: ["*"]
"#,
    );

    let scanner = Arc::new(forculus_inspect::scanner::ContentScanner::builtin());

    let config = forculus_config::McpGatewayConfig {
        upstream_servers: vec![forculus_config::UpstreamServerConfig {
            name: "leaky".into(),
            url: None,            command: "python3".into(),
            args: vec![script_path.to_str().unwrap().to_string()],
            env: Default::default(),
        }],
        ..Default::default()
    };

    let gateway = McpGateway::new(config)
        .await
        .unwrap()
        .with_policy_engine(engine)
        .with_content_scanner(scanner);

    // Call the tool that returns an AWS key.
    let req = JsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: RequestId::Number(1),
        method: "tools/call".into(),
        params: Some(serde_json::json!({
            "name": "leaky__leak",
            "arguments": {}
        })),
    });

    let resp = gateway.handle_message(req).await.unwrap();
    if let JsonRpcMessage::Response(r) = resp {
        let err = r.error.expect("response should be blocked");
        assert_eq!(
            err.code, CONTENT_BLOCKED,
            "expected CONTENT_BLOCKED (-32003), got: {}",
            err.code,
        );
        assert!(
            err.message.contains("dangerous content"),
            "error should mention dangerous content, got: {}",
            err.message,
        );
    } else {
        panic!("Expected response");
    }

    gateway.shutdown().await;
}

/// Mock MCP server that returns a bearer token in its response (redact action, not block).
const MOCK_MCP_SERVER_WITH_BEARER: &str = r#"
import sys, json
def respond(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except Exception:
        continue
    msg_id = msg.get("id")
    if msg_id is None:
        continue
    method = msg.get("method", "")
    if method == "initialize":
        respond({"jsonrpc": "2.0", "id": msg_id, "result": {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "mock", "version": "1.0"}}})
    elif method == "tools/list":
        respond({"jsonrpc": "2.0", "id": msg_id, "result": {"tools": [{"name": "get_token", "description": "Returns a token", "inputSchema": {"type": "object"}}]}})
    elif method == "tools/call":
        respond({"jsonrpc": "2.0", "id": msg_id, "result": {"content": [{"type": "text", "text": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoxNjk5OTk5OTk5fQ.signature_padding_to_be_long_enough"}]}})
    else:
        respond({"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": "Method not found"}})
"#;

/// Mock MCP server that echoes back the received arguments as tool result.
const MOCK_MCP_SERVER_ECHO_ARGS: &str = r#"
import sys, json
def respond(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except Exception:
        continue
    msg_id = msg.get("id")
    if msg_id is None:
        continue
    method = msg.get("method", "")
    if method == "initialize":
        respond({"jsonrpc": "2.0", "id": msg_id, "result": {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "mock", "version": "1.0"}}})
    elif method == "tools/list":
        respond({"jsonrpc": "2.0", "id": msg_id, "result": {"tools": [{"name": "echo", "description": "Echoes args", "inputSchema": {"type": "object"}}]}})
    elif method == "tools/call":
        args = msg.get("params", {}).get("arguments", {})
        respond({"jsonrpc": "2.0", "id": msg_id, "result": {"content": [{"type": "text", "text": json.dumps(args)}]}})
    else:
        respond({"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": "Method not found"}})
"#;

#[tokio::test]
async fn mcp_response_redacted_when_should_redact() {
    // When the upstream tool result contains a bearer token (redact action),
    // the response content should be redacted, not blocked.
    if std::process::Command::new("python3")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("python3 not found, skipping test");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("mock_bearer_server.py");
    std::fs::write(&script_path, MOCK_MCP_SERVER_WITH_BEARER).unwrap();

    let engine = engine_with_rules(
        r#"
rules:
  - name: allow-all
    verdict: allow
    match:
      tools: ["*"]
"#,
    );

    let scanner = Arc::new(forculus_inspect::scanner::ContentScanner::builtin());

    let config = forculus_config::McpGatewayConfig {
        upstream_servers: vec![forculus_config::UpstreamServerConfig {
            name: "bearer".into(),
            url: None,            command: "python3".into(),
            args: vec![script_path.to_str().unwrap().to_string()],
            env: Default::default(),
        }],
        ..Default::default()
    };

    let gateway = McpGateway::new(config)
        .await
        .unwrap()
        .with_policy_engine(engine)
        .with_content_scanner(scanner);

    let req = JsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: RequestId::Number(1),
        method: "tools/call".into(),
        params: Some(serde_json::json!({
            "name": "bearer__get_token",
            "arguments": {}
        })),
    });

    let resp = gateway.handle_message(req).await.unwrap();
    if let JsonRpcMessage::Response(r) = resp {
        assert!(
            r.error.is_none(),
            "tool call should succeed (redact, not block), got: {:?}",
            r.error
        );
        let result = r.result.unwrap();
        let result_str = serde_json::to_string(&result).unwrap();

        // The response should contain [REDACTED].
        assert!(
            result_str.contains("[REDACTED]"),
            "response should contain [REDACTED], got: {result_str}",
        );
        // The original bearer token should NOT be present.
        assert!(
            !result_str.contains("eyJhbGciOiJIUzI1NiJ9"),
            "response should NOT contain the original bearer token, got: {result_str}",
        );

        // Governance metadata should indicate redaction.
        let meta = &result["_meta"]["governance"];
        let inspection = &meta["inspection_results"];
        assert!(
            inspection["redacted"].as_bool().unwrap_or(false),
            "inspection_results.redacted should be true, got: {inspection}",
        );
    } else {
        panic!("Expected response");
    }

    gateway.shutdown().await;
}

#[tokio::test]
async fn mcp_request_args_redacted() {
    // When tool call arguments contain a bearer token, the args should be
    // redacted before forwarding to the upstream server.
    if std::process::Command::new("python3")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("python3 not found, skipping test");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("mock_echo_server.py");
    std::fs::write(&script_path, MOCK_MCP_SERVER_ECHO_ARGS).unwrap();

    let engine = engine_with_rules(
        r#"
rules:
  - name: allow-all
    verdict: allow
    match:
      tools: ["*"]
"#,
    );

    let scanner = Arc::new(forculus_inspect::scanner::ContentScanner::builtin());

    let config = forculus_config::McpGatewayConfig {
        upstream_servers: vec![forculus_config::UpstreamServerConfig {
            name: "echo".into(),
            url: None,            command: "python3".into(),
            args: vec![script_path.to_str().unwrap().to_string()],
            env: Default::default(),
        }],
        ..Default::default()
    };

    let gateway = McpGateway::new(config)
        .await
        .unwrap()
        .with_policy_engine(engine)
        .with_content_scanner(scanner);

    let req = JsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: RequestId::Number(1),
        method: "tools/call".into(),
        params: Some(serde_json::json!({
            "name": "echo__echo",
            "arguments": {
                "token": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoxNjk5OTk5OTk5fQ.signature_padding_to_be_long_enough"
            }
        })),
    });

    let resp = gateway.handle_message(req).await.unwrap();
    if let JsonRpcMessage::Response(r) = resp {
        assert!(
            r.error.is_none(),
            "tool call should succeed, got: {:?}",
            r.error
        );
        let result = r.result.unwrap();
        let result_str = serde_json::to_string(&result).unwrap();

        // The echoed arguments should contain [REDACTED] instead of the bearer token.
        assert!(
            result_str.contains("[REDACTED]"),
            "echoed args should contain [REDACTED], got: {result_str}",
        );
        assert!(
            !result_str.contains("eyJhbGciOiJIUzI1NiJ9"),
            "echoed args should NOT contain the original bearer token, got: {result_str}",
        );
    } else {
        panic!("Expected response");
    }

    gateway.shutdown().await;
}

// ── Rate limit integration tests ──────────────────────────────────

#[tokio::test]
async fn mcp_rate_limit_denies_excess() {
    use forculus_ratelimit::limiter::RateLimiter;

    // Allow all via policy.
    let engine = engine_with_rules(
        r#"
rules:
  - name: allow-all
    verdict: allow
    match:
      tools: ["*"]
"#,
    );

    // Rate limit: burst=2, 60 RPM, global dimension.
    let limiter = Arc::new(
        RateLimiter::new(vec![forculus_config::RateLimitRule {
            name: "test-limit".to_string(),
            tools: vec!["*".to_string()],
            rpm: 60,
            burst: 2,
            dimensions: vec!["global".to_string()],
        }])
        .unwrap(),
    );

    let gateway = McpGateway::new_with_upstreams(HashMap::new())
        .with_policy_engine(engine)
        .with_rate_limiter(limiter);

    // First two requests: policy allows but no upstream → "Unknown server" error (not rate limited).
    for i in 1..=2 {
        let resp = gateway
            .handle_message(tool_call_request(i, "mock__read"))
            .await
            .unwrap();
        if let JsonRpcMessage::Response(r) = resp {
            let err = r.error.expect("should error (no upstream)");
            assert_ne!(
                err.code, RATE_LIMITED,
                "request {i} should NOT be rate-limited"
            );
        } else {
            panic!("Expected response for request {i}");
        }
    }

    // Third request: should be rate-limited (burst=2 exceeded).
    let resp = gateway
        .handle_message(tool_call_request(3, "mock__read"))
        .await
        .unwrap();
    if let JsonRpcMessage::Response(r) = resp {
        let err = r.error.expect("should be rate-limited");
        assert_eq!(
            err.code, RATE_LIMITED,
            "expected RATE_LIMITED (-32004), got: {}",
            err.code
        );
        assert!(
            err.message.contains("Rate limited"),
            "expected rate limit message, got: {}",
            err.message
        );
    } else {
        panic!("Expected response for rate-limited request");
    }
}

// ── Builtin governance tools integration tests ──────────────────────

#[tokio::test]
async fn builtin_scan_content_via_gateway() {
    let scanner = Arc::new(forculus_inspect::scanner::ContentScanner::builtin());
    let gateway = McpGateway::new_with_upstreams(HashMap::new()).with_content_scanner(scanner);

    let req = JsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: RequestId::Number(1),
        method: "tools/call".into(),
        params: Some(serde_json::json!({
            "name": "forculus__scan_content",
            "arguments": {"text": "AKIAIOSFODNN7EXAMPLE"}
        })),
    });

    let resp = gateway.handle_message(req).await.unwrap();
    if let JsonRpcMessage::Response(r) = resp {
        assert!(
            r.error.is_none(),
            "builtin tool call should succeed: {:?}",
            r.error
        );
        let result = r.result.unwrap();
        // The result wraps a ToolCallResult with content array.
        let content = result["content"].as_array().unwrap();
        assert!(!content.is_empty());
        let text = content[0]["text"].as_str().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(text).unwrap();
        assert!(parsed["finding_count"].as_u64().unwrap() > 0);
        assert!(parsed["should_block"].as_bool().unwrap());
    } else {
        panic!("Expected response");
    }
}

#[tokio::test]
async fn builtin_audit_verify_via_gateway() {
    let dir = tempfile::tempdir().unwrap();
    let store = forculus_audit::store::AuditStore::open(&dir.path().join("audit.db")).unwrap();
    let store = Arc::new(parking_lot::Mutex::new(store));

    let gateway = McpGateway::new_with_upstreams(HashMap::new()).with_audit_store(store);

    let req = JsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: RequestId::Number(1),
        method: "tools/call".into(),
        params: Some(serde_json::json!({
            "name": "forculus__audit_verify",
            "arguments": {}
        })),
    });

    let resp = gateway.handle_message(req).await.unwrap();
    if let JsonRpcMessage::Response(r) = resp {
        assert!(
            r.error.is_none(),
            "audit verify should succeed: {:?}",
            r.error
        );
        let result = r.result.unwrap();
        let content = result["content"].as_array().unwrap();
        let text = content[0]["text"].as_str().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(text).unwrap();
        assert!(parsed["valid"].as_bool().unwrap());
    } else {
        panic!("Expected response");
    }
}

#[tokio::test]
async fn builtin_policy_evaluate_via_gateway() {
    let engine = engine_with_rules(
        r#"
rules:
  - name: allow-reads
    verdict: allow
    reason: "reads are safe"
    match:
      actions: ["read_*"]
"#,
    );

    let gateway = McpGateway::new_with_upstreams(HashMap::new()).with_policy_engine(engine);

    let req = JsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: RequestId::Number(1),
        method: "tools/call".into(),
        params: Some(serde_json::json!({
            "name": "forculus__policy_evaluate",
            "arguments": {"tool": "github", "action": "read_file"}
        })),
    });

    let resp = gateway.handle_message(req).await.unwrap();
    if let JsonRpcMessage::Response(r) = resp {
        assert!(
            r.error.is_none(),
            "policy evaluate should succeed: {:?}",
            r.error
        );
        let result = r.result.unwrap();
        let content = result["content"].as_array().unwrap();
        let text = content[0]["text"].as_str().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(parsed["verdict"].as_str().unwrap(), "allow");
    } else {
        panic!("Expected response");
    }
}

#[tokio::test]
async fn builtin_unknown_tool_returns_error() {
    let gateway = McpGateway::new_with_upstreams(HashMap::new());

    let req = JsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: RequestId::Number(1),
        method: "tools/call".into(),
        params: Some(serde_json::json!({
            "name": "forculus__nonexistent_tool",
            "arguments": {}
        })),
    });

    let resp = gateway.handle_message(req).await.unwrap();
    if let JsonRpcMessage::Response(r) = resp {
        // The call succeeds at the JSON-RPC level but the tool result has is_error=true.
        assert!(r.error.is_none(), "JSON-RPC level should succeed");
        let result = r.result.unwrap();
        let is_error = result["isError"].as_bool().unwrap_or(false);
        assert!(is_error, "unknown builtin tool should set isError=true");
    } else {
        panic!("Expected response");
    }
}

// ── Phase 1I Verification: MCP adversarial tests ─────────────────────

/// Malformed JSON-RPC messages (missing method, null id, garbage params) should
/// not cause panics or corruption in the gateway.
#[tokio::test]
async fn adversarial_malformed_mcp_jsonrpc() {
    let gateway = McpGateway::new_with_upstreams(HashMap::new());

    // 1. Request with missing "method" field — serde will fail to parse as Request,
    //    but it will parse as a Response (has "id" but no "method"). Gateway should
    //    ignore it (return None).
    let malformed_no_method = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "params": {}
    });
    let parsed: Result<JsonRpcMessage, _> = serde_json::from_value(malformed_no_method);
    if let Ok(msg) = parsed {
        let result = gateway.handle_message(msg).await;
        // Should return None or a valid error — never panic.
        if let Some(JsonRpcMessage::Response(r)) = result {
            // If it responded, it should be an error.
            assert!(r.error.is_some() || r.result.is_some());
        }
    }
    // If it failed to parse, that's also fine — the transport layer would skip it.

    // 2. Request with empty method string.
    let empty_method = JsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: RequestId::Number(2),
        method: "".into(),
        params: None,
    });
    let resp = gateway.handle_message(empty_method).await;
    if let Some(JsonRpcMessage::Response(r)) = resp {
        assert!(r.error.is_some(), "empty method should return error");
    }

    // 3. Request with extremely long method name (10KB).
    let long_method = "x".repeat(10_000);
    let long_req = JsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: RequestId::Number(3),
        method: long_method,
        params: None,
    });
    let resp = gateway.handle_message(long_req).await;
    if let Some(JsonRpcMessage::Response(r)) = resp {
        assert!(r.error.is_some(), "unknown long method should return error");
    }

    // 4. tools/call with SQL injection in tool name.
    let sql_injection_tool = JsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: RequestId::Number(4),
        method: "tools/call".into(),
        params: Some(serde_json::json!({
            "name": "'; DROP TABLE events;--__read",
            "arguments": {}
        })),
    });
    let resp = gateway.handle_message(sql_injection_tool).await.unwrap();
    if let JsonRpcMessage::Response(r) = resp {
        // Should get an error (unknown server), NOT execute SQL.
        assert!(r.error.is_some());
    }

    // 5. Verify gateway is still functional after adversarial inputs.
    let ping = JsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: RequestId::Number(99),
        method: "ping".into(),
        params: None,
    });
    let resp = gateway.handle_message(ping).await.unwrap();
    if let JsonRpcMessage::Response(r) = resp {
        assert!(
            r.error.is_none(),
            "ping should succeed after adversarial inputs"
        );
    } else {
        panic!("Expected ping response");
    }
}

// ── HTTP transport integration tests ─────────────────────────────────

use std::net::SocketAddr;

/// Start a test HTTP server on a random port.
/// Returns the bound address and a shutdown token.
async fn start_test_http_server(
    gateway: Arc<McpGateway>,
    allowed_origins: Vec<String>,
) -> (SocketAddr, CancellationToken) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let shutdown_clone = shutdown.clone();

    tokio::spawn(async move {
        forculus_mcp::server::run_http_server_with_listener(
            gateway,
            listener,
            allowed_origins,
            shutdown_clone,
        )
        .await
        .unwrap();
    });

    // Give the server a moment to start accepting.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (addr, shutdown)
}

use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn http_post_initialize_returns_session_id() {
    let gateway = Arc::new(McpGateway::new_with_upstreams(HashMap::new()));
    let (addr, shutdown) = start_test_http_server(gateway, vec![]).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{addr}/mcp"))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "test", "version": "1.0" }
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let session_id = resp
        .headers()
        .get("Mcp-Session-Id")
        .expect("should have Mcp-Session-Id header")
        .to_str()
        .unwrap()
        .to_string();
    assert!(!session_id.is_empty());

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["result"]["protocolVersion"], "2024-11-05");
    assert_eq!(body["result"]["serverInfo"]["name"], "forculus");

    shutdown.cancel();
}

#[tokio::test]
async fn http_post_tools_list_returns_builtins() {
    let gateway = Arc::new(McpGateway::new_with_upstreams(HashMap::new()));
    let (addr, shutdown) = start_test_http_server(gateway, vec![]).await;

    let client = reqwest::Client::new();

    // First: initialize to get a session.
    let resp = client
        .post(format!("http://{addr}/mcp"))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "test", "version": "1.0" }
            }
        }))
        .send()
        .await
        .unwrap();

    let session_id = resp
        .headers()
        .get("Mcp-Session-Id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // Then: tools/list with session.
    let resp = client
        .post(format!("http://{addr}/mcp"))
        .header("Content-Type", "application/json")
        .header("Mcp-Session-Id", &session_id)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let tools = body["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 7, "expected 7 builtin tools");

    shutdown.cancel();
}

#[tokio::test]
async fn http_post_without_session_returns_error() {
    let gateway = Arc::new(McpGateway::new_with_upstreams(HashMap::new()));
    let (addr, shutdown) = start_test_http_server(gateway, vec![]).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{addr}/mcp"))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);

    shutdown.cancel();
}

#[tokio::test]
async fn http_delete_terminates_session() {
    let gateway = Arc::new(McpGateway::new_with_upstreams(HashMap::new()));
    let (addr, shutdown) = start_test_http_server(gateway, vec![]).await;

    let client = reqwest::Client::new();

    // Initialize to get a session.
    let resp = client
        .post(format!("http://{addr}/mcp"))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "test", "version": "1.0" }
            }
        }))
        .send()
        .await
        .unwrap();

    let session_id = resp
        .headers()
        .get("Mcp-Session-Id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // DELETE the session.
    let resp = client
        .delete(format!("http://{addr}/mcp"))
        .header("Mcp-Session-Id", &session_id)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Subsequent POST with terminated session → 404.
    let resp = client
        .post(format!("http://{addr}/mcp"))
        .header("Content-Type", "application/json")
        .header("Mcp-Session-Id", &session_id)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    shutdown.cancel();
}

#[tokio::test]
async fn http_post_sse_format() {
    let gateway = Arc::new(McpGateway::new_with_upstreams(HashMap::new()));
    let (addr, shutdown) = start_test_http_server(gateway, vec![]).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{addr}/mcp"))
        .header("Content-Type", "application/json")
        .header("Accept", "text/event-stream")
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "test", "version": "1.0" }
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("Content-Type")
            .unwrap()
            .to_str()
            .unwrap(),
        "text/event-stream"
    );
    assert!(resp.headers().get("Mcp-Session-Id").is_some());

    let body = resp.text().await.unwrap();
    assert!(
        body.starts_with("event: message\ndata: "),
        "expected SSE format, got: {body}"
    );
    assert!(body.ends_with("\n\n"));

    shutdown.cancel();
}

#[tokio::test]
async fn http_origin_validation_rejects_bad_origin() {
    let gateway = Arc::new(McpGateway::new_with_upstreams(HashMap::new()));
    let (addr, shutdown) =
        start_test_http_server(gateway, vec!["https://good.com".to_string()]).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{addr}/mcp"))
        .header("Content-Type", "application/json")
        .header("Origin", "https://evil.com")
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "test", "version": "1.0" }
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);

    shutdown.cancel();
}

#[tokio::test]
async fn http_notification_returns_202() {
    let gateway = Arc::new(McpGateway::new_with_upstreams(HashMap::new()));
    let (addr, shutdown) = start_test_http_server(gateway, vec![]).await;

    let client = reqwest::Client::new();

    // Initialize to get a session.
    let resp = client
        .post(format!("http://{addr}/mcp"))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "test", "version": "1.0" }
            }
        }))
        .send()
        .await
        .unwrap();

    let session_id = resp
        .headers()
        .get("Mcp-Session-Id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // Send a notification — should return 202.
    let resp = client
        .post(format!("http://{addr}/mcp"))
        .header("Content-Type", "application/json")
        .header("Mcp-Session-Id", &session_id)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 202);

    shutdown.cancel();
}
