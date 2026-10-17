use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::process::{Command, Stdio};
use std::path::PathBuf;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use secrecy::SecretString;
use tokio::net::TcpListener;
use tokio::process::{Child, Command as TokioCommand};
use tokio_util::sync::CancellationToken;

use forculus_config::ProxyConfig;
use forculus_policy::engine::PolicyEngine;
use forculus_proxy::server::ProxyServer;
use forculus_vault::credential::{Credential, CredentialType};
use forculus_vault::session::CreateSessionParams;
use forculus_vault::store::Vault;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("forculus=debug,info")
        .try_init();
}

/// Start a Forculus proxy on a random port. Returns the bound address and a
/// cancellation token.
async fn start_test_proxy(ca_dir: &PathBuf) -> (SocketAddr, CancellationToken, Arc<ProxyServer>) {
    let config = ProxyConfig {
        listen_address: "127.0.0.1:0".to_string(),
        tls: forculus_config::TlsConfig {
            ca_dir: ca_dir.to_string_lossy().to_string(),
        },
        tool_mappings: Vec::new(),
        tls_passthrough: Vec::new(),
    };

    let server = Arc::new(ProxyServer::new(config).await.expect("proxy server"));
    let token = server.shutdown_token();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test proxy");
    let addr = listener.local_addr().expect("local addr");

    let server_clone = Arc::clone(&server);
    tokio::spawn(async move {
        server_clone.run().await
    });

    (addr, token, server)
}

/// Start a simple HTTP server that serves MCP tool definitions from a directory.
/// This simulates the mock hostile MCP server for testing.
async fn start_mock_mcp_server(server_dir: &str, port: u16) -> (SocketAddr, Child) {
    let listener = TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .expect("bind mock MCP server");
    let addr = listener.local_addr().expect("local addr");

    // Node.js server path
    let server_path = format!("{}/index.js", server_dir);

    // Start the Node.js MCP server
    let child_result = TokioCommand::new("node")
        .arg(&server_path)
        .arg("--http")
        .arg(port.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();

    // Give the server a moment to start
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    let child = child_result.expect("failed to start mock MCP server");
    (addr, child)
}

// ---------------------------------------------------------------------------
// Test cases
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mock_hostile_mcp_server_blocks_malicious_and_passes_benign() {
    init_tracing();

    // Create temporary directory for CA certs
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");
    std::fs::create_dir_all(&ca_dir).expect("create ca dir");

    // Path to our mock hostile MCP server fixtures
    let mock_server_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/mock-hostile-server");

    // Start the mock hostile MCP server on a random port
    let (mock_server_addr, _mock_server_child) =
        start_mock_mcp_server(mock_server_dir, 0).await;

    // Create scanner with inspect_responses enabled (default)
    let _scanner = Arc::new(forculus_inspect::scanner::ContentScanner::builtin());

    // Start the Forculus proxy pointing to our mock MCP server
    let config = ProxyConfig {
        listen_address: "127.0.0.1:0".to_string(),
        tls: forculus_config::TlsConfig {
            ca_dir: ca_dir.to_string_lossy().to_string(),
        },
        tool_mappings: Vec::new(),
        tls_passthrough: Vec::new(),
    };

    let server = Arc::new(ProxyServer::new(config).await.expect("proxy server"));
    let token = server.shutdown_token();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test proxy");
    let proxy_addr = listener.local_addr().expect("local addr");

    let server_clone = Arc::clone(&server);
    tokio::spawn(async move {
        server_clone.run().await
    });

    // Create HTTP client that goes through the proxy
    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    // Test 1: Fetch tool list - should pass through (benign request)
    let resp = client
        .post(format!("http://{}/mcp", mock_server_addr))
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list"
        }))
        .send()
        .await
        .expect("proxied request");

    // Tool listing should pass through (not blocked)
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "tool list request should pass through proxy"
    );

    // Test 2: Call a benign tool - should pass through
    let resp = client
        .post(format!("http://{}/mcp", mock_server_addr))
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {
                    "path": "/etc/passwd"
                }
            }
        }))
        .send()
        .await
        .expect("proxied request");

    // Benign tool call should pass through
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "benign tool call should pass through proxy"
    );

    // Test 3: Call a malicious tool with hidden unicode - should be blocked
    let resp = client
        .post(format!("http://{}/mcp", mock_server_addr))
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "safe_read", // This has hidden unicode in the mock server
                "arguments": {
                    "path": "/etc/passwd"
                }
            }
        }))
        .send()
        .await
        .expect("proxied request");

    // Malicious tool should be blocked with 502
    assert_eq!(
        resp.status(),
        StatusCode::BAD_GATEWAY,
        "malicious tool call should be blocked by proxy"
    );

    // Test 4: Call a malicious tool with instruction override - should be blocked
    let resp = client
        .post(format!("http://{}/mcp", mock_server_addr))
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "process_document", // This has instruction override
                "arguments": {
                    "document": "test document"
                }
            }
        }))
        .send()
        .await
        .expect("proxied request");

    // Malicious tool should be blocked with 502
    assert_eq!(
        resp.status(),
        StatusCode::BAD_GATEWAY,
        "malicious tool call should be blocked by proxy"
    );

    // Clean up
    token.cancel();
}