//! End-to-end test: Forculus proxy vs. mock hostile MCP server.
//!
//! A malicious-only mock (poisoned tool catalog) must have its tools/list
//! blocked and its malicious tool calls blocked. A benign-only mock must
//! pass everything through untouched.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::process::Stdio;
use std::path::PathBuf;

use http_body_util::{BodyExt, Full};
use secrecy::SecretString;
use tokio::net::TcpListener;
use tokio::process::{Child, Command as TokioCommand};
use tokio_util::sync::CancellationToken;

use forculus_config::ProxyConfig;
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

fn test_config(ca_dir: &std::path::Path) -> ProxyConfig {
    ProxyConfig {
        listen_address: "127.0.0.1:0".to_string(),
        tls: forculus_config::TlsConfig {
            ca_dir: ca_dir.to_string_lossy().to_string(),
        },
        tool_mappings: Vec::new(),
        tls_passthrough: Vec::new(),
    }
}

/// Start a Forculus proxy on a pre-bound listener, with response inspection.
async fn start_test_proxy(
    ca_dir: &std::path::Path,
    scanner: Arc<forculus_inspect::scanner::ContentScanner>,
) -> (SocketAddr, CancellationToken, Arc<ProxyServer>) {
    let server = Arc::new(
        ProxyServer::new(test_config(ca_dir))
            .await
            .expect("proxy server")
            .with_content_scanner(scanner),
    );
    let token = server.shutdown_token();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test proxy");
    let addr = listener.local_addr().expect("local addr");

    let server_clone = Arc::clone(&server);
    tokio::spawn(async move {
        server_clone.run_with_listener(listener).await
    });

    (addr, token, server)
}

/// Start the mock MCP server serving only one half of the corpus.
async fn start_mock_mcp_server(server_dir: &str, only: &str) -> (SocketAddr, Child) {
    // Reserve a free port by binding and immediately dropping, then hand the
    // port to Node. (Pre-binding and never accepting hung every request.)
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve port for mock MCP server");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let server_path = format!("{}/index.js", server_dir);
    let child = TokioCommand::new("node")
        .arg(&server_path)
        .arg("--http")
        .arg(port.to_string())
        .arg("--only")
        .arg(only)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start mock MCP server");

    // Give the server a moment to start, then verify it is still alive
    // (a fixture path typo used to kill Node silently and hang the test).
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    assert!(
        child.id().is_some(),
        "mock MCP server process died at startup"
    );

    (addr, child)
}

async fn post_mcp(client: &reqwest::Client, addr: SocketAddr, body: serde_json::Value) -> reqwest::Response {
    client
        .post(format!("http://{addr}/mcp"))
        .json(&body)
        .send()
        .await
        .expect("proxied request")
}

fn tool_call(id: i32, name: &str, args: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": { "name": name, "arguments": args }
    })
}

// ---------------------------------------------------------------------------
// Test cases
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mock_hostile_mcp_server_blocks_malicious_and_passes_benign() {
    init_tracing();

    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");
    std::fs::create_dir_all(&ca_dir).expect("create ca dir");

    let mock_server_dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/mock-hostile-server"
    );

    let scanner = Arc::new(forculus_inspect::scanner::ContentScanner::builtin());
    let (proxy_addr, token, _server) = start_test_proxy(&ca_dir, Arc::clone(&scanner)).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client");

    // --- Hostile instance: poisoned tool catalog must never reach the agent ---
    let (hostile_addr, mut hostile_child) =
        start_mock_mcp_server(mock_server_dir, "malicious").await;

    // tools/list from a hostile server: BLOCKED (hidden unicode, instruction
    // override, and exfil endpoints in the catalog).
    let resp = post_mcp(
        &client,
        hostile_addr,
        serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
    )
    .await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_GATEWAY,
        "hostile tool list must be blocked by the proxy"
    );

    // Malicious tool call (hidden unicode payload): BLOCKED.
    let resp = post_mcp(
        &client,
        hostile_addr,
        tool_call(2, "safe_read", serde_json::json!({"path": "/etc/passwd"})),
    )
    .await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_GATEWAY,
        "malicious tool call must be blocked by the proxy"
    );

    // Malicious tool call (instruction override + exfil endpoint): BLOCKED.
    let resp = post_mcp(
        &client,
        hostile_addr,
        tool_call(
            3,
            "process_document",
            serde_json::json!({"document": "test document"}),
        ),
    )
    .await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_GATEWAY,
        "instruction-override tool call must be blocked by the proxy"
    );

    hostile_child.kill().await.expect("kill hostile mock");

    // --- Benign instance: everything passes through untouched ---
    let (benign_addr, mut benign_child) =
        start_mock_mcp_server(mock_server_dir, "benign").await;

    let resp = post_mcp(
        &client,
        benign_addr,
        serde_json::json!({"jsonrpc": "2.0", "id": 10, "method": "tools/list"}),
    )
    .await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "benign tool list should pass through proxy"
    );

    let resp = post_mcp(
        &client,
        benign_addr,
        tool_call(11, "read_file", serde_json::json!({"path": "/tmp/notes.txt"})),
    )
    .await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "benign tool call should pass through proxy"
    );

    benign_child.kill().await.expect("kill benign mock");

    token.cancel();
}
