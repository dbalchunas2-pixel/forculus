//! Integration tests for the Forculus HTTP/HTTPS forward proxy.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use forculus_config::ProxyConfig;
use forculus_policy::engine::PolicyEngine;
use forculus_proxy::server::ProxyServer;
use forculus_vault::credential::{Credential, CredentialType};
use forculus_vault::session::CreateSessionParams;
use forculus_vault::store::Vault;
use secrecy::SecretString;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Start a Forculus proxy on a random port. Returns the bound address and a
/// cancellation token.
async fn start_test_proxy(ca_dir: &str) -> (SocketAddr, CancellationToken, Arc<ProxyServer>) {
    let config = ProxyConfig {
        listen_address: "127.0.0.1:0".to_string(),
        tls: forculus_config::TlsConfig {
            ca_dir: ca_dir.to_string(),
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
        server_clone
            .run_with_listener(listener)
            .await
            .expect("proxy run");
    });

    // Give the server a moment to start accepting.
    tokio::time::sleep(Duration::from_millis(50)).await;

    (addr, token, server)
}

/// Start a simple echo HTTP server that returns request metadata as JSON.
/// Returns the bound address.
async fn start_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo server");
    let addr = listener.local_addr().expect("echo addr");

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let service = service_fn(|req: Request<hyper::body::Incoming>| async move {
                    let method = req.method().to_string();
                    let path = req.uri().path().to_string();
                    let query = req.uri().query().unwrap_or("").to_string();

                    let body = serde_json::json!({
                        "method": method,
                        "path": path,
                        "query": query,
                    });

                    Ok::<_, hyper::Error>(Response::new(
                        Full::new(Bytes::from(body.to_string()))
                            .map_err(|never| match never {})
                            .boxed(),
                    ))
                });

                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    addr
}

/// Initialise tracing (only once per process).
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("forculus=debug,info")
        .try_init();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn health_check() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let (addr, token, _server) = start_test_proxy(ca_dir.to_str().unwrap()).await;

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/healthz"))
        .send()
        .await
        .expect("health request");

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["status"], "ok");
    assert_eq!(body["version"], forculus_common::VERSION);
    assert!(body["uptime_seconds"].is_number());

    token.cancel();
}

#[tokio::test]
async fn http_forward_proxy() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let echo_addr = start_echo_server().await;
    let (proxy_addr, token, _server) = start_test_proxy(ca_dir.to_str().unwrap()).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    let resp = client
        .get(format!("http://{echo_addr}/test?q=hello"))
        .send()
        .await
        .expect("proxied request");

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["method"], "GET");
    assert_eq!(body["path"], "/test");
    assert_eq!(body["query"], "q=hello");

    token.cancel();
}

#[tokio::test]
async fn graceful_shutdown() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let (addr, token, _server) = start_test_proxy(ca_dir.to_str().unwrap()).await;

    // Verify the proxy is running.
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/healthz"))
        .send()
        .await
        .expect("health");
    assert_eq!(resp.status(), 200);

    // Trigger shutdown.
    token.cancel();

    // Give the server time to shut down (grace period is 5s, but we just need
    // to confirm it stops accepting).
    tokio::time::sleep(Duration::from_millis(500)).await;

    // New connection should fail.
    let result = reqwest::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()
        .unwrap()
        .get(format!("http://{addr}/healthz"))
        .send()
        .await;

    assert!(result.is_err(), "proxy should not accept after shutdown");
}

#[tokio::test]
async fn concurrent_requests() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let echo_addr = start_echo_server().await;
    let (proxy_addr, token, _server) = start_test_proxy(ca_dir.to_str().unwrap()).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    let mut handles = Vec::new();
    for i in 0..50 {
        let c = client.clone();
        let addr = echo_addr;
        handles.push(tokio::spawn(async move {
            let resp = c
                .get(format!("http://{addr}/item/{i}"))
                .send()
                .await
                .expect("concurrent request");
            assert_eq!(resp.status(), 200);
        }));
    }

    for h in handles {
        h.await.expect("task join");
    }

    token.cancel();
}

#[tokio::test]
async fn connection_to_nonexistent_server() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let (proxy_addr, token, _server) = start_test_proxy(ca_dir.to_str().unwrap()).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client");

    let resp = client
        .get("http://127.0.0.1:1/nothing")
        .send()
        .await
        .expect("should get a response (502)");

    assert_eq!(resp.status(), 502);

    token.cancel();
}

#[tokio::test]
async fn malformed_request() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let (proxy_addr, token, _server) = start_test_proxy(ca_dir.to_str().unwrap()).await;

    // Send raw garbage bytes to the proxy.
    let mut stream = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("connect");

    use tokio::io::AsyncWriteExt;
    stream.write_all(b"NOT HTTP AT ALL\r\n\r\n").await.ok();

    // The proxy should close the connection gracefully (not panic).
    use tokio::io::AsyncReadExt;
    let mut buf = vec![0u8; 4096];
    let result = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await;

    // Either we get a response or the connection closes — either is fine.
    // The key point is the proxy didn't crash.
    match result {
        Ok(Ok(_n)) => {} // got some response or EOF
        Ok(Err(_)) => {} // IO error on read — fine
        Err(_) => {}     // timeout — connection stayed open, still fine
    }

    // Verify proxy is still healthy.
    let resp = reqwest::Client::new()
        .get(format!("http://{proxy_addr}/healthz"))
        .send()
        .await
        .expect("health after malformed");
    assert_eq!(resp.status(), 200);

    token.cancel();
}

/// Start a Forculus proxy with a policy engine attached.
async fn start_test_proxy_with_policy(
    ca_dir: &str,
    engine: Arc<PolicyEngine>,
) -> (SocketAddr, CancellationToken) {
    let config = ProxyConfig {
        listen_address: "127.0.0.1:0".to_string(),
        tls: forculus_config::TlsConfig {
            ca_dir: ca_dir.to_string(),
        },
        tool_mappings: Vec::new(),
        tls_passthrough: Vec::new(),
    };

    let server = Arc::new(
        ProxyServer::new(config)
            .await
            .expect("proxy server")
            .with_policy_engine(engine),
    );
    let token = server.shutdown_token();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test proxy");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        server.run_with_listener(listener).await.expect("proxy run");
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    (addr, token)
}

/// Build a PolicyEngine from inline YAML.
fn engine_with_rules(yaml: &str) -> Arc<PolicyEngine> {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("test.yaml"), yaml).unwrap();
    Arc::new(PolicyEngine::from_directory(dir.path()).unwrap())
}

#[tokio::test]
async fn http_request_denied_by_policy() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let echo_addr = start_echo_server().await;

    // Policy denies everything.
    let engine = engine_with_rules(
        r#"
rules:
  - name: deny-all
    verdict: deny
    reason: "all requests blocked"
"#,
    );

    let (proxy_addr, token) = start_test_proxy_with_policy(ca_dir.to_str().unwrap(), engine).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    let resp = client
        .get(format!("http://{echo_addr}/test"))
        .send()
        .await
        .expect("proxied request");

    assert_eq!(resp.status(), 403);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(
        body["error"].as_str().unwrap_or(""),
        "policy_denied",
        "expected policy_denied error code, got: {body}",
    );

    token.cancel();
}

#[tokio::test]
async fn http_request_allowed_by_policy() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let echo_addr = start_echo_server().await;

    // Policy allows all requests.
    let engine = engine_with_rules(
        r#"
rules:
  - name: allow-all
    verdict: allow
    match:
      tools: ["*"]
"#,
    );

    let (proxy_addr, token) = start_test_proxy_with_policy(ca_dir.to_str().unwrap(), engine).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    let resp = client
        .get(format!("http://{echo_addr}/test?q=hello"))
        .send()
        .await
        .expect("proxied request");

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["method"], "GET");
    assert_eq!(body["path"], "/test");
    assert_eq!(body["query"], "q=hello");

    token.cancel();
}

/// Start a proxy with a vault attached (sessions enabled).
async fn start_test_proxy_with_vault(
    ca_dir: &str,
    vault: Vault,
) -> (SocketAddr, CancellationToken) {
    let config = ProxyConfig {
        listen_address: "127.0.0.1:0".to_string(),
        tls: forculus_config::TlsConfig {
            ca_dir: ca_dir.to_string(),
        },
        tool_mappings: Vec::new(),
        tls_passthrough: Vec::new(),
    };

    let server = Arc::new(
        ProxyServer::new(config)
            .await
            .expect("proxy server")
            .with_vault(Arc::new(parking_lot::Mutex::new(vault))),
    );
    let token = server.shutdown_token();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test proxy");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        server.run_with_listener(listener).await.expect("proxy run");
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, token)
}

/// Create a test vault with require_sessions enabled.
fn test_vault_required(dir: &std::path::Path) -> Vault {
    let config = forculus_config::VaultConfig {
        key_path: dir.join("vault-key.age").to_str().unwrap().to_string(),
        credentials_dir: dir.join("credentials").to_str().unwrap().to_string(),
        bindings_path: dir.join("bindings.yaml").to_str().unwrap().to_string(),
        sessions_db_path: dir.join("sessions.db").to_str().unwrap().to_string(),
        require_sessions: true,
    };
    Vault::open(&config).unwrap()
}

/// Create a test vault without require_sessions.
fn test_vault_optional(dir: &std::path::Path) -> Vault {
    let config = forculus_config::VaultConfig {
        key_path: dir.join("vault-key.age").to_str().unwrap().to_string(),
        credentials_dir: dir.join("credentials").to_str().unwrap().to_string(),
        bindings_path: dir.join("bindings.yaml").to_str().unwrap().to_string(),
        sessions_db_path: dir.join("sessions.db").to_str().unwrap().to_string(),
        require_sessions: false,
    };
    Vault::open(&config).unwrap()
}

#[tokio::test]
async fn proxy_returns_401_when_session_required_and_missing() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");
    let vault_dir = tmp.path().join("vault");
    std::fs::create_dir_all(&vault_dir).unwrap();

    let vault = test_vault_required(&vault_dir);
    let echo_addr = start_echo_server().await;
    let (proxy_addr, token) = start_test_proxy_with_vault(ca_dir.to_str().unwrap(), vault).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    // Request without session header → 401.
    let resp = client
        .get(format!("http://{echo_addr}/test"))
        .send()
        .await
        .expect("proxied request");

    assert_eq!(resp.status(), 401);

    token.cancel();
}

#[tokio::test]
async fn proxy_returns_401_for_invalid_session_token() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");
    let vault_dir = tmp.path().join("vault");
    std::fs::create_dir_all(&vault_dir).unwrap();

    let vault = test_vault_required(&vault_dir);
    let echo_addr = start_echo_server().await;
    let (proxy_addr, token) = start_test_proxy_with_vault(ca_dir.to_str().unwrap(), vault).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    // Request with invalid token → 401.
    let resp = client
        .get(format!("http://{echo_addr}/test"))
        .header("X-Forculus-Session", "bwk_sess_invalid_token_value_here00")
        .send()
        .await
        .expect("proxied request");

    assert_eq!(resp.status(), 401);

    token.cancel();
}

#[tokio::test]
async fn proxy_allows_request_with_valid_session() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");
    let vault_dir = tmp.path().join("vault");
    std::fs::create_dir_all(&vault_dir).unwrap();

    let vault = test_vault_optional(&vault_dir);
    let session = vault
        .create_session(CreateSessionParams {
            operator: "test-operator".to_string(),
            team: None,
            project: None,
            environment: None,
            agent_type: None,
            ttl_seconds: None,
            description: None,
        })
        .unwrap();
    let session_token = session.token.clone();

    let echo_addr = start_echo_server().await;
    let (proxy_addr, token) = start_test_proxy_with_vault(ca_dir.to_str().unwrap(), vault).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    // Request with valid session → 200.
    let resp = client
        .get(format!("http://{echo_addr}/test"))
        .header("X-Forculus-Session", &session_token)
        .send()
        .await
        .expect("proxied request");

    assert_eq!(resp.status(), 200);

    token.cancel();
}

/// Start an echo HTTP server that reflects request headers in the response JSON.
/// Returns the bound address.
async fn start_header_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind header echo server");
    let addr = listener.local_addr().expect("echo addr");

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let service = service_fn(|req: Request<hyper::body::Incoming>| async move {
                    let method = req.method().to_string();
                    let path = req.uri().path().to_string();

                    // Collect all headers into a JSON object.
                    let mut headers = serde_json::Map::new();
                    for (name, value) in req.headers() {
                        if let Ok(v) = value.to_str() {
                            headers.insert(
                                name.as_str().to_string(),
                                serde_json::Value::String(v.to_string()),
                            );
                        }
                    }

                    let body = serde_json::json!({
                        "method": method,
                        "path": path,
                        "headers": headers,
                    });

                    Ok::<_, hyper::Error>(Response::new(
                        Full::new(Bytes::from(body.to_string()))
                            .map_err(|never| match never {})
                            .boxed(),
                    ))
                });

                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    addr
}

#[tokio::test]
async fn credential_injected_into_outbound_request() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");
    let vault_dir = tmp.path().join("vault");
    std::fs::create_dir_all(&vault_dir).unwrap();

    // Create a vault with a credential and a binding.
    let mut vault = test_vault_optional(&vault_dir);

    // Add a bearer token credential.
    vault
        .add_credential(
            "test-token",
            &Credential::BearerToken(SecretString::from("injected-secret-42".to_string())),
            &CredentialType::BearerToken,
            Some("test credential"),
        )
        .unwrap();

    // Write a binding that maps the echo server's host to our credential.
    // The tool name in HTTP proxy is the target host, so we use a wildcard.
    let bindings_yaml = "bindings:\n  - credential: test-token\n    tool: \"*\"\n";
    std::fs::write(vault_dir.join("bindings.yaml"), bindings_yaml).unwrap();
    vault.reload_bindings().unwrap();

    // Create a session.
    let session = vault
        .create_session(CreateSessionParams {
            operator: "test-operator".to_string(),
            team: None,
            project: None,
            environment: None,
            agent_type: None,
            ttl_seconds: None,
            description: None,
        })
        .unwrap();
    let session_token = session.token.clone();

    let echo_addr = start_header_echo_server().await;
    let (proxy_addr, token) = start_test_proxy_with_vault(ca_dir.to_str().unwrap(), vault).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    // Send request with session token.
    let resp = client
        .get(format!("http://{echo_addr}/test"))
        .header("X-Forculus-Session", &session_token)
        .send()
        .await
        .expect("proxied request");

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.expect("json body");

    // Verify the authorization header was injected.
    let auth_header = body["headers"]["authorization"]
        .as_str()
        .expect("authorization header should be present");
    assert_eq!(
        auth_header, "Bearer injected-secret-42",
        "credential should be injected into outbound request"
    );

    // Verify the X-Forculus-Session header was stripped (not forwarded to upstream).
    assert!(
        body["headers"]["x-forculus-session"].is_null(),
        "x-forculus-session header should be stripped from outbound request"
    );

    token.cancel();
}

#[tokio::test]
async fn credential_not_injected_without_binding() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");
    let vault_dir = tmp.path().join("vault");
    std::fs::create_dir_all(&vault_dir).unwrap();

    // Create a vault with NO bindings (empty bindings file).
    let vault = test_vault_optional(&vault_dir);

    // Create a session.
    let session = vault
        .create_session(CreateSessionParams {
            operator: "test-operator".to_string(),
            team: None,
            project: None,
            environment: None,
            agent_type: None,
            ttl_seconds: None,
            description: None,
        })
        .unwrap();
    let session_token = session.token.clone();

    let echo_addr = start_header_echo_server().await;
    let (proxy_addr, token) = start_test_proxy_with_vault(ca_dir.to_str().unwrap(), vault).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    // Send request with session but no matching binding.
    let resp = client
        .get(format!("http://{echo_addr}/test"))
        .header("X-Forculus-Session", &session_token)
        .send()
        .await
        .expect("proxied request");

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.expect("json body");

    // No authorization header should be present (no binding matched).
    assert!(
        body["headers"]["authorization"].is_null(),
        "no authorization header should be injected without a matching binding"
    );

    token.cancel();
}

// ── Audit cross-crate integration test ───────────────────────────────

#[tokio::test]
async fn http_request_produces_audit_event() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let echo_addr = start_echo_server().await;

    // Set up audit logger.
    let audit_db = tmp.path().join("audit.db");
    let logger = forculus_audit::logger::AuditLogger::new(&audit_db).unwrap();

    let config = ProxyConfig {
        listen_address: "127.0.0.1:0".to_string(),
        tls: forculus_config::TlsConfig {
            ca_dir: ca_dir.to_str().unwrap().to_string(),
        },
        tool_mappings: Vec::new(),
        tls_passthrough: Vec::new(),
    };

    let server = Arc::new(
        ProxyServer::new(config)
            .await
            .expect("proxy server")
            .with_audit_logger(logger.clone()),
    );
    let token = server.shutdown_token();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test proxy");
    let proxy_addr = listener.local_addr().expect("local addr");

    let server_clone = Arc::clone(&server);
    tokio::spawn(async move {
        server_clone
            .run_with_listener(listener)
            .await
            .expect("proxy run");
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Make an HTTP request through the proxy.
    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    let resp = client
        .get(format!("http://{echo_addr}/test?q=audit"))
        .send()
        .await
        .expect("proxied request");
    assert_eq!(resp.status(), 200);

    // Shut down the logger to flush events, then stop proxy.
    logger.shutdown().await;
    token.cancel();

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
    assert_eq!(event.channel, forculus_audit::event::Channel::HttpProxy);
}

// ── Content inspection cross-crate integration test ──────────────────

/// Start a Forculus proxy with a content scanner attached.
async fn start_test_proxy_with_scanner(
    ca_dir: &str,
    scanner: Arc<forculus_inspect::scanner::ContentScanner>,
) -> (SocketAddr, CancellationToken) {
    let config = ProxyConfig {
        listen_address: "127.0.0.1:0".to_string(),
        tls: forculus_config::TlsConfig {
            ca_dir: ca_dir.to_string(),
        },
        tool_mappings: Vec::new(),
        tls_passthrough: Vec::new(),
    };

    // Need an allow-all policy so the request reaches content inspection.
    let policy_dir = tempfile::tempdir().unwrap();
    std::fs::write(
        policy_dir.path().join("allow.yaml"),
        "rules:\n  - name: allow-all\n    verdict: allow\n    match:\n      tools: [\"*\"]\n",
    )
    .unwrap();
    let engine = Arc::new(PolicyEngine::from_directory(policy_dir.path()).unwrap());

    let server = Arc::new(
        ProxyServer::new(config)
            .await
            .expect("proxy server")
            .with_policy_engine(engine)
            .with_content_scanner(scanner),
    );
    let token = server.shutdown_token();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test proxy");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        server.run_with_listener(listener).await.expect("proxy run");
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    (addr, token)
}

#[tokio::test]
async fn http_request_blocked_by_content_inspection() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let echo_addr = start_echo_server().await;
    let scanner = Arc::new(forculus_inspect::scanner::ContentScanner::builtin());

    let (proxy_addr, token) =
        start_test_proxy_with_scanner(ca_dir.to_str().unwrap(), scanner).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    // POST a body containing an AWS access key — should be blocked.
    let resp = client
        .post(format!("http://{echo_addr}/upload"))
        .body("aws_access_key_id = AKIAIOSFODNN7EXAMPLE")
        .send()
        .await
        .expect("proxied request");

    assert_eq!(
        resp.status(),
        403,
        "request with AWS key in body should be blocked"
    );

    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(
        body["error"].as_str().unwrap_or(""),
        "content_blocked",
        "error should be content_blocked, got: {body}",
    );

    // Verify clean requests still go through.
    let resp = client
        .post(format!("http://{echo_addr}/upload"))
        .body("just a normal request body with no secrets")
        .send()
        .await
        .expect("proxied request");

    assert_eq!(
        resp.status(),
        200,
        "clean request should be forwarded normally"
    );

    token.cancel();
}

#[tokio::test]
async fn proxy_strips_forculus_session_header() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let echo_addr = start_header_echo_server().await;

    // Use allow-all policy, no vault, no injection — just a bare proxy.
    let engine = engine_with_rules(
        r#"
rules:
  - name: allow-all
    verdict: allow
    match:
      tools: ["*"]
"#,
    );

    let (proxy_addr, token) = start_test_proxy_with_policy(ca_dir.to_str().unwrap(), engine).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    let resp = client
        .get(format!("http://{echo_addr}/test"))
        .header(
            "X-Forculus-Session",
            "bwk_sess_test123456789abcdef0123456789abcdef",
        )
        .send()
        .await
        .expect("proxied request");

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.expect("json body");
    assert!(
        body["headers"]["x-forculus-session"].is_null(),
        "x-forculus-session must be stripped from forwarded request, got: {:?}",
        body["headers"]
    );

    token.cancel();
}

#[tokio::test]
async fn proxy_strips_proxy_authorization_header() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let echo_addr = start_header_echo_server().await;

    let engine = engine_with_rules(
        r#"
rules:
  - name: allow-all
    verdict: allow
    match:
      tools: ["*"]
"#,
    );

    let (proxy_addr, token) = start_test_proxy_with_policy(ca_dir.to_str().unwrap(), engine).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    let resp = client
        .get(format!("http://{echo_addr}/test"))
        .header("Proxy-Authorization", "Basic dXNlcjpwYXNz")
        .send()
        .await
        .expect("proxied request");

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.expect("json body");
    assert!(
        body["headers"]["proxy-authorization"].is_null(),
        "proxy-authorization must be stripped, got: {:?}",
        body["headers"]
    );

    token.cancel();
}

#[tokio::test]
async fn proxy_preserves_regular_headers() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let echo_addr = start_header_echo_server().await;

    let engine = engine_with_rules(
        r#"
rules:
  - name: allow-all
    verdict: allow
    match:
      tools: ["*"]
"#,
    );

    let (proxy_addr, token) = start_test_proxy_with_policy(ca_dir.to_str().unwrap(), engine).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    let resp = client
        .get(format!("http://{echo_addr}/test"))
        .header("X-Custom-Header", "keep-me")
        .header("Authorization", "Bearer agent-token")
        .send()
        .await
        .expect("proxied request");

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(
        body["headers"]["x-custom-header"].as_str(),
        Some("keep-me"),
        "custom headers must be preserved"
    );
    assert_eq!(
        body["headers"]["authorization"].as_str(),
        Some("Bearer agent-token"),
        "Authorization header must be preserved (not stripped)"
    );

    token.cancel();
}

/// Start an echo HTTP server that echoes back the request body.
/// Returns the bound address.
async fn start_body_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind body echo server");
    let addr = listener.local_addr().expect("echo addr");

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let service = service_fn(|req: Request<hyper::body::Incoming>| async move {
                    let method = req.method().to_string();
                    let path = req.uri().path().to_string();

                    // Collect the request body.
                    let body_bytes = req
                        .into_body()
                        .collect()
                        .await
                        .map(|c| c.to_bytes())
                        .unwrap_or_default();
                    let body_str = String::from_utf8_lossy(&body_bytes).to_string();

                    let resp = serde_json::json!({
                        "method": method,
                        "path": path,
                        "body": body_str,
                    });

                    Ok::<_, hyper::Error>(Response::new(
                        Full::new(Bytes::from(resp.to_string()))
                            .map_err(|never| match never {})
                            .boxed(),
                    ))
                });

                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    addr
}

#[tokio::test]
async fn proxy_redacts_request_body() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let echo_addr = start_body_echo_server().await;
    let scanner = Arc::new(forculus_inspect::scanner::ContentScanner::builtin());

    let (proxy_addr, token) =
        start_test_proxy_with_scanner(ca_dir.to_str().unwrap(), scanner).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    // POST a body containing a bearer token — should be redacted, not blocked.
    let bearer_token = "token: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.padding_to_make_it_long_enough_for_detection";
    let resp = client
        .post(format!("http://{echo_addr}/upload"))
        .body(bearer_token)
        .send()
        .await
        .expect("proxied request");

    assert_eq!(
        resp.status(),
        200,
        "bearer token should be redacted, not blocked"
    );

    let body: serde_json::Value = resp.json().await.expect("json body");
    let echoed_body = body["body"].as_str().expect("echoed body");

    assert!(
        echoed_body.contains("[REDACTED]"),
        "echoed body should contain [REDACTED], got: {echoed_body}"
    );
    assert!(
        !echoed_body.contains("eyJhbGciOiJIUzI1NiJ9"),
        "echoed body should NOT contain the original token, got: {echoed_body}"
    );

    token.cancel();
}

#[tokio::test]
async fn proxy_block_still_works_after_redaction_wiring() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let echo_addr = start_body_echo_server().await;
    let scanner = Arc::new(forculus_inspect::scanner::ContentScanner::builtin());

    let (proxy_addr, token) =
        start_test_proxy_with_scanner(ca_dir.to_str().unwrap(), scanner).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    // POST a body containing an AWS access key — should be blocked (not redacted).
    let resp = client
        .post(format!("http://{echo_addr}/upload"))
        .body("key: AKIAIOSFODNN7EXAMPLE")
        .send()
        .await
        .expect("proxied request");

    assert_eq!(
        resp.status(),
        403,
        "AWS key should be blocked, not redacted"
    );

    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(
        body["error"].as_str().unwrap_or(""),
        "content_blocked",
        "error should be content_blocked, got: {body}",
    );

    token.cancel();
}

/// Start a mock HTTP server that returns a fixed response body for every request.
async fn start_fixed_response_server(response_body: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixed response server");
    let addr = listener.local_addr().expect("addr");

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let service = service_fn(move |_req: Request<hyper::body::Incoming>| {
                    let body = response_body;
                    async move {
                        Ok::<_, hyper::Error>(Response::new(
                            Full::new(Bytes::from(body))
                                .map_err(|never| match never {})
                                .boxed(),
                        ))
                    }
                });

                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    addr
}

#[tokio::test]
async fn proxy_blocks_dangerous_response() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    // Mock upstream returns an AWS key in its response body.
    let upstream_addr = start_fixed_response_server("secret_key = AKIAIOSFODNN7EXAMPLE").await;
    let scanner = Arc::new(forculus_inspect::scanner::ContentScanner::builtin());

    let (proxy_addr, token) =
        start_test_proxy_with_scanner(ca_dir.to_str().unwrap(), scanner).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    let resp = client
        .get(format!("http://{upstream_addr}/data"))
        .send()
        .await
        .expect("proxied request");

    assert_eq!(
        resp.status(),
        502,
        "dangerous upstream response should be blocked with 502"
    );

    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(
        body["error"].as_str().unwrap_or(""),
        "response_blocked",
        "error should be response_blocked, got: {body}",
    );

    token.cancel();
}

#[tokio::test]
async fn proxy_redacts_response_body() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    // Mock upstream returns a bearer token (action: Redact) in its response.
    let upstream_addr = start_fixed_response_server(
        "output: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.padding_long_enough_for_detection",
    )
    .await;
    let scanner = Arc::new(forculus_inspect::scanner::ContentScanner::builtin());

    let (proxy_addr, token) =
        start_test_proxy_with_scanner(ca_dir.to_str().unwrap(), scanner).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    let resp = client
        .get(format!("http://{upstream_addr}/data"))
        .send()
        .await
        .expect("proxied request");

    assert_eq!(
        resp.status(),
        200,
        "bearer token in response should be redacted, not blocked"
    );

    let body_text = resp.text().await.expect("response text");
    assert!(
        body_text.contains("[REDACTED]"),
        "response should contain [REDACTED], got: {body_text}"
    );
    assert!(
        !body_text.contains("eyJhbGciOiJIUzI1NiJ9"),
        "response should NOT contain original bearer token, got: {body_text}"
    );

    token.cancel();
}

#[tokio::test]
async fn proxy_passes_clean_response() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let echo_addr = start_echo_server().await;
    let scanner = Arc::new(forculus_inspect::scanner::ContentScanner::builtin());

    let (proxy_addr, token) =
        start_test_proxy_with_scanner(ca_dir.to_str().unwrap(), scanner).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    let resp = client
        .get(format!("http://{echo_addr}/test?q=hello"))
        .send()
        .await
        .expect("proxied request");

    assert_eq!(resp.status(), 200, "clean response should pass through");

    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["method"], "GET");
    assert_eq!(body["path"], "/test");

    // Verify no [REDACTED] markers in the clean response.
    let body_str = serde_json::to_string(&body).unwrap();
    assert!(
        !body_str.contains("[REDACTED]"),
        "clean response should have no [REDACTED] markers"
    );

    token.cancel();
}

/// Start a Forculus proxy with a content scanner built from a custom config.
async fn start_test_proxy_with_scanner_config(
    ca_dir: &str,
    scanner: Arc<forculus_inspect::scanner::ContentScanner>,
) -> (SocketAddr, CancellationToken) {
    // Reuse existing helper — scanner config flags are on the scanner itself.
    start_test_proxy_with_scanner(ca_dir, scanner).await
}

#[tokio::test]
async fn proxy_skips_response_inspection_when_disabled() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    // Mock upstream returns an AWS key — normally would be blocked.
    let upstream_addr = start_fixed_response_server("secret_key = AKIAIOSFODNN7EXAMPLE").await;

    // Create scanner with inspect_responses disabled.
    let config = forculus_inspect::InspectionConfig {
        inspect_responses: false,
        ..Default::default()
    };
    let scanner = Arc::new(forculus_inspect::scanner::ContentScanner::from_config(&config).unwrap());

    let (proxy_addr, token) =
        start_test_proxy_with_scanner_config(ca_dir.to_str().unwrap(), scanner).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    let resp = client
        .get(format!("http://{upstream_addr}/data"))
        .send()
        .await
        .expect("proxied request");

    // Response inspection disabled — should pass through, not 502.
    assert_eq!(
        resp.status(),
        200,
        "response inspection disabled, should pass through"
    );

    let body_text = resp.text().await.expect("response text");
    assert!(
        body_text.contains("AKIAIOSFODNN7EXAMPLE"),
        "AWS key should pass through when response inspection disabled"
    );

    token.cancel();
}

#[tokio::test]
async fn proxy_skips_request_inspection_when_disabled() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    // Use regular echo server (not body echo) to avoid the AWS key appearing in the response.
    let echo_addr = start_echo_server().await;

    // Create scanner with inspect_requests disabled.
    let config = forculus_inspect::InspectionConfig {
        inspect_requests: false,
        ..Default::default()
    };
    let scanner = Arc::new(forculus_inspect::scanner::ContentScanner::from_config(&config).unwrap());

    let (proxy_addr, token) =
        start_test_proxy_with_scanner_config(ca_dir.to_str().unwrap(), scanner).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    // POST a body with an AWS key — normally would be blocked (403).
    let resp = client
        .post(format!("http://{echo_addr}/upload"))
        .body("key: AKIAIOSFODNN7EXAMPLE")
        .send()
        .await
        .expect("proxied request");

    // Request inspection disabled — should pass through, not 403.
    assert_eq!(
        resp.status(),
        200,
        "request inspection disabled, should pass through"
    );

    token.cancel();
}

#[tokio::test]
async fn https_connect_tunnel() {
    // This test verifies the CONNECT tunnel works with the local CA.
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let (proxy_addr, token, server) = start_test_proxy(ca_dir.to_str().unwrap()).await;

    // Build a reqwest client that trusts our CA and uses the proxy.
    let ca_der = server.ca_cert_der().to_vec();
    let ca_cert = reqwest::Certificate::from_der(&ca_der).expect("parse CA cert");

    let proxy = reqwest::Proxy::all(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .add_root_certificate(ca_cert)
        .timeout(Duration::from_secs(15))
        .build()
        .expect("client");

    // Make an HTTPS request through the proxy. Uses an external endpoint.
    // Mark as ignored if you don't want network access in CI.
    let resp = client.get("https://httpbin.org/get").send().await;

    match resp {
        Ok(r) => {
            assert_eq!(r.status(), 200);
        }
        Err(e) => {
            // If we're in an environment without network access, that's OK.
            eprintln!("HTTPS tunnel test skipped (network error): {e}");
        }
    }

    token.cancel();
}

// ── Phase 1G: Tool mapping + Rate limiting integration tests ──────────

use forculus_config::ToolMapping;
use forculus_proxy::toolmap::ToolMapper;
use forculus_ratelimit::limiter::RateLimiter;

/// Start a Forculus proxy with a tool mapper and policy engine.
async fn start_test_proxy_with_toolmap(
    ca_dir: &str,
    mapper: Arc<ToolMapper>,
    engine: Arc<PolicyEngine>,
) -> (SocketAddr, CancellationToken) {
    let config = ProxyConfig {
        listen_address: "127.0.0.1:0".to_string(),
        tls: forculus_config::TlsConfig {
            ca_dir: ca_dir.to_string(),
        },
        tool_mappings: Vec::new(),
        tls_passthrough: Vec::new(),
    };

    let server = Arc::new(
        ProxyServer::new(config)
            .await
            .expect("proxy server")
            .with_policy_engine(engine)
            .with_tool_mapper(mapper),
    );
    let token = server.shutdown_token();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test proxy");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        server.run_with_listener(listener).await.expect("proxy run");
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    (addr, token)
}

#[tokio::test]
async fn test_tool_mapping_affects_policy() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let echo_addr = start_echo_server().await;

    // Map the echo server's host to tool "echo".
    let mapper = Arc::new(
        ToolMapper::new(vec![ToolMapping {
            url_pattern: format!("{}/*", echo_addr),
            tool: "echo".to_string(),
            action_from: forculus_config::ActionFrom::UrlPath,
        }])
        .unwrap(),
    );

    // Policy denies tool "echo".
    let engine = engine_with_rules(
        r#"
rules:
  - name: deny-echo
    verdict: deny
    reason: "echo tool denied"
    match:
      tools: ["echo"]
"#,
    );

    let (proxy_addr, token) =
        start_test_proxy_with_toolmap(ca_dir.to_str().unwrap(), mapper, engine).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    let resp = client
        .get(format!("http://{echo_addr}/api/data"))
        .send()
        .await
        .expect("proxied request");

    assert_eq!(
        resp.status(),
        403,
        "request should be denied because tool mapper maps to 'echo' which is denied by policy"
    );

    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(
        body["error"].as_str().unwrap_or(""),
        "policy_denied",
        "error should be policy_denied, got: {body}",
    );

    token.cancel();
}

#[tokio::test]
async fn test_rate_limit_denies_excess() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let echo_addr = start_echo_server().await;

    // Allow-all policy so rate limit is the only blocker.
    let engine = engine_with_rules(
        r#"
rules:
  - name: allow-all
    verdict: allow
    match:
      tools: ["*"]
"#,
    );

    // Rate limit: 60 RPM, burst=2, global dimension.
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

    let config = ProxyConfig {
        listen_address: "127.0.0.1:0".to_string(),
        tls: forculus_config::TlsConfig {
            ca_dir: ca_dir.to_str().unwrap().to_string(),
        },
        tool_mappings: Vec::new(),
        tls_passthrough: Vec::new(),
    };

    let server = Arc::new(
        ProxyServer::new(config)
            .await
            .expect("proxy server")
            .with_policy_engine(engine)
            .with_rate_limiter(limiter),
    );
    let token = server.shutdown_token();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test proxy");
    let proxy_addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        server.run_with_listener(listener).await.expect("proxy run");
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    // First 2 requests should succeed (burst=2).
    for i in 0..2 {
        let resp = client
            .get(format!("http://{echo_addr}/test/{i}"))
            .send()
            .await
            .expect("proxied request");
        assert_eq!(resp.status(), 200, "request {i} should succeed");
    }

    // Third request should be rate limited (429).
    let resp = client
        .get(format!("http://{echo_addr}/test/3"))
        .send()
        .await
        .expect("proxied request");

    assert_eq!(
        resp.status(),
        429,
        "third request should be rate limited (burst=2)"
    );

    token.cancel();
}

#[tokio::test]
async fn test_rate_limit_per_session() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");
    let vault_dir = tmp.path().join("vault");
    std::fs::create_dir_all(&vault_dir).unwrap();

    let echo_addr = start_echo_server().await;

    let engine = engine_with_rules(
        r#"
rules:
  - name: allow-all
    verdict: allow
    match:
      tools: ["*"]
"#,
    );

    // Rate limit: burst=1, per-session dimension.
    let limiter = Arc::new(
        RateLimiter::new(vec![forculus_config::RateLimitRule {
            name: "session-limit".to_string(),
            tools: vec!["*".to_string()],
            rpm: 60,
            burst: 1,
            dimensions: vec!["session".to_string()],
        }])
        .unwrap(),
    );

    let vault = test_vault_optional(&vault_dir);

    // Create two sessions.
    let session_a = vault
        .create_session(CreateSessionParams {
            operator: "alice".to_string(),
            team: None,
            project: None,
            environment: None,
            agent_type: None,
            ttl_seconds: None,
            description: None,
        })
        .unwrap();
    let session_b = vault
        .create_session(CreateSessionParams {
            operator: "bob".to_string(),
            team: None,
            project: None,
            environment: None,
            agent_type: None,
            ttl_seconds: None,
            description: None,
        })
        .unwrap();

    let config = ProxyConfig {
        listen_address: "127.0.0.1:0".to_string(),
        tls: forculus_config::TlsConfig {
            ca_dir: ca_dir.to_str().unwrap().to_string(),
        },
        tool_mappings: Vec::new(),
        tls_passthrough: Vec::new(),
    };

    let server = Arc::new(
        ProxyServer::new(config)
            .await
            .expect("proxy server")
            .with_policy_engine(engine)
            .with_vault(Arc::new(parking_lot::Mutex::new(vault)))
            .with_rate_limiter(limiter),
    );
    let token = server.shutdown_token();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test proxy");
    let proxy_addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        server.run_with_listener(listener).await.expect("proxy run");
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    // Session A: first request succeeds.
    let resp = client
        .get(format!("http://{echo_addr}/test"))
        .header("X-Forculus-Session", &session_a.token)
        .send()
        .await
        .expect("proxied request");
    assert_eq!(resp.status(), 200, "session A first request should succeed");

    // Session A: second request gets rate limited.
    let resp = client
        .get(format!("http://{echo_addr}/test"))
        .header("X-Forculus-Session", &session_a.token)
        .send()
        .await
        .expect("proxied request");
    assert_eq!(
        resp.status(),
        429,
        "session A second request should be rate limited"
    );

    // Session B: still has its own bucket, should succeed.
    let resp = client
        .get(format!("http://{echo_addr}/test"))
        .header("X-Forculus-Session", &session_b.token)
        .send()
        .await
        .expect("proxied request");
    assert_eq!(
        resp.status(),
        200,
        "session B first request should succeed (separate bucket)"
    );

    token.cancel();
}

#[tokio::test]
async fn test_cross_agent_same_policy() {
    // This test proves one policy YAML governs both MCP and HTTP identically.
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let echo_addr = start_echo_server().await;

    // Policy denies tool "echo" with action matching "dangerous*".
    let engine = engine_with_rules(
        r#"
rules:
  - name: deny-dangerous
    verdict: deny
    reason: "dangerous action denied"
    priority: 10
    match:
      tools: ["echo"]
      actions: ["dangerous*"]
  - name: allow-all
    verdict: allow
    match:
      tools: ["*"]
"#,
    );

    // HTTP proxy: tool mapper resolves to tool=echo, action=dangerous_action.
    let mapper = Arc::new(
        ToolMapper::new(vec![ToolMapping {
            url_pattern: format!("{}/*", echo_addr),
            tool: "echo".to_string(),
            action_from: forculus_config::ActionFrom::Static("dangerous_action".to_string()),
        }])
        .unwrap(),
    );

    let (proxy_addr, token) =
        start_test_proxy_with_toolmap(ca_dir.to_str().unwrap(), mapper, engine.clone()).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    // HTTP proxy should deny because tool=echo, action=dangerous_action matches deny-dangerous.
    let resp = client
        .get(format!("http://{echo_addr}/api/data"))
        .send()
        .await
        .expect("proxied request");

    assert_eq!(
        resp.status(),
        403,
        "HTTP proxy should deny dangerous action via tool mapper"
    );

    // MCP gateway: same engine. Tool "echo" with action "dangerous_action" should also be denied.
    // We test this by directly evaluating the policy engine (since full MCP integration
    // requires an upstream server process).
    use forculus_policy::context::RequestContext;
    use forculus_policy::verdict::Verdict;

    let mcp_ctx = RequestContext::new("echo", "dangerous_action");
    let eval = engine.evaluate(&mcp_ctx);
    assert_eq!(
        eval.verdict,
        Verdict::Deny,
        "MCP gateway policy should deny echo/dangerous_action"
    );
    assert_eq!(eval.matched_rule.as_deref(), Some("deny-dangerous"));

    // And a safe action should be allowed.
    let safe_ctx = RequestContext::new("echo", "safe_read");
    let safe_eval = engine.evaluate(&safe_ctx);
    assert_eq!(
        safe_eval.verdict,
        Verdict::Allow,
        "safe action should be allowed by both"
    );

    token.cancel();
}

// ── Phase 1I: Adversarial / hardening integration tests ───────────────

#[tokio::test]
async fn adversarial_oversized_request_body() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let echo_addr = start_echo_server().await;
    let (proxy_addr, token, _server) = start_test_proxy(ca_dir.to_str().unwrap()).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    // Send a 2 MB request body — proxy should handle without panic.
    let large_body = "X".repeat(2 * 1024 * 1024);
    let resp = client
        .post(format!("http://{echo_addr}/upload"))
        .body(large_body)
        .send()
        .await
        .expect("proxied request");

    // Should succeed (no size limit enforced in forward proxy by default).
    assert!(
        resp.status().is_success() || resp.status().is_client_error(),
        "proxy should handle large body gracefully, got {}",
        resp.status()
    );

    // Proxy still healthy.
    let health = reqwest::Client::new()
        .get(format!("http://{proxy_addr}/healthz"))
        .send()
        .await
        .expect("health");
    assert_eq!(health.status(), 200);

    token.cancel();
}

#[tokio::test]
async fn adversarial_extremely_long_url() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let echo_addr = start_echo_server().await;
    let (proxy_addr, token, _server) = start_test_proxy(ca_dir.to_str().unwrap()).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    // URL with a 10k character path segment.
    let long_path = "a".repeat(10_000);
    let result = client
        .get(format!("http://{echo_addr}/{long_path}"))
        .send()
        .await;

    // Might succeed or fail, but proxy must not crash.
    if let Ok(resp) = result {
        assert!(
            resp.status().is_success()
                || resp.status().is_client_error()
                || resp.status().is_server_error(),
            "proxy returned valid HTTP status"
        );
    }

    // Proxy still healthy.
    let health = reqwest::Client::new()
        .get(format!("http://{proxy_addr}/healthz"))
        .send()
        .await
        .expect("health");
    assert_eq!(health.status(), 200);

    token.cancel();
}

#[tokio::test]
async fn adversarial_many_headers() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let echo_addr = start_echo_server().await;
    let (proxy_addr, token, _server) = start_test_proxy(ca_dir.to_str().unwrap()).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    // Send request with 100 custom headers.
    let mut req = client.get(format!("http://{echo_addr}/test"));
    for i in 0..100 {
        req = req.header(format!("X-Custom-{i}"), format!("value-{i}"));
    }
    let result = req.send().await;

    if let Ok(resp) = result {
        // 431 (Request Header Fields Too Large) is valid — hyper enforces limits.
        assert!(
            resp.status().is_success()
                || resp.status().is_client_error()
                || resp.status().is_server_error(),
            "proxy should handle many headers gracefully, got {}",
            resp.status()
        );
    }

    // Proxy still healthy.
    let health = reqwest::Client::new()
        .get(format!("http://{proxy_addr}/healthz"))
        .send()
        .await
        .expect("health");
    assert_eq!(health.status(), 200);

    token.cancel();
}

#[tokio::test]
async fn adversarial_binary_body() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let echo_addr = start_echo_server().await;
    let scanner = Arc::new(forculus_inspect::scanner::ContentScanner::builtin());

    let (proxy_addr, token) =
        start_test_proxy_with_scanner(ca_dir.to_str().unwrap(), scanner).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    // Send binary data (including null bytes) — scanner should handle gracefully.
    let binary_body: Vec<u8> = (0..256).map(|b| b as u8).cycle().take(4096).collect();
    let resp = client
        .post(format!("http://{echo_addr}/upload"))
        .body(binary_body)
        .send()
        .await
        .expect("proxied request");

    // Binary content should pass through (no secret patterns match).
    assert_eq!(resp.status(), 200, "binary body should pass through");

    token.cancel();
}

#[tokio::test]
async fn adversarial_concurrent_sessions_isolated() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");
    let vault_dir = tmp.path().join("vault");
    std::fs::create_dir_all(&vault_dir).unwrap();

    let echo_addr = start_echo_server().await;
    let vault = test_vault_optional(&vault_dir);

    // Create 10 sessions.
    let sessions: Vec<_> = (0..10)
        .map(|i| {
            vault
                .create_session(CreateSessionParams {
                    operator: format!("operator-{i}"),
                    team: None,
                    project: None,
                    environment: None,
                    agent_type: None,
                    ttl_seconds: None,
                    description: None,
                })
                .unwrap()
        })
        .collect();

    let (proxy_addr, token) = start_test_proxy_with_vault(ca_dir.to_str().unwrap(), vault).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    // Send concurrent requests across all sessions.
    let mut handles = Vec::new();
    for (i, session) in sessions.iter().enumerate() {
        let c = client.clone();
        let addr = echo_addr;
        let token = session.token.clone();
        handles.push(tokio::spawn(async move {
            let resp = c
                .get(format!("http://{addr}/test/{i}"))
                .header("X-Forculus-Session", &token)
                .send()
                .await
                .expect("concurrent session request");
            assert_eq!(resp.status(), 200, "session {i} request should succeed");
        }));
    }

    for h in handles {
        h.await.expect("task join");
    }

    token.cancel();
}

#[tokio::test]
async fn adversarial_empty_request_body() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let echo_addr = start_echo_server().await;
    let scanner = Arc::new(forculus_inspect::scanner::ContentScanner::builtin());

    let (proxy_addr, token) =
        start_test_proxy_with_scanner(ca_dir.to_str().unwrap(), scanner).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    // POST with empty body should work.
    let resp = client
        .post(format!("http://{echo_addr}/upload"))
        .body("")
        .send()
        .await
        .expect("proxied request");

    assert_eq!(resp.status(), 200, "empty body should pass through");

    token.cancel();
}

#[tokio::test]
async fn adversarial_rapid_reconnects() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let (proxy_addr, token, _server) = start_test_proxy(ca_dir.to_str().unwrap()).await;

    // Open and close 50 connections rapidly.
    for _ in 0..50 {
        let result = tokio::net::TcpStream::connect(proxy_addr).await;
        if let Ok(stream) = result {
            drop(stream); // Immediately close
        }
    }

    // Small delay for the proxy to process disconnections.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Proxy must still be healthy.
    let health = reqwest::Client::new()
        .get(format!("http://{proxy_addr}/healthz"))
        .send()
        .await
        .expect("health after rapid reconnects");
    assert_eq!(health.status(), 200);

    token.cancel();
}

#[tokio::test]
async fn adversarial_request_after_policy_denial_still_works() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let echo_addr = start_echo_server().await;

    // Policy denies tool "blocked-host" but allows everything else.
    let engine = engine_with_rules(
        r#"
rules:
  - name: deny-blocked
    verdict: deny
    reason: "blocked host"
    priority: 10
    match:
      tools: ["blocked-host"]
  - name: allow-rest
    verdict: allow
    match:
      tools: ["*"]
"#,
    );

    let mapper = Arc::new(
        ToolMapper::new(vec![ToolMapping {
            url_pattern: "blocked-host:*/*".to_string(),
            tool: "blocked-host".to_string(),
            action_from: forculus_config::ActionFrom::UrlPath,
        }])
        .unwrap(),
    );

    let (proxy_addr, token) =
        start_test_proxy_with_toolmap(ca_dir.to_str().unwrap(), mapper, engine).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    // First: request to allowed endpoint.
    let resp = client
        .get(format!("http://{echo_addr}/test"))
        .send()
        .await
        .expect("allowed request");
    assert_eq!(resp.status(), 200, "allowed request should succeed");

    // Second: request to denied endpoint.
    let resp = client.get("http://blocked-host:1234/test").send().await;
    // Might be 403 or connection error (no server at blocked-host).
    if let Ok(r) = resp {
        assert!(
            r.status() == 403 || r.status().is_server_error(),
            "denied or unreachable"
        );
    }

    // Third: another allowed request should still work.
    let resp = client
        .get(format!("http://{echo_addr}/test2"))
        .send()
        .await
        .expect("allowed request after denial");
    assert_eq!(resp.status(), 200, "proxy recovers after denial");

    token.cancel();
}

#[tokio::test]
async fn adversarial_unicode_in_request() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let echo_addr = start_body_echo_server().await;
    let scanner = Arc::new(forculus_inspect::scanner::ContentScanner::builtin());

    let (proxy_addr, token) =
        start_test_proxy_with_scanner(ca_dir.to_str().unwrap(), scanner).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    // Send body with multi-byte UTF-8 characters.
    let unicode_body =
        "Hello \u{1F600} emoji and \u{4E16}\u{754C} (world) and \u{00E9}\u{00E8}\u{00EA} accents";
    let resp = client
        .post(format!("http://{echo_addr}/upload"))
        .body(unicode_body)
        .send()
        .await
        .expect("proxied request");

    assert_eq!(resp.status(), 200, "unicode body should pass through");

    let body: serde_json::Value = resp.json().await.expect("json body");
    let echoed = body["body"].as_str().expect("echoed body");
    assert!(echoed.contains("emoji"), "unicode content preserved");

    token.cancel();
}

#[tokio::test]
async fn adversarial_double_shutdown() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let (_addr, token, _server) = start_test_proxy(ca_dir.to_str().unwrap()).await;

    // Cancel twice — should not panic.
    token.cancel();
    token.cancel();

    tokio::time::sleep(Duration::from_millis(100)).await;
    // If we got here without panic, the test passes.
}

#[tokio::test]
async fn adversarial_slow_upstream() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    // Start a server that takes 3 seconds to respond.
    let slow_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind slow server");
    let slow_addr = slow_listener.local_addr().expect("addr");

    tokio::spawn(async move {
        loop {
            let (stream, _) = match slow_listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let service = service_fn(|_req: Request<hyper::body::Incoming>| async {
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    Ok::<_, hyper::Error>(Response::new(
                        Full::new(Bytes::from("slow response"))
                            .map_err(|never| match never {})
                            .boxed(),
                    ))
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    let (proxy_addr, token, _server) = start_test_proxy(ca_dir.to_str().unwrap()).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client");

    let resp = client
        .get(format!("http://{slow_addr}/slow"))
        .send()
        .await
        .expect("proxied slow request");

    assert_eq!(resp.status(), 200, "slow upstream response should arrive");
    let body = resp.text().await.expect("text");
    assert_eq!(body, "slow response");

    // Proxy still healthy during/after slow request.
    let health = reqwest::Client::new()
        .get(format!("http://{proxy_addr}/healthz"))
        .send()
        .await
        .expect("health");
    assert_eq!(health.status(), 200);

    token.cancel();
}

// ── Phase 1I Verification: Security adversarial tests ──────────────────

/// SQL injection in the tool name or URL should not corrupt policy evaluation
/// or any internal store.
#[tokio::test]
async fn adversarial_sql_injection_in_tool_name() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let echo_addr = start_echo_server().await;

    // Map the echo server to a tool name containing SQL injection.
    let mapper = Arc::new(
        ToolMapper::new(vec![ToolMapping {
            url_pattern: format!("{}/*", echo_addr),
            tool: "echo'; DROP TABLE events;--".to_string(),
            action_from: forculus_config::ActionFrom::UrlPath,
        }])
        .unwrap(),
    );

    // Allow-all policy.
    let engine = engine_with_rules(
        r#"
rules:
  - name: allow-all
    verdict: allow
    match:
      tools: ["*"]
"#,
    );

    // Set up audit logger to verify SQL injection doesn't corrupt the DB.
    let audit_db = tmp.path().join("audit.db");
    let logger = forculus_audit::logger::AuditLogger::new(&audit_db).unwrap();

    let config = ProxyConfig {
        listen_address: "127.0.0.1:0".to_string(),
        tls: forculus_config::TlsConfig {
            ca_dir: ca_dir.to_str().unwrap().to_string(),
        },
        tool_mappings: Vec::new(),
        tls_passthrough: Vec::new(),
    };

    let server = Arc::new(
        ProxyServer::new(config)
            .await
            .expect("proxy server")
            .with_policy_engine(engine)
            .with_tool_mapper(mapper)
            .with_audit_logger(logger.clone()),
    );
    let token = server.shutdown_token();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test proxy");
    let proxy_addr = listener.local_addr().expect("local addr");

    let server_clone = Arc::clone(&server);
    tokio::spawn(async move {
        server_clone
            .run_with_listener(listener)
            .await
            .expect("proxy run");
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    // Send request — the tool name contains SQL injection payload.
    let resp = client
        .get(format!("http://{echo_addr}/api/data"))
        .send()
        .await
        .expect("proxied request");

    assert_eq!(
        resp.status(),
        200,
        "request should succeed (tool name is just a string)"
    );

    // Flush audit log and verify the DB is intact.
    logger.shutdown().await;
    token.cancel();

    let store = forculus_audit::store::AuditStore::open(&audit_db).unwrap();
    let events = store
        .query(&forculus_audit::query::AuditFilter::default())
        .unwrap();
    assert!(!events.is_empty(), "audit events should be present");

    // Verify the SQL injection payload was stored as a literal string, not executed.
    let event = &events[0];
    assert!(
        event.request.as_ref().unwrap().tool.contains("DROP TABLE"),
        "tool name with SQL injection should be stored literally"
    );

    // Verify hash chain is intact (SQL injection didn't corrupt the store).
    let chain = store.verify_chain().unwrap();
    assert!(
        chain.valid,
        "audit hash chain should be valid after SQL injection attempt"
    );
}

/// Null bytes in headers/body should not cause panics or truncation issues.
#[tokio::test]
async fn adversarial_null_bytes_in_request() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let echo_addr = start_body_echo_server().await;
    let scanner = Arc::new(forculus_inspect::scanner::ContentScanner::builtin());

    let (proxy_addr, token) =
        start_test_proxy_with_scanner(ca_dir.to_str().unwrap(), scanner).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    // Body with embedded null bytes and control characters.
    let null_body = b"before\x00null\x00middle\x01\x02\x03after";
    let resp = client
        .post(format!("http://{echo_addr}/upload"))
        .body(null_body.to_vec())
        .send()
        .await
        .expect("proxied request");

    // Should pass through — null bytes are not secret patterns.
    assert!(
        resp.status().is_success(),
        "null bytes in body should not crash the proxy, got {}",
        resp.status()
    );

    // Proxy still healthy.
    let health = reqwest::Client::new()
        .get(format!("http://{proxy_addr}/healthz"))
        .send()
        .await
        .expect("health");
    assert_eq!(health.status(), 200);

    token.cancel();
}

/// Error responses from the proxy must never contain credential material
/// (session tokens, vault secrets, internal paths).
#[tokio::test]
async fn adversarial_credential_not_leaked_in_errors() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");
    let vault_dir = tmp.path().join("vault");
    std::fs::create_dir_all(&vault_dir).unwrap();

    let vault = test_vault_required(&vault_dir);
    let echo_addr = start_echo_server().await;
    let (proxy_addr, token) = start_test_proxy_with_vault(ca_dir.to_str().unwrap(), vault).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    // 1. Request with an invalid session token → 401.
    let bad_token = "bwk_sess_0000000000000000000000000000dead";
    let resp = client
        .get(format!("http://{echo_addr}/test"))
        .header("X-Forculus-Session", bad_token)
        .send()
        .await
        .expect("proxied request");

    assert_eq!(resp.status(), 401);
    let body_text = resp.text().await.expect("body text");

    // The error response must NOT leak the submitted token.
    assert!(
        !body_text.contains(bad_token),
        "error response must not echo back the session token"
    );
    // Must not contain internal paths.
    assert!(
        !body_text.contains("vault") && !body_text.contains("sessions.db"),
        "error response must not reveal internal paths, got: {body_text}"
    );

    // 2. Request without session (when required) → 401.
    let resp = client
        .get(format!("http://{echo_addr}/test"))
        .send()
        .await
        .expect("proxied request");

    assert_eq!(resp.status(), 401);
    let body_text = resp.text().await.expect("body text");
    assert!(
        !body_text.contains(&vault_dir.to_string_lossy().to_string()),
        "error response must not reveal vault directory path"
    );

    token.cancel();
}

/// Session validation should be timing-safe: valid-format tokens that don't
/// exist should take roughly the same time as tokens that do exist but are
/// revoked or expired.
#[tokio::test]
async fn adversarial_timing_safe_session_validation() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");
    let vault_dir = tmp.path().join("vault");
    std::fs::create_dir_all(&vault_dir).unwrap();

    let vault = test_vault_required(&vault_dir);

    // Create a valid session.
    let session = vault
        .create_session(CreateSessionParams {
            operator: "timing-test".to_string(),
            team: None,
            project: None,
            environment: None,
            agent_type: None,
            ttl_seconds: None,
            description: None,
        })
        .unwrap();

    let echo_addr = start_echo_server().await;
    let (proxy_addr, token) = start_test_proxy_with_vault(ca_dir.to_str().unwrap(), vault).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    // Measure time for 10 requests with a non-existent valid-format token.
    let nonexistent_token = "bwk_sess_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1";
    let mut nonexistent_durations = Vec::new();
    for _ in 0..10 {
        let start = std::time::Instant::now();
        let resp = client
            .get(format!("http://{echo_addr}/test"))
            .header("X-Forculus-Session", nonexistent_token)
            .send()
            .await
            .expect("proxied request");
        nonexistent_durations.push(start.elapsed());
        assert_eq!(resp.status(), 401);
    }

    // Measure time for 10 requests with a valid token.
    let mut valid_durations = Vec::new();
    for _ in 0..10 {
        let start = std::time::Instant::now();
        let resp = client
            .get(format!("http://{echo_addr}/test"))
            .header("X-Forculus-Session", &session.token)
            .send()
            .await
            .expect("proxied request");
        valid_durations.push(start.elapsed());
        assert_eq!(resp.status(), 200);
    }

    // Compute median durations (excludes warm-up outliers).
    nonexistent_durations.sort();
    valid_durations.sort();
    let median_nonexistent = nonexistent_durations[5];
    let median_valid = valid_durations[5];

    // The key assertion: the ratio between the two medians should not be extreme.
    // A timing oracle would show >10x difference. We allow up to 5x.
    let ratio = if median_nonexistent > median_valid {
        median_nonexistent.as_micros() as f64 / median_valid.as_micros().max(1) as f64
    } else {
        median_valid.as_micros() as f64 / median_nonexistent.as_micros().max(1) as f64
    };

    assert!(
        ratio < 5.0,
        "timing ratio between valid and nonexistent tokens ({ratio:.2}x) suggests \
         a timing oracle vulnerability. Median valid={median_valid:?}, nonexistent={median_nonexistent:?}"
    );

    token.cancel();
}

/// Sending raw malformed HTTP requests (not just non-HTTP data, but technically
/// HTTP-like but broken) should not crash the proxy. This specifically tests
/// protocol-level resilience.
#[tokio::test]
async fn adversarial_malformed_http_protocol() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let (proxy_addr, token, _server) = start_test_proxy(ca_dir.to_str().unwrap()).await;

    // 1. Send an HTTP/1.0 request with garbage content-length.
    let mut stream = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("connect");

    use tokio::io::AsyncWriteExt;
    stream
        .write_all(
            b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: -1\r\n\r\n",
        )
        .await
        .ok();
    drop(stream);

    // 2. Send an HTTP request with duplicate Content-Length headers (CL smuggling probe).
    let mut stream2 = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("connect");
    stream2
        .write_all(
            b"POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nContent-Length: 100\r\n\r\nhello",
        )
        .await
        .ok();
    drop(stream2);

    // 3. Send truncated request line.
    let mut stream3 = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("connect");
    stream3.write_all(b"GET\r\n").await.ok();
    drop(stream3);

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Proxy still healthy.
    let health = reqwest::Client::new()
        .get(format!("http://{proxy_addr}/healthz"))
        .send()
        .await
        .expect("health after malformed HTTP");
    assert_eq!(health.status(), 200);

    token.cancel();
}

/// Tool names injected into audit log events should not cause audit log
/// corruption (e.g. via newlines, control characters, or oversized values).
#[tokio::test]
async fn adversarial_audit_log_injection() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let echo_addr = start_echo_server().await;

    // Create audit logger.
    let audit_db = tmp.path().join("audit_injection.db");
    let logger = forculus_audit::logger::AuditLogger::new(&audit_db).unwrap();

    // Create a tool mapper with a tool name containing SQL injection payloads,
    // quotes, tabs, and unicode characters (no newlines — glob `*` doesn't match \n).
    let mapper = Arc::new(
        ToolMapper::new(vec![ToolMapping {
            url_pattern: format!("{}/*", echo_addr),
            tool: "tool'; DROP TABLE events;--\twith\ttabs\"and'quotes\u{1F600}".to_string(),
            action_from: forculus_config::ActionFrom::UrlPath,
        }])
        .unwrap(),
    );

    let engine = engine_with_rules(
        r#"
rules:
  - name: allow-all
    verdict: allow
    match:
      tools: ["*"]
"#,
    );

    let config = ProxyConfig {
        listen_address: "127.0.0.1:0".to_string(),
        tls: forculus_config::TlsConfig {
            ca_dir: ca_dir.to_str().unwrap().to_string(),
        },
        tool_mappings: Vec::new(),
        tls_passthrough: Vec::new(),
    };

    // No content scanner — we are testing audit log injection, not content inspection.
    let server = Arc::new(
        ProxyServer::new(config)
            .await
            .expect("proxy server")
            .with_policy_engine(engine)
            .with_tool_mapper(mapper)
            .with_audit_logger(logger.clone()),
    );
    let token = server.shutdown_token();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test proxy");
    let proxy_addr = listener.local_addr().expect("local addr");

    let server_clone = Arc::clone(&server);
    tokio::spawn(async move {
        server_clone
            .run_with_listener(listener)
            .await
            .expect("proxy run");
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    // Send 3 requests to build a chain.
    for i in 0..3 {
        let resp = client
            .get(format!("http://{echo_addr}/test/{i}"))
            .send()
            .await
            .expect("proxied request");
        assert_eq!(resp.status(), 200);
    }

    // Flush and verify.
    logger.shutdown().await;
    token.cancel();

    let store = forculus_audit::store::AuditStore::open(&audit_db).unwrap();
    let events = store
        .query(&forculus_audit::query::AuditFilter::default())
        .unwrap();
    assert_eq!(events.len(), 3, "should have 3 audit events");

    // Verify the control characters were stored literally without corrupting the chain.
    let chain = store.verify_chain().unwrap();
    assert!(
        chain.valid,
        "audit hash chain should be valid even with control characters in tool names"
    );
    assert_eq!(chain.events_checked, 3);
}

/// Concurrent requests to a rate-limited endpoint should not exceed the burst
/// limit due to race conditions (i.e. the token bucket is thread-safe).
#[tokio::test]
async fn adversarial_rate_limit_concurrent_accuracy() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let echo_addr = start_echo_server().await;

    let engine = engine_with_rules(
        r#"
rules:
  - name: allow-all
    verdict: allow
    match:
      tools: ["*"]
"#,
    );

    // Rate limit: burst=5, 60 RPM, global dimension.
    let limiter = Arc::new(
        RateLimiter::new(vec![forculus_config::RateLimitRule {
            name: "concurrent-test".to_string(),
            tools: vec!["*".to_string()],
            rpm: 60,
            burst: 5,
            dimensions: vec!["global".to_string()],
        }])
        .unwrap(),
    );

    let config = ProxyConfig {
        listen_address: "127.0.0.1:0".to_string(),
        tls: forculus_config::TlsConfig {
            ca_dir: ca_dir.to_str().unwrap().to_string(),
        },
        tool_mappings: Vec::new(),
        tls_passthrough: Vec::new(),
    };

    let server = Arc::new(
        ProxyServer::new(config)
            .await
            .expect("proxy server")
            .with_policy_engine(engine)
            .with_rate_limiter(limiter),
    );
    let token = server.shutdown_token();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test proxy");
    let proxy_addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        server.run_with_listener(listener).await.expect("proxy run");
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    // Fire 20 concurrent requests. With burst=5, at most 5 should succeed.
    let mut handles = Vec::new();
    for i in 0..20 {
        let c = client.clone();
        let addr = echo_addr;
        handles.push(tokio::spawn(async move {
            let resp = c
                .get(format!("http://{addr}/test/{i}"))
                .send()
                .await
                .expect("request");
            resp.status().as_u16()
        }));
    }

    let mut successes = 0u32;
    let mut rate_limited = 0u32;
    for h in handles {
        let status = h.await.expect("task join");
        if status == 200 {
            successes += 1;
        } else if status == 429 {
            rate_limited += 1;
        }
    }

    // At most burst (5) + a small refill allowance should succeed.
    // The exact count depends on timing, but we should not get all 20 through.
    assert!(
        successes <= 7,
        "at most burst + small refill should succeed, but got {successes} successes \
         (rate_limited={rate_limited})"
    );
    assert!(
        rate_limited > 0,
        "at least some requests should be rate limited, but got 0 rate-limited \
         (successes={successes})"
    );

    token.cancel();
}

// ---------------------------------------------------------------------------
// TLS Passthrough tests
// ---------------------------------------------------------------------------

/// Verify that GlobPattern matching works correctly for passthrough host patterns.
#[tokio::test]
async fn test_tls_passthrough_pattern_matching() {
    use forculus_policy::glob::GlobPattern;

    let patterns: Vec<GlobPattern> = vec![
        GlobPattern::compile("*.pinned-service.com").unwrap(),
        GlobPattern::compile("vault.internal:8200").unwrap(),
        GlobPattern::compile("exact-host.example.org").unwrap(),
    ];

    // Wildcard matching.
    assert!(patterns.iter().any(|p| p.matches("api.pinned-service.com")));
    assert!(
        patterns
            .iter()
            .any(|p| p.matches("deep.sub.pinned-service.com"))
    );

    // Exact matching with port.
    assert!(patterns.iter().any(|p| p.matches("vault.internal:8200")));

    // Exact host matching.
    assert!(patterns.iter().any(|p| p.matches("exact-host.example.org")));

    // Non-matching hosts.
    assert!(!patterns.iter().any(|p| p.matches("other-service.com")));
    assert!(!patterns.iter().any(|p| p.matches("vault.internal:9200")));
    assert!(!patterns.iter().any(|p| p.matches("wrong-host.example.org")));
}

/// Verify that the passthrough path sends a 200 and tunnels bytes directly
/// (no TLS MITM). We test by CONNECT-ing to a matched host and verifying
/// the proxy returns 200 and pipes TCP bytes through.
#[tokio::test]
async fn test_tls_passthrough_tunnels_tcp() {
    use forculus_policy::glob::GlobPattern;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Start a simple TCP echo server (non-TLS).
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let echo_addr = echo_listener.local_addr().expect("echo addr");

    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match echo_listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    let n = match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    // Start proxy with passthrough pattern matching the echo server's host:port.
    let tmp = tempfile::tempdir().expect("tmpdir");
    let ca_dir = tmp.path().to_str().expect("ca dir");

    let config = ProxyConfig {
        listen_address: "127.0.0.1:0".to_string(),
        tls: forculus_config::TlsConfig {
            ca_dir: ca_dir.to_string(),
        },
        tool_mappings: Vec::new(),
        tls_passthrough: Vec::new(),
    };

    let passthrough_patterns =
        vec![GlobPattern::compile(&format!("127.0.0.1:{}", echo_addr.port())).unwrap()];

    let server = Arc::new(
        ProxyServer::new(config)
            .await
            .expect("proxy server")
            .with_tls_passthrough(passthrough_patterns),
    );
    let token = server.shutdown_token();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let proxy_addr = listener.local_addr().expect("proxy addr");

    let server_clone = Arc::clone(&server);
    tokio::spawn(async move {
        server_clone
            .run_with_listener(listener)
            .await
            .expect("proxy run");
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Send a CONNECT request to the proxy for the echo server address.
    let mut stream = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("connect to proxy");

    let connect_req = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        echo_addr.port(),
        echo_addr.port()
    );
    stream
        .write_all(connect_req.as_bytes())
        .await
        .expect("send CONNECT");

    // Read the 200 response.
    let mut resp_buf = vec![0u8; 1024];
    let n = stream.read(&mut resp_buf).await.expect("read response");
    let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
    assert!(
        resp_str.contains("200"),
        "expected 200 response, got: {resp_str}"
    );

    // Now the tunnel is established. Send raw bytes and expect them echoed.
    let test_data = b"hello passthrough!";
    stream
        .write_all(test_data)
        .await
        .expect("write through tunnel");

    let mut echo_buf = vec![0u8; 1024];
    let n = stream.read(&mut echo_buf).await.expect("read echo");
    assert_eq!(&echo_buf[..n], test_data, "expected echoed data");

    token.cancel();
}

/// Verify backward compatibility — proxy without passthrough patterns works normally.
#[tokio::test]
async fn test_no_passthrough_backward_compatible() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let ca_dir = tmp.path().to_str().expect("ca dir");

    let echo_addr = start_echo_server().await;

    let config = ProxyConfig {
        listen_address: "127.0.0.1:0".to_string(),
        tls: forculus_config::TlsConfig {
            ca_dir: ca_dir.to_string(),
        },
        tool_mappings: Vec::new(),
        tls_passthrough: Vec::new(),
    };

    // No passthrough patterns at all (None).
    let server = Arc::new(ProxyServer::new(config).await.expect("proxy server"));
    let token = server.shutdown_token();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let proxy_addr = listener.local_addr().expect("proxy addr");

    let server_clone = Arc::clone(&server);
    tokio::spawn(async move {
        server_clone
            .run_with_listener(listener)
            .await
            .expect("proxy run");
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // HTTP request through proxy should still work normally.
    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    let resp = client
        .get(format!("http://{echo_addr}/hello"))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["path"], "/hello");

    token.cancel();
}
