//! `forculus auth` — OIDC authentication commands and management server.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use forculus_audit::event::{AuditEvent, Channel, EventType, RequestInfo, SessionInfo};
use forculus_audit::logger::AuditLogger;
use forculus_auth::provider::{AuthProvider, AuthProviderConfig, ClientSecretSource};
use forculus_auth::{Nonce, PkceCodeVerifier};
use forculus_config::{AuthOidcConfig, SecretSource, load_config};
use forculus_vault::session::CreateSessionParams;
use forculus_vault::store::Vault;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1::Builder;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

// ---------------------------------------------------------------------------
// Config mapping
// ---------------------------------------------------------------------------

/// Convert YAML-facing config types to the auth crate's config types.
/// Bridges `crates/config/` and `crates/auth/` without creating a dependency.
fn to_auth_provider_config(oidc: &AuthOidcConfig) -> AuthProviderConfig {
    AuthProviderConfig {
        issuer_url: oidc.issuer_url.clone(),
        client_id: oidc.client_id.clone(),
        client_secret_source: match &oidc.client_secret_source {
            SecretSource::Env => ClientSecretSource::Env(oidc.client_secret_env.clone()),
            SecretSource::File => {
                ClientSecretSource::File(oidc.client_secret_path.clone().unwrap_or_default())
            }
            SecretSource::Vault => ClientSecretSource::Vault,
        },
        redirect_uri: oidc.redirect_uri.clone(),
        scopes: oidc.scopes.clone(),
        group_claim: oidc.group_claim.clone(),
        group_mapping: oidc
            .group_mapping
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    forculus_auth::GroupMappingEntry {
                        team: v.team.clone(),
                        environment: v.environment.clone(),
                        agent_type: v.agent_type.clone(),
                        labels: v.labels.clone(),
                    },
                )
            })
            .collect(),
        default_session_ttl: Duration::from_secs(oidc.default_session_ttl),
        service_accounts_enabled: oidc.service_accounts.enabled,
    }
}

// ---------------------------------------------------------------------------
// Pending auth store (in-memory, 5-minute TTL)
// ---------------------------------------------------------------------------

struct PendingAuth {
    pkce_verifier: PkceCodeVerifier,
    nonce: Nonce,
    created_at: Instant,
}

/// In-memory store keyed by CSRF state token.
struct PendingAuthStore {
    entries: parking_lot::Mutex<HashMap<String, PendingAuth>>,
}

const PENDING_AUTH_TTL: Duration = Duration::from_secs(300); // 5 minutes

impl PendingAuthStore {
    fn new() -> Self {
        Self {
            entries: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    fn insert(&self, state: &str, auth: PendingAuth) {
        self.entries.lock().insert(state.to_string(), auth);
    }

    /// Returns and removes the entry if it exists and hasn't expired.
    fn take(&self, state: &str) -> Option<PendingAuth> {
        let mut entries = self.entries.lock();
        // Opportunistically clean expired entries
        entries.retain(|_, v| v.created_at.elapsed() < PENDING_AUTH_TTL);
        let entry = entries.remove(state)?;
        if entry.created_at.elapsed() >= PENDING_AUTH_TTL {
            return None;
        }
        Some(entry)
    }
}

// ---------------------------------------------------------------------------
// Session creation from MappedClaims
// ---------------------------------------------------------------------------

fn create_session_from_claims(
    vault: &Vault,
    claims: &forculus_auth::MappedClaims,
) -> Result<forculus_vault::session::Session> {
    let params = CreateSessionParams {
        operator: claims.operator.clone(),
        team: claims.team.clone(),
        project: None,
        environment: claims.environment.clone(),
        agent_type: claims.agent_type.clone(),
        ttl_seconds: Some(claims.ttl.as_secs()),
        description: Some("Created via OIDC authentication".to_string()),
    };
    vault
        .create_session(params)
        .context("creating session from OIDC claims")
}

// ---------------------------------------------------------------------------
// Audit helpers
// ---------------------------------------------------------------------------

fn emit_oidc_audit(
    logger: &Option<AuditLogger>,
    session: &forculus_vault::session::Session,
    claims: &forculus_auth::MappedClaims,
    action: &str,
    issuer_url: &str,
) {
    let Some(logger) = logger else { return };
    let event = AuditEvent::builder(EventType::OidcSessionCreated, Channel::Cli)
        .session(SessionInfo {
            session_id: session.id.clone(),
            operator: claims.operator.clone(),
            team: claims.team.clone(),
            project: None,
            environment: claims.environment.clone(),
            agent_type: claims.agent_type.clone(),
        })
        .request(RequestInfo {
            tool: "oidc".to_string(),
            action: action.to_string(),
            resource: Some(issuer_url.to_string()),
            target: issuer_url.to_string(),
        })
        .build();
    logger.log(event);
}

// ---------------------------------------------------------------------------
// HTML callback page
// ---------------------------------------------------------------------------

fn callback_html(token: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head>
  <title>Forculus — Session Created</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 60px auto; padding: 0 20px; }}
    code {{ display: block; padding: 12px; background: #f4f4f4; border-radius: 4px; word-break: break-all; margin: 12px 0; }}
    button {{ padding: 8px 16px; cursor: pointer; background: #2563eb; color: white; border: none; border-radius: 4px; }}
    button:hover {{ background: #1d4ed8; }}
  </style>
</head>
<body>
  <h1>Session Created</h1>
  <p>Your Forculus session token:</p>
  <code id="token">{token}</code>
  <button onclick="navigator.clipboard.writeText(document.getElementById('token').textContent)">
    Copy to Clipboard
  </button>
  <p>Configure your agent with this token. It will not be shown again.</p>
  <p>Set it as:</p>
  <ul>
    <li><strong>HTTP:</strong> <code>X-Forculus-Session: {token}</code></li>
    <li><strong>MCP:</strong> via initialize params</li>
  </ul>
</body>
</html>"#,
        token = token
    )
}

fn error_html(message: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Forculus — Error</title>
<style>body {{ font-family: sans-serif; max-width: 600px; margin: 60px auto; padding: 0 20px; }}</style>
</head>
<body>
  <h1>Authentication Error</h1>
  <p>{message}</p>
</body>
</html>"#,
        message = message
    )
}

// ---------------------------------------------------------------------------
// HTTP request handling for auth server
// ---------------------------------------------------------------------------

struct AuthServerState {
    auth_provider: Arc<AuthProvider>,
    vault: Arc<parking_lot::Mutex<Vault>>,
    audit_logger: Option<AuditLogger>,
    pending: Arc<PendingAuthStore>,
    issuer_url: String,
}

async fn handle_auth_request(
    req: hyper::Request<hyper::body::Incoming>,
    state: Arc<AuthServerState>,
) -> Result<hyper::Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    let response = match (method.as_str(), path.as_str()) {
        ("GET", "/auth/login") => handle_login(&state, &req),
        ("GET", "/auth/callback") | ("GET", "/callback") => handle_callback(&state, &req).await,
        ("POST", "/auth/token") => handle_token_exchange(&state, req).await,
        ("GET", "/auth/status") => handle_status(&state),
        _ => hyper::Response::builder()
            .status(404)
            .body(Full::new(Bytes::from("Not Found")))
            .unwrap(),
    };

    Ok(response)
}

fn handle_login(
    state: &AuthServerState,
    _req: &hyper::Request<hyper::body::Incoming>,
) -> hyper::Response<Full<Bytes>> {
    let scopes: Vec<String> = Vec::new(); // Use provider's configured scopes
    let auth_request = state.auth_provider.authorization_url(&scopes);

    let pending = PendingAuth {
        pkce_verifier: auth_request.pkce_verifier,
        nonce: auth_request.nonce,
        created_at: Instant::now(),
    };
    state
        .pending
        .insert(auth_request.csrf_state.secret(), pending);

    hyper::Response::builder()
        .status(302)
        .header("Location", auth_request.authorization_url.as_str())
        .body(Full::new(Bytes::new()))
        .unwrap()
}

async fn handle_callback(
    state: &AuthServerState,
    req: &hyper::Request<hyper::body::Incoming>,
) -> hyper::Response<Full<Bytes>> {
    // Parse query parameters
    let query = req.uri().query().unwrap_or("");
    let params: HashMap<String, String> = url::form_urlencoded::parse(query.as_bytes())
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let code = match params.get("code") {
        Some(c) => c.clone(),
        None => {
            return hyper::Response::builder()
                .status(400)
                .header("Content-Type", "text/html")
                .body(Full::new(Bytes::from(error_html(
                    "Missing 'code' parameter in callback",
                ))))
                .unwrap();
        }
    };

    let csrf_state = match params.get("state") {
        Some(s) => s.clone(),
        None => {
            return hyper::Response::builder()
                .status(400)
                .header("Content-Type", "text/html")
                .body(Full::new(Bytes::from(error_html(
                    "Missing 'state' parameter in callback",
                ))))
                .unwrap();
        }
    };

    // Look up pending auth
    let pending = match state.pending.take(&csrf_state) {
        Some(p) => p,
        None => {
            return hyper::Response::builder()
                .status(400)
                .header("Content-Type", "text/html")
                .body(Full::new(Bytes::from(error_html(
                    "Invalid or expired authentication request. Please try logging in again.",
                ))))
                .unwrap();
        }
    };

    // Exchange code for claims
    let claims = match state
        .auth_provider
        .exchange_code(&code, pending.pkce_verifier, &pending.nonce)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "OIDC code exchange failed");
            return hyper::Response::builder()
                .status(500)
                .header("Content-Type", "text/html")
                .body(Full::new(Bytes::from(error_html(&format!(
                    "Authentication failed: {e}"
                )))))
                .unwrap();
        }
    };

    // Create session
    let session = match create_session_from_claims(&state.vault.lock(), &claims) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "session creation from OIDC claims failed");
            return hyper::Response::builder()
                .status(500)
                .header("Content-Type", "text/html")
                .body(Full::new(Bytes::from(error_html(&format!(
                    "Session creation failed: {e}"
                )))))
                .unwrap();
        }
    };

    // Audit
    emit_oidc_audit(
        &state.audit_logger,
        &session,
        &claims,
        "session_create",
        &state.issuer_url,
    );

    hyper::Response::builder()
        .status(200)
        .header("Content-Type", "text/html")
        .body(Full::new(Bytes::from(callback_html(&session.token))))
        .unwrap()
}

async fn handle_token_exchange(
    state: &AuthServerState,
    req: hyper::Request<hyper::body::Incoming>,
) -> hyper::Response<Full<Bytes>> {
    // Extract token from Authorization header or JSON body
    let token = if let Some(auth_header) = req.headers().get("authorization") {
        let header_str = auth_header.to_str().unwrap_or("");
        header_str
            .strip_prefix("Bearer ")
            .map(|bearer| bearer.to_string())
    } else {
        // Try JSON body
        let body_bytes = match http_body_util::BodyExt::collect(req.into_body()).await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => {
                return hyper::Response::builder()
                    .status(400)
                    .header("Content-Type", "application/json")
                    .body(Full::new(Bytes::from(
                        r#"{"error":"failed to read request body"}"#,
                    )))
                    .unwrap();
            }
        };
        serde_json::from_slice::<serde_json::Value>(&body_bytes)
            .ok()
            .and_then(|v| v.get("token").and_then(|t| t.as_str()).map(String::from))
    };

    let token = match token {
        Some(t) if !t.is_empty() => t,
        _ => {
            return hyper::Response::builder()
                .status(400)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(
                    r#"{"error":"missing token: provide Bearer token in Authorization header or {\"token\":\"...\"} in request body"}"#,
                )))
                .unwrap();
        }
    };

    // Validate service token
    let claims = match state.auth_provider.validate_service_token(&token).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "service token validation failed");
            return hyper::Response::builder()
                .status(401)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(format!(
                    r#"{{"error":"token validation failed: {e}"}}"#
                ))))
                .unwrap();
        }
    };

    // Create session
    let session = match create_session_from_claims(&state.vault.lock(), &claims) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "session creation from service token failed");
            return hyper::Response::builder()
                .status(500)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(format!(
                    r#"{{"error":"session creation failed: {e}"}}"#
                ))))
                .unwrap();
        }
    };

    // Audit
    emit_oidc_audit(
        &state.audit_logger,
        &session,
        &claims,
        "service_account_session_create",
        &state.issuer_url,
    );

    let response = serde_json::json!({
        "session_token": session.token,
        "expires_in": claims.ttl.as_secs(),
        "operator": claims.operator,
        "team": claims.team,
        "environment": claims.environment,
    });

    hyper::Response::builder()
        .status(200)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(response.to_string())))
        .unwrap()
}

fn handle_status(state: &AuthServerState) -> hyper::Response<Full<Bytes>> {
    let response = serde_json::json!({
        "issuer_url": state.issuer_url,
        "status": "connected",
    });

    hyper::Response::builder()
        .status(200)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(response.to_string())))
        .unwrap()
}

// ---------------------------------------------------------------------------
// Run auth HTTP server
// ---------------------------------------------------------------------------

async fn run_auth_server(
    state: Arc<AuthServerState>,
    listen_addr: &str,
    shutdown: CancellationToken,
) -> Result<()> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("binding auth server to {listen_addr}"))?;
    let local_addr = listener.local_addr()?;
    tracing::info!(address = %local_addr, "auth management server started");

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            accept = listener.accept() => {
                match accept {
                    Ok((stream, addr)) => {
                        let state = Arc::clone(&state);
                        tokio::spawn(async move {
                            let service = service_fn(move |req| {
                                let state = Arc::clone(&state);
                                async move { handle_auth_request(req, state).await }
                            });
                            let conn = Builder::new().serve_connection(TokioIo::new(stream), service);
                            if let Err(e) = conn.await {
                                tracing::debug!(error = %e, peer = %addr, "auth connection error");
                            }
                        });
                    }
                    Err(e) => tracing::warn!(error = %e, "auth server accept error"),
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// CLI: forculus auth serve
// ---------------------------------------------------------------------------

pub fn serve(
    config_path: &Path,
    log_level: Option<&str>,
    listen_override: Option<&str>,
) -> Result<()> {
    let config = load_config(config_path).context("loading configuration")?;

    let level = log_level
        .map(String::from)
        .unwrap_or_else(|| config.logging.level.clone());
    let filter = EnvFilter::try_new(&level).unwrap_or_else(|_| EnvFilter::new("info"));

    match config.logging.format {
        forculus_config::LogFormat::Json => {
            tracing_subscriber::registry()
                .with(filter)
                .with(
                    tracing_subscriber::fmt::layer()
                        .json()
                        .with_writer(std::io::stderr),
                )
                .init();
        }
        forculus_config::LogFormat::Pretty => {
            tracing_subscriber::registry()
                .with(filter)
                .with(
                    tracing_subscriber::fmt::layer()
                        .pretty()
                        .with_writer(std::io::stderr),
                )
                .init();
        }
    }

    let oidc_config = config
        .auth
        .oidc
        .as_ref()
        .filter(|o| o.enabled)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "OIDC is not configured or not enabled. Add auth.oidc section to forculus.yaml"
            )
        })?;

    let auth_config = to_auth_provider_config(oidc_config);
    let vault_config = config.vault.clone();
    let audit_config = config.audit.clone();
    let issuer_url = oidc_config.issuer_url.clone();
    let listen_address = listen_override
        .map(String::from)
        .unwrap_or_else(|| config.auth.server.listen_address.clone());

    let rt = tokio::runtime::Runtime::new().context("creating tokio runtime")?;
    rt.block_on(async {
        let auth_provider = AuthProvider::from_discovery(&auth_config)
            .await
            .context("OIDC discovery failed")?;

        let vault = Vault::open(&vault_config).context("opening vault")?;

        let audit_logger = if audit_config.enabled {
            let audit_db_path = forculus_config::expand_tilde(&audit_config.db_path);
            match AuditLogger::new(Path::new(&audit_db_path)) {
                Ok(logger) => {
                    tracing::info!(db = %audit_db_path, "audit logger started");
                    Some(logger)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to start audit logger");
                    None
                }
            }
        } else {
            None
        };

        let state = Arc::new(AuthServerState {
            auth_provider: Arc::new(auth_provider),
            vault: Arc::new(parking_lot::Mutex::new(vault)),
            audit_logger,
            pending: Arc::new(PendingAuthStore::new()),
            issuer_url,
        });

        let shutdown = CancellationToken::new();
        let shutdown_clone = shutdown.clone();

        tokio::spawn(async move {
            shutdown_signal().await;
            tracing::info!("shutdown signal received");
            shutdown_clone.cancel();
        });

        run_auth_server(state, &listen_address, shutdown)
            .await
            .context("running auth server")?;

        Ok(())
    })
}

// ---------------------------------------------------------------------------
// CLI: forculus auth status
// ---------------------------------------------------------------------------

pub fn status(config_path: &Path) -> Result<()> {
    let config = load_config(config_path).context("loading configuration")?;

    let oidc_config = match config.auth.oidc.as_ref() {
        Some(oidc) if oidc.enabled => oidc,
        Some(_) => {
            println!("OIDC is configured but not enabled.");
            return Ok(());
        }
        None => {
            println!("OIDC is not configured.");
            return Ok(());
        }
    };

    println!("OIDC Configuration:");
    println!("  Issuer URL:        {}", oidc_config.issuer_url);

    // Mask client ID
    let masked_id = if oidc_config.client_id.len() > 6 {
        format!(
            "{}...{}",
            &oidc_config.client_id[..3],
            &oidc_config.client_id[oidc_config.client_id.len() - 3..]
        )
    } else {
        "***".to_string()
    };
    println!("  Client ID:         {masked_id}");
    println!("  Scopes:            {}", oidc_config.scopes.join(", "));
    println!("  Group claim:       {}", oidc_config.group_claim);
    println!(
        "  Service accounts:  {}",
        if oidc_config.service_accounts.enabled {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!("  Session TTL:       {}s", oidc_config.default_session_ttl);

    if !oidc_config.group_mapping.is_empty() {
        println!("  Group mappings:");
        for (group, entry) in &oidc_config.group_mapping {
            let team = entry.team.as_deref().unwrap_or("-");
            let env = entry.environment.as_deref().unwrap_or("-");
            println!("    {group} → team={team}, env={env}");
        }
    }

    // Test connectivity
    println!();
    let auth_config = to_auth_provider_config(oidc_config);
    let rt = tokio::runtime::Runtime::new().context("creating tokio runtime")?;
    match rt.block_on(AuthProvider::from_discovery(&auth_config)) {
        Ok(_) => {
            println!("  Discovery:         OK (reachable)");
        }
        Err(e) => {
            println!("  Discovery:         FAILED ({e})");
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// CLI: forculus session create --oidc
// ---------------------------------------------------------------------------

pub fn session_create_oidc(config_path: &Path) -> Result<()> {
    let config = load_config(config_path).context("loading configuration")?;

    let oidc_config = config
        .auth
        .oidc
        .as_ref()
        .filter(|o| o.enabled)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "OIDC is not configured or not enabled. Add auth.oidc section to forculus.yaml"
            )
        })?;

    let mut auth_config = to_auth_provider_config(oidc_config);
    let vault_config = config.vault.clone();
    let audit_config = config.audit.clone();
    let issuer_url = oidc_config.issuer_url.clone();

    let rt = tokio::runtime::Runtime::new().context("creating tokio runtime")?;
    rt.block_on(async {
        // Bind temporary server to get a port
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .context("binding temporary callback server")?;
        let local_addr = listener.local_addr()?;
        let redirect_uri = format!("http://127.0.0.1:{}/callback", local_addr.port());

        // Override redirect_uri with the temporary server's address
        auth_config.redirect_uri = Some(redirect_uri.clone());

        let auth_provider = AuthProvider::from_discovery(&auth_config)
            .await
            .context("OIDC discovery failed")?;

        let vault = Vault::open(&vault_config).context("opening vault")?;

        let audit_logger = if audit_config.enabled {
            let audit_db_path = forculus_config::expand_tilde(&audit_config.db_path);
            AuditLogger::new(Path::new(&audit_db_path)).ok()
        } else {
            None
        };

        // Generate authorization URL
        let scopes: Vec<String> = Vec::new();
        let auth_request = auth_provider.authorization_url(&scopes);

        let pending_store = Arc::new(PendingAuthStore::new());
        pending_store.insert(
            auth_request.csrf_state.secret(),
            PendingAuth {
                pkce_verifier: auth_request.pkce_verifier,
                nonce: auth_request.nonce,
                created_at: Instant::now(),
            },
        );

        let auth_url = auth_request.authorization_url.to_string();

        // Try to open browser
        println!("Opening browser for authentication...");
        if open::that(&auth_url).is_err() {
            println!("Could not open browser. Please visit this URL manually:");
            println!("  {auth_url}");
        }
        println!();
        println!("Waiting for authentication callback (timeout: 2 minutes)...");

        // Wait for callback with timeout
        let auth_provider = Arc::new(auth_provider);
        let vault = Arc::new(parking_lot::Mutex::new(vault));
        let (result_tx, result_rx) = tokio::sync::oneshot::channel::<Result<String>>();
        let result_tx = Arc::new(parking_lot::Mutex::new(Some(result_tx)));

        let shutdown = CancellationToken::new();
        let shutdown_for_server = shutdown.clone();

        let server_state = Arc::new(AuthServerState {
            auth_provider: Arc::clone(&auth_provider),
            vault: Arc::clone(&vault),
            audit_logger: audit_logger.clone(),
            pending: Arc::clone(&pending_store),
            issuer_url: issuer_url.clone(),
        });

        // Spawn temporary callback server
        let result_tx_clone = Arc::clone(&result_tx);
        let shutdown_clone = shutdown.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_for_server.cancelled() => break,
                    accept = listener.accept() => {
                        match accept {
                            Ok((stream, _addr)) => {
                                let server_state = Arc::clone(&server_state);
                                let result_tx = Arc::clone(&result_tx_clone);
                                let shutdown = shutdown_clone.clone();
                                tokio::spawn(async move {
                                    let service = service_fn(move |req| {
                                        let state = Arc::clone(&server_state);
                                        async move { handle_auth_request(req, state).await }
                                    });
                                    let conn = Builder::new().serve_connection(TokioIo::new(stream), service);
                                    if let Err(e) = conn.await {
                                        tracing::debug!(error = %e, "callback connection error");
                                    }
                                    // After serving the callback, signal completion
                                    // We check if there's a session token in the vault
                                    // by checking the pending store is now empty
                                    if let Some(tx) = result_tx.lock().take() {
                                        let _ = tx.send(Ok("done".to_string()));
                                    }
                                    shutdown.cancel();
                                });
                            }
                            Err(e) => tracing::debug!(error = %e, "callback accept error"),
                        }
                    }
                }
            }
        });

        // Wait for result or timeout
        let timeout = tokio::time::timeout(Duration::from_secs(120), result_rx).await;

        shutdown.cancel();

        match timeout {
            Ok(Ok(Ok(_))) => {
                // Session was created successfully
                // The token was already displayed in the HTML callback page
                println!("Authentication successful! Session token was displayed in browser.");
                println!();
                println!("To trust the Forculus CA certificate:");
                println!("  Node.js: export NODE_EXTRA_CA_CERTS=\"$(forculus ca path)\"");
                println!("  Python:  export REQUESTS_CA_BUNDLE=\"$(forculus ca path)\"");
            }
            Ok(Ok(Err(e))) => bail!("Authentication failed: {e}"),
            Ok(Err(_)) => bail!("Authentication callback channel closed unexpectedly"),
            Err(_) => bail!("Authentication timed out after 2 minutes. Please try again."),
        }

        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Shutdown signal (reused from mcp.rs pattern)
// ---------------------------------------------------------------------------

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {}
            _ = sigterm.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_auth_store_insert_and_take() {
        let store = PendingAuthStore::new();
        let verifier = PkceCodeVerifier::new("test-verifier".to_string());
        let nonce = Nonce::new("test-nonce".to_string());

        store.insert(
            "test-state",
            PendingAuth {
                pkce_verifier: verifier,
                nonce,
                created_at: Instant::now(),
            },
        );

        let taken = store.take("test-state");
        assert!(taken.is_some());
        assert_eq!(taken.unwrap().nonce.secret(), "test-nonce");
    }

    #[test]
    fn pending_auth_store_take_removes_entry() {
        let store = PendingAuthStore::new();
        store.insert(
            "state-1",
            PendingAuth {
                pkce_verifier: PkceCodeVerifier::new("v".to_string()),
                nonce: Nonce::new("n".to_string()),
                created_at: Instant::now(),
            },
        );

        assert!(store.take("state-1").is_some());
        assert!(store.take("state-1").is_none()); // Second take returns None
    }

    #[test]
    fn pending_auth_store_expired_returns_none() {
        let store = PendingAuthStore::new();
        store.insert(
            "expired-state",
            PendingAuth {
                pkce_verifier: PkceCodeVerifier::new("v".to_string()),
                nonce: Nonce::new("n".to_string()),
                created_at: Instant::now() - Duration::from_secs(301), // > 5 minutes
            },
        );

        assert!(store.take("expired-state").is_none());
    }

    #[test]
    fn pending_auth_store_missing_state_returns_none() {
        let store = PendingAuthStore::new();
        assert!(store.take("nonexistent").is_none());
    }

    #[test]
    fn callback_html_contains_token() {
        let html = callback_html("bwk_sess_abc123");
        assert!(html.contains("bwk_sess_abc123"));
        assert!(html.contains("Session Created"));
        assert!(html.contains("Copy to Clipboard"));
    }

    #[test]
    fn error_html_contains_message() {
        let html = error_html("something went wrong");
        assert!(html.contains("something went wrong"));
        assert!(html.contains("Authentication Error"));
    }

    #[test]
    fn config_mapping_env_source() {
        let oidc = AuthOidcConfig {
            enabled: true,
            issuer_url: "https://example.com".to_string(),
            client_id: "test-id".to_string(),
            client_secret_source: SecretSource::Env,
            client_secret_path: None,
            client_secret_env: "MY_SECRET_VAR".to_string(),
            redirect_uri: Some("http://localhost:9082/callback".to_string()),
            scopes: vec!["openid".to_string()],
            group_claim: "groups".to_string(),
            group_mapping: HashMap::new(),
            default_session_ttl: 3600,
            service_accounts: forculus_config::ServiceAccountConfig { enabled: false },
        };

        let config = to_auth_provider_config(&oidc);
        assert_eq!(config.issuer_url, "https://example.com");
        assert_eq!(config.client_id, "test-id");
        assert!(matches!(
            config.client_secret_source,
            ClientSecretSource::Env(ref v) if v == "MY_SECRET_VAR"
        ));
        assert_eq!(
            config.redirect_uri.as_deref(),
            Some("http://localhost:9082/callback")
        );
    }

    #[test]
    fn config_mapping_file_source() {
        let oidc = AuthOidcConfig {
            enabled: true,
            issuer_url: "https://example.com".to_string(),
            client_id: "test-id".to_string(),
            client_secret_source: SecretSource::File,
            client_secret_path: Some("/path/to/secret".to_string()),
            client_secret_env: "UNUSED".to_string(),
            redirect_uri: None,
            scopes: vec!["openid".to_string(), "profile".to_string()],
            group_claim: "groups".to_string(),
            group_mapping: HashMap::new(),
            default_session_ttl: 7200,
            service_accounts: forculus_config::ServiceAccountConfig { enabled: true },
        };

        let config = to_auth_provider_config(&oidc);
        assert!(matches!(
            config.client_secret_source,
            ClientSecretSource::File(ref p) if p == "/path/to/secret"
        ));
        assert!(config.service_accounts_enabled);
        assert_eq!(config.default_session_ttl, Duration::from_secs(7200));
    }

    #[test]
    fn config_mapping_vault_source() {
        let oidc = AuthOidcConfig {
            enabled: true,
            issuer_url: "https://example.com".to_string(),
            client_id: "test-id".to_string(),
            client_secret_source: SecretSource::Vault,
            client_secret_path: None,
            client_secret_env: "UNUSED".to_string(),
            redirect_uri: None,
            scopes: vec!["openid".to_string()],
            group_claim: "groups".to_string(),
            group_mapping: HashMap::new(),
            default_session_ttl: 3600,
            service_accounts: forculus_config::ServiceAccountConfig { enabled: false },
        };

        let config = to_auth_provider_config(&oidc);
        assert!(matches!(
            config.client_secret_source,
            ClientSecretSource::Vault
        ));
    }

    #[test]
    fn config_mapping_with_group_mapping() {
        let mut group_mapping = HashMap::new();
        group_mapping.insert(
            "engineering".to_string(),
            forculus_config::GroupMappingEntry {
                team: Some("eng".to_string()),
                environment: Some("staging".to_string()),
                agent_type: None,
                labels: HashMap::new(),
            },
        );

        let oidc = AuthOidcConfig {
            enabled: true,
            issuer_url: "https://example.com".to_string(),
            client_id: "test-id".to_string(),
            client_secret_source: SecretSource::Env,
            client_secret_path: None,
            client_secret_env: "SECRET".to_string(),
            redirect_uri: None,
            scopes: vec!["openid".to_string()],
            group_claim: "groups".to_string(),
            group_mapping,
            default_session_ttl: 3600,
            service_accounts: forculus_config::ServiceAccountConfig { enabled: false },
        };

        let config = to_auth_provider_config(&oidc);
        assert_eq!(config.group_mapping.len(), 1);
        let entry = &config.group_mapping["engineering"];
        assert_eq!(entry.team.as_deref(), Some("eng"));
        assert_eq!(entry.environment.as_deref(), Some("staging"));
    }
}
