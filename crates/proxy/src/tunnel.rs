//! HTTPS CONNECT tunnelling with TLS man-in-the-middle.
//!
//! When a client sends `CONNECT host:port`, Forculus:
//! 1. Responds with `200 Connection Established`
//! 2. Upgrades the connection to get the raw TCP stream
//! 3. Performs a TLS handshake with the client (presenting a leaf cert for
//!    the target hostname, signed by Forculus's CA)
//! 4. Connects to the real server over TLS using system root certs
//! 5. Reads decrypted HTTP from the client, forwards to the server, and
//!    returns the response — logging every request

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

use forculus_audit::event::{
    AuditEvent, Channel, EventOutcome, EventType, RequestInfo, SessionInfo,
};

use crate::context::ProxyRequestContext;
use crate::error_response;
use crate::forward::BoxBody;
use crate::logging::RequestLog;
use crate::pincheck;
use crate::tls::TlsState;

/// Handle a CONNECT request: upgrade the connection, perform TLS MITM, and
/// proxy the inner HTTP traffic.
pub async fn handle_connect(
    req: Request<Incoming>,
    _client_addr: SocketAddr,
    tls_state: Arc<TlsState>,
    ctx: ProxyRequestContext,
) -> Result<Response<BoxBody>, hyper::Error> {
    // Extract the target host:port from the CONNECT URI.
    let target_authority = match req.uri().authority() {
        Some(auth) => auth.to_string(),
        None => {
            return Ok(error_response::bad_request("CONNECT missing authority"));
        }
    };

    let target_host = req.uri().host().unwrap_or("unknown").to_string();
    let target_port = req.uri().port_u16().unwrap_or(443);

    // Check if this host matches a TLS passthrough pattern.
    if let Some(ref patterns) = ctx.tls_passthrough {
        let matches = patterns
            .iter()
            .any(|p| p.matches(&target_authority) || p.matches(&target_host));
        if matches {
            tracing::info!(
                host = %target_host,
                authority = %target_authority,
                "TLS passthrough — bypassing MITM"
            );

            // Emit audit event for passthrough connection.
            if let Some(ref logger) = ctx.audit_logger {
                let builder = AuditEvent::builder(EventType::TlsPassthrough, Channel::HttpsProxy)
                    .outcome(EventOutcome::Success)
                    .request(RequestInfo {
                        tool: target_host.clone(),
                        action: format!("CONNECT {}", target_authority),
                        resource: None,
                        target: target_authority.clone(),
                    });
                logger.log(builder.build());
            }

            // Spawn a task that upgrades and pipes bytes.
            let target_host_pt = target_host.clone();
            tokio::spawn(async move {
                let upgraded = match hyper::upgrade::on(req).await {
                    Ok(u) => u,
                    Err(e) => {
                        tracing::error!(error = %e, "passthrough upgrade failed");
                        return;
                    }
                };

                let upstream =
                    match tokio::net::TcpStream::connect((target_host_pt.as_str(), target_port))
                        .await
                    {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::warn!(
                                host = %target_host_pt,
                                error = %e,
                                "passthrough upstream connect failed"
                            );
                            return;
                        }
                    };

                let mut client = TokioIo::new(upgraded);
                let mut server = upstream;

                match tokio::io::copy_bidirectional(&mut client, &mut server).await {
                    Ok((c2s, s2c)) => {
                        tracing::debug!(
                            host = %target_host_pt,
                            client_to_server = c2s,
                            server_to_client = s2c,
                            "passthrough tunnel closed"
                        );
                    }
                    Err(e) => {
                        tracing::debug!(
                            host = %target_host_pt,
                            error = %e,
                            "passthrough tunnel error"
                        );
                    }
                }
            });

            // Return 200 to establish the tunnel.
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .body(
                    Full::new(Bytes::new())
                        .map_err(|never| match never {})
                        .boxed(),
                )
                .expect("valid CONNECT passthrough response"));
        }
    }

    // Evaluate policy on the CONNECT target if engine is configured.
    if let Some(engine) = &ctx.policy_engine {
        use forculus_policy::context::RequestContext;
        use forculus_policy::verdict::Verdict;

        let pctx = RequestContext::new(&target_host, format!("CONNECT {}", target_authority));
        let eval = engine.evaluate(&pctx);

        match eval.verdict {
            Verdict::Allow | Verdict::Transform => {}
            Verdict::Deny | Verdict::Escalate => {
                tracing::warn!(
                    host = %target_host,
                    verdict = ?eval.verdict,
                    reason = %eval.reason,
                    "policy denied CONNECT"
                );
                return Ok(error_response::policy_denied(
                    &eval,
                    &target_host,
                    &format!("CONNECT {}", target_authority),
                ));
            }
        }
    }

    // Spawn the MITM task after the upgrade completes.
    let tls_state_clone = Arc::clone(&tls_state);
    let target_host_clone = target_host.clone();
    let target_authority_clone = target_authority.clone();

    tokio::spawn(async move {
        // Wait for the HTTP upgrade to complete.
        let upgraded = match hyper::upgrade::on(req).await {
            Ok(u) => u,
            Err(e) => {
                tracing::error!(error = %e, "upgrade failed");
                return;
            }
        };

        if let Err(e) = mitm_tunnel(
            upgraded,
            &target_host_clone,
            target_port,
            &target_authority_clone,
            tls_state_clone,
            ctx,
        )
        .await
        {
            tracing::debug!(error = %e, host = %target_host_clone, "tunnel error");
        }
    });

    // Respond with 200 to tell the client the tunnel is established.
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(
            Full::new(Bytes::new())
                .map_err(|never| match never {})
                .boxed(),
        )
        .expect("valid CONNECT response"))
}

/// Perform the TLS MITM: accept TLS from the client, connect TLS to the
/// server, and proxy decrypted HTTP between them.
async fn mitm_tunnel(
    upgraded: hyper::upgrade::Upgraded,
    target_host: &str,
    target_port: u16,
    _target_authority: &str,
    tls_state: Arc<TlsState>,
    ctx: ProxyRequestContext,
) -> forculus_common::Result<()> {
    // --- Client-side TLS (we are the "server" to the client) ---
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::clone(&tls_state) as Arc<dyn rustls::server::ResolvesServerCert>);

    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let client_tls = acceptor
        .accept(TokioIo::new(upgraded))
        .await
        .map_err(|e| forculus_common::ForculusError::Tls(format!("client TLS handshake: {e}")))?;

    // --- Server-side TLS (we are the "client" to the real server) ---
    let server_name = rustls::pki_types::ServerName::try_from(target_host.to_string())
        .map_err(|e| forculus_common::ForculusError::Tls(format!("invalid server name: {e}")))?;

    let tcp = tokio::net::TcpStream::connect((target_host, target_port))
        .await
        .map_err(|e| {
            forculus_common::ForculusError::Proxy(format!(
                "connect to {target_host}:{target_port}: {e}"
            ))
        })?;

    let _server_tls = tls_state
        .server_connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| forculus_common::ForculusError::Tls(format!("server TLS handshake: {e}")))?;

    // Set up a hyper HTTP/1 server on the client side to read decrypted
    // requests, and use a hyper client to forward them over the server TLS
    // connection.
    let target_host_owned = target_host.to_string();
    let target_port_owned = target_port;

    let service = service_fn(move |req: Request<Incoming>| {
        let host = target_host_owned.clone();
        let port = target_port_owned;
        let connector = tls_state.server_connector.clone();
        let ctx = ctx.clone();
        async move { forward_tls_request(req, &host, port, connector, ctx).await }
    });

    let conn = http1::Builder::new()
        .preserve_header_case(true)
        .serve_connection(TokioIo::new(client_tls), service)
        .with_upgrades();

    conn.await
        .map_err(|e| forculus_common::ForculusError::Proxy(format!("MITM connection: {e}")))?;

    Ok(())
}

/// Forward a single decrypted HTTP request to the real server over a fresh
/// TLS connection.
async fn forward_tls_request(
    req: Request<Incoming>,
    target_host: &str,
    target_port: u16,
    connector: TlsConnector,
    ctx: ProxyRequestContext,
) -> Result<Response<BoxBody>, hyper::Error> {
    let start = Instant::now();
    let request_id = Uuid::new_v4();

    let method = req.method().clone();
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.to_string())
        .unwrap_or_else(|| "/".to_string());
    let url = format!("https://{target_host}{path}");
    let host = target_host.to_string();

    // Validate session from X-Forculus-Session header if vault is configured.
    let session = if let Some(ref vault) = ctx.vault {
        let vault_guard = vault.lock();
        let token = req
            .headers()
            .get("x-forculus-session")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        match token {
            Some(t) => match vault_guard.validate_session(&t) {
                Ok(Some(s)) => Some(s),
                Ok(None) => {
                    return Ok(error_response::session_invalid());
                }
                Err(e) => {
                    tracing::error!(error = %e, "session validation error");
                    return Ok(error_response::internal_error("Session validation error"));
                }
            },
            None => {
                if vault_guard.require_sessions() {
                    return Ok(error_response::session_required());
                }
                None
            }
        }
    } else {
        None
    };

    // Resolve tool/action via tool mapper if present.
    let (resolved_tool, resolved_action) = if let Some(mapper) = &ctx.tool_mapper {
        match mapper.resolve(&url, method.as_str()) {
            Some(resolved) => (resolved.tool, resolved.action),
            None => (host.clone(), format!("{} {}", method, path)),
        }
    } else {
        (host.clone(), format!("{} {}", method, path))
    };

    // Check rate limit if limiter is configured.
    if let Some(limiter) = &ctx.rate_limiter {
        let session_id = session.as_ref().map(|s| s.id.as_str());
        let operator = session.as_ref().map(|s| s.operator.as_str());
        if let Err(denial) = limiter.check_rate_limit(session_id, operator, &resolved_tool) {
            tracing::warn!(
                rule = %denial.rule_name,
                dimension = %denial.dimension,
                tool = %resolved_tool,
                "rate limit denied HTTPS request"
            );
            // Emit audit event for rate-limited request.
            if let Some(ref logger) = ctx.audit_logger {
                let mut builder = AuditEvent::builder(EventType::RateLimited, Channel::HttpsProxy)
                    .outcome(EventOutcome::Denied)
                    .request(RequestInfo {
                        tool: resolved_tool.clone(),
                        action: resolved_action.clone(),
                        resource: None,
                        target: url.clone(),
                    })
                    .error(forculus_audit::event::ErrorInfo {
                        category: "rate_limit".to_string(),
                        message: format!(
                            "rule={} dimension={}",
                            denial.rule_name, denial.dimension
                        ),
                    });
                if let Some(ref s) = session {
                    builder = builder.session(SessionInfo {
                        session_id: s.id.clone(),
                        operator: s.operator.clone(),
                        team: s.team.clone(),
                        project: s.project.clone(),
                        environment: s.environment.clone(),
                        agent_type: s.agent_type.clone(),
                    });
                }
                logger.log(builder.build());
            }
            return Ok(error_response::rate_limited(
                &denial.rule_name,
                denial.retry_after_secs,
            ));
        }
    }

    // Evaluate policy if engine is configured.
    if let Some(engine) = &ctx.policy_engine {
        use forculus_policy::context::RequestContext;
        use forculus_policy::verdict::Verdict;

        let mut pctx = RequestContext::new(&resolved_tool, &resolved_action);
        if let Some(ref s) = session {
            pctx = pctx.with_operator(&s.operator);
            if let Some(ref team) = s.team {
                pctx = pctx.with_team(team);
            }
            if let Some(ref project) = s.project {
                pctx = pctx.with_project(project);
            }
            if let Some(ref env) = s.environment {
                pctx = pctx.with_environment(env);
            }
            if let Some(ref agent) = s.agent_type {
                pctx = pctx.with_agent_type(agent);
            }
        }
        let eval = engine.evaluate(&pctx);

        match eval.verdict {
            Verdict::Allow | Verdict::Transform => {}
            Verdict::Deny | Verdict::Escalate => {
                tracing::warn!(
                    host = %host,
                    method = %method,
                    verdict = ?eval.verdict,
                    reason = %eval.reason,
                    "policy denied HTTPS request"
                );
                return Ok(error_response::policy_denied(
                    &eval,
                    &resolved_tool,
                    &resolved_action,
                ));
            }
        }
    }

    // Resolve credential injection if vault + session are available.
    let injection = if let (Some(vault), Some(session)) = (&ctx.vault, &session) {
        let vault_guard = vault.lock();
        match vault_guard.resolve_credential(target_host, session) {
            Ok(Some(cred)) => Some(forculus_vault::injection::http_injection(&cred)),
            Ok(None) => None,
            Err(e) => {
                tracing::warn!(error = %e, "credential resolution failed");
                None
            }
        }
    } else {
        None
    };

    // Collect request body.
    let (parts, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_e) => {
            return Ok(error_response::bad_request("failed to read request body"));
        }
    };
    let request_bytes = body_bytes.len() as u64;

    // F3: detect MCP tools/list requests before body_bytes is consumed.
    let mcp_tools_list = ctx.pin_store.is_some() && pincheck::is_tools_list_request(&body_bytes);
    let mcp_req_id: Option<serde_json::Value> = if mcp_tools_list {
        pincheck::request_id(&body_bytes)
    } else {
        None
    };

    // Inspect request body if scanner is configured and request inspection is enabled.
    let mut inspection_info: Option<forculus_audit::event::InspectionInfo> = None;
    let body_bytes = if let Some(scanner) = ctx
        .content_scanner
        .as_ref()
        .filter(|s| s.inspect_requests())
    {
        let result = scanner.scan_bytes(&body_bytes);
        if result.should_block {
            tracing::warn!(
                host = %host,
                findings = result.findings.len(),
                "Content inspection blocked HTTPS request"
            );
            return Ok(error_response::content_blocked(
                "Request blocked by content inspection",
            ));
        }
        if result.should_redact {
            let body_str = std::str::from_utf8(&body_bytes).unwrap_or_default();
            let redacted = forculus_inspect::redact_text(body_str, &result.findings);
            tracing::info!(
                finding_count = result.findings.len(),
                "redacted request body before forwarding"
            );
            inspection_info = Some(forculus_audit::event::InspectionInfo {
                finding_count: result.findings.len() as u64,
                action_taken: "redacted".to_string(),
                max_severity: result
                    .max_severity
                    .map(|s| format!("{:?}", s).to_lowercase()),
            });
            Bytes::from(redacted.into_bytes())
        } else if !result.findings.is_empty() {
            inspection_info = Some(forculus_audit::event::InspectionInfo {
                finding_count: result.findings.len() as u64,
                action_taken: "logged".to_string(),
                max_severity: result
                    .max_severity
                    .map(|s| format!("{:?}", s).to_lowercase()),
            });
            body_bytes
        } else {
            body_bytes
        }
    } else {
        body_bytes
    };

    // Connect to the real server.
    let tcp = match tokio::net::TcpStream::connect((target_host, target_port)).await {
        Ok(t) => t,
        Err(e) => {
            log_request(RequestLog {
                id: request_id,
                timestamp: Utc::now(),
                method: method.to_string(),
                url: url.clone(),
                host: host.clone(),
                status: 502,
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                request_bytes,
                response_bytes: 0,
                tls: true,
                error: Some(e.to_string()),
            });
            return Ok(error_response::upstream_error(&format!(
                "connect failed: {e}"
            )));
        }
    };

    let server_name = match rustls::pki_types::ServerName::try_from(target_host.to_string()) {
        Ok(sn) => sn,
        Err(e) => {
            log_request(RequestLog {
                id: request_id,
                timestamp: Utc::now(),
                method: method.to_string(),
                url: url.clone(),
                host: host.clone(),
                status: 502,
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                request_bytes,
                response_bytes: 0,
                tls: true,
                error: Some(e.to_string()),
            });
            return Ok(error_response::upstream_error(&format!(
                "invalid server name: {e}"
            )));
        }
    };

    let tls_stream = match connector.connect(server_name, tcp).await {
        Ok(s) => s,
        Err(e) => {
            log_request(RequestLog {
                id: request_id,
                timestamp: Utc::now(),
                method: method.to_string(),
                url: url.clone(),
                host: host.clone(),
                status: 502,
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                request_bytes,
                response_bytes: 0,
                tls: true,
                error: Some(e.to_string()),
            });
            return Ok(error_response::upstream_error(&format!(
                "TLS connect failed: {e}"
            )));
        }
    };

    // Use hyper to send the HTTP request over the TLS stream.
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls_stream)).await?;

    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!(error = %e, "outbound connection closed");
        }
    });

    // Build the outbound request.
    let mut builder = Request::builder().method(parts.method).uri(&path);
    if let Some(headers) = builder.headers_mut() {
        // Determine which headers to strip (injection strips).
        let strip_set: std::collections::HashSet<String> = injection
            .as_ref()
            .map(|inj| inj.strip_headers.iter().cloned().collect())
            .unwrap_or_default();

        for (name, value) in &parts.headers {
            if !is_hop_by_hop(name.as_str())
                && !is_forculus_internal(name.as_str())
                && !strip_set.contains(&name.as_str().to_lowercase())
                && name.as_str() != "content-length"
            {
                headers.insert(name.clone(), value.clone());
            }
        }
        headers.insert(
            "host",
            target_host
                .parse()
                .unwrap_or_else(|_| "unknown".parse().unwrap()),
        );

        // Inject credential headers.
        if let Some(ref inj) = injection {
            use secrecy::ExposeSecret;
            for (header_name, header_value) in &inj.headers {
                if let Ok(hv) = header_value
                    .expose_secret()
                    .parse::<hyper::header::HeaderValue>()
                {
                    if let Ok(hn) = header_name.parse::<hyper::header::HeaderName>() {
                        headers.insert(hn, hv);
                    }
                }
            }
        }
    }

    let outbound: Request<BoxBody> = match builder.body(
        Full::new(body_bytes)
            .map_err(|never| match never {})
            .boxed(),
    ) {
        Ok(r) => r,
        Err(e) => {
            log_request(RequestLog {
                id: request_id,
                timestamp: Utc::now(),
                method: method.to_string(),
                url: url.clone(),
                host: host.clone(),
                status: 500,
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                request_bytes,
                response_bytes: 0,
                tls: true,
                error: Some(e.to_string()),
            });
            return Ok(error_response::internal_error("internal error"));
        }
    };

    // Build audit session info if available.
    let audit_session = session.as_ref().map(|s| SessionInfo {
        session_id: s.id.clone(),
        operator: s.operator.clone(),
        team: s.team.clone(),
        project: s.project.clone(),
        environment: s.environment.clone(),
        agent_type: s.agent_type.clone(),
    });

    match sender.send_request(outbound).await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let (mut resp_parts, resp_body) = resp.into_parts();
            let resp_bytes = match resp_body.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => Bytes::new(),
            };

            // Inspect response body if scanner is configured and response inspection is enabled.
            let resp_bytes = if let Some(scanner) = ctx
                .content_scanner
                .as_ref()
                .filter(|s| s.inspect_responses())
            {
                if resp_bytes.len() <= scanner.max_content_size() {
                    let inspection = scanner.scan_bytes(&resp_bytes);
                    if inspection.should_block {
                        tracing::warn!(
                            host = %host,
                            findings = inspection.findings.len(),
                            "blocking upstream HTTPS response due to dangerous content"
                        );
                        return Ok(error_response::response_blocked(
                            "Response blocked: upstream returned dangerous content",
                        ));
                    }
                    if inspection.should_redact {
                        let body_str = std::str::from_utf8(&resp_bytes).unwrap_or_default();
                        let redacted =
                            forculus_inspect::redact_text(body_str, &inspection.findings);
                        tracing::info!(
                            finding_count = inspection.findings.len(),
                            "redacted upstream HTTPS response before returning to agent"
                        );
                        inspection_info = Some(forculus_audit::event::InspectionInfo {
                            finding_count: inspection.findings.len() as u64,
                            action_taken: "redacted".to_string(),
                            max_severity: inspection
                                .max_severity
                                .map(|s| format!("{:?}", s).to_lowercase()),
                        });
                        let redacted_bytes = Bytes::from(redacted.into_bytes());
                        resp_parts.headers.insert(
                            hyper::header::CONTENT_LENGTH,
                            hyper::header::HeaderValue::from(redacted_bytes.len()),
                        );
                        redacted_bytes
                    } else if !inspection.findings.is_empty() {
                        inspection_info = Some(forculus_audit::event::InspectionInfo {
                            finding_count: inspection.findings.len() as u64,
                            action_taken: "logged".to_string(),
                            max_severity: inspection
                                .max_severity
                                .map(|s| format!("{:?}", s).to_lowercase()),
                        });
                        resp_bytes
                    } else {
                        resp_bytes
                    }
                } else {
                    resp_bytes
                }
            } else {
                resp_bytes
            };

            // F3: verify tool-definition pins on MCP tools/list responses.
            if let (Some(pin_store), true) = (&ctx.pin_store, mcp_tools_list) {
                if let Some(tools) = pincheck::parse_tools_list(&resp_bytes) {
                    if let Err(msg) = pincheck::verify_tools_list(
                        pin_store,
                        forculus_audit::event::Channel::HttpsProxy,
                        &host,
                        &tools,
                        ctx.audit_logger.as_ref(),
                        audit_session.as_ref(),
                        &resolved_tool,
                        &resolved_action,
                        &url,
                        start.elapsed().as_micros() as u64,
                    ) {
                        tracing::warn!(host = %host, %msg, "blocking MCP tools/list response");
                        let err_body =
                            pincheck::pin_violation_error_body(mcp_req_id.as_ref(), &msg);
                        let resp = Response::builder()
                            .status(403)
                            .header("content-type", "application/json")
                            .body(Full::new(err_body).map_err(|never| match never {}).boxed())
                            .expect("valid pin violation response");
                        return Ok(resp);
                    }
                }
            }

            let response_bytes = resp_bytes.len() as u64;

            log_request(RequestLog {
                id: request_id,
                timestamp: Utc::now(),
                method: method.to_string(),
                url: url.clone(),
                host: host.clone(),
                status,
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                request_bytes,
                response_bytes,
                tls: true,
                error: None,
            });

            // Record cost if tracker is configured.
            if let Some(tracker) = &ctx.cost_tracker {
                if let Some(ref s) = session {
                    let cost = tracker.estimate_cost(&resolved_tool);
                    if let Err(e) = tracker.record_cost(&s.operator, cost) {
                        tracing::warn!(operator = %s.operator, error = %e, "budget exceeded");
                        // Emit audit event for budget exceeded.
                        if let Some(ref logger) = ctx.audit_logger {
                            let mut builder =
                                AuditEvent::builder(EventType::BudgetExceeded, Channel::HttpsProxy)
                                    .outcome(EventOutcome::Denied)
                                    .request(RequestInfo {
                                        tool: resolved_tool.clone(),
                                        action: resolved_action.clone(),
                                        resource: None,
                                        target: url.clone(),
                                    })
                                    .error(forculus_audit::event::ErrorInfo {
                                        category: "budget".to_string(),
                                        message: e.to_string(),
                                    });
                            if let Some(ref si) = audit_session {
                                builder = builder.session(si.clone());
                            }
                            logger.log(builder.build());
                        }
                    }
                }
            }

            // Emit audit event.
            if let Some(ref logger) = ctx.audit_logger {
                let mut builder =
                    AuditEvent::builder(EventType::RequestProcessed, Channel::HttpsProxy)
                        .outcome(EventOutcome::Success)
                        .request(RequestInfo {
                            tool: resolved_tool.clone(),
                            action: resolved_action.clone(),
                            resource: None,
                            target: url.clone(),
                        })
                        .duration_us(start.elapsed().as_micros() as u64);
                if let Some(ref si) = audit_session {
                    builder = builder.session(si.clone());
                }
                if let Some(ref ii) = inspection_info {
                    builder = builder.inspection(ii.clone());
                }
                logger.log(builder.build());
            }

            let body = Full::new(resp_bytes)
                .map_err(|never| match never {})
                .boxed();
            Ok(Response::from_parts(resp_parts, body))
        }
        Err(e) => {
            log_request(RequestLog {
                id: request_id,
                timestamp: Utc::now(),
                method: method.to_string(),
                url: url.clone(),
                host: host.clone(),
                status: 502,
                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                request_bytes,
                response_bytes: 0,
                tls: true,
                error: Some(e.to_string()),
            });

            // Emit audit event for failed request.
            if let Some(ref logger) = ctx.audit_logger {
                let mut builder =
                    AuditEvent::builder(EventType::RequestProcessed, Channel::HttpsProxy)
                        .outcome(EventOutcome::Failed)
                        .request(RequestInfo {
                            tool: resolved_tool.clone(),
                            action: resolved_action.clone(),
                            resource: None,
                            target: url.clone(),
                        })
                        .error(forculus_audit::event::ErrorInfo {
                            category: "upstream".to_string(),
                            message: e.to_string(),
                        })
                        .duration_us(start.elapsed().as_micros() as u64);
                if let Some(ref si) = audit_session {
                    builder = builder.session(si.clone());
                }
                logger.log(builder.build());
            }

            Ok(error_response::upstream_error(&format!(
                "upstream error: {e}"
            )))
        }
    }
}

/// Emit a structured log entry for a proxied request.
fn log_request(log: RequestLog) {
    log.emit();
}

/// Returns `true` for headers that must not be forwarded by a proxy.
fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Returns `true` for Forculus-internal headers that must be stripped before
/// forwarding to upstream servers.
fn is_forculus_internal(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "x-forculus-session"
            | "x-forculus-operator"
            | "x-forculus-team"
            | "x-forculus-project"
            | "x-forculus-environment"
    )
}

use tokio_rustls::TlsConnector;
