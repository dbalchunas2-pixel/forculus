//! Plain HTTP forward proxy — handles non-CONNECT requests where the client
//! sends an absolute URI (e.g. `GET http://example.com/path`).

use std::net::SocketAddr;
use std::time::Instant;

use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use uuid::Uuid;

use forculus_audit::event::{
    AuditEvent, Channel, EventOutcome, EventType, RequestInfo, SessionInfo,
};

use crate::context::ProxyRequestContext;
use crate::error_response;
use crate::logging::RequestLog;

/// Boxed body type used for proxy responses.
pub type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

/// Forward a plain HTTP request to the target server and return the response.
pub async fn forward_request(
    req: Request<Incoming>,
    _client_addr: SocketAddr,
    ctx: ProxyRequestContext,
) -> Result<Response<BoxBody>, hyper::Error> {
    let start = Instant::now();
    let request_id = Uuid::new_v4();

    let method = req.method().clone();
    let uri = req.uri().clone();
    let host = uri.host().unwrap_or("unknown").to_string();
    let url = uri.to_string();

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

    // Resolve tool/action via tool mapper if present, else fallback to host/method+path.
    let (resolved_tool, resolved_action) = if let Some(mapper) = &ctx.tool_mapper {
        match mapper.resolve(&url, method.as_str()) {
            Some(resolved) => (resolved.tool, resolved.action),
            None => {
                let path = uri
                    .path_and_query()
                    .map(|pq| pq.to_string())
                    .unwrap_or_else(|| "/".to_string());
                (host.clone(), format!("{} {}", method, path))
            }
        }
    } else {
        let path = uri
            .path_and_query()
            .map(|pq| pq.to_string())
            .unwrap_or_else(|| "/".to_string());
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
                "rate limit denied HTTP request"
            );
            // Emit audit event for rate-limited request.
            if let Some(ref logger) = ctx.audit_logger {
                let mut builder = AuditEvent::builder(EventType::RateLimited, Channel::HttpProxy)
                    .outcome(EventOutcome::Denied)
                    .request(RequestInfo {
                        tool: resolved_tool.clone(),
                        action: resolved_action.clone(),
                        resource: None,
                        target: uri.to_string(),
                    })
                    .error(forculus_audit::event::ErrorInfo {
                        category: "rate_limit".to_string(),
                        message: format!(
                            "rule={} dimension={}",
                            denial.rule_name, denial.dimension
                        ),
                    })
                    .duration_us(start.elapsed().as_micros() as u64);
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
                    "policy denied HTTP request"
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
        match vault_guard.resolve_credential(&host, session) {
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

    // Capture content type before consuming the request.
    let req_content_type = req
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    // Collect the request body so we can measure its size.
    let (parts, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_e) => {
            return Ok(error_response::bad_request("failed to read request body"));
        }
    };
    let request_bytes = body_bytes.len() as u64;

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
                "Content inspection blocked HTTP request"
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

    // Tier 2: HTTP callout analyzers (only if Tier 1 didn't block).
    if let Some(ref pipeline) = ctx.http_analyzers {
        let tier2_findings = pipeline
            .analyze(
                "outbound",
                &body_bytes,
                Some(&resolved_tool),
                Some(&resolved_action),
                req_content_type.as_deref(),
                session.as_ref().map(|s| s.id.as_str()),
                session.as_ref().map(|s| s.operator.as_str()),
            )
            .await;

        if !tier2_findings.is_empty() {
            let has_block = tier2_findings
                .iter()
                .any(|f| f.action == forculus_inspect::FindingAction::Block);
            if has_block {
                tracing::warn!(
                    host = %host,
                    findings = tier2_findings.len(),
                    "Tier 2 HTTP analyzer blocked request"
                );
                return Ok(error_response::content_blocked(
                    "Request blocked by HTTP callout analyzer",
                ));
            }
            // Merge Tier 2 findings into inspection info.
            let existing_count = inspection_info
                .as_ref()
                .map(|ii| ii.finding_count)
                .unwrap_or(0);
            inspection_info = Some(forculus_audit::event::InspectionInfo {
                finding_count: existing_count + tier2_findings.len() as u64,
                action_taken: "logged".to_string(),
                max_severity: inspection_info
                    .as_ref()
                    .and_then(|ii| ii.max_severity.clone()),
            });
        }
    }

    // Build the outbound request, stripping hop-by-hop and Forculus-internal headers.
    let mut builder = Request::builder().method(parts.method).uri(&uri);
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
    let outbound = match builder.body(
        Full::new(body_bytes)
            .map_err(|never| match never {})
            .boxed(),
    ) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "failed to build outbound request");
            return Ok(error_response::internal_error("internal error"));
        }
    };

    // Send via a pooled hyper client.
    let client: Client<_, BoxBody> = Client::builder(TokioExecutor::new()).build_http();

    let result = client.request(outbound).await;
    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

    // Build audit session info if available.
    let audit_session = session.as_ref().map(|s| SessionInfo {
        session_id: s.id.clone(),
        operator: s.operator.clone(),
        team: s.team.clone(),
        project: s.project.clone(),
        environment: s.environment.clone(),
        agent_type: s.agent_type.clone(),
    });

    match result {
        Ok(resp) => {
            let status = resp.status().as_u16();

            // Collect the response body.
            let (mut resp_parts, resp_body) = resp.into_parts();
            let resp_bytes = match resp_body.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_e) => Bytes::new(),
            };

            // Inspect response body if scanner is configured and response inspection is enabled.
            let resp_bytes = if let Some(scanner) = ctx
                .content_scanner
                .as_ref()
                .filter(|s| s.inspect_responses())
            {
                // Only inspect if response is within max_content_size.
                if resp_bytes.len() <= scanner.max_content_size() {
                    let inspection = scanner.scan_bytes(&resp_bytes);
                    if inspection.should_block {
                        tracing::warn!(
                            host = %host,
                            findings = inspection.findings.len(),
                            "blocking upstream response due to dangerous content"
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
                            "redacted upstream response before returning to agent"
                        );
                        inspection_info = Some(forculus_audit::event::InspectionInfo {
                            finding_count: inspection.findings.len() as u64,
                            action_taken: "redacted".to_string(),
                            max_severity: inspection
                                .max_severity
                                .map(|s| format!("{:?}", s).to_lowercase()),
                        });
                        let redacted_bytes = Bytes::from(redacted.into_bytes());
                        // Update Content-Length to match redacted body.
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

            let response_bytes = resp_bytes.len() as u64;

            RequestLog {
                id: request_id,
                timestamp: Utc::now(),
                method: method.to_string(),
                url,
                host: host.clone(),
                status,
                latency_ms,
                request_bytes,
                response_bytes,
                tls: false,
                error: None,
            }
            .emit();

            // Record cost if tracker is configured.
            if let Some(tracker) = &ctx.cost_tracker {
                if let Some(ref s) = session {
                    let cost = tracker.estimate_cost(&resolved_tool);
                    if let Err(e) = tracker.record_cost(&s.operator, cost) {
                        tracing::warn!(operator = %s.operator, error = %e, "budget exceeded");
                        // Emit audit event for budget exceeded.
                        if let Some(ref logger) = ctx.audit_logger {
                            let mut builder =
                                AuditEvent::builder(EventType::BudgetExceeded, Channel::HttpProxy)
                                    .outcome(EventOutcome::Denied)
                                    .request(RequestInfo {
                                        tool: resolved_tool.clone(),
                                        action: resolved_action.clone(),
                                        resource: None,
                                        target: uri.to_string(),
                                    })
                                    .error(forculus_audit::event::ErrorInfo {
                                        category: "budget".to_string(),
                                        message: e.to_string(),
                                    })
                                    .duration_us(start.elapsed().as_micros() as u64);
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
                    AuditEvent::builder(EventType::RequestProcessed, Channel::HttpProxy)
                        .outcome(EventOutcome::Success)
                        .request(RequestInfo {
                            tool: resolved_tool.clone(),
                            action: resolved_action.clone(),
                            resource: None,
                            target: uri.to_string(),
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
            RequestLog {
                id: request_id,
                timestamp: Utc::now(),
                method: method.to_string(),
                url,
                host: host.clone(),
                status: 502,
                latency_ms,
                request_bytes,
                response_bytes: 0,
                tls: false,
                error: Some(e.to_string()),
            }
            .emit();

            // Emit audit event for failed request.
            if let Some(ref logger) = ctx.audit_logger {
                let mut builder =
                    AuditEvent::builder(EventType::RequestProcessed, Channel::HttpProxy)
                        .outcome(EventOutcome::Failed)
                        .request(RequestInfo {
                            tool: resolved_tool.clone(),
                            action: resolved_action.clone(),
                            resource: None,
                            target: uri.to_string(),
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
/// forwarding to upstream servers. These headers are used for governance
/// between the agent and Forculus and must never leak to the upstream.
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
