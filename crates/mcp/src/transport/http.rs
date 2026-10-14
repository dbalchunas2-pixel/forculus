//! HTTP transport for MCP Streamable HTTP (2025-03-26 spec).
//!
//! Handles POST/GET/DELETE on `/mcp`, session management via
//! `Mcp-Session-Id` header, SSE response format, and origin validation.

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode};

use crate::gateway::McpGateway;
use crate::transport::session::SessionManager;
use crate::types::{
    FORCULUS_SESSION_HEADER, JsonRpcMessage, MCP_SESSION_HEADER, PARSE_ERROR, SESSION_TERMINATED,
};

/// Configuration for the HTTP transport layer.
pub struct HttpTransportConfig {
    /// Allowed origins for DNS rebinding protection. Empty = allow all.
    pub allowed_origins: Vec<String>,
}

/// HTTP transport — routes requests to the MCP gateway.
pub struct HttpTransport {
    pub gateway: Arc<McpGateway>,
    pub sessions: Arc<SessionManager>,
    pub config: HttpTransportConfig,
}

impl HttpTransport {
    /// Handle an inbound HTTP request.
    pub async fn handle_request(
        &self,
        req: Request<hyper::body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        // Validate origin first.
        if let Err(resp) = validate_origin(&req, &self.config.allowed_origins) {
            return Ok(resp);
        }

        let path = req.uri().path();
        let method = req.method().clone();

        if path != "/mcp" {
            return Ok(response(StatusCode::NOT_FOUND, "Not Found"));
        }

        let resp = match method {
            hyper::Method::POST => self.handle_post(req).await,
            hyper::Method::GET => self.handle_get(req).await,
            hyper::Method::DELETE => self.handle_delete(req).await,
            _ => response(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed"),
        };

        Ok(resp)
    }

    /// POST /mcp — process a JSON-RPC message.
    async fn handle_post(&self, req: Request<hyper::body::Incoming>) -> Response<Full<Bytes>> {
        let wants_sse = req
            .headers()
            .get(hyper::header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains("text/event-stream"));

        let session_header = req
            .headers()
            .get(MCP_SESSION_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let vault_token = req
            .headers()
            .get(FORCULUS_SESSION_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // Read body.
        let body = match http_body_util::BodyExt::collect(req.into_body()).await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => return response(StatusCode::BAD_REQUEST, "Failed to read body"),
        };

        // Parse JSON-RPC message.
        let msg: JsonRpcMessage = match serde_json::from_slice(&body) {
            Ok(m) => m,
            Err(e) => {
                let err_resp = crate::types::JsonRpcResponse::error(
                    crate::types::RequestId::Number(0),
                    PARSE_ERROR,
                    format!("Invalid JSON: {e}"),
                );
                return json_response(StatusCode::BAD_REQUEST, &err_resp);
            }
        };

        // Check if this is an initialize request (creates a new session).
        let is_initialize = matches!(&msg, JsonRpcMessage::Request(r) if r.method == "initialize");

        if is_initialize {
            // Create a new session.
            let session_id = self.sessions.create_session();

            // If a vault token was provided, associate it with the session.
            if let Some(ref token) = vault_token {
                self.sessions.set_vault_token(&session_id, token.clone());
            }

            let result = self
                .gateway
                .handle_message_with_session_token(msg, vault_token.as_deref())
                .await;

            self.sessions.mark_initialized(&session_id);

            match result {
                Some(response_msg) => {
                    if wants_sse {
                        sse_response_with_session(&response_msg, &session_id)
                    } else {
                        json_response_with_session(StatusCode::OK, &response_msg, &session_id)
                    }
                }
                None => response_with_session(StatusCode::ACCEPTED, "", &session_id),
            }
        } else {
            // Non-initialize request: require session header.
            let session_id = match session_header {
                Some(id) => id,
                None => {
                    return response(StatusCode::BAD_REQUEST, "Missing Mcp-Session-Id header");
                }
            };

            // Validate session exists.
            if self.sessions.get_session(&session_id).is_none() {
                let err_resp = crate::types::JsonRpcResponse::error(
                    crate::types::RequestId::Number(0),
                    SESSION_TERMINATED,
                    "Unknown or expired session".to_string(),
                );
                return json_response(StatusCode::NOT_FOUND, &err_resp);
            }

            // If a vault token was provided on this request, update the session.
            if let Some(ref token) = vault_token {
                self.sessions.set_vault_token(&session_id, token.clone());
            }

            // Resolve vault token: request header > session stored > none.
            let effective_vault_token = vault_token.or_else(|| {
                self.sessions
                    .get_session(&session_id)
                    .and_then(|s| s.vault_token)
            });

            let result = self
                .gateway
                .handle_message_with_session_token(msg, effective_vault_token.as_deref())
                .await;

            match result {
                Some(response_msg) => {
                    if wants_sse {
                        sse_response(&response_msg)
                    } else {
                        json_response(StatusCode::OK, &response_msg)
                    }
                }
                // Notification — no response body.
                None => response(StatusCode::ACCEPTED, ""),
            }
        }
    }

    /// GET /mcp — SSE stream for server-initiated messages (placeholder).
    async fn handle_get(&self, req: Request<hyper::body::Incoming>) -> Response<Full<Bytes>> {
        let session_id = match req
            .headers()
            .get(MCP_SESSION_HEADER)
            .and_then(|v| v.to_str().ok())
        {
            Some(id) => id.to_string(),
            None => {
                return response(StatusCode::BAD_REQUEST, "Missing Mcp-Session-Id header");
            }
        };

        if self.sessions.get_session(&session_id).is_none() {
            return response(StatusCode::NOT_FOUND, "Unknown or expired session");
        }

        // Return a minimal SSE stream with a comment (keep-alive placeholder).
        let body = ": keepalive\n\n";
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/event-stream")
            .header("Cache-Control", "no-cache")
            .body(Full::new(Bytes::from(body)))
            .unwrap()
    }

    /// DELETE /mcp — terminate a session.
    async fn handle_delete(&self, req: Request<hyper::body::Incoming>) -> Response<Full<Bytes>> {
        let session_id = match req
            .headers()
            .get(MCP_SESSION_HEADER)
            .and_then(|v| v.to_str().ok())
        {
            Some(id) => id.to_string(),
            None => {
                return response(StatusCode::BAD_REQUEST, "Missing Mcp-Session-Id header");
            }
        };

        if self.sessions.remove_session(&session_id) {
            response(StatusCode::OK, "Session terminated")
        } else {
            response(StatusCode::NOT_FOUND, "Unknown or expired session")
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Format a JSON string as an SSE event.
pub fn format_sse(json: &str) -> String {
    format!("event: message\ndata: {json}\n\n")
}

/// Validate the Origin header against allowed origins.
#[allow(clippy::result_large_err)]
fn validate_origin<B>(req: &Request<B>, allowed: &[String]) -> Result<(), Response<Full<Bytes>>> {
    if allowed.is_empty() {
        return Ok(());
    }

    let origin = req
        .headers()
        .get(hyper::header::ORIGIN)
        .and_then(|v| v.to_str().ok());

    match origin {
        Some(o) if allowed.iter().any(|a| a == o) => Ok(()),
        Some(_) | None => Err(response(StatusCode::FORBIDDEN, "Origin not allowed")),
    }
}

/// Build a plain text response.
fn response(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

/// Build a plain text response with the Mcp-Session-Id header.
fn response_with_session(
    status: StatusCode,
    body: &str,
    session_id: &str,
) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .header(MCP_SESSION_HEADER, session_id)
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

/// Build a JSON response from a serializable value.
fn json_response<T: serde::Serialize>(status: StatusCode, value: &T) -> Response<Full<Bytes>> {
    let json = serde_json::to_string(value).unwrap_or_default();
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(json)))
        .unwrap()
}

/// Build a JSON response with the Mcp-Session-Id header.
fn json_response_with_session<T: serde::Serialize>(
    status: StatusCode,
    value: &T,
    session_id: &str,
) -> Response<Full<Bytes>> {
    let json = serde_json::to_string(value).unwrap_or_default();
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .header(MCP_SESSION_HEADER, session_id)
        .body(Full::new(Bytes::from(json)))
        .unwrap()
}

/// Build an SSE response from a JSON-RPC message.
fn sse_response<T: serde::Serialize>(value: &T) -> Response<Full<Bytes>> {
    let json = serde_json::to_string(value).unwrap_or_default();
    let sse = format_sse(&json);
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/event-stream")
        .header("Cache-Control", "no-cache")
        .body(Full::new(Bytes::from(sse)))
        .unwrap()
}

/// Build an SSE response with the Mcp-Session-Id header.
fn sse_response_with_session<T: serde::Serialize>(
    value: &T,
    session_id: &str,
) -> Response<Full<Bytes>> {
    let json = serde_json::to_string(value).unwrap_or_default();
    let sse = format_sse(&json);
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/event-stream")
        .header("Cache-Control", "no-cache")
        .header(MCP_SESSION_HEADER, session_id)
        .body(Full::new(Bytes::from(sse)))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::RequestId;

    #[test]
    fn format_sse_produces_correct_output() {
        let json = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
        let sse = format_sse(json);
        assert!(sse.starts_with("event: message\ndata: "));
        assert!(sse.ends_with("\n\n"));
        assert!(sse.contains(json));
    }

    #[test]
    fn validate_origin_allows_all_when_empty() {
        let req = Request::builder()
            .uri("/mcp")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert!(validate_origin(&req, &[]).is_ok());
    }

    #[test]
    fn validate_origin_rejects_wrong_origin() {
        let req = Request::builder()
            .uri("/mcp")
            .header(hyper::header::ORIGIN, "https://evil.com")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let result = validate_origin(&req, &["https://good.com".to_string()]);
        assert!(result.is_err());
        let resp = result.unwrap_err();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn validate_origin_allows_matching_origin() {
        let req = Request::builder()
            .uri("/mcp")
            .header(hyper::header::ORIGIN, "https://good.com")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert!(validate_origin(&req, &["https://good.com".to_string()]).is_ok());
    }

    #[test]
    fn validate_origin_rejects_missing_origin_when_configured() {
        let req = Request::builder()
            .uri("/mcp")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let result = validate_origin(&req, &["https://good.com".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn json_response_sets_content_type() {
        let resp = json_response(StatusCode::OK, &serde_json::json!({"ok": true}));
        assert_eq!(
            resp.headers().get("Content-Type").unwrap(),
            "application/json"
        );
    }

    #[test]
    fn json_response_with_session_sets_header() {
        let resp =
            json_response_with_session(StatusCode::OK, &serde_json::json!({}), "test-session-id");
        assert_eq!(
            resp.headers().get(MCP_SESSION_HEADER).unwrap(),
            "test-session-id"
        );
    }

    #[test]
    fn sse_response_format() {
        let msg =
            crate::types::JsonRpcResponse::success(RequestId::Number(1), serde_json::json!({}));
        let resp = sse_response(&msg);
        assert_eq!(
            resp.headers().get("Content-Type").unwrap(),
            "text/event-stream"
        );
    }

    #[test]
    fn session_manager_lifecycle() {
        let mgr = SessionManager::new();
        let id = mgr.create_session();
        assert_eq!(mgr.session_count(), 1);
        assert!(mgr.get_session(&id).is_some());
        mgr.remove_session(&id);
        assert_eq!(mgr.session_count(), 0);
    }
}
