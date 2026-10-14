//! Request routing: decides whether an incoming request is a health check,
//! an HTTP forward-proxy request, or an HTTPS CONNECT tunnel.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Method, Request, Response};

use crate::context::ProxyRequestContext;
use crate::error_response;
use crate::forward::{self, BoxBody};
use crate::tls::TlsState;
use crate::tunnel;

/// Handle a single inbound HTTP request.
///
/// Routing:
/// - `CONNECT` → HTTPS MITM tunnel
/// - Absolute URI → HTTP forward proxy
/// - Relative path `/healthz` → health check
/// - Everything else → 400 Bad Request
pub async fn handle_request(
    req: Request<Incoming>,
    client_addr: SocketAddr,
    tls_state: Arc<TlsState>,
    start_time: Instant,
    ctx: ProxyRequestContext,
) -> Result<Response<BoxBody>, hyper::Error> {
    // CONNECT method → HTTPS tunnel with TLS MITM
    if req.method() == Method::CONNECT {
        return tunnel::handle_connect(req, client_addr, tls_state, ctx).await;
    }

    // Check for internal routes (relative path, no scheme/authority).
    let is_absolute = req.uri().scheme().is_some();
    if !is_absolute {
        return Ok(handle_internal(req, start_time));
    }

    // Absolute URI → forward proxy
    forward::forward_request(req, client_addr, ctx).await
}

/// Handle requests aimed at Forculus itself (health check, etc.).
fn handle_internal(req: Request<Incoming>, start_time: Instant) -> Response<BoxBody> {
    match req.uri().path() {
        "/healthz" => health_check(start_time),
        _ => error_response::bad_request("not a proxy request (missing absolute URI)"),
    }
}

/// Return `200 OK` with JSON status information.
fn health_check(start_time: Instant) -> Response<BoxBody> {
    let uptime = start_time.elapsed().as_secs();
    let body = serde_json::json!({
        "status": "ok",
        "version": forculus_common::VERSION,
        "uptime_seconds": uptime,
    });
    Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(
            Full::new(Bytes::from(body.to_string()))
                .map_err(|never| match never {})
                .boxed(),
        )
        .expect("valid health response")
}
