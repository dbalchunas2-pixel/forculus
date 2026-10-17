//! Shared context for proxy request processing.
//!
//! Bundles all subsystem handles into a single struct that is cloned
//! per-connection, replacing the long parameter lists in handler/forward/tunnel.

use std::sync::Arc;

use forculus_audit::logger::AuditLogger;
use forculus_inspect::scanner::ContentScanner;
use forculus_inspect_http::HttpAnalyzerPipeline;
use forculus_policy::engine::PolicyEngine;
use forculus_policy::glob::GlobPattern;
use forculus_ratelimit::cost::CostTracker;
use forculus_ratelimit::limiter::RateLimiter;
use forculus_vault::store::Vault;

use crate::pins::PinStore;
use crate::toolmap::ToolMapper;

/// Shared context for processing a proxy request.
/// Cloned per-connection (all fields are Arc or cheap Clone).
#[derive(Clone)]
pub struct ProxyRequestContext {
    pub policy_engine: Option<Arc<PolicyEngine>>,
    pub vault: Option<Arc<parking_lot::Mutex<Vault>>>,
    pub audit_logger: Option<AuditLogger>,
    pub content_scanner: Option<Arc<ContentScanner>>,
    pub tool_mapper: Option<Arc<ToolMapper>>,
    pub rate_limiter: Option<Arc<RateLimiter>>,
    pub cost_tracker: Option<Arc<CostTracker>>,
    /// Shared mutable store for tool-definition hash pins.
    pub pin_store: Option<Arc<parking_lot::Mutex<PinStore>>>,
    pub http_analyzers: Option<Arc<HttpAnalyzerPipeline>>,
    /// Compiled host patterns that bypass TLS MITM (plain TCP passthrough).
    pub tls_passthrough: Option<Arc<Vec<GlobPattern>>>,
}

impl ProxyRequestContext {
    pub fn new() -> Self {
        Self {
            policy_engine: None,
            vault: None,
            audit_logger: None,
            content_scanner: None,
            tool_mapper: None,
            rate_limiter: None,
            cost_tracker: None,
            pin_store: None,
            http_analyzers: None,
            tls_passthrough: None,
        }
    }
}

impl Default for ProxyRequestContext {
    fn default() -> Self {
        Self::new()
    }
}
