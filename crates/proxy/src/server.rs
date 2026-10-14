//! TCP listener, per-connection task spawning, and graceful shutdown.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use forculus_audit::logger::AuditLogger;
use forculus_config::ProxyConfig;
use forculus_inspect::scanner::ContentScanner;
use forculus_inspect_http::HttpAnalyzerPipeline;
use forculus_policy::engine::PolicyEngine;
use forculus_policy::glob::GlobPattern;
use forculus_ratelimit::cost::CostTracker;
use forculus_ratelimit::limiter::RateLimiter;
use forculus_vault::store::Vault;

use crate::toolmap::ToolMapper;

use crate::context::ProxyRequestContext;
use crate::handler;
use crate::tls::TlsState;

/// The Forculus forward proxy server.
pub struct ProxyServer {
    config: ProxyConfig,
    tls_state: Arc<TlsState>,
    shutdown: CancellationToken,
    start_time: Instant,
    ctx: ProxyRequestContext,
}

impl ProxyServer {
    /// Create a new proxy server from the given configuration.
    ///
    /// This initialises the TLS subsystem (loading or generating the CA) but
    /// does **not** start listening.
    pub async fn new(config: ProxyConfig) -> forculus_common::Result<Self> {
        let tls_state = Arc::new(TlsState::new(&config.tls.ca_dir)?);
        Ok(Self {
            config,
            tls_state,
            shutdown: CancellationToken::new(),
            start_time: Instant::now(),
            ctx: ProxyRequestContext::new(),
        })
    }

    /// Attach a policy engine for request evaluation.
    pub fn with_policy_engine(mut self, engine: Arc<PolicyEngine>) -> Self {
        self.ctx.policy_engine = Some(engine);
        self
    }

    /// Attach a vault for session validation and credential injection.
    pub fn with_vault(mut self, vault: Arc<parking_lot::Mutex<Vault>>) -> Self {
        self.ctx.vault = Some(vault);
        self
    }

    /// Attach an audit logger for event logging.
    pub fn with_audit_logger(mut self, logger: AuditLogger) -> Self {
        self.ctx.audit_logger = Some(logger);
        self
    }

    /// Attach a content scanner for request/response inspection.
    pub fn with_content_scanner(mut self, scanner: Arc<ContentScanner>) -> Self {
        self.ctx.content_scanner = Some(scanner);
        self
    }

    /// Attach a tool mapper for URL-to-tool resolution.
    pub fn with_tool_mapper(mut self, mapper: Arc<ToolMapper>) -> Self {
        self.ctx.tool_mapper = Some(mapper);
        self
    }

    /// Attach a rate limiter.
    pub fn with_rate_limiter(mut self, limiter: Arc<RateLimiter>) -> Self {
        self.ctx.rate_limiter = Some(limiter);
        self
    }

    /// Attach a cost tracker.
    pub fn with_cost_tracker(mut self, tracker: Arc<CostTracker>) -> Self {
        self.ctx.cost_tracker = Some(tracker);
        self
    }

    /// Attach an HTTP analyzer pipeline for Tier 2 content inspection.
    pub fn with_http_analyzers(mut self, pipeline: Arc<HttpAnalyzerPipeline>) -> Self {
        self.ctx.http_analyzers = Some(pipeline);
        self
    }

    /// Attach TLS passthrough patterns (hosts that bypass TLS MITM).
    pub fn with_tls_passthrough(mut self, patterns: Vec<GlobPattern>) -> Self {
        self.ctx.tls_passthrough = Some(Arc::new(patterns));
        self
    }

    /// Return the CA certificate in DER form (useful for tests).
    pub fn ca_cert_der(&self) -> &rustls::pki_types::CertificateDer<'static> {
        self.tls_state.ca_cert_der()
    }

    /// Return a handle that can be used to trigger graceful shutdown.
    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    /// Start listening and serving connections.
    ///
    /// This method runs until [`ProxyServer::trigger_shutdown`] is called or a
    /// `SIGINT`/`SIGTERM` is received.
    pub async fn run(&self) -> forculus_common::Result<()> {
        let listener = TcpListener::bind(&self.config.listen_address)
            .await
            .map_err(|e| {
                forculus_common::ForculusError::Proxy(format!(
                    "failed to bind {}: {e}",
                    self.config.listen_address
                ))
            })?;

        let local_addr = listener.local_addr()?;
        tracing::info!(
            address = %local_addr,
            version = forculus_common::VERSION,
            "Forculus proxy started"
        );

        self.accept_loop(listener).await;

        tracing::info!("Forculus proxy shut down");
        Ok(())
    }

    /// Like [`run`](Self::run) but binds to the given listener (useful for
    /// tests that pre-bind to port 0).
    pub async fn run_with_listener(&self, listener: TcpListener) -> forculus_common::Result<()> {
        let local_addr = listener.local_addr()?;
        tracing::info!(
            address = %local_addr,
            version = forculus_common::VERSION,
            "Forculus proxy started"
        );

        self.accept_loop(listener).await;

        tracing::info!("Forculus proxy shut down");
        Ok(())
    }

    /// Request a graceful shutdown.
    pub fn trigger_shutdown(&self) {
        self.shutdown.cancel();
    }

    // -----------------------------------------------------------------------
    // Private
    // -----------------------------------------------------------------------

    async fn accept_loop(&self, listener: TcpListener) {
        loop {
            tokio::select! {
                _ = self.shutdown.cancelled() => {
                    break;
                }
                accept = listener.accept() => {
                    match accept {
                        Ok((stream, addr)) => {
                            self.spawn_connection(stream, addr);
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "accept error");
                        }
                    }
                }
            }
        }

        // Grace period for in-flight connections.
        tracing::info!("waiting for in-flight connections (5 s grace period)");
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }

    fn spawn_connection(&self, stream: tokio::net::TcpStream, addr: SocketAddr) {
        let tls_state = Arc::clone(&self.tls_state);
        let start_time = self.start_time;
        let ctx = self.ctx.clone();

        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let tls = Arc::clone(&tls_state);
                let ctx = ctx.clone();
                async move { handler::handle_request(req, addr, tls, start_time, ctx).await }
            });

            let builder = Builder::new(TokioExecutor::new());
            let conn = builder.serve_connection_with_upgrades(TokioIo::new(stream), service);

            if let Err(e) = conn.await {
                tracing::debug!(error = %e, peer = %addr, "connection error");
            }
        });
    }
}
