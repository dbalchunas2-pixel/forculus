//! MCP server — runs the gateway over stdio and HTTP transports.

use std::sync::Arc;

use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use crate::gateway::McpGateway;
use crate::transport::http::{HttpTransport, HttpTransportConfig};
use crate::transport::session::SessionManager;
use crate::transport::stdio::StdioTransport;

/// Run the MCP gateway as a server over stdio.
///
/// Blocks until stdin closes (agent disconnects) or shutdown is triggered.
pub async fn run_stdio_server(
    gateway: Arc<McpGateway>,
    shutdown: CancellationToken,
) -> forculus_common::Result<()> {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    let mut transport = StdioTransport::new(stdin, stdout);

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                tracing::info!("MCP server shutting down");
                break;
            }
            msg = transport.read_message() => {
                match msg {
                    Ok(Some(message)) => {
                        if let Some(response) = gateway.handle_message(message).await {
                            transport.write_message(&response).await?;
                        }
                    }
                    Ok(None) => {
                        tracing::info!("Agent disconnected (EOF)");
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Error reading message");
                    }
                }
            }
        }
    }

    gateway.shutdown().await;
    Ok(())
}

/// Run the MCP gateway as an HTTP server (Streamable HTTP transport).
///
/// Blocks until shutdown is triggered.
pub async fn run_http_server(
    gateway: Arc<McpGateway>,
    listen_addr: &str,
    allowed_origins: Vec<String>,
    shutdown: CancellationToken,
) -> forculus_common::Result<()> {
    let listener = TcpListener::bind(listen_addr).await.map_err(|e| {
        forculus_common::ForculusError::Mcp(format!("failed to bind {listen_addr}: {e}"))
    })?;

    let local_addr = listener.local_addr()?;
    tracing::info!(
        address = %local_addr,
        version = forculus_common::VERSION,
        "MCP HTTP server started"
    );

    let sessions = Arc::new(SessionManager::new());

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                tracing::info!("MCP HTTP server shutting down");
                break;
            }
            accept = listener.accept() => {
                match accept {
                    Ok((stream, addr)) => {
                        let gateway = Arc::clone(&gateway);
                        let sessions = Arc::clone(&sessions);
                        let allowed = allowed_origins.clone();

                        tokio::spawn(async move {
                            let transport = Arc::new(HttpTransport {
                                gateway,
                                sessions,
                                config: HttpTransportConfig {
                                    allowed_origins: allowed,
                                },
                            });

                            let service = service_fn(move |req| {
                                let transport = Arc::clone(&transport);
                                async move { transport.handle_request(req).await }
                            });

                            let builder = Builder::new(TokioExecutor::new());
                            let conn = builder.serve_connection(TokioIo::new(stream), service);

                            if let Err(e) = conn.await {
                                tracing::debug!(error = %e, peer = %addr, "connection error");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "accept error");
                    }
                }
            }
        }
    }

    gateway.shutdown().await;
    Ok(())
}

/// Like [`run_http_server`] but accepts a pre-bound [`TcpListener`] (for tests).
pub async fn run_http_server_with_listener(
    gateway: Arc<McpGateway>,
    listener: TcpListener,
    allowed_origins: Vec<String>,
    shutdown: CancellationToken,
) -> forculus_common::Result<()> {
    let local_addr = listener.local_addr()?;
    tracing::info!(
        address = %local_addr,
        version = forculus_common::VERSION,
        "MCP HTTP server started"
    );

    let sessions = Arc::new(SessionManager::new());

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                tracing::info!("MCP HTTP server shutting down");
                break;
            }
            accept = listener.accept() => {
                match accept {
                    Ok((stream, addr)) => {
                        let gateway = Arc::clone(&gateway);
                        let sessions = Arc::clone(&sessions);
                        let allowed = allowed_origins.clone();

                        tokio::spawn(async move {
                            let transport = Arc::new(HttpTransport {
                                gateway,
                                sessions,
                                config: HttpTransportConfig {
                                    allowed_origins: allowed,
                                },
                            });

                            let service = service_fn(move |req| {
                                let transport = Arc::clone(&transport);
                                async move { transport.handle_request(req).await }
                            });

                            let builder = Builder::new(TokioExecutor::new());
                            let conn = builder.serve_connection(TokioIo::new(stream), service);

                            if let Err(e) = conn.await {
                                tracing::debug!(error = %e, peer = %addr, "connection error");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "accept error");
                    }
                }
            }
        }
    }

    gateway.shutdown().await;
    Ok(())
}
