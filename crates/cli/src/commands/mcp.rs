//! `forculus mcp start` — run the MCP governance gateway over stdio.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use forculus_audit::logger::AuditLogger;
use forculus_config::{LogFormat, load_config};
use forculus_mcp::gateway::McpGateway;
use forculus_mcp::server::run_stdio_server;
use forculus_policy::engine::PolicyEngine;
use forculus_vault::store::Vault;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

/// Start the MCP gateway in stdio mode.
///
/// **Critical**: All tracing output goes to stderr.  stdout is exclusively
/// for JSON-RPC messages — a single stray log line on stdout will corrupt
/// the transport and disconnect the agent.
pub fn start(config_path: &Path, log_level: Option<&str>) -> Result<()> {
    let config = load_config(config_path).context("loading configuration")?;

    let level = log_level
        .map(String::from)
        .unwrap_or_else(|| config.logging.level.clone());

    let filter = EnvFilter::try_new(&level).unwrap_or_else(|_| EnvFilter::new("info"));

    // Tracing MUST go to stderr — stdout is the MCP transport.
    match config.logging.format {
        LogFormat::Json => {
            tracing_subscriber::registry()
                .with(filter)
                .with(
                    tracing_subscriber::fmt::layer()
                        .json()
                        .with_writer(std::io::stderr),
                )
                .init();
        }
        LogFormat::Pretty => {
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

    let policies_dir = config.policy.policies_dir.clone();
    let vault_config = config.vault.clone();
    let audit_config = config.audit.clone();
    let inspect_config = config.inspect.clone();

    let rt = tokio::runtime::Runtime::new().context("creating tokio runtime")?;
    rt.block_on(async {
        let mut gateway = McpGateway::new(config.mcp_gateway)
            .await
            .context("initialising MCP gateway")?;

        // Load the policy engine if the policies directory exists.
        let policies_path = Path::new(&policies_dir);
        if policies_path.exists() {
            match PolicyEngine::from_directory(policies_path) {
                Ok(engine) => {
                    let engine = Arc::new(engine);
                    tracing::info!(
                        rules = engine.rule_count(),
                        dir = %policies_path.display(),
                        "policy engine loaded"
                    );
                    gateway = gateway.with_policy_engine(engine);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to load policies, running without policy enforcement");
                }
            }
        } else {
            tracing::info!(dir = %policies_path.display(), "policies directory not found, running without policy enforcement");
        }

        // Load the vault if the key exists.
        let key_path = forculus_config::expand_tilde(&vault_config.key_path);
        if Path::new(&key_path).exists() {
            match Vault::open(&vault_config) {
                Ok(vault) => {
                    tracing::info!("vault loaded");
                    gateway = gateway.with_vault(Arc::new(parking_lot::Mutex::new(vault)));
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to open vault, running without credential injection");
                }
            }
        }

        // Start audit logger and store if enabled.
        let _audit_logger = if audit_config.enabled {
            let audit_db_path = forculus_config::expand_tilde(&audit_config.db_path);
            match AuditLogger::new(Path::new(&audit_db_path)) {
                Ok(logger) => {
                    tracing::info!(db = %audit_db_path, "audit logger started");

                    // Run retention cleanup on startup.
                    if audit_config.retention_days > 0 {
                        match forculus_audit::store::AuditStore::open(Path::new(&audit_db_path)) {
                            Ok(retention_store) => {
                                match forculus_audit::retention::run_retention(
                                    &retention_store,
                                    audit_config.retention_days,
                                ) {
                                    Ok(deleted) if deleted > 0 => {
                                        tracing::info!(
                                            deleted = deleted,
                                            days = audit_config.retention_days,
                                            "audit retention cleanup on startup"
                                        );
                                    }
                                    Ok(_) => {}
                                    Err(e) => {
                                        tracing::warn!(error = %e, "audit retention cleanup failed");
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "failed to open audit store for retention");
                            }
                        }
                    }

                    // Open a separate audit store connection for builtin query tools.
                    match forculus_audit::store::AuditStore::open(Path::new(&audit_db_path)) {
                        Ok(query_store) => {
                            gateway = gateway.with_audit_store(Arc::new(
                                parking_lot::Mutex::new(query_store),
                            ));
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "failed to open audit store for query tools");
                        }
                    }

                    gateway = gateway.with_audit_logger(logger.clone());
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

        // Load content scanner if inspection is enabled.
        if inspect_config.enabled {
            match forculus_inspect::scanner::ContentScanner::from_config(&inspect_config) {
                Ok(scanner) => {
                    tracing::info!(
                        rules = scanner.rule_set().enabled_count(),
                        "content inspection enabled"
                    );
                    gateway = gateway.with_content_scanner(Arc::new(scanner));
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to create content scanner, running without inspection");
                }
            }
        } else {
            tracing::info!("content inspection disabled");
        }

        let gateway = Arc::new(gateway);

        let shutdown = CancellationToken::new();
        let shutdown_clone = shutdown.clone();

        tokio::spawn(async move {
            shutdown_signal().await;
            tracing::info!("shutdown signal received");
            shutdown_clone.cancel();
        });

        run_stdio_server(gateway, shutdown)
            .await
            .context("running MCP server")?;

        Ok(())
    })
}

/// Start the MCP gateway in HTTP mode (Streamable HTTP transport).
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

    // For HTTP mode, tracing goes to stderr (same as stdio mode for consistency).
    match config.logging.format {
        LogFormat::Json => {
            tracing_subscriber::registry()
                .with(filter)
                .with(
                    tracing_subscriber::fmt::layer()
                        .json()
                        .with_writer(std::io::stderr),
                )
                .init();
        }
        LogFormat::Pretty => {
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

    let policies_dir = config.policy.policies_dir.clone();
    let vault_config = config.vault.clone();
    let audit_config = config.audit.clone();
    let inspect_config = config.inspect.clone();
    let listen_address = listen_override
        .map(String::from)
        .or(config.mcp_gateway.listen_address.clone())
        .unwrap_or_else(|| "127.0.0.1:3000".to_string());
    let allowed_origins = config.mcp_gateway.allowed_origins.clone();

    let rt = tokio::runtime::Runtime::new().context("creating tokio runtime")?;
    rt.block_on(async {
        let mut gateway = McpGateway::new(config.mcp_gateway)
            .await
            .context("initialising MCP gateway")?;

        // Load the policy engine if the policies directory exists.
        let policies_path = Path::new(&policies_dir);
        if policies_path.exists() {
            match PolicyEngine::from_directory(policies_path) {
                Ok(engine) => {
                    let engine = Arc::new(engine);
                    tracing::info!(
                        rules = engine.rule_count(),
                        dir = %policies_path.display(),
                        "policy engine loaded"
                    );
                    gateway = gateway.with_policy_engine(engine);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to load policies, running without policy enforcement");
                }
            }
        } else {
            tracing::info!(dir = %policies_path.display(), "policies directory not found, running without policy enforcement");
        }

        // Load the vault if the key exists.
        let key_path = forculus_config::expand_tilde(&vault_config.key_path);
        if Path::new(&key_path).exists() {
            match Vault::open(&vault_config) {
                Ok(vault) => {
                    tracing::info!("vault loaded");
                    gateway = gateway.with_vault(Arc::new(parking_lot::Mutex::new(vault)));
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to open vault, running without credential injection");
                }
            }
        }

        // Start audit logger and store if enabled.
        let _audit_logger = if audit_config.enabled {
            let audit_db_path = forculus_config::expand_tilde(&audit_config.db_path);
            match AuditLogger::new(Path::new(&audit_db_path)) {
                Ok(logger) => {
                    tracing::info!(db = %audit_db_path, "audit logger started");

                    // Run retention cleanup on startup.
                    if audit_config.retention_days > 0 {
                        match forculus_audit::store::AuditStore::open(Path::new(&audit_db_path)) {
                            Ok(retention_store) => {
                                match forculus_audit::retention::run_retention(
                                    &retention_store,
                                    audit_config.retention_days,
                                ) {
                                    Ok(deleted) if deleted > 0 => {
                                        tracing::info!(
                                            deleted = deleted,
                                            days = audit_config.retention_days,
                                            "audit retention cleanup on startup"
                                        );
                                    }
                                    Ok(_) => {}
                                    Err(e) => {
                                        tracing::warn!(error = %e, "audit retention cleanup failed");
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "failed to open audit store for retention");
                            }
                        }
                    }

                    // Open a separate audit store connection for builtin query tools.
                    match forculus_audit::store::AuditStore::open(Path::new(&audit_db_path)) {
                        Ok(query_store) => {
                            gateway = gateway.with_audit_store(Arc::new(
                                parking_lot::Mutex::new(query_store),
                            ));
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "failed to open audit store for query tools");
                        }
                    }

                    gateway = gateway.with_audit_logger(logger.clone());
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

        // Load content scanner if inspection is enabled.
        if inspect_config.enabled {
            match forculus_inspect::scanner::ContentScanner::from_config(&inspect_config) {
                Ok(scanner) => {
                    tracing::info!(
                        rules = scanner.rule_set().enabled_count(),
                        "content inspection enabled"
                    );
                    gateway = gateway.with_content_scanner(Arc::new(scanner));
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to create content scanner, running without inspection");
                }
            }
        } else {
            tracing::info!("content inspection disabled");
        }

        let gateway = Arc::new(gateway);

        let shutdown = CancellationToken::new();
        let shutdown_clone = shutdown.clone();

        tokio::spawn(async move {
            shutdown_signal().await;
            tracing::info!("shutdown signal received");
            shutdown_clone.cancel();
        });

        forculus_mcp::server::run_http_server(gateway, &listen_address, allowed_origins, shutdown)
            .await
            .context("running MCP HTTP server")?;

        Ok(())
    })
}

/// Wait for SIGINT or SIGTERM.
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
