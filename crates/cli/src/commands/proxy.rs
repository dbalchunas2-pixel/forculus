//! `forculus proxy start` — load config, set up tracing, run the proxy.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use forculus_audit::logger::AuditLogger;
use forculus_config::{LogFormat, load_config};
use forculus_policy::engine::PolicyEngine;
use forculus_policy::glob::GlobPattern;
use forculus_proxy::server::ProxyServer;
use forculus_vault::store::Vault;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

/// Start the Forculus proxy server.
pub fn start(
    config_path: &Path,
    log_level: Option<&str>,
    listen_override: Option<&str>,
) -> Result<()> {
    let mut config = load_config(config_path).context("loading configuration")?;

    // Apply CLI overrides.
    if let Some(addr) = listen_override {
        config.proxy.listen_address = addr.to_string();
    }

    // Determine log level: CLI flag > config > default.
    let level = log_level
        .map(String::from)
        .unwrap_or_else(|| config.logging.level.clone());

    // Set up tracing.
    let filter = EnvFilter::try_new(&level).unwrap_or_else(|_| EnvFilter::new("info"));

    match config.logging.format {
        LogFormat::Json => {
            tracing_subscriber::registry()
                .with(filter)
                .with(tracing_subscriber::fmt::layer().json())
                .init();
        }
        LogFormat::Pretty => {
            tracing_subscriber::registry()
                .with(filter)
                .with(tracing_subscriber::fmt::layer().pretty())
                .init();
        }
    }

    // Build a tokio runtime and run the server.
    let rt = tokio::runtime::Runtime::new().context("creating tokio runtime")?;
    let policies_dir = config.policy.policies_dir.clone();

    let vault_config = config.vault.clone();
    let audit_config = config.audit.clone();
    let inspect_config = config.inspect.clone();
    let tls_passthrough_patterns = config.proxy.tls_passthrough.clone();

    rt.block_on(async {
        let mut server = ProxyServer::new(config.proxy)
            .await
            .context("initialising proxy server")?;

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
                    server = server.with_policy_engine(engine);
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
                    server = server.with_vault(Arc::new(parking_lot::Mutex::new(vault)));
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to open vault, running without credential injection");
                }
            }
        }

        // Start audit logger if enabled.
        let audit_logger = if audit_config.enabled {
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

                    // Verify audit hash chain integrity on startup.
                    match forculus_audit::store::AuditStore::open(Path::new(&audit_db_path)) {
                        Ok(verify_store) => match verify_store.verify_chain() {
                            Ok(result) if result.valid => {
                                tracing::info!(
                                    events_verified = result.events_checked,
                                    "audit hash chain verified"
                                );
                            }
                            Ok(result) => {
                                tracing::error!(
                                    first_invalid = result.first_invalid_index,
                                    error = ?result.error,
                                    "audit hash chain INVALID — log may have been tampered with"
                                );
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "audit chain verification failed");
                            }
                        },
                        Err(e) => {
                            tracing::warn!(error = %e, "failed to open audit store for chain verification");
                        }
                    }

                    server = server.with_audit_logger(logger.clone());
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
                    server = server.with_content_scanner(Arc::new(scanner));
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to create content scanner, running without inspection");
                }
            }
        } else {
            tracing::info!("content inspection disabled");
        }

        // Compile TLS passthrough patterns.
        if !tls_passthrough_patterns.is_empty() {
            let mut compiled = Vec::with_capacity(tls_passthrough_patterns.len());
            for pattern in &tls_passthrough_patterns {
                match GlobPattern::compile(pattern) {
                    Ok(g) => compiled.push(g),
                    Err(e) => {
                        tracing::warn!(pattern = %pattern, error = %e, "invalid tls_passthrough pattern, skipping");
                    }
                }
            }
            if !compiled.is_empty() {
                tracing::info!(
                    patterns = compiled.len(),
                    "TLS passthrough enabled"
                );
                server = server.with_tls_passthrough(compiled);
            }
        }

        let shutdown_token = server.shutdown_token();

        // Listen for SIGINT / SIGTERM.
        tokio::spawn(async move {
            shutdown_signal().await;
            tracing::info!("shutdown signal received");
            shutdown_token.cancel();
        });

        server.run().await.context("running proxy server")?;

        // Flush and shut down audit logger.
        if let Some(logger) = audit_logger {
            logger.shutdown().await;
        }

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
