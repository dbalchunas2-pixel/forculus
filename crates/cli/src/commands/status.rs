//! `forculus status` — health dashboard showing the state of all subsystems.

use std::path::Path;

use anyhow::{Context, Result};
use forculus_config::load_config;
use serde::Serialize;

#[derive(Serialize)]
struct StatusReport {
    config_path: String,
    policies: PolicyStatus,
    credentials: CredentialStatus,
    sessions: SessionStatus,
    audit: AuditStatus,
    rate_limiting: RateLimitStatus,
    cost_tracking: CostTrackStatus,
    inspection: InspectionStatus,
}

#[derive(Serialize)]
struct PolicyStatus {
    file_count: usize,
    rule_count: usize,
    errors: usize,
}

#[derive(Serialize)]
struct CredentialStatus {
    count: usize,
}

#[derive(Serialize)]
struct SessionStatus {
    active: usize,
}

#[derive(Serialize)]
struct AuditStatus {
    event_count: u64,
    hash_chain_valid: Option<bool>,
}

#[derive(Serialize)]
struct RateLimitStatus {
    enabled: bool,
    rule_count: usize,
}

#[derive(Serialize)]
struct CostTrackStatus {
    enabled: bool,
    rule_count: usize,
}

#[derive(Serialize)]
struct InspectionStatus {
    enabled: bool,
    rule_count: usize,
    inspect_requests: bool,
    inspect_responses: bool,
}

fn build_report(config_path: &Path) -> Result<StatusReport> {
    let config = load_config(config_path).context("loading configuration")?;

    // Policies.
    let policies_dir = Path::new(&config.policy.policies_dir);
    let (file_count, rule_count, policy_errors) = if policies_dir.exists() {
        let result = forculus_policy::validation::validate_policies(policies_dir);
        let engine = forculus_policy::engine::PolicyEngine::from_directory(policies_dir);
        let rules = engine.map(|e| e.rule_count()).unwrap_or(0);
        let files = std::fs::read_dir(policies_dir)
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .filter(|e| {
                        e.path()
                            .extension()
                            .is_some_and(|ext| ext == "yaml" || ext == "yml")
                    })
                    .count()
            })
            .unwrap_or(0);
        (files, rules, result.errors.len())
    } else {
        (0, 0, 0)
    };

    // Credentials.
    let creds_dir = forculus_config::expand_tilde(&config.vault.credentials_dir);
    let cred_count = if Path::new(&creds_dir).exists() {
        std::fs::read_dir(&creds_dir)
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .filter(|e| e.path().extension().is_some_and(|ext| ext == "age"))
                    .count()
            })
            .unwrap_or(0)
    } else {
        0
    };

    // Sessions.
    let active_sessions = match forculus_vault::store::Vault::open(&config.vault) {
        Ok(vault) => vault
            .list_sessions(false)
            .map(|sessions| {
                sessions
                    .iter()
                    .filter(|s| !s.revoked && s.expires_at.is_none_or(|e| e > chrono::Utc::now()))
                    .count()
            })
            .unwrap_or(0),
        Err(_) => 0,
    };

    // Audit.
    let audit_db = forculus_config::expand_tilde(&config.audit.db_path);
    let (event_count, chain_valid) = if Path::new(&audit_db).exists() {
        match forculus_audit::store::AuditStore::open(Path::new(&audit_db)) {
            Ok(store) => {
                let count = store
                    .count(&forculus_audit::query::AuditFilter::default())
                    .unwrap_or(0);
                let valid = store.verify_chain().ok().map(|v| v.valid);
                (count, valid)
            }
            Err(_) => (0, None),
        }
    } else {
        (0, None)
    };

    // Inspection.
    let inspect_config = &config.inspect;
    let inspection_rule_count =
        forculus_inspect::scanner::ContentScanner::from_config(inspect_config)
            .map(|s| s.rule_set().enabled_count())
            .unwrap_or(0);

    let report = StatusReport {
        config_path: config_path.display().to_string(),
        policies: PolicyStatus {
            file_count,
            rule_count,
            errors: policy_errors,
        },
        credentials: CredentialStatus { count: cred_count },
        sessions: SessionStatus {
            active: active_sessions,
        },
        audit: AuditStatus {
            event_count,
            hash_chain_valid: chain_valid,
        },
        rate_limiting: RateLimitStatus {
            enabled: config.rate_limit.enabled,
            rule_count: config.rate_limit.rules.len(),
        },
        cost_tracking: CostTrackStatus {
            enabled: config.cost_estimation.enabled,
            rule_count: config.cost_estimation.rules.len(),
        },
        inspection: InspectionStatus {
            enabled: inspect_config.enabled,
            rule_count: inspection_rule_count,
            inspect_requests: inspect_config.inspect_requests,
            inspect_responses: inspect_config.inspect_responses,
        },
    };

    Ok(report)
}

/// Run the status command.
pub fn run(config_path: &Path, json: bool) -> Result<()> {
    let report = build_report(config_path)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("Forculus Status");
    println!("{}\n", "=".repeat(40));

    println!("Configuration: {}", report.config_path);
    println!();
    println!(
        "Policies:      {} files, {} rules{}",
        report.policies.file_count,
        report.policies.rule_count,
        if report.policies.errors > 0 {
            format!(" ({} errors)", report.policies.errors)
        } else {
            String::new()
        }
    );
    println!("Credentials:   {} stored", report.credentials.count);
    println!("Sessions:      {} active", report.sessions.active);
    println!(
        "Audit:         {} events{}",
        report.audit.event_count,
        match report.audit.hash_chain_valid {
            Some(true) => ", hash chain valid".to_string(),
            Some(false) => ", hash chain INVALID".to_string(),
            None => String::new(),
        }
    );
    println!(
        "Rate Limiting: {}{}",
        if report.rate_limiting.enabled {
            "enabled"
        } else {
            "disabled"
        },
        if report.rate_limiting.enabled {
            format!(" ({} rules)", report.rate_limiting.rule_count)
        } else {
            String::new()
        }
    );
    println!(
        "Cost Tracking: {}",
        if report.cost_tracking.enabled {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!(
        "Inspection:    {}{}",
        if report.inspection.enabled {
            "enabled"
        } else {
            "disabled"
        },
        if report.inspection.enabled {
            format!(
                " ({} rules, requests: {}, responses: {})",
                report.inspection.rule_count,
                if report.inspection.inspect_requests {
                    "on"
                } else {
                    "off"
                },
                if report.inspection.inspect_responses {
                    "on"
                } else {
                    "off"
                },
            )
        } else {
            String::new()
        }
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_test_config(dir: &std::path::Path) -> std::path::PathBuf {
        let config = format!(
            r#"proxy:
  listen_address: "127.0.0.1:0"
  tls:
    ca_dir: "{ca_dir}"

policy:
  policies_dir: "{policies_dir}"

vault:
  key_path: "{key_path}"
  credentials_dir: "{creds_dir}"
  bindings_path: "{bindings_path}"
  sessions_db_path: "{sessions_db}"
  require_sessions: false

audit:
  db_path: "{audit_db}"
  enabled: true
  retention_days: 90
"#,
            ca_dir = dir.join("ca").display(),
            policies_dir = dir.join("policies").display(),
            key_path = dir.join("vault-key.age").display(),
            creds_dir = dir.join("credentials").display(),
            bindings_path = dir.join("bindings.yaml").display(),
            sessions_db = dir.join("sessions.db").display(),
            audit_db = dir.join("audit.db").display(),
        );
        let config_path = dir.join("forculus.yaml");
        std::fs::write(&config_path, config).unwrap();
        config_path
    }

    #[test]
    fn status_reports_subsystem_states() {
        let dir = tempfile::tempdir().unwrap();

        // Create policies dir with valid YAML.
        let policies_dir = dir.path().join("policies");
        std::fs::create_dir_all(&policies_dir).unwrap();
        std::fs::write(
            policies_dir.join("test.yaml"),
            "metadata:\n  name: test\n  scope: global\nrules:\n  - name: allow-all\n    verdict: allow\n    priority: 1\n    match: {}\n",
        )
        .unwrap();

        std::fs::create_dir_all(dir.path().join("credentials")).unwrap();

        let config_path = write_test_config(dir.path());
        let report = build_report(&config_path).unwrap();

        assert_eq!(report.policies.file_count, 1);
        assert!(report.policies.rule_count >= 1);
        assert_eq!(report.policies.errors, 0);
        assert_eq!(report.credentials.count, 0);
        assert_eq!(report.sessions.active, 0);
        // Built-in inspection rules should be present.
        assert!(report.inspection.rule_count > 0);
    }

    #[test]
    fn status_json_output_parses() {
        let dir = tempfile::tempdir().unwrap();

        let policies_dir = dir.path().join("policies");
        std::fs::create_dir_all(&policies_dir).unwrap();
        std::fs::write(
            policies_dir.join("test.yaml"),
            "metadata:\n  name: test\n  scope: global\nrules:\n  - name: allow-all\n    verdict: allow\n    priority: 1\n    match: {}\n",
        )
        .unwrap();

        std::fs::create_dir_all(dir.path().join("credentials")).unwrap();

        let config_path = write_test_config(dir.path());
        let report = build_report(&config_path).unwrap();
        let json = serde_json::to_string_pretty(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(parsed.get("policies").is_some());
        assert!(parsed.get("audit").is_some());
        assert!(parsed.get("sessions").is_some());
        assert!(parsed.get("credentials").is_some());
        assert!(parsed.get("rate_limiting").is_some());
        assert!(parsed.get("cost_tracking").is_some());
        assert!(parsed.get("inspection").is_some());

        // Values have expected types.
        assert!(parsed["policies"]["rule_count"].is_number());
        assert!(parsed["rate_limiting"]["enabled"].is_boolean());
        assert!(parsed["inspection"]["enabled"].is_boolean());
    }
}
