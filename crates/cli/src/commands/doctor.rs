//! `forculus doctor` — diagnose common setup issues.

use std::net::TcpListener;
use std::path::Path;

use anyhow::{Context, Result};
use forculus_config::load_config;
use colored::Colorize;
use serde::Serialize;

#[derive(Serialize)]
struct CheckResult {
    name: String,
    status: String,
    detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    remediation: Option<String>,
}

#[derive(Serialize)]
struct DoctorReport {
    checks: Vec<CheckResult>,
    passed: usize,
    failed: usize,
}

struct Check {
    name: String,
    passed: bool,
    detail: String,
    remediation: Option<String>,
}

impl Check {
    fn pass(name: &str, detail: &str) -> Self {
        Self {
            name: name.to_string(),
            passed: true,
            detail: detail.to_string(),
            remediation: None,
        }
    }

    fn fail(name: &str, detail: &str, remediation: Option<&str>) -> Self {
        Self {
            name: name.to_string(),
            passed: false,
            detail: detail.to_string(),
            remediation: remediation.map(String::from),
        }
    }
}

fn collect_checks(config_path: &Path) -> Vec<Check> {
    let mut checks = Vec::new();

    // 1. Config file exists and parses.
    let config = match load_config(config_path) {
        Ok(c) => {
            checks.push(Check::pass("config", "Configuration file loads correctly"));
            Some(c)
        }
        Err(e) => {
            checks.push(Check::fail(
                "config",
                &format!("Failed to load config: {e}"),
                Some("Create a forculus.yaml or run: forculus init"),
            ));
            None
        }
    };

    // 2. Policy directory exists and has valid YAML.
    if let Some(ref config) = config {
        let policies_dir = &config.policy.policies_dir;
        let dir = Path::new(policies_dir);
        if dir.exists() {
            let result = forculus_policy::validation::validate_policies(dir);
            if result.is_ok() {
                let engine = forculus_policy::engine::PolicyEngine::from_directory(dir);
                let rule_count = engine.map(|e| e.rule_count()).unwrap_or(0);
                checks.push(Check::pass(
                    "policies",
                    &format!("Policy directory valid ({rule_count} rules)"),
                ));
            } else {
                checks.push(Check::fail(
                    "policies",
                    &format!("{} error(s) in policy files", result.errors.len()),
                    Some("Run: forculus policy validate"),
                ));
            }
        } else {
            checks.push(Check::fail(
                "policies",
                &format!("Policy directory not found: {}", dir.display()),
                Some(&format!("mkdir -p {}", dir.display())),
            ));
        }
    }

    // 3. Vault key exists.
    if let Some(ref config) = config {
        let key_path = forculus_config::expand_tilde(&config.vault.key_path);
        let key_file = Path::new(&key_path);
        if key_file.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let meta = std::fs::metadata(key_file);
                if let Ok(meta) = meta {
                    let mode = meta.mode() & 0o777;
                    if mode == 0o600 {
                        checks.push(Check::pass(
                            "vault_key",
                            "Vault key exists with correct permissions (0600)",
                        ));
                    } else {
                        checks.push(Check::fail(
                            "vault_key_permissions",
                            &format!("Vault key permissions are {:04o} (expected 0600)", mode),
                            Some(&format!("chmod 600 {key_path}")),
                        ));
                    }
                } else {
                    checks.push(Check::pass("vault_key", "Vault key exists"));
                }
            }
            #[cfg(not(unix))]
            {
                checks.push(Check::pass("vault_key", "Vault key exists"));
            }
        } else {
            checks.push(Check::fail(
                "vault_key",
                &format!("Vault key not found: {key_path}"),
                Some("Run: forculus init"),
            ));
        }
    }

    // 4. CA certificate exists.
    if let Some(ref config) = config {
        let ca_dir = forculus_config::expand_tilde(&config.proxy.tls.ca_dir);
        let ca_cert = Path::new(&ca_dir).join("ca.pem");
        if ca_cert.exists() {
            checks.push(Check::pass("ca_certificate", "CA certificate exists"));
        } else {
            checks.push(Check::fail(
                "ca_certificate",
                &format!("CA certificate not found: {}", ca_cert.display()),
                Some("Start proxy once to auto-generate, or run: forculus ca export"),
            ));
        }
    }

    // 5. Credentials directory accessible.
    if let Some(ref config) = config {
        let creds_dir = forculus_config::expand_tilde(&config.vault.credentials_dir);
        let dir = Path::new(&creds_dir);
        if dir.exists() {
            let count = std::fs::read_dir(dir)
                .map(|entries| {
                    entries
                        .filter_map(|e| e.ok())
                        .filter(|e| e.path().extension().is_some_and(|ext| ext == "age"))
                        .count()
                })
                .unwrap_or(0);
            checks.push(Check::pass(
                "credentials",
                &format!("Credentials directory accessible ({count} credentials)"),
            ));
        } else {
            checks.push(Check::fail(
                "credentials",
                &format!("Credentials directory not found: {}", dir.display()),
                Some(&format!("mkdir -p {}", dir.display())),
            ));
        }
    }

    // 6. SQLite databases writable.
    if let Some(ref config) = config {
        // Sessions DB.
        let sessions_db = forculus_config::expand_tilde(&config.vault.sessions_db_path);
        match check_db_writable(&sessions_db) {
            Ok(()) => checks.push(Check::pass("sessions_db", "Sessions database writable")),
            Err(e) => checks.push(Check::fail(
                "sessions_db",
                &format!("Sessions database not writable: {e}"),
                None,
            )),
        }

        // Audit DB.
        let audit_db = forculus_config::expand_tilde(&config.audit.db_path);
        match check_db_writable(&audit_db) {
            Ok(()) => checks.push(Check::pass("audit_db", "Audit database writable")),
            Err(e) => checks.push(Check::fail(
                "audit_db",
                &format!("Audit database not writable: {e}"),
                None,
            )),
        }
    }

    // 7. Port availability.
    if let Some(ref config) = config {
        let addr = &config.proxy.listen_address;
        match TcpListener::bind(addr) {
            Ok(_listener) => {
                checks.push(Check::pass(
                    "proxy_port",
                    &format!("Proxy port available ({addr})"),
                ));
            }
            Err(_) => {
                checks.push(Check::fail(
                    "proxy_port",
                    &format!("Proxy port {addr} is in use"),
                    Some("Change listen_address in forculus.yaml or stop the process using it"),
                ));
            }
        }
    }

    // 8. Audit hash chain integrity.
    if let Some(ref config) = config {
        let audit_db = forculus_config::expand_tilde(&config.audit.db_path);
        let audit_path = Path::new(&audit_db);
        if audit_path.exists() {
            match forculus_audit::store::AuditStore::open(audit_path) {
                Ok(store) => match store.verify_chain() {
                    Ok(verification) => {
                        if verification.valid {
                            checks.push(Check::pass(
                                "audit_chain",
                                &format!(
                                    "Audit hash chain valid ({} events)",
                                    verification.events_checked
                                ),
                            ));
                        } else {
                            checks.push(Check::fail(
                                "audit_chain",
                                &format!(
                                    "Audit hash chain INVALID at event {}",
                                    verification.first_invalid_index.unwrap_or(0)
                                ),
                                Some("Investigate tampered events with: forculus audit verify"),
                            ));
                        }
                    }
                    Err(e) => checks.push(Check::fail(
                        "audit_chain",
                        &format!("Failed to verify audit chain: {e}"),
                        None,
                    )),
                },
                Err(e) => checks.push(Check::fail(
                    "audit_chain",
                    &format!("Failed to open audit database: {e}"),
                    None,
                )),
            }
        }
    }

    checks
}

/// Run the doctor diagnostic.
pub fn run(config_path: &Path, json: bool) -> Result<()> {
    let checks = collect_checks(config_path);
    let passed = checks.iter().filter(|c| c.passed).count();
    let failed = checks.iter().filter(|c| !c.passed).count();

    if json {
        let report = DoctorReport {
            checks: checks
                .iter()
                .map(|c| CheckResult {
                    name: c.name.clone(),
                    status: if c.passed { "pass" } else { "fail" }.to_string(),
                    detail: c.detail.clone(),
                    remediation: c.remediation.clone(),
                })
                .collect(),
            passed,
            failed,
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("Forculus Doctor");
    println!("{}\n", "=".repeat(40));

    for check in &checks {
        if check.passed {
            println!("  {} {}", "+".green(), check.detail);
        } else {
            println!("  {} {}", "x".red(), check.detail);
            if let Some(ref rem) = check.remediation {
                println!("    -> {rem}");
            }
        }
    }

    println!(
        "\n{}/{} checks passed.{}",
        passed,
        passed + failed,
        if failed > 0 {
            format!(" {} issue(s) found.", failed)
        } else {
            " All good!".to_string()
        }
    );

    Ok(())
}

fn check_db_writable(path: &str) -> Result<()> {
    let p = Path::new(path);
    if let Some(parent) = p.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent).context("creating parent directory")?;
        }
    }
    // Try opening — this creates if missing and verifies write access.
    forculus_audit::store::AuditStore::open(p).context("opening database")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_test_config(dir: &std::path::Path, listen_addr: &str) -> std::path::PathBuf {
        let config = format!(
            r#"proxy:
  listen_address: "{listen_addr}"
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
    fn doctor_config_check_reports_invalid_file() {
        let dir = tempfile::tempdir().unwrap();
        // Write invalid YAML so load_config fails (missing file returns defaults).
        let bad_config = dir.path().join("bad.yaml");
        std::fs::write(&bad_config, "{{{{not valid yaml at all").unwrap();
        let checks = collect_checks(&bad_config);

        assert!(!checks.is_empty());
        let config_check = &checks[0];
        assert_eq!(config_check.name, "config");
        assert!(!config_check.passed);
        assert!(config_check.detail.contains("Failed to load config"));
        assert!(
            config_check
                .remediation
                .as_ref()
                .unwrap()
                .contains("forculus init")
        );
        // Only the config check should be present (subsequent checks need config).
        assert_eq!(checks.len(), 1);
    }

    #[test]
    fn doctor_port_check_detects_in_use() {
        let dir = tempfile::tempdir().unwrap();

        // Bind an ephemeral port to mark it as in-use.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let addr = format!("127.0.0.1:{port}");

        // Create config using that port.
        let config_path = write_test_config(dir.path(), &addr);

        // Create minimum dirs so config loads and other checks can proceed.
        std::fs::create_dir_all(dir.path().join("policies")).unwrap();
        std::fs::create_dir_all(dir.path().join("credentials")).unwrap();

        let checks = collect_checks(&config_path);

        let port_check = checks.iter().find(|c| c.name == "proxy_port").unwrap();
        assert!(!port_check.passed);
        assert!(port_check.detail.contains("in use"));

        drop(listener);
    }

    #[test]
    fn doctor_all_checks_run_independently() {
        let dir = tempfile::tempdir().unwrap();

        // Create policies dir with valid YAML.
        let policies_dir = dir.path().join("policies");
        std::fs::create_dir_all(&policies_dir).unwrap();
        std::fs::write(
            policies_dir.join("test.yaml"),
            "metadata:\n  name: test\n  scope: global\nrules:\n  - name: allow-all\n    verdict: allow\n    priority: 1\n    match: {}\n",
        )
        .unwrap();

        // Create credentials dir.
        std::fs::create_dir_all(dir.path().join("credentials")).unwrap();

        // Deliberately DO NOT create vault key or CA cert.
        let config_path = write_test_config(dir.path(), "127.0.0.1:0");

        let checks = collect_checks(&config_path);

        // Should have many checks (not just config).
        assert!(checks.len() > 3);

        // Config check should pass.
        let config_check = checks.iter().find(|c| c.name == "config").unwrap();
        assert!(config_check.passed);

        // Policies check should pass.
        let policy_check = checks.iter().find(|c| c.name == "policies").unwrap();
        assert!(policy_check.passed);

        // Vault key check should fail.
        let vault_check = checks.iter().find(|c| c.name == "vault_key").unwrap();
        assert!(!vault_check.passed);

        // CA check should fail.
        let ca_check = checks.iter().find(|c| c.name == "ca_certificate").unwrap();
        assert!(!ca_check.passed);

        // Both passed and failed checks exist (doctor didn't short-circuit).
        let passed = checks.iter().filter(|c| c.passed).count();
        let failed = checks.iter().filter(|c| !c.passed).count();
        assert!(passed > 0);
        assert!(failed > 0);
    }
}
