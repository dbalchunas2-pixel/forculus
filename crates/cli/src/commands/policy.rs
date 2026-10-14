//! `forculus policy` — validate and test policy files.

use std::path::Path;

use anyhow::{Context, Result};
use forculus_policy::engine::PolicyEngine;
use forculus_policy::validation::validate_policies;

/// Validate policy files in the given directory.
pub fn validate(path: &Path) -> Result<()> {
    println!("Validating policies in {}", path.display());
    println!();

    let result = validate_policies(path);

    for error in &result.errors {
        println!("  ERROR: {error}");
    }
    for warning in &result.warnings {
        println!("  WARN:  {warning}");
    }

    if result.errors.is_empty() && result.warnings.is_empty() {
        println!("  All policies valid.");
    }

    println!();

    if result.is_ok() {
        println!("Validation passed.");
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "validation failed with {} error(s)",
            result.errors.len()
        ))
    }
}

struct ReplayResult {
    replayed: usize,
    unchanged: usize,
    allow_to_deny: usize,
    deny_to_allow: usize,
    changes: Vec<String>,
}

fn run_replay(
    config_path: &Path,
    dir: &Path,
    since: Option<&str>,
    limit: usize,
) -> Result<ReplayResult> {
    let engine =
        PolicyEngine::from_directory(dir).map_err(|e| anyhow::anyhow!("loading policies: {e}"))?;

    let config = forculus_config::load_config(config_path).context("loading configuration")?;
    let db_path = forculus_config::expand_tilde(&config.audit.db_path);
    let store =
        forculus_audit::store::AuditStore::open(Path::new(&db_path)).context("opening audit db")?;

    let mut filter = forculus_audit::query::AuditFilter {
        limit: Some(limit),
        sort: forculus_audit::query::SortOrder::Ascending,
        ..Default::default()
    };

    if let Some(s) = since {
        filter.after = parse_relative_time(s);
    }

    let events = store.query(&filter).context("querying audit events")?;

    let mut replayed = 0usize;
    let mut unchanged = 0usize;
    let mut allow_to_deny = 0usize;
    let mut deny_to_allow = 0usize;
    let mut changes: Vec<String> = Vec::new();

    for event in &events {
        let req = match &event.request {
            Some(r) if !r.tool.is_empty() => r,
            _ => continue,
        };

        replayed += 1;

        let mut ctx = forculus_policy::context::RequestContext::new(&req.tool, &req.action);
        if let Some(ref si) = event.session {
            ctx = ctx.with_operator(&si.operator);
            if let Some(ref team) = si.team {
                ctx = ctx.with_team(team);
            }
            if let Some(ref project) = si.project {
                ctx = ctx.with_project(project);
            }
            if let Some(ref env) = si.environment {
                ctx = ctx.with_environment(env);
            }
            if let Some(ref at) = si.agent_type {
                ctx = ctx.with_agent_type(at);
            }
        }

        let evaluation = engine.evaluate(&ctx);
        let new_verdict = format!("{:?}", evaluation.verdict).to_uppercase();

        let old_verdict = match &event.outcome {
            forculus_audit::event::EventOutcome::Success => "ALLOW",
            forculus_audit::event::EventOutcome::Denied => "DENY",
            forculus_audit::event::EventOutcome::Escalated => "ESCALATE",
            forculus_audit::event::EventOutcome::Failed => continue,
        };

        let new_simple = match new_verdict.as_str() {
            "ALLOW" => "ALLOW",
            "DENY" => "DENY",
            "ESCALATE" => "ESCALATE",
            _ => "DENY",
        };

        if old_verdict == new_simple {
            unchanged += 1;
        } else {
            match (old_verdict, new_simple) {
                ("ALLOW", "DENY") => allow_to_deny += 1,
                ("DENY", "ALLOW") => deny_to_allow += 1,
                _ => {}
            }
            let rule_info = evaluation
                .matched_rule
                .as_ref()
                .map(|r| format!("(new rule: {r})"))
                .unwrap_or_default();
            changes.push(format!(
                "{} / {} {} -> {} {}",
                req.tool, req.action, old_verdict, new_simple, rule_info,
            ));
        }
    }

    Ok(ReplayResult {
        replayed,
        unchanged,
        allow_to_deny,
        deny_to_allow,
        changes,
    })
}

/// Test policies by replaying audit events.
pub fn test_replay(
    config_path: &Path,
    dir: &Path,
    since: Option<&str>,
    limit: usize,
    show_unchanged: bool,
) -> Result<()> {
    let result = run_replay(config_path, dir, since, limit)?;

    println!(
        "Policy Test: Replaying {} events against {}\n",
        result.replayed,
        dir.display()
    );

    if !result.changes.is_empty() || (show_unchanged && result.unchanged > 0) {
        let change_count = result.allow_to_deny + result.deny_to_allow;
        if change_count > 0 {
            println!(
                "Verdict Changes ({change_count} of {} events):\n",
                result.replayed
            );
        }
        for line in &result.changes {
            println!("  {line}");
        }
        println!();
    }

    println!("Summary:");
    println!("  {} events replayed", result.replayed);
    println!("  {} unchanged", result.unchanged);
    if result.allow_to_deny > 0 {
        println!(
            "  {} ALLOW -> DENY  (would have been blocked)",
            result.allow_to_deny
        );
    }
    if result.deny_to_allow > 0 {
        println!(
            "  {} DENY -> ALLOW  (would have been permitted)",
            result.deny_to_allow
        );
    }

    if result.replayed > 0 {
        println!("\nNote: this replay uses stored event metadata which may not capture");
        println!("all original request context (e.g., labels, custom conditions).");
    }

    Ok(())
}

/// Parse a relative time string like "1h", "24h", "7d" into a DateTime.
fn parse_relative_time(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    let s = s.trim();
    if let Some(hours) = s.strip_suffix('h') {
        let h: i64 = hours.parse().ok()?;
        Some(chrono::Utc::now() - chrono::Duration::hours(h))
    } else if let Some(days) = s.strip_suffix('d') {
        let d: i64 = days.parse().ok()?;
        Some(chrono::Utc::now() - chrono::Duration::days(d))
    } else if let Some(minutes) = s.strip_suffix('m') {
        let m: i64 = minutes.parse().ok()?;
        Some(chrono::Utc::now() - chrono::Duration::minutes(m))
    } else {
        chrono::DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|dt| dt.with_timezone(&chrono::Utc))
    }
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

    fn write_audit_event(
        store: &forculus_audit::store::AuditStore,
        tool: &str,
        action: &str,
        outcome: forculus_audit::event::EventOutcome,
    ) {
        store
            .insert(
                &forculus_audit::event::AuditEvent::builder(
                    forculus_audit::event::EventType::RequestProcessed,
                    forculus_audit::event::Channel::HttpProxy,
                )
                .outcome(outcome)
                .session(forculus_audit::event::SessionInfo {
                    session_id: "test-session".into(),
                    operator: "alice".into(),
                    team: None,
                    project: None,
                    environment: None,
                    agent_type: None,
                })
                .request(forculus_audit::event::RequestInfo {
                    tool: tool.into(),
                    action: action.into(),
                    resource: None,
                    target: "https://example.com".into(),
                })
                .build(),
            )
            .unwrap();
    }

    fn write_policy(dir: &std::path::Path, name: &str, yaml: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(format!("{name}.yaml")), yaml).unwrap();
    }

    #[test]
    fn policy_replay_detects_verdict_change() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = write_test_config(dir.path());

        // Write audit events (all originally allowed).
        let audit_path = dir.path().join("audit.db");
        let store = forculus_audit::store::AuditStore::open(&audit_path).unwrap();

        write_audit_event(
            &store,
            "github",
            "list_issues",
            forculus_audit::event::EventOutcome::Success,
        );
        write_audit_event(
            &store,
            "github",
            "create_issue",
            forculus_audit::event::EventOutcome::Success,
        );
        write_audit_event(
            &store,
            "github",
            "delete_repo",
            forculus_audit::event::EventOutcome::Success,
        );

        // Create a stricter policy that denies delete*.
        let policy_dir = dir.path().join("proposed_policies");
        write_policy(
            &policy_dir,
            "strict",
            "metadata:\n  name: strict\n  scope: global\nrules:\n  - name: deny-delete\n    verdict: deny\n    priority: 100\n    match:\n      actions: [\"delete*\"]\n  - name: allow-all\n    verdict: allow\n    priority: 1\n    match: {}\n",
        );

        let result = run_replay(&config_path, &policy_dir, None, 1000).unwrap();

        assert_eq!(result.replayed, 3);
        assert_eq!(result.unchanged, 2);
        assert_eq!(result.allow_to_deny, 1);
        assert_eq!(result.deny_to_allow, 0);
        assert_eq!(result.changes.len(), 1);
        assert!(result.changes[0].contains("delete_repo"));
    }

    #[test]
    fn policy_replay_skips_non_policy_events() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = write_test_config(dir.path());

        let audit_path = dir.path().join("audit.db");
        let store = forculus_audit::store::AuditStore::open(&audit_path).unwrap();

        // Event 1: SessionCreated (no tool/action).
        store
            .insert(
                &forculus_audit::event::AuditEvent::builder(
                    forculus_audit::event::EventType::SessionCreated,
                    forculus_audit::event::Channel::Cli,
                )
                .outcome(forculus_audit::event::EventOutcome::Success)
                .build(),
            )
            .unwrap();

        // Event 2: CredentialInjected (no request info).
        store
            .insert(
                &forculus_audit::event::AuditEvent::builder(
                    forculus_audit::event::EventType::CredentialInjected,
                    forculus_audit::event::Channel::HttpProxy,
                )
                .outcome(forculus_audit::event::EventOutcome::Success)
                .build(),
            )
            .unwrap();

        // Event 3: RequestProcessed WITH tool/action.
        write_audit_event(
            &store,
            "github",
            "push",
            forculus_audit::event::EventOutcome::Success,
        );

        let policy_dir = dir.path().join("policies");
        write_policy(
            &policy_dir,
            "allow",
            "metadata:\n  name: allow-all\n  scope: global\nrules:\n  - name: allow-all\n    verdict: allow\n    priority: 1\n    match: {}\n",
        );

        let result = run_replay(&config_path, &policy_dir, None, 1000).unwrap();

        // Only the RequestProcessed event should be replayed.
        assert_eq!(result.replayed, 1);
        assert_eq!(result.unchanged, 1);
    }

    #[test]
    fn policy_replay_respects_limit() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = write_test_config(dir.path());

        let audit_path = dir.path().join("audit.db");
        let store = forculus_audit::store::AuditStore::open(&audit_path).unwrap();

        // Write 20 events.
        for i in 0..20 {
            write_audit_event(
                &store,
                "github",
                &format!("action_{i}"),
                forculus_audit::event::EventOutcome::Success,
            );
        }

        let policy_dir = dir.path().join("policies");
        write_policy(
            &policy_dir,
            "allow",
            "metadata:\n  name: allow-all\n  scope: global\nrules:\n  - name: allow-all\n    verdict: allow\n    priority: 1\n    match: {}\n",
        );

        // Replay with limit of 5.
        let result = run_replay(&config_path, &policy_dir, None, 5).unwrap();

        assert_eq!(result.replayed, 5);
    }
}
