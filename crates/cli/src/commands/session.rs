//! `forculus session` — session management commands.

use std::path::Path;

use anyhow::{Context, Result};
use forculus_config::load_config;
use forculus_vault::session::CreateSessionParams;
use forculus_vault::store::Vault;

/// Create a new session.
#[allow(clippy::too_many_arguments)]
pub fn create(
    config_path: &Path,
    operator: &str,
    team: Option<&str>,
    project: Option<&str>,
    environment: Option<&str>,
    agent_type: Option<&str>,
    ttl: Option<u64>,
    description: Option<&str>,
) -> Result<()> {
    let config = load_config(config_path).context("loading configuration")?;
    let vault = Vault::open(&config.vault).context("opening vault")?;

    let params = CreateSessionParams {
        operator: operator.to_string(),
        team: team.map(String::from),
        project: project.map(String::from),
        environment: environment.map(String::from),
        agent_type: agent_type.map(String::from),
        ttl_seconds: ttl,
        description: description.map(String::from),
    };

    let session = vault.create_session(params).context("creating session")?;

    println!("Session created:");
    println!("  ID:       {}", session.id);
    println!("  Token:    {}", session.token);
    println!("  Operator: {}", session.operator);
    if let Some(ref team) = session.team {
        println!("  Team:     {team}");
    }
    if let Some(ref project) = session.project {
        println!("  Project:  {project}");
    }
    if let Some(ref env) = session.environment {
        println!("  Env:      {env}");
    }
    if let Some(ref expires) = session.expires_at {
        println!("  Expires:  {expires}");
    }
    println!();
    println!("Give the token to the agent. Set it as:");
    println!("  HTTP: X-Forculus-Session: {}", session.token);
    println!("  MCP:  via initialize params");
    println!();
    println!("To trust the Forculus CA certificate:");
    println!("  Node.js: export NODE_EXTRA_CA_CERTS=\"$(forculus ca path)\"");
    println!("  Python:  export REQUESTS_CA_BUNDLE=\"$(forculus ca path)\"");
    println!("  OpenSSL: export SSL_CERT_FILE=\"$(forculus ca path)\"");
    println!("  curl:    curl --cacert \"$(forculus ca path)\" ...");

    Ok(())
}

/// List sessions.
pub fn list(config_path: &Path, include_revoked: bool, json: bool) -> Result<()> {
    let config = load_config(config_path).context("loading configuration")?;
    let vault = Vault::open(&config.vault).context("opening vault")?;

    let sessions = vault
        .list_sessions(include_revoked)
        .context("listing sessions")?;

    if json {
        let items: Vec<serde_json::Value> = sessions
            .iter()
            .map(|s| {
                let status = if s.revoked {
                    "revoked"
                } else if s.expires_at.is_some_and(|e| e < chrono::Utc::now()) {
                    "expired"
                } else {
                    "active"
                };
                serde_json::json!({
                    "id": s.id,
                    "operator": s.operator,
                    "team": s.team,
                    "project": s.project,
                    "environment": s.environment,
                    "agent_type": s.agent_type,
                    "status": status,
                    "created_at": s.created_at.to_rfc3339(),
                    "expires_at": s.expires_at.map(|e| e.to_rfc3339()),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
        return Ok(());
    }

    if sessions.is_empty() {
        println!("No sessions found.");
        return Ok(());
    }

    println!(
        "{:<38} {:<12} {:<10} {:<10} CREATED",
        "ID", "OPERATOR", "TEAM", "STATUS"
    );
    println!("{}", "-".repeat(90));
    for s in &sessions {
        let status = if s.revoked {
            "revoked"
        } else if s.expires_at.is_some_and(|e| e < chrono::Utc::now()) {
            "expired"
        } else {
            "active"
        };
        let team = s.team.as_deref().unwrap_or("-");
        println!(
            "{:<38} {:<12} {:<10} {:<10} {}",
            s.id,
            s.operator,
            team,
            status,
            s.created_at.format("%Y-%m-%d %H:%M")
        );
    }
    Ok(())
}

/// Revoke a session.
pub fn revoke(config_path: &Path, session_id: &str) -> Result<()> {
    let config = load_config(config_path).context("loading configuration")?;
    let vault = Vault::open(&config.vault).context("opening vault")?;

    vault
        .revoke_session(session_id)
        .context("revoking session")?;

    println!("Session '{session_id}' revoked.");
    Ok(())
}

struct InspectTimeline {
    events: Vec<forculus_audit::event::AuditEvent>,
    session_info: Option<forculus_audit::event::SessionInfo>,
    allowed: u32,
    denied: u32,
    rate_limited: u32,
    other: u32,
}

fn collect_inspect_data(config_path: &Path, session_id: &str) -> Result<InspectTimeline> {
    let config = load_config(config_path).context("loading configuration")?;
    let db_path = forculus_config::expand_tilde(&config.audit.db_path);
    let store =
        forculus_audit::store::AuditStore::open(Path::new(&db_path)).context("opening audit db")?;

    let filter = forculus_audit::query::AuditFilter {
        session_id: Some(session_id.to_string()),
        sort: forculus_audit::query::SortOrder::Ascending,
        ..Default::default()
    };
    let events = store.query(&filter).context("querying audit events")?;

    let session_info = events.first().and_then(|e| e.session.clone());
    let mut allowed = 0u32;
    let mut denied = 0u32;
    let mut rate_limited = 0u32;
    let mut other = 0u32;

    for event in &events {
        match &event.outcome {
            forculus_audit::event::EventOutcome::Success => allowed += 1,
            forculus_audit::event::EventOutcome::Denied => denied += 1,
            forculus_audit::event::EventOutcome::Escalated
            | forculus_audit::event::EventOutcome::Failed => other += 1,
        }
        let event_type_str = serde_json::to_value(&event.event_type)
            .map_or_else(|_| String::new(), |v| v.as_str().unwrap_or("").to_string());
        if event_type_str == "rate_limited" {
            rate_limited += 1;
        }
    }

    Ok(InspectTimeline {
        events,
        session_info,
        allowed,
        denied,
        rate_limited,
        other,
    })
}

/// Inspect a session's activity timeline.
pub fn inspect(config_path: &Path, session_id: &str, json: bool) -> Result<()> {
    let timeline = collect_inspect_data(config_path, session_id)?;

    if json {
        let items: Vec<serde_json::Value> = timeline
            .events
            .iter()
            .map(|e| {
                serde_json::json!({
                    "timestamp": e.timestamp.to_rfc3339(),
                    "event_type": serde_json::to_value(&e.event_type).ok(),
                    "outcome": serde_json::to_value(&e.outcome).ok(),
                    "tool": e.request.as_ref().map(|r| &r.tool),
                    "action": e.request.as_ref().map(|r| &r.action),
                    "policy_rule": e.policy.as_ref().map(|p| &p.matched_rule),
                    "error": e.error.as_ref().map(|err| &err.message),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
        return Ok(());
    }

    if timeline.events.is_empty() {
        println!("No events found for session {session_id}.");
        return Ok(());
    }

    println!("Session Inspection: {session_id}");
    println!("{}\n", "=".repeat(50));

    if let Some(ref si) = timeline.session_info {
        println!("Operator:   {}", si.operator);
        if let Some(ref team) = si.team {
            println!("Team:       {team}");
        }
    }
    println!();

    println!("Activity Timeline");
    println!("{}", "-".repeat(80));

    for event in &timeline.events {
        let time = event.timestamp.format("%H:%M:%S");
        let outcome_str = match &event.outcome {
            forculus_audit::event::EventOutcome::Success => "allowed",
            forculus_audit::event::EventOutcome::Denied => "DENIED",
            forculus_audit::event::EventOutcome::Escalated => "ESCALATED",
            forculus_audit::event::EventOutcome::Failed => "FAILED",
        };

        let icon = match &event.outcome {
            forculus_audit::event::EventOutcome::Success => "+",
            forculus_audit::event::EventOutcome::Denied => "x",
            _ => "!",
        };

        let event_type_str = serde_json::to_value(&event.event_type).map_or_else(
            |_| "?".to_string(),
            |v| v.as_str().unwrap_or("?").to_string(),
        );

        let tool_action = if let Some(ref req) = event.request {
            format!("{} / {}", req.tool, req.action)
        } else {
            event_type_str
        };

        let rule = event
            .policy
            .as_ref()
            .and_then(|p| p.matched_rule.as_ref())
            .map(|r| format!("(rule: {r})"))
            .unwrap_or_default();

        println!("  {time}  {icon} {tool_action:<30} {outcome_str:<12} {rule}");
    }

    println!("\nSummary");
    println!("{}", "-".repeat(40));
    println!("Total actions:  {}", timeline.events.len());
    println!("Allowed:        {}", timeline.allowed);
    println!("Denied:         {}", timeline.denied);
    if timeline.rate_limited > 0 {
        println!("Rate limited:   {}", timeline.rate_limited);
    }
    if timeline.other > 0 {
        println!("Other:          {}", timeline.other);
    }

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

    fn make_session_info(session_id: &str) -> forculus_audit::event::SessionInfo {
        forculus_audit::event::SessionInfo {
            session_id: session_id.to_string(),
            operator: "alice".to_string(),
            team: None,
            project: None,
            environment: None,
            agent_type: None,
        }
    }

    #[test]
    fn session_inspect_shows_events() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = write_test_config(dir.path());
        let session_id = "test-session-123";

        // Create audit DB and insert events.
        let audit_path = dir.path().join("audit.db");
        let store = forculus_audit::store::AuditStore::open(&audit_path).unwrap();

        // Event 1: allowed request.
        store
            .insert(
                &forculus_audit::event::AuditEvent::builder(
                    forculus_audit::event::EventType::RequestProcessed,
                    forculus_audit::event::Channel::HttpProxy,
                )
                .outcome(forculus_audit::event::EventOutcome::Success)
                .session(make_session_info(session_id))
                .request(forculus_audit::event::RequestInfo {
                    tool: "github".into(),
                    action: "list_repos".into(),
                    resource: None,
                    target: "https://api.github.com".into(),
                })
                .build(),
            )
            .unwrap();

        // Event 2: denied request.
        store
            .insert(
                &forculus_audit::event::AuditEvent::builder(
                    forculus_audit::event::EventType::RequestProcessed,
                    forculus_audit::event::Channel::HttpProxy,
                )
                .outcome(forculus_audit::event::EventOutcome::Denied)
                .session(make_session_info(session_id))
                .request(forculus_audit::event::RequestInfo {
                    tool: "github".into(),
                    action: "delete_repo".into(),
                    resource: None,
                    target: "https://api.github.com".into(),
                })
                .build(),
            )
            .unwrap();

        // Event 3: another allowed request.
        store
            .insert(
                &forculus_audit::event::AuditEvent::builder(
                    forculus_audit::event::EventType::RequestProcessed,
                    forculus_audit::event::Channel::HttpProxy,
                )
                .outcome(forculus_audit::event::EventOutcome::Success)
                .session(make_session_info(session_id))
                .request(forculus_audit::event::RequestInfo {
                    tool: "slack".into(),
                    action: "post_message".into(),
                    resource: None,
                    target: "https://slack.com/api".into(),
                })
                .build(),
            )
            .unwrap();

        let timeline = collect_inspect_data(&config_path, session_id).unwrap();

        assert_eq!(timeline.events.len(), 3);
        assert_eq!(timeline.allowed, 2);
        assert_eq!(timeline.denied, 1);
        assert_eq!(timeline.other, 0);

        // Events should be in chronological order.
        assert!(timeline.events[0].timestamp <= timeline.events[1].timestamp);
        assert!(timeline.events[1].timestamp <= timeline.events[2].timestamp);

        // Session info should be present.
        assert!(timeline.session_info.is_some());
        assert_eq!(timeline.session_info.unwrap().operator, "alice");
    }

    #[test]
    fn session_inspect_no_events() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = write_test_config(dir.path());

        // Create empty audit DB.
        let audit_path = dir.path().join("audit.db");
        let _store = forculus_audit::store::AuditStore::open(&audit_path).unwrap();

        let timeline = collect_inspect_data(&config_path, "nonexistent-session").unwrap();

        assert_eq!(timeline.events.len(), 0);
        assert_eq!(timeline.allowed, 0);
        assert_eq!(timeline.denied, 0);
        assert_eq!(timeline.other, 0);
        assert!(timeline.session_info.is_none());
    }
}
