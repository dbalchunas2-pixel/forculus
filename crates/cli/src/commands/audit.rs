//! `forculus audit` — search, tail, stats, export, and cleanup audit events.

use std::path::Path;

use anyhow::{Context, Result};
use forculus_audit::query::{AuditFilter, SortOrder};
use forculus_audit::retention::run_retention;
use forculus_audit::store::AuditStore;
use forculus_config::load_config;

/// Search audit events with optional filters.
pub fn search(
    config_path: &Path,
    event_type: Option<&str>,
    outcome: Option<&str>,
    operator: Option<&str>,
    tool: Option<&str>,
    since: Option<&str>,
    limit: Option<usize>,
) -> Result<()> {
    let config = load_config(config_path).context("loading configuration")?;
    let db_path = forculus_config::expand_tilde(&config.audit.db_path);
    let store = AuditStore::open(Path::new(&db_path)).context("opening audit database")?;

    let mut filter = AuditFilter {
        limit: Some(limit.unwrap_or(50)),
        sort: SortOrder::Descending,
        ..Default::default()
    };

    if let Some(et) = event_type {
        if let Ok(parsed) = serde_json::from_value(serde_json::Value::String(et.to_string())) {
            filter.event_types = vec![parsed];
        }
    }

    if let Some(o) = outcome {
        if let Ok(parsed) = serde_json::from_value(serde_json::Value::String(o.to_string())) {
            filter.outcomes = vec![parsed];
        }
    }

    if let Some(op) = operator {
        filter.operators = vec![op.to_string()];
    }

    if let Some(t) = tool {
        filter.tool = Some(t.to_string());
    }

    if let Some(s) = since {
        if let Some(dt) = parse_relative_time(s) {
            filter.after = Some(dt);
        }
    }

    let events = store.query(&filter).context("querying audit events")?;
    for event in &events {
        println!("{}", serde_json::to_string(event).unwrap());
    }
    eprintln!("{} events found", events.len());
    Ok(())
}

/// Tail the most recent N audit events.
pub fn tail(config_path: &Path, count: usize) -> Result<()> {
    let config = load_config(config_path).context("loading configuration")?;
    let db_path = forculus_config::expand_tilde(&config.audit.db_path);
    let store = AuditStore::open(Path::new(&db_path)).context("opening audit database")?;

    let events = store.recent(count).context("querying recent events")?;
    for event in &events {
        println!("{}", serde_json::to_string(event).unwrap());
    }
    Ok(())
}

/// Show aggregate statistics.
pub fn stats(config_path: &Path, since: Option<&str>) -> Result<()> {
    let config = load_config(config_path).context("loading configuration")?;
    let db_path = forculus_config::expand_tilde(&config.audit.db_path);
    let store = AuditStore::open(Path::new(&db_path)).context("opening audit database")?;

    let since_dt = since.and_then(parse_relative_time);
    let stats = store.stats(since_dt).context("computing stats")?;

    println!("Total events: {}", stats.total_events);
    println!("Last hour:    {}", stats.last_hour);
    println!("Last day:     {}", stats.last_day);
    println!("Last week:    {}", stats.last_week);

    if !stats.by_event_type.is_empty() {
        println!("\nBy event type:");
        for (k, v) in &stats.by_event_type {
            println!("  {k}: {v}");
        }
    }

    if !stats.by_outcome.is_empty() {
        println!("\nBy outcome:");
        for (k, v) in &stats.by_outcome {
            println!("  {k}: {v}");
        }
    }

    if !stats.top_operators.is_empty() {
        println!("\nTop operators:");
        for (k, v) in &stats.top_operators {
            println!("  {k}: {v}");
        }
    }

    if !stats.top_tools.is_empty() {
        println!("\nTop tools:");
        for (k, v) in &stats.top_tools {
            println!("  {k}: {v}");
        }
    }

    Ok(())
}

/// Export audit events as JSON lines.
pub fn export(config_path: &Path, since: Option<&str>) -> Result<()> {
    let config = load_config(config_path).context("loading configuration")?;
    let db_path = forculus_config::expand_tilde(&config.audit.db_path);
    let store = AuditStore::open(Path::new(&db_path)).context("opening audit database")?;

    let mut filter = AuditFilter {
        sort: SortOrder::Ascending,
        ..Default::default()
    };

    if let Some(s) = since {
        if let Some(dt) = parse_relative_time(s) {
            filter.after = Some(dt);
        }
    }

    let events = store.query(&filter).context("querying audit events")?;
    for event in &events {
        println!("{}", serde_json::to_string(event).unwrap());
    }
    eprintln!("{} events exported", events.len());
    Ok(())
}

/// Run retention cleanup.
pub fn cleanup(config_path: &Path, days_override: Option<u32>) -> Result<()> {
    let config = load_config(config_path).context("loading configuration")?;
    let db_path = forculus_config::expand_tilde(&config.audit.db_path);
    let store = AuditStore::open(Path::new(&db_path)).context("opening audit database")?;

    let days = days_override.unwrap_or(config.audit.retention_days);
    let deleted = run_retention(&store, days).context("running retention")?;

    if deleted > 0 {
        eprintln!("Deleted {deleted} events older than {days} days");
    } else {
        eprintln!("No events older than {days} days to clean up");
    }
    Ok(())
}

/// Verify the integrity of the audit hash chain.
pub fn verify(config_path: &Path) -> Result<()> {
    let config = load_config(config_path).context("loading configuration")?;
    let db_path = forculus_config::expand_tilde(&config.audit.db_path);
    let store = AuditStore::open(Path::new(&db_path)).context("opening audit database")?;

    let result = store.verify_chain().context("verifying audit hash chain")?;

    if result.valid {
        eprintln!(
            "Audit hash chain is valid ({} events verified)",
            result.events_checked
        );
    } else {
        eprintln!("Audit hash chain INVALID!");
        eprintln!("  Events checked: {}", result.events_checked);
        if let Some(idx) = result.first_invalid_index {
            eprintln!("  First invalid event index: {idx}");
        }
        if let Some(err) = &result.error {
            eprintln!("  Error: {err}");
        }
        std::process::exit(1);
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
        // Try parsing as RFC 3339.
        chrono::DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|dt| dt.with_timezone(&chrono::Utc))
    }
}
