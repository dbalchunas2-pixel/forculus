//! `forculus inspect` — scan content for sensitive data and list rules.

use std::path::Path;

use anyhow::{Context, Result};
use forculus_config::load_config;
use forculus_inspect::scanner::ContentScanner;

/// Scan text or a file for sensitive content.
pub fn scan(
    config_path: &Path,
    text: Option<&str>,
    file: Option<&Path>,
    format: &str,
) -> Result<()> {
    let config = load_config(config_path).context("loading configuration")?;
    let scanner =
        ContentScanner::from_config(&config.inspect).context("creating content scanner")?;

    let content = if let Some(t) = text {
        t.to_string()
    } else if let Some(f) = file {
        std::fs::read_to_string(f).with_context(|| format!("reading file {}", f.display()))?
    } else {
        // Read from stdin.
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("reading from stdin")?;
        buf
    };

    let result = scanner.scan_text(&content);

    if format == "json" {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).context("serializing results")?
        );
        return Ok(());
    }

    // Table format.
    println!("Scanning content ({} bytes)...\n", content.len());

    if result.findings.is_empty() {
        println!("  No findings.");
        return Ok(());
    }

    println!(
        "  {:<28} {:<10} {:<18} {:<8} {:<18} SNIPPET",
        "RULE", "SEVERITY", "CATEGORY", "ACTION", "LOCATION"
    );
    for f in &result.findings {
        let severity = format!("{:?}", f.severity).to_lowercase();
        let category = serde_json::to_value(&f.category)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| format!("{:?}", f.category));
        let action = format!("{:?}", f.action).to_lowercase();
        let location = match &f.location {
            forculus_inspect::FindingLocation::ByteRange { start, end } => {
                format!("bytes {start}-{end}")
            }
            forculus_inspect::FindingLocation::JsonPath { path } => path.clone(),
            forculus_inspect::FindingLocation::Line { line } => format!("line {line}"),
            forculus_inspect::FindingLocation::Unknown => "unknown".to_string(),
        };
        let snippet = f.snippet.as_deref().unwrap_or("");
        println!(
            "  {:<28} {:<10} {:<18} {:<8} {:<18} {}",
            f.rule_id, severity, category, action, location, snippet
        );
    }

    let mut severity_counts = std::collections::HashMap::new();
    for f in &result.findings {
        *severity_counts
            .entry(format!("{:?}", f.severity).to_lowercase())
            .or_insert(0u32) += 1;
    }
    let summary: Vec<String> = severity_counts
        .iter()
        .map(|(k, v)| format!("{v} {k}"))
        .collect();

    let action_word = if result.should_block {
        "WOULD BLOCK"
    } else if result.should_redact {
        "WOULD REDACT"
    } else {
        "LOG ONLY"
    };
    println!(
        "\n{} findings ({}) -- {}",
        result.findings.len(),
        summary.join(", "),
        action_word
    );

    Ok(())
}

/// List all inspection rules.
pub fn rules(config_path: &Path, show_all: bool, json: bool) -> Result<()> {
    let config = load_config(config_path).context("loading configuration")?;
    let scanner =
        ContentScanner::from_config(&config.inspect).context("creating content scanner")?;
    let rule_set = scanner.rule_set();

    if json {
        let rules: Vec<serde_json::Value> = rule_set
            .all_rules()
            .iter()
            .filter(|r| show_all || r.enabled)
            .map(|r| {
                let m = &r.matcher;
                serde_json::json!({
                    "id": m.id,
                    "severity": format!("{:?}", m.severity).to_lowercase(),
                    "category": serde_json::to_value(&m.category).ok(),
                    "action": format!("{:?}", m.action).to_lowercase(),
                    "description": m.description,
                    "enabled": r.enabled,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&rules)?);
        return Ok(());
    }

    let enabled = rule_set.enabled_count();
    let total = rule_set.rule_count();
    let disabled = total - enabled;

    println!("Inspection Rules ({enabled} enabled, {disabled} disabled)\n");
    println!(
        "  {:<30} {:<10} {:<18} {:<8} DESCRIPTION",
        "ID", "SEVERITY", "CATEGORY", "ACTION"
    );

    for rule in rule_set.all_rules() {
        if !show_all && !rule.enabled {
            continue;
        }
        let m = &rule.matcher;
        let severity = format!("{:?}", m.severity).to_lowercase();
        let category = serde_json::to_value(&m.category)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| format!("{:?}", m.category));
        let action = format!("{:?}", m.action).to_lowercase();
        let status = if rule.enabled { "" } else { " [disabled]" };
        println!(
            "  {:<30} {:<10} {:<18} {:<8} {}{}",
            m.id, severity, category, action, m.description, status
        );
    }

    Ok(())
}
