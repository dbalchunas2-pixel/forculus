//! `forculus__audit_*` — audit log query tools.

use forculus_audit::event::{EventOutcome, EventType};
use forculus_audit::query::AuditFilter;

use crate::types::{Tool, ToolCallResult};

use super::{BuiltinContext, error_result, json_result};

pub fn search_tool_definition() -> Tool {
    Tool {
        name: "forculus__audit_search".to_string(),
        description: Some("Search audit events with filters".to_string()),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "event_type": {
                    "type": "string",
                    "description": "Filter by event type (e.g. request_processed, policy_decision)"
                },
                "outcome": {
                    "type": "string",
                    "description": "Filter by outcome (e.g. success, denied, failed)"
                },
                "operator": {
                    "type": "string",
                    "description": "Filter by operator name"
                },
                "tool": {
                    "type": "string",
                    "description": "Filter by tool name (supports * wildcard)"
                },
                "session_id": {
                    "type": "string",
                    "description": "Filter by session ID"
                },
                "limit": {
                    "type": "integer",
                    "description": "Max results (default 50)"
                }
            }
        }),
    }
}

pub fn tail_tool_definition() -> Tool {
    Tool {
        name: "forculus__audit_tail".to_string(),
        description: Some("Show the most recent audit events".to_string()),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "count": {
                    "type": "integer",
                    "description": "Number of events to return (default 20)"
                }
            }
        }),
    }
}

pub fn stats_tool_definition() -> Tool {
    Tool {
        name: "forculus__audit_stats".to_string(),
        description: Some("Show aggregate audit statistics".to_string()),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "since_hours": {
                    "type": "integer",
                    "description": "Show stats for the last N hours"
                }
            }
        }),
    }
}

pub fn verify_tool_definition() -> Tool {
    Tool {
        name: "forculus__audit_verify".to_string(),
        description: Some("Verify integrity of the audit hash chain".to_string()),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {}
        }),
    }
}

pub fn handle_search(ctx: &BuiltinContext, arguments: Option<serde_json::Value>) -> ToolCallResult {
    let store = match &ctx.audit_store {
        Some(s) => s,
        None => return error_result("Audit store not configured"),
    };

    let args = arguments.unwrap_or_default();

    let mut filter = AuditFilter::default();

    if let Some(et) = args.get("event_type").and_then(|v| v.as_str()) {
        if let Ok(event_type) =
            serde_json::from_value::<EventType>(serde_json::Value::String(et.to_string()))
        {
            filter.event_types = vec![event_type];
        }
    }
    if let Some(oc) = args.get("outcome").and_then(|v| v.as_str()) {
        if let Ok(outcome) =
            serde_json::from_value::<EventOutcome>(serde_json::Value::String(oc.to_string()))
        {
            filter.outcomes = vec![outcome];
        }
    }
    if let Some(op) = args.get("operator").and_then(|v| v.as_str()) {
        filter.operators = vec![op.to_string()];
    }
    if let Some(tool) = args.get("tool").and_then(|v| v.as_str()) {
        filter.tool = Some(tool.to_string());
    }
    if let Some(sid) = args.get("session_id").and_then(|v| v.as_str()) {
        filter.session_id = Some(sid.to_string());
    }
    filter.limit = Some(args.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize);

    let store_guard = store.lock();
    match store_guard.query(&filter) {
        Ok(events) => {
            let events_json: Vec<serde_json::Value> = events
                .iter()
                .map(|e| serde_json::to_value(e).unwrap_or_default())
                .collect();
            json_result(serde_json::json!({
                "count": events_json.len(),
                "events": events_json,
            }))
        }
        Err(e) => error_result(&format!("Audit query failed: {e}")),
    }
}

pub fn handle_tail(ctx: &BuiltinContext, arguments: Option<serde_json::Value>) -> ToolCallResult {
    let store = match &ctx.audit_store {
        Some(s) => s,
        None => return error_result("Audit store not configured"),
    };

    let count = arguments
        .as_ref()
        .and_then(|a| a.get("count"))
        .and_then(|v| v.as_u64())
        .unwrap_or(20) as usize;

    let store_guard = store.lock();
    match store_guard.recent(count) {
        Ok(events) => {
            let events_json: Vec<serde_json::Value> = events
                .iter()
                .map(|e| serde_json::to_value(e).unwrap_or_default())
                .collect();
            json_result(serde_json::json!({
                "count": events_json.len(),
                "events": events_json,
            }))
        }
        Err(e) => error_result(&format!("Audit tail failed: {e}")),
    }
}

pub fn handle_stats(ctx: &BuiltinContext, arguments: Option<serde_json::Value>) -> ToolCallResult {
    let store = match &ctx.audit_store {
        Some(s) => s,
        None => return error_result("Audit store not configured"),
    };

    let since = arguments
        .as_ref()
        .and_then(|a| a.get("since_hours"))
        .and_then(|v| v.as_u64())
        .map(|h| chrono::Utc::now() - chrono::Duration::hours(h as i64));

    let store_guard = store.lock();
    match store_guard.stats(since) {
        Ok(stats) => json_result(serde_json::to_value(&stats).unwrap_or_default()),
        Err(e) => error_result(&format!("Audit stats failed: {e}")),
    }
}

pub fn handle_verify(ctx: &BuiltinContext) -> ToolCallResult {
    let store = match &ctx.audit_store {
        Some(s) => s,
        None => return error_result("Audit store not configured"),
    };

    let store_guard = store.lock();
    match store_guard.verify_chain() {
        Ok(result) => json_result(serde_json::json!({
            "valid": result.valid,
            "events_checked": result.events_checked,
            "first_invalid_index": result.first_invalid_index,
            "error": result.error,
        })),
        Err(e) => error_result(&format!("Chain verification failed: {e}")),
    }
}
