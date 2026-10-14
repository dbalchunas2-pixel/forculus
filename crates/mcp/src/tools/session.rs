//! `forculus__session_list` — list active sessions in the vault.

use crate::types::{Tool, ToolCallResult};

use super::{BuiltinContext, error_result, json_result};

pub fn tool_definition() -> Tool {
    Tool {
        name: "forculus__session_list".to_string(),
        description: Some("List active sessions in the vault".to_string()),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "include_revoked": {
                    "type": "boolean",
                    "description": "Include revoked sessions (default false)"
                }
            }
        }),
    }
}

pub fn handle(ctx: &BuiltinContext, arguments: Option<serde_json::Value>) -> ToolCallResult {
    let vault = match &ctx.vault {
        Some(v) => v,
        None => return error_result("Vault not configured"),
    };

    let include_revoked = arguments
        .as_ref()
        .and_then(|a| a.get("include_revoked"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let vault_guard = vault.lock();
    match vault_guard.list_sessions(include_revoked) {
        Ok(sessions) => {
            let sessions_json: Vec<serde_json::Value> = sessions
                .iter()
                .map(|s| {
                    serde_json::json!({
                        "id": s.id,
                        "operator": s.operator,
                        "team": s.team,
                        "project": s.project,
                        "environment": s.environment,
                        "agent_type": s.agent_type,
                        "created_at": s.created_at.to_rfc3339(),
                        "expires_at": s.expires_at.map(|t| t.to_rfc3339()),
                        "revoked": s.revoked,
                        "description": s.description,
                    })
                })
                .collect();
            json_result(serde_json::json!({
                "count": sessions_json.len(),
                "sessions": sessions_json,
            }))
        }
        Err(e) => error_result(&format!("Failed to list sessions: {e}")),
    }
}
