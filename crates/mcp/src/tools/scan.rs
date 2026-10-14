//! `forculus__scan_content` — scan text for sensitive content.

use crate::types::{Tool, ToolCallResult};

use super::{BuiltinContext, error_result, json_result};

pub fn tool_definition() -> Tool {
    Tool {
        name: "forculus__scan_content".to_string(),
        description: Some("Scan text for secrets, PII, and prompt injection patterns".to_string()),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "Text content to scan"
                }
            },
            "required": ["text"]
        }),
    }
}

pub fn handle(ctx: &BuiltinContext, arguments: Option<serde_json::Value>) -> ToolCallResult {
    let scanner = match &ctx.content_scanner {
        Some(s) => s,
        None => return error_result("Content scanner not configured"),
    };

    let text = match arguments
        .as_ref()
        .and_then(|a| a.get("text"))
        .and_then(|v| v.as_str())
    {
        Some(t) => t,
        None => return error_result("Missing required parameter: text"),
    };

    let result = scanner.scan_text(text);

    json_result(serde_json::json!({
        "finding_count": result.findings.len(),
        "should_block": result.should_block,
        "should_redact": result.should_redact,
        "max_severity": result.max_severity,
        "inspection_time_us": result.inspection_time_us,
        "findings": result.findings.iter().map(|f| serde_json::json!({
            "rule_id": f.rule_id,
            "description": f.description,
            "severity": f.severity,
            "category": f.category,
            "action": f.action,
        })).collect::<Vec<_>>(),
    }))
}
