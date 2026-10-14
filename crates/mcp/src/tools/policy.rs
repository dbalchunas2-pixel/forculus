//! `forculus__policy_evaluate` — evaluate policy rules for a given request context.

use forculus_policy::context::RequestContext;

use crate::types::{Tool, ToolCallResult};

use super::{BuiltinContext, error_result, json_result};

pub fn tool_definition() -> Tool {
    Tool {
        name: "forculus__policy_evaluate".to_string(),
        description: Some("Evaluate policy rules for a given tool and action".to_string()),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "tool": {
                    "type": "string",
                    "description": "Tool name to evaluate"
                },
                "action": {
                    "type": "string",
                    "description": "Action to evaluate"
                },
                "operator": {
                    "type": "string",
                    "description": "Operator name"
                },
                "team": {
                    "type": "string",
                    "description": "Team scope"
                },
                "project": {
                    "type": "string",
                    "description": "Project scope"
                },
                "environment": {
                    "type": "string",
                    "description": "Environment scope"
                },
                "agent_type": {
                    "type": "string",
                    "description": "Agent type"
                }
            },
            "required": ["tool", "action"]
        }),
    }
}

pub fn handle(ctx: &BuiltinContext, arguments: Option<serde_json::Value>) -> ToolCallResult {
    let engine = match &ctx.policy_engine {
        Some(e) => e,
        None => return error_result("Policy engine not configured"),
    };

    let args = match arguments {
        Some(a) => a,
        None => return error_result("Missing arguments"),
    };

    let tool = match args.get("tool").and_then(|v| v.as_str()) {
        Some(t) => t,
        None => return error_result("Missing required parameter: tool"),
    };
    let action = match args.get("action").and_then(|v| v.as_str()) {
        Some(a) => a,
        None => return error_result("Missing required parameter: action"),
    };

    let mut req_ctx = RequestContext::new(tool, action);
    if let Some(op) = args.get("operator").and_then(|v| v.as_str()) {
        req_ctx = req_ctx.with_operator(op);
    }
    if let Some(team) = args.get("team").and_then(|v| v.as_str()) {
        req_ctx = req_ctx.with_team(team);
    }
    if let Some(project) = args.get("project").and_then(|v| v.as_str()) {
        req_ctx = req_ctx.with_project(project);
    }
    if let Some(env) = args.get("environment").and_then(|v| v.as_str()) {
        req_ctx = req_ctx.with_environment(env);
    }
    if let Some(agent) = args.get("agent_type").and_then(|v| v.as_str()) {
        req_ctx = req_ctx.with_agent_type(agent);
    }

    let eval = engine.evaluate(&req_ctx);

    json_result(serde_json::json!({
        "verdict": format!("{:?}", eval.verdict).to_lowercase(),
        "matched_rule": eval.matched_rule,
        "matched_policy": eval.matched_policy,
        "reason": eval.reason,
        "scope": format!("{:?}", eval.scope).to_lowercase(),
        "evaluation_time_us": eval.evaluation_time.as_micros() as u64,
    }))
}
