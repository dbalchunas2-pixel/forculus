//! Forculus builtin governance tools — exposed as `forculus__*` in the MCP tools/list.

use std::sync::Arc;

use forculus_audit::store::AuditStore;
use forculus_inspect::scanner::ContentScanner;
use forculus_policy::engine::PolicyEngine;
use forculus_vault::store::Vault;

use crate::types::{Tool, ToolCallResult, ToolContent};

mod audit;
mod policy;
mod scan;
mod session;

/// The namespace prefix for builtin tools.
pub const BUILTIN_PREFIX: &str = "forculus";

/// Subsystem references for builtin tool handlers.
pub struct BuiltinContext {
    pub content_scanner: Option<Arc<ContentScanner>>,
    pub audit_store: Option<Arc<parking_lot::Mutex<AuditStore>>>,
    pub policy_engine: Option<Arc<PolicyEngine>>,
    pub vault: Option<Arc<parking_lot::Mutex<Vault>>>,
}

/// Return the list of builtin tool definitions (already namespaced with `forculus__`).
pub fn builtin_tools() -> Vec<Tool> {
    vec![
        scan::tool_definition(),
        audit::search_tool_definition(),
        audit::tail_tool_definition(),
        audit::stats_tool_definition(),
        audit::verify_tool_definition(),
        policy::tool_definition(),
        session::tool_definition(),
    ]
}

/// Dispatch a builtin tool call by tool name (without the `forculus__` prefix).
pub fn dispatch(
    ctx: &BuiltinContext,
    tool_name: &str,
    arguments: Option<serde_json::Value>,
) -> ToolCallResult {
    match tool_name {
        "scan_content" => scan::handle(ctx, arguments),
        "audit_search" => audit::handle_search(ctx, arguments),
        "audit_tail" => audit::handle_tail(ctx, arguments),
        "audit_stats" => audit::handle_stats(ctx, arguments),
        "audit_verify" => audit::handle_verify(ctx),
        "policy_evaluate" => policy::handle(ctx, arguments),
        "session_list" => session::handle(ctx, arguments),
        _ => error_result(&format!("Unknown builtin tool: {tool_name}")),
    }
}

/// Helper to create an error result.
fn error_result(message: &str) -> ToolCallResult {
    ToolCallResult {
        content: vec![ToolContent::Text {
            text: message.to_string(),
        }],
        is_error: Some(true),
    }
}

/// Helper to create a success result with JSON.
fn json_result(value: serde_json::Value) -> ToolCallResult {
    ToolCallResult {
        content: vec![ToolContent::Text {
            text: serde_json::to_string_pretty(&value)
                .unwrap_or_else(|e| format!("Error serializing: {e}")),
        }],
        is_error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_context() -> BuiltinContext {
        BuiltinContext {
            content_scanner: None,
            audit_store: None,
            policy_engine: None,
            vault: None,
        }
    }

    #[test]
    fn builtin_tools_returns_seven_tools() {
        let tools = builtin_tools();
        assert_eq!(tools.len(), 7);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"forculus__scan_content"));
        assert!(names.contains(&"forculus__audit_search"));
        assert!(names.contains(&"forculus__audit_tail"));
        assert!(names.contains(&"forculus__audit_stats"));
        assert!(names.contains(&"forculus__audit_verify"));
        assert!(names.contains(&"forculus__policy_evaluate"));
        assert!(names.contains(&"forculus__session_list"));
    }

    #[test]
    fn all_builtin_tools_have_descriptions() {
        for tool in builtin_tools() {
            assert!(
                tool.description.is_some(),
                "tool {} missing description",
                tool.name
            );
        }
    }

    #[test]
    fn all_builtin_tools_have_input_schemas() {
        for tool in builtin_tools() {
            assert!(
                tool.input_schema.is_object(),
                "tool {} has non-object input_schema",
                tool.name
            );
        }
    }

    #[test]
    fn dispatch_unknown_tool_returns_error() {
        let ctx = empty_context();
        let result = dispatch(&ctx, "nonexistent", None);
        assert_eq!(result.is_error, Some(true));
        match &result.content[0] {
            ToolContent::Text { text } => {
                assert!(text.contains("Unknown builtin tool"));
            }
            _ => panic!("expected text content"),
        }
    }

    #[test]
    fn scan_content_without_scanner_returns_error() {
        let ctx = empty_context();
        let result = dispatch(
            &ctx,
            "scan_content",
            Some(serde_json::json!({"text": "hello"})),
        );
        assert_eq!(result.is_error, Some(true));
    }

    #[test]
    fn scan_content_with_scanner_returns_findings() {
        let scanner = Arc::new(ContentScanner::builtin());
        let ctx = BuiltinContext {
            content_scanner: Some(scanner),
            ..empty_context()
        };
        let result = dispatch(
            &ctx,
            "scan_content",
            Some(serde_json::json!({"text": "AKIAIOSFODNN7EXAMPLE"})),
        );
        assert!(result.is_error.is_none());
        match &result.content[0] {
            ToolContent::Text { text } => {
                let parsed: serde_json::Value = serde_json::from_str(text).unwrap();
                assert!(parsed["finding_count"].as_u64().unwrap() > 0);
                assert!(parsed["should_block"].as_bool().unwrap());
            }
            _ => panic!("expected text content"),
        }
    }

    #[test]
    fn scan_content_missing_text_param_returns_error() {
        let scanner = Arc::new(ContentScanner::builtin());
        let ctx = BuiltinContext {
            content_scanner: Some(scanner),
            ..empty_context()
        };
        let result = dispatch(&ctx, "scan_content", Some(serde_json::json!({})));
        assert_eq!(result.is_error, Some(true));
    }

    #[test]
    fn scan_content_clean_text_returns_no_findings() {
        let scanner = Arc::new(ContentScanner::builtin());
        let ctx = BuiltinContext {
            content_scanner: Some(scanner),
            ..empty_context()
        };
        let result = dispatch(
            &ctx,
            "scan_content",
            Some(serde_json::json!({"text": "Hello world, this is fine."})),
        );
        assert!(result.is_error.is_none());
        match &result.content[0] {
            ToolContent::Text { text } => {
                let parsed: serde_json::Value = serde_json::from_str(text).unwrap();
                assert_eq!(parsed["finding_count"].as_u64().unwrap(), 0);
                assert!(!parsed["should_block"].as_bool().unwrap());
            }
            _ => panic!("expected text content"),
        }
    }

    #[test]
    fn audit_search_without_store_returns_error() {
        let ctx = empty_context();
        let result = dispatch(&ctx, "audit_search", None);
        assert_eq!(result.is_error, Some(true));
    }

    #[test]
    fn audit_search_with_store_returns_results() {
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(&dir.path().join("audit.db")).unwrap();
        let ctx = BuiltinContext {
            audit_store: Some(Arc::new(parking_lot::Mutex::new(store))),
            ..empty_context()
        };
        let result = dispatch(&ctx, "audit_search", Some(serde_json::json!({"limit": 10})));
        assert!(result.is_error.is_none());
        match &result.content[0] {
            ToolContent::Text { text } => {
                let parsed: serde_json::Value = serde_json::from_str(text).unwrap();
                assert_eq!(parsed["count"].as_u64().unwrap(), 0);
                assert!(parsed["events"].as_array().unwrap().is_empty());
            }
            _ => panic!("expected text content"),
        }
    }

    #[test]
    fn audit_tail_returns_recent_events() {
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(&dir.path().join("audit.db")).unwrap();

        // Insert a test event.
        let event = forculus_audit::event::AuditEvent::builder(
            forculus_audit::event::EventType::RequestProcessed,
            forculus_audit::event::Channel::McpGateway,
        )
        .build();
        store.insert(&event).unwrap();

        let ctx = BuiltinContext {
            audit_store: Some(Arc::new(parking_lot::Mutex::new(store))),
            ..empty_context()
        };
        let result = dispatch(&ctx, "audit_tail", Some(serde_json::json!({"count": 5})));
        assert!(result.is_error.is_none());
        match &result.content[0] {
            ToolContent::Text { text } => {
                let parsed: serde_json::Value = serde_json::from_str(text).unwrap();
                assert_eq!(parsed["count"].as_u64().unwrap(), 1);
            }
            _ => panic!("expected text content"),
        }
    }

    #[test]
    fn audit_stats_returns_statistics() {
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(&dir.path().join("audit.db")).unwrap();
        let ctx = BuiltinContext {
            audit_store: Some(Arc::new(parking_lot::Mutex::new(store))),
            ..empty_context()
        };
        let result = dispatch(&ctx, "audit_stats", None);
        assert!(result.is_error.is_none());
        match &result.content[0] {
            ToolContent::Text { text } => {
                let parsed: serde_json::Value = serde_json::from_str(text).unwrap();
                assert_eq!(parsed["total_events"].as_u64().unwrap(), 0);
            }
            _ => panic!("expected text content"),
        }
    }

    #[test]
    fn audit_verify_on_empty_chain() {
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(&dir.path().join("audit.db")).unwrap();
        let ctx = BuiltinContext {
            audit_store: Some(Arc::new(parking_lot::Mutex::new(store))),
            ..empty_context()
        };
        let result = dispatch(&ctx, "audit_verify", None);
        assert!(result.is_error.is_none());
        match &result.content[0] {
            ToolContent::Text { text } => {
                let parsed: serde_json::Value = serde_json::from_str(text).unwrap();
                assert!(parsed["valid"].as_bool().unwrap());
                assert_eq!(parsed["events_checked"].as_u64().unwrap(), 0);
            }
            _ => panic!("expected text content"),
        }
    }

    #[test]
    fn policy_evaluate_without_engine_returns_error() {
        let ctx = empty_context();
        let result = dispatch(
            &ctx,
            "policy_evaluate",
            Some(serde_json::json!({"tool": "test", "action": "read"})),
        );
        assert_eq!(result.is_error, Some(true));
    }

    #[test]
    fn policy_evaluate_missing_params_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path()).unwrap();
        let engine = Arc::new(PolicyEngine::from_directory(dir.path()).unwrap());
        let ctx = BuiltinContext {
            policy_engine: Some(engine),
            ..empty_context()
        };
        // Missing required "action" parameter.
        let result = dispatch(
            &ctx,
            "policy_evaluate",
            Some(serde_json::json!({"tool": "test"})),
        );
        assert_eq!(result.is_error, Some(true));
    }

    #[test]
    fn policy_evaluate_with_engine_returns_verdict() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("test.yaml"),
            r#"
metadata:
  name: test
  scope: global
rules:
  - name: allow-reads
    verdict: allow
    reason: "reads are safe"
    match:
      actions: ["read_*"]
"#,
        )
        .unwrap();
        let engine = Arc::new(PolicyEngine::from_directory(dir.path()).unwrap());
        let ctx = BuiltinContext {
            policy_engine: Some(engine),
            ..empty_context()
        };
        let result = dispatch(
            &ctx,
            "policy_evaluate",
            Some(serde_json::json!({"tool": "github", "action": "read_file"})),
        );
        assert!(result.is_error.is_none());
        match &result.content[0] {
            ToolContent::Text { text } => {
                let parsed: serde_json::Value = serde_json::from_str(text).unwrap();
                assert_eq!(parsed["verdict"].as_str().unwrap(), "allow");
                assert_eq!(parsed["matched_rule"].as_str().unwrap(), "allow-reads");
            }
            _ => panic!("expected text content"),
        }
    }

    #[test]
    fn session_list_without_vault_returns_error() {
        let ctx = empty_context();
        let result = dispatch(&ctx, "session_list", None);
        assert_eq!(result.is_error, Some(true));
    }
}
