//! Schema diet transformations for MCP tool definitions.

use crate::types::Tool;

const META_TOOL_SEARCH: &str = "forculus_tool_search";
const META_TOOL_SCHEMA: &str = "forculus_tool_schema";
const META_TOOL_CALL: &str = "forculus_tool_call";

pub const MAX_DESCRIPTION_CHARS: usize = 256;

pub fn meta_tool_names() -> [&'static str; 3] {
    [META_TOOL_SEARCH, META_TOOL_SCHEMA, META_TOOL_CALL]
}

pub fn is_meta_tool(name: &str) -> bool {
    matches!(name, META_TOOL_SEARCH | META_TOOL_SCHEMA | META_TOOL_CALL)
}

pub fn progressive_meta_tools() -> Vec<Tool> {
    vec![
        Tool {
            name: META_TOOL_SEARCH.to_string(),
            description: Some(
                "Search available tools first; returns matching names and summaries.".to_string(),
            ),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Text to match against tool names and descriptions"
                    },
                    "server": {
                        "type": "string",
                        "description": "Optional upstream server filter"
                    }
                },
                "required": ["query"],
                "additionalProperties": false
            }),
        },
        Tool {
            name: META_TOOL_SCHEMA.to_string(),
            description: Some(
                "After search, fetch one tool schema by name before calling it.".to_string(),
            ),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "tool": {
                        "type": "string",
                        "description": "Tool name (namespaced or bare with server)"
                    },
                    "server": {
                        "type": "string",
                        "description": "Optional upstream server when tool name is bare"
                    }
                },
                "required": ["tool"],
                "additionalProperties": false
            }),
        },
        Tool {
            name: META_TOOL_CALL.to_string(),
            description: Some(
                "After search/schema, call one tool via gateway policy and audit path.".to_string(),
            ),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "tool": {
                        "type": "string",
                        "description": "Tool name (namespaced or bare with server)"
                    },
                    "server": {
                        "type": "string",
                        "description": "Optional upstream server when tool name is bare"
                    },
                    "arguments": {
                        "type": "object",
                        "description": "Tool arguments object"
                    }
                },
                "required": ["tool"],
                "additionalProperties": false
            }),
        },
    ]
}

pub fn summarize_description(description: Option<&str>) -> String {
    let text = description.unwrap_or("").trim();
    if text.is_empty() {
        return String::new();
    }
    let clipped = text.chars().take(120).collect::<String>();
    if text.chars().count() > 120 {
        format!("{}…", clipped.trim_end())
    } else {
        clipped
    }
}

pub fn truncate_with_ellipsis(input: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    let input_chars = input.chars().count();
    if input_chars <= max_chars {
        return input.to_string();
    }
    if max_chars == 1 {
        return "…".to_string();
    }

    let budget = max_chars - 1;
    let mut candidate = String::new();
    for c in input.chars().take(budget) {
        candidate.push(c);
    }

    if let Some(last_ws_idx) = candidate.rfind(char::is_whitespace) {
        candidate.truncate(last_ws_idx);
        candidate = candidate.trim_end().to_string();
    }

    if candidate.is_empty() {
        candidate = input.chars().take(budget).collect();
    }

    format!("{}…", candidate)
}

pub fn minify_tool(tool: &mut Tool, max_description_chars: usize) {
    if let Some(desc) = &tool.description {
        tool.description = Some(truncate_with_ellipsis(desc, max_description_chars));
    }
    minify_schema_value(&mut tool.input_schema, max_description_chars);
}

pub fn minify_schema_value(value: &mut serde_json::Value, max_description_chars: usize) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::String(desc)) = map.get_mut("description") {
                *desc = truncate_with_ellipsis(desc, max_description_chars);
            }

            // Recurse first.
            for child in map.values_mut() {
                minify_schema_value(child, max_description_chars);
            }

            // Drop keys that are non-essential for invocation.
            map.remove("examples");
            map.remove("default");
            map.remove("$schema");
            map.remove("$id");
            map.remove("title");

            if let Some(serde_json::Value::String(format_hint)) = map.get("format") {
                if is_plain_format_hint(format_hint) {
                    map.remove("format");
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                minify_schema_value(item, max_description_chars);
            }
        }
        _ => {}
    }
}

fn is_plain_format_hint(value: &str) -> bool {
    if value.is_empty() || value.len() > 32 {
        return false;
    }
    value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncates_at_word_boundary_with_ellipsis() {
        let text = "This is a long sentence that should be truncated cleanly";
        let got = truncate_with_ellipsis(text, 24);
        assert_eq!(got, "This is a long…");
        assert!(got.chars().count() <= 24);
    }

    #[test]
    fn strips_nonessential_schema_keys() {
        let mut schema = serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "x",
            "title": "Top",
            "type": "object",
            "format": "email",
            "properties": {
                "path": {
                    "type": "string",
                    "title": "Path",
                    "examples": ["/tmp/a"],
                    "default": "/tmp/a",
                    "description": "A very long parameter description that should be truncated"
                }
            },
            "required": ["path"],
            "anyOf": [
                {
                    "type": "object",
                    "properties": {
                        "mode": {
                            "type": "string",
                            "enum": ["r", "w"],
                            "title": "Mode"
                        }
                    }
                }
            ]
        });

        minify_schema_value(&mut schema, 40);

        assert!(schema.get("$schema").is_none());
        assert!(schema.get("$id").is_none());
        assert!(schema.get("title").is_none());
        assert!(schema.get("format").is_none());
        assert_eq!(schema["type"], "object");
        assert!(schema.get("anyOf").is_some());
        assert!(schema["properties"]["path"].get("examples").is_none());
        assert!(schema["properties"]["path"].get("default").is_none());
        assert!(schema["properties"]["path"].get("title").is_none());
        assert!(
            schema["properties"]["path"]["description"]
                .as_str()
                .unwrap()
                .ends_with('…')
        );
    }
}
