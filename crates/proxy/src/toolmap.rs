//! URL-to-tool mapper — resolves HTTP URLs to semantic tool/action names
//! so the same YAML policies can govern both MCP and HTTP agents.

use forculus_config::{ActionFrom, ToolMapping};
use forculus_policy::glob::GlobPattern;

/// A compiled URL-to-tool mapping entry.
#[derive(Debug)]
struct CompiledMapping {
    url_pattern: GlobPattern,
    tool: String,
    action_from: ActionFrom,
}

/// Resolved semantic tool and action for a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTool {
    /// Semantic tool name.
    pub tool: String,
    /// Semantic action name.
    pub action: String,
}

/// Maps URL patterns to semantic tool/action names. First match wins.
#[derive(Debug)]
pub struct ToolMapper {
    mappings: Vec<CompiledMapping>,
}

impl ToolMapper {
    /// Compile tool mappings from config. Returns an error if any glob pattern is invalid.
    pub fn new(mappings: Vec<ToolMapping>) -> Result<Self, String> {
        let compiled = mappings
            .into_iter()
            .map(|m| {
                let pattern = GlobPattern::compile(&m.url_pattern)?;
                Ok(CompiledMapping {
                    url_pattern: pattern,
                    tool: m.tool,
                    action_from: m.action_from,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;

        Ok(Self { mappings: compiled })
    }

    /// Resolve a URL and HTTP method to a semantic tool/action.
    ///
    /// The URL is matched as `host/path` (no scheme or query string).
    /// Returns `None` if no mapping matches.
    pub fn resolve(&self, url: &str, method: &str) -> Option<ResolvedTool> {
        let match_target = normalize_url(url);

        for mapping in &self.mappings {
            if mapping.url_pattern.matches(&match_target) {
                let path = extract_path(url);
                let action = match &mapping.action_from {
                    ActionFrom::UrlPath => path,
                    ActionFrom::Method => method.to_uppercase(),
                    ActionFrom::PathSegment(idx) => {
                        extract_path_segment(&path, *idx).unwrap_or_else(|| path.clone())
                    }
                    ActionFrom::Static(s) => s.clone(),
                };
                return Some(ResolvedTool {
                    tool: mapping.tool.clone(),
                    action,
                });
            }
        }

        None
    }
}

/// Normalize a URL to `host/path` for pattern matching.
fn normalize_url(url: &str) -> String {
    // Strip scheme.
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);

    // Strip query string and fragment.
    let without_query = without_scheme.split('?').next().unwrap_or(without_scheme);
    without_query
        .split('#')
        .next()
        .unwrap_or(without_query)
        .to_string()
}

/// Extract the path portion from a URL.
fn extract_path(url: &str) -> String {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);

    // Find the first `/` after the host.
    match without_scheme.find('/') {
        Some(idx) => {
            let path = &without_scheme[idx..];
            // Strip query string.
            path.split('?').next().unwrap_or(path).to_string()
        }
        None => "/".to_string(),
    }
}

/// Extract a specific path segment (0-indexed).
fn extract_path_segment(path: &str, index: usize) -> Option<String> {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    segments.get(index).map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapping(pattern: &str, tool: &str, action_from: ActionFrom) -> ToolMapping {
        ToolMapping {
            url_pattern: pattern.to_string(),
            tool: tool.to_string(),
            action_from,
        }
    }

    #[test]
    fn exact_host_match() {
        let mapper = ToolMapper::new(vec![mapping(
            "api.openai.com/*",
            "openai",
            ActionFrom::UrlPath,
        )])
        .unwrap();
        let result = mapper.resolve("https://api.openai.com/v1/chat", "POST");
        assert_eq!(
            result,
            Some(ResolvedTool {
                tool: "openai".to_string(),
                action: "/v1/chat".to_string(),
            })
        );
    }

    #[test]
    fn wildcard_host() {
        let mapper = ToolMapper::new(vec![mapping(
            "*.github.com/*",
            "github",
            ActionFrom::Method,
        )])
        .unwrap();
        let result = mapper.resolve("https://api.github.com/repos", "GET");
        assert_eq!(
            result,
            Some(ResolvedTool {
                tool: "github".to_string(),
                action: "GET".to_string(),
            })
        );
    }

    #[test]
    fn path_segment_action() {
        let mapper = ToolMapper::new(vec![mapping(
            "api.example.com/*",
            "example",
            ActionFrom::PathSegment(1),
        )])
        .unwrap();
        // /v1/users → segment 1 = "users"
        let result = mapper.resolve("http://api.example.com/v1/users/123", "GET");
        assert_eq!(
            result,
            Some(ResolvedTool {
                tool: "example".to_string(),
                action: "users".to_string(),
            })
        );
    }

    #[test]
    fn static_action() {
        let mapper = ToolMapper::new(vec![mapping(
            "api.openai.com/*",
            "openai",
            ActionFrom::Static("chat".to_string()),
        )])
        .unwrap();
        let result = mapper.resolve("https://api.openai.com/anything", "POST");
        assert_eq!(
            result,
            Some(ResolvedTool {
                tool: "openai".to_string(),
                action: "chat".to_string(),
            })
        );
    }

    #[test]
    fn no_match_returns_none() {
        let mapper = ToolMapper::new(vec![mapping(
            "api.openai.com/*",
            "openai",
            ActionFrom::UrlPath,
        )])
        .unwrap();
        assert!(mapper.resolve("https://example.com/test", "GET").is_none());
    }

    #[test]
    fn first_match_wins() {
        let mapper = ToolMapper::new(vec![
            mapping("api.openai.com/*", "openai-specific", ActionFrom::UrlPath),
            mapping("*", "catch-all", ActionFrom::Method),
        ])
        .unwrap();
        let result = mapper.resolve("https://api.openai.com/v1/chat", "POST");
        assert_eq!(result.unwrap().tool, "openai-specific");
    }

    #[test]
    fn case_insensitive_matching() {
        let mapper = ToolMapper::new(vec![mapping(
            "API.OPENAI.COM/*",
            "openai",
            ActionFrom::UrlPath,
        )])
        .unwrap();
        let result = mapper.resolve("https://api.openai.com/v1/chat", "POST");
        assert!(result.is_some());
    }

    #[test]
    fn strips_query_string() {
        let mapper = ToolMapper::new(vec![mapping(
            "api.example.com/search",
            "example",
            ActionFrom::UrlPath,
        )])
        .unwrap();
        let result = mapper.resolve("http://api.example.com/search?q=hello", "GET");
        assert!(result.is_some());
    }

    #[test]
    fn method_action_uppercase() {
        let mapper = ToolMapper::new(vec![mapping(
            "api.example.com/*",
            "example",
            ActionFrom::Method,
        )])
        .unwrap();
        let result = mapper.resolve("http://api.example.com/test", "post");
        assert_eq!(result.unwrap().action, "POST");
    }

    #[test]
    fn path_segment_fallback() {
        let mapper = ToolMapper::new(vec![mapping(
            "api.example.com/*",
            "example",
            ActionFrom::PathSegment(10), // way out of range
        )])
        .unwrap();
        let result = mapper.resolve("http://api.example.com/short", "GET");
        // Falls back to full path.
        assert_eq!(result.unwrap().action, "/short");
    }

    #[test]
    fn url_without_scheme() {
        let mapper = ToolMapper::new(vec![mapping(
            "api.example.com/*",
            "example",
            ActionFrom::UrlPath,
        )])
        .unwrap();
        let result = mapper.resolve("api.example.com/test", "GET");
        assert!(result.is_some());
    }

    #[test]
    fn empty_mapper() {
        let mapper = ToolMapper::new(vec![]).unwrap();
        assert!(mapper.resolve("https://anything.com/path", "GET").is_none());
    }

    #[test]
    fn normalize_url_strips_fragment() {
        assert_eq!(
            normalize_url("http://example.com/page#section"),
            "example.com/page"
        );
    }
}
