//! Rate limiter — enforces per-dimension rate limits using token buckets.

use std::collections::HashMap;
use std::fmt;

use forculus_policy::glob::GlobPattern;

use crate::bucket::TokenBucket;

/// The dimension on which a rate limit is applied.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Dimension {
    /// Per-session rate limit.
    Session,
    /// Per-operator rate limit.
    Operator,
    /// Per-tool rate limit.
    Tool,
    /// Global rate limit (shared across all sessions/operators).
    Global,
}

impl fmt::Display for Dimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Dimension::Session => write!(f, "session"),
            Dimension::Operator => write!(f, "operator"),
            Dimension::Tool => write!(f, "tool"),
            Dimension::Global => write!(f, "global"),
        }
    }
}

impl Dimension {
    fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "session" => Some(Dimension::Session),
            "operator" => Some(Dimension::Operator),
            "tool" => Some(Dimension::Tool),
            "global" => Some(Dimension::Global),
            _ => None,
        }
    }
}

/// A compiled rate limit rule.
#[derive(Debug)]
struct CompiledRule {
    name: String,
    tool_patterns: Vec<GlobPattern>,
    rpm: u32,
    burst: u32,
    dimensions: Vec<Dimension>,
}

/// Key for looking up a token bucket.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct BucketKey {
    rule_name: String,
    dimension: Dimension,
    value: String,
}

/// Information about a rate limit denial.
#[derive(Debug, Clone)]
pub struct RateLimitDenial {
    /// Name of the rule that triggered the denial.
    pub rule_name: String,
    /// Which dimension was exhausted.
    pub dimension: Dimension,
    /// Estimated seconds until the request can be retried.
    pub retry_after_secs: Option<f64>,
}

/// The rate limiter — thread-safe, holds per-dimension token buckets.
pub struct RateLimiter {
    state: parking_lot::Mutex<LimiterState>,
}

struct LimiterState {
    rules: Vec<CompiledRule>,
    buckets: HashMap<BucketKey, TokenBucket>,
}

impl RateLimiter {
    /// Create a rate limiter from config rules.
    pub fn new(rules: Vec<forculus_config::RateLimitRule>) -> Result<Self, String> {
        let compiled = rules
            .into_iter()
            .map(|r| {
                let patterns: Result<Vec<GlobPattern>, String> =
                    r.tools.iter().map(|p| GlobPattern::compile(p)).collect();
                let dimensions: Vec<Dimension> = r
                    .dimensions
                    .iter()
                    .filter_map(|d| Dimension::from_str(d))
                    .collect();
                // Default to Global if no dimensions specified.
                let dimensions = if dimensions.is_empty() {
                    vec![Dimension::Global]
                } else {
                    dimensions
                };
                Ok(CompiledRule {
                    name: r.name.clone(),
                    tool_patterns: patterns?,
                    rpm: r.rpm,
                    burst: r.burst,
                    dimensions,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;

        Ok(Self {
            state: parking_lot::Mutex::new(LimiterState {
                rules: compiled,
                buckets: HashMap::new(),
            }),
        })
    }

    /// Check whether a request should be rate limited.
    ///
    /// Returns `Ok(())` if allowed, or `Err(RateLimitDenial)` if denied.
    pub fn check_rate_limit(
        &self,
        session_id: Option<&str>,
        operator: Option<&str>,
        tool: &str,
    ) -> Result<(), RateLimitDenial> {
        let mut state = self.state.lock();
        let LimiterState { rules, buckets } = &mut *state;

        for rule in rules.iter() {
            // Check if tool matches any of the rule's tool patterns.
            // Empty tool_patterns means "match all".
            let tool_matches =
                rule.tool_patterns.is_empty() || rule.tool_patterns.iter().any(|p| p.matches(tool));
            if !tool_matches {
                continue;
            }

            // Check each dimension.
            for dimension in &rule.dimensions {
                let key_value = match dimension {
                    Dimension::Session => match session_id {
                        Some(s) => s.to_string(),
                        None => continue, // skip session dimension if no session
                    },
                    Dimension::Operator => match operator {
                        Some(o) => o.to_string(),
                        None => continue,
                    },
                    Dimension::Tool => tool.to_string(),
                    Dimension::Global => "__global__".to_string(),
                };

                let bucket_key = BucketKey {
                    rule_name: rule.name.clone(),
                    dimension: dimension.clone(),
                    value: key_value,
                };

                let bucket = buckets
                    .entry(bucket_key)
                    .or_insert_with(|| TokenBucket::from_rpm(rule.rpm, rule.burst));

                if !bucket.try_consume(1.0) {
                    let retry_after = bucket.seconds_until_available(1.0);
                    return Err(RateLimitDenial {
                        rule_name: rule.name.clone(),
                        dimension: dimension.clone(),
                        retry_after_secs: if retry_after.is_finite() {
                            Some(retry_after)
                        } else {
                            None
                        },
                    });
                }
            }
        }

        Ok(())
    }
}

impl fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RateLimiter").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use forculus_config::RateLimitRule;

    fn rule(name: &str, tools: &[&str], rpm: u32, burst: u32, dims: &[&str]) -> RateLimitRule {
        RateLimitRule {
            name: name.to_string(),
            tools: tools.iter().map(|s| s.to_string()).collect(),
            rpm,
            burst,
            dimensions: dims.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn empty_rules_allows_all() {
        let limiter = RateLimiter::new(vec![]).unwrap();
        assert!(limiter.check_rate_limit(None, None, "anything").is_ok());
    }

    #[test]
    fn global_rate_limit() {
        let limiter = RateLimiter::new(vec![rule("global", &["*"], 60, 2, &["global"])]).unwrap();
        assert!(limiter.check_rate_limit(None, None, "tool").is_ok());
        assert!(limiter.check_rate_limit(None, None, "tool").is_ok());
        // Third request should be denied (burst=2).
        let result = limiter.check_rate_limit(None, None, "tool");
        assert!(result.is_err());
        let denial = result.unwrap_err();
        assert_eq!(denial.rule_name, "global");
        assert_eq!(denial.dimension, Dimension::Global);
    }

    #[test]
    fn per_session_isolation() {
        let limiter =
            RateLimiter::new(vec![rule("session-limit", &["*"], 60, 1, &["session"])]).unwrap();
        // Session A gets 1 request.
        assert!(
            limiter
                .check_rate_limit(Some("sess-a"), None, "tool")
                .is_ok()
        );
        assert!(
            limiter
                .check_rate_limit(Some("sess-a"), None, "tool")
                .is_err()
        );
        // Session B still has its own bucket.
        assert!(
            limiter
                .check_rate_limit(Some("sess-b"), None, "tool")
                .is_ok()
        );
    }

    #[test]
    fn per_operator_isolation() {
        let limiter =
            RateLimiter::new(vec![rule("op-limit", &["*"], 60, 1, &["operator"])]).unwrap();
        assert!(
            limiter
                .check_rate_limit(None, Some("alice"), "tool")
                .is_ok()
        );
        assert!(
            limiter
                .check_rate_limit(None, Some("alice"), "tool")
                .is_err()
        );
        assert!(limiter.check_rate_limit(None, Some("bob"), "tool").is_ok());
    }

    #[test]
    fn per_tool_dimension() {
        let limiter = RateLimiter::new(vec![rule("tool-limit", &["*"], 60, 1, &["tool"])]).unwrap();
        assert!(limiter.check_rate_limit(None, None, "openai").is_ok());
        assert!(limiter.check_rate_limit(None, None, "openai").is_err());
        // Different tool has its own bucket.
        assert!(limiter.check_rate_limit(None, None, "github").is_ok());
    }

    #[test]
    fn tool_pattern_matching() {
        let limiter =
            RateLimiter::new(vec![rule("openai-only", &["openai*"], 60, 1, &["global"])]).unwrap();
        // Matches openai.
        assert!(limiter.check_rate_limit(None, None, "openai").is_ok());
        assert!(limiter.check_rate_limit(None, None, "openai").is_err());
        // Doesn't match github — no limit.
        assert!(limiter.check_rate_limit(None, None, "github").is_ok());
        assert!(limiter.check_rate_limit(None, None, "github").is_ok());
    }

    #[test]
    fn multiple_rules() {
        let limiter = RateLimiter::new(vec![
            rule("tight", &["openai"], 60, 1, &["global"]),
            rule("loose", &["*"], 60, 100, &["global"]),
        ])
        .unwrap();
        // First openai request: passes both rules.
        assert!(limiter.check_rate_limit(None, None, "openai").is_ok());
        // Second openai: fails tight rule.
        assert!(limiter.check_rate_limit(None, None, "openai").is_err());
        // github only hits "loose" rule, still plenty of budget.
        assert!(limiter.check_rate_limit(None, None, "github").is_ok());
    }

    #[test]
    fn skip_session_dimension_when_no_session() {
        let limiter =
            RateLimiter::new(vec![rule("session-only", &["*"], 60, 1, &["session"])]).unwrap();
        // No session ID → session dimension is skipped → always allowed.
        assert!(limiter.check_rate_limit(None, None, "tool").is_ok());
        assert!(limiter.check_rate_limit(None, None, "tool").is_ok());
    }

    #[test]
    fn denial_has_retry_after() {
        let limiter = RateLimiter::new(vec![rule("test", &["*"], 60, 1, &["global"])]).unwrap();
        assert!(limiter.check_rate_limit(None, None, "tool").is_ok());
        let denial = limiter.check_rate_limit(None, None, "tool").unwrap_err();
        assert!(denial.retry_after_secs.is_some());
        assert!(denial.retry_after_secs.unwrap() > 0.0);
    }

    #[test]
    fn multiple_dimensions_per_rule() {
        let limiter =
            RateLimiter::new(vec![rule("multi", &["*"], 60, 1, &["session", "global"])]).unwrap();
        // First request: both session and global get 1 token.
        assert!(
            limiter
                .check_rate_limit(Some("sess-a"), None, "tool")
                .is_ok()
        );
        // Second: both session and global are depleted.
        assert!(
            limiter
                .check_rate_limit(Some("sess-a"), None, "tool")
                .is_err()
        );
    }

    #[test]
    fn empty_tool_patterns_match_all() {
        let limiter = RateLimiter::new(vec![rule("catch-all", &[], 60, 2, &["global"])]).unwrap();
        assert!(limiter.check_rate_limit(None, None, "anything").is_ok());
        assert!(limiter.check_rate_limit(None, None, "whatever").is_ok());
        assert!(limiter.check_rate_limit(None, None, "more").is_err());
    }

    #[test]
    fn global_bucket_shared_across_sessions_and_operators() {
        // A global dimension bucket is shared regardless of session/operator identity.
        let limiter = RateLimiter::new(vec![rule("shared", &["*"], 60, 2, &["global"])]).unwrap();
        // Different session IDs and operators all consume from the same global bucket.
        assert!(
            limiter
                .check_rate_limit(Some("sess-a"), Some("alice"), "tool")
                .is_ok()
        );
        assert!(
            limiter
                .check_rate_limit(Some("sess-b"), Some("bob"), "tool")
                .is_ok()
        );
        // Third request from yet another session/operator exceeds the global burst of 2.
        assert!(
            limiter
                .check_rate_limit(Some("sess-c"), Some("charlie"), "tool")
                .is_err()
        );
    }
}
