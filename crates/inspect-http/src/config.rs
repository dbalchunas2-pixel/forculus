//! Configuration types for HTTP callout analyzers.

use serde::{Deserialize, Serialize};

/// Configuration for a single HTTP callout analyzer.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HttpAnalyzerConfig {
    /// Human-readable name for this analyzer.
    pub name: String,
    /// HTTP endpoint to POST analysis requests to.
    pub endpoint: String,
    /// Request timeout in milliseconds.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Behavior on error: `fail_open` or `fail_closed`.
    #[serde(default)]
    pub on_error: OnError,
    /// Circuit breaker settings.
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfig,
    /// Response caching settings.
    #[serde(default)]
    pub cache: CacheConfig,
    /// Conditions under which this analyzer runs.
    #[serde(default)]
    pub condition: AnalyzerCondition,
}

/// Behavior when an analyzer fails (timeout, HTTP error, parse error).
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OnError {
    /// Return empty findings on failure (don't block).
    #[default]
    FailOpen,
    /// Return a synthetic deny finding on failure.
    FailClosed,
}

/// Circuit breaker configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures before opening the circuit.
    pub failure_threshold: u32,
    /// Cooldown period in seconds before trying again.
    pub cooldown_seconds: u64,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            cooldown_seconds: 30,
        }
    }
}

/// Cache configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct CacheConfig {
    /// Whether caching is enabled.
    pub enabled: bool,
    /// TTL for cached entries in seconds.
    pub ttl_seconds: u64,
    /// Maximum number of cached entries.
    pub max_entries: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ttl_seconds: 60,
            max_entries: 1000,
        }
    }
}

/// Conditions under which an analyzer runs.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct AnalyzerCondition {
    /// Only run for these content types (empty = all).
    pub content_types: Vec<String>,
    /// Minimum body size in bytes to trigger this analyzer.
    pub min_body_bytes: usize,
}

fn default_timeout_ms() -> u64 {
    200
}

impl From<&forculus_inspect::config::HttpAnalyzerConfigRef> for HttpAnalyzerConfig {
    fn from(r: &forculus_inspect::config::HttpAnalyzerConfigRef) -> Self {
        let on_error = if r.on_error == "fail_closed" {
            OnError::FailClosed
        } else {
            OnError::FailOpen
        };
        Self {
            name: r.name.clone(),
            endpoint: r.endpoint.clone(),
            timeout_ms: r.timeout_ms,
            on_error,
            circuit_breaker: CircuitBreakerConfig {
                failure_threshold: r.circuit_breaker.failure_threshold,
                cooldown_seconds: r.circuit_breaker.cooldown_seconds,
            },
            cache: CacheConfig {
                enabled: r.cache.enabled,
                ttl_seconds: r.cache.ttl_seconds,
                max_entries: r.cache.max_entries,
            },
            condition: AnalyzerCondition {
                content_types: r.condition.content_types.clone(),
                min_body_bytes: r.condition.min_body_bytes,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_deserializes_from_yaml() {
        let yaml = r#"
name: acme-pii-classifier
endpoint: http://pii-service.internal:8080/analyze
timeout_ms: 200
on_error: fail_open
circuit_breaker:
  failure_threshold: 5
  cooldown_seconds: 30
cache:
  enabled: true
  ttl_seconds: 60
  max_entries: 1000
condition:
  content_types: ["application/json"]
  min_body_bytes: 100
"#;
        let cfg: HttpAnalyzerConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.name, "acme-pii-classifier");
        assert_eq!(cfg.timeout_ms, 200);
        assert_eq!(cfg.on_error, OnError::FailOpen);
        assert_eq!(cfg.circuit_breaker.failure_threshold, 5);
        assert!(cfg.cache.enabled);
        assert_eq!(cfg.condition.content_types, vec!["application/json"]);
        assert_eq!(cfg.condition.min_body_bytes, 100);
    }

    #[test]
    fn config_defaults() {
        let yaml = r#"
name: minimal
endpoint: http://localhost:8080/analyze
"#;
        let cfg: HttpAnalyzerConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.timeout_ms, 200);
        assert_eq!(cfg.on_error, OnError::FailOpen);
        assert_eq!(cfg.circuit_breaker.failure_threshold, 5);
        assert!(!cfg.cache.enabled);
        assert!(cfg.condition.content_types.is_empty());
    }
}
