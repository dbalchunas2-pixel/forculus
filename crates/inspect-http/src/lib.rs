//! Forculus inspect-http — Tier 2 HTTP callout analyzers for content inspection.
//!
//! Extends the synchronous regex-based inspection in [`forculus_inspect`] with
//! async HTTP callouts to external analyzer services (ML classifiers, toxicity
//! filters, domain-specific content policies).
//!
//! The core [`inspect`](forculus_inspect) crate stays fully synchronous.  This
//! crate adds the async HTTP callout logic in a separate layer that the proxy
//! and MCP crates can call directly.
#![forbid(unsafe_code)]

pub mod cache;
pub mod circuit_breaker;
pub mod client;
pub mod config;
pub mod protocol;

use crate::cache::AnalyzerCache;
use crate::circuit_breaker::CircuitBreaker;
use crate::client::AnalyzerClient;
use crate::config::HttpAnalyzerConfig;
use crate::protocol::{AnalyzerMetadata, AnalyzerRequest};

/// Pipeline that fans out content to all configured HTTP analyzers,
/// merges their findings, and applies circuit breaker + cache logic.
pub struct HttpAnalyzerPipeline {
    analyzers: Vec<ManagedAnalyzer>,
}

struct ManagedAnalyzer {
    config: HttpAnalyzerConfig,
    client: AnalyzerClient,
    circuit_breaker: CircuitBreaker,
    cache: Option<AnalyzerCache>,
}

impl HttpAnalyzerPipeline {
    /// Create a new pipeline from analyzer configurations.
    pub fn new(configs: &[HttpAnalyzerConfig]) -> Self {
        let analyzers = configs
            .iter()
            .map(|cfg| {
                let client = AnalyzerClient::new(cfg);
                let circuit_breaker = CircuitBreaker::new(
                    cfg.circuit_breaker.failure_threshold,
                    std::time::Duration::from_secs(cfg.circuit_breaker.cooldown_seconds),
                );
                let cache = if cfg.cache.enabled {
                    Some(AnalyzerCache::new(
                        cfg.cache.max_entries,
                        std::time::Duration::from_secs(cfg.cache.ttl_seconds),
                    ))
                } else {
                    None
                };
                ManagedAnalyzer {
                    config: cfg.clone(),
                    client,
                    circuit_breaker,
                    cache,
                }
            })
            .collect();

        Self { analyzers }
    }

    /// Run all configured analyzers against the content.
    ///
    /// Returns merged findings from all analyzers. Respects conditions,
    /// circuit breakers, caching, and timeouts.
    #[allow(clippy::too_many_arguments)]
    pub async fn analyze(
        &self,
        direction: &str,
        body: &[u8],
        tool: Option<&str>,
        action: Option<&str>,
        content_type: Option<&str>,
        session_id: Option<&str>,
        operator: Option<&str>,
    ) -> Vec<forculus_inspect::InspectionFinding> {
        let mut all_findings = Vec::new();

        for analyzer in &self.analyzers {
            let findings = self
                .run_single_analyzer(
                    analyzer,
                    direction,
                    body,
                    tool,
                    action,
                    content_type,
                    session_id,
                    operator,
                )
                .await;
            all_findings.extend(findings);
        }

        all_findings
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_single_analyzer(
        &self,
        analyzer: &ManagedAnalyzer,
        direction: &str,
        body: &[u8],
        tool: Option<&str>,
        action: Option<&str>,
        content_type: Option<&str>,
        session_id: Option<&str>,
        operator: Option<&str>,
    ) -> Vec<forculus_inspect::InspectionFinding> {
        // Check condition: content_type filter.
        if !analyzer.config.condition.content_types.is_empty() {
            let ct = content_type.unwrap_or("");
            if !analyzer
                .config
                .condition
                .content_types
                .iter()
                .any(|allowed| ct.contains(allowed.as_str()))
            {
                return Vec::new();
            }
        }

        // Check condition: min_body_bytes.
        if body.len() < analyzer.config.condition.min_body_bytes {
            return Vec::new();
        }

        // Check circuit breaker.
        if !analyzer.circuit_breaker.should_allow() {
            tracing::debug!(
                analyzer = %analyzer.config.name,
                "circuit breaker open, skipping analyzer"
            );
            return self.fail_behavior(&analyzer.config);
        }

        // Check cache.
        let cache_key = AnalyzerCache::compute_key(&analyzer.config.name, body);
        if let Some(ref cache) = analyzer.cache {
            if let Some(cached) = cache.get(&cache_key) {
                tracing::debug!(
                    analyzer = %analyzer.config.name,
                    "cache hit"
                );
                return convert_findings(&cached.findings);
            }
        }

        // Build request.
        let request = AnalyzerRequest {
            request_id: uuid::Uuid::new_v4().to_string(),
            direction: direction.to_string(),
            tool: tool.map(String::from),
            action: action.map(String::from),
            content_type: content_type.map(String::from),
            body: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, body),
            metadata: AnalyzerMetadata {
                session_id: session_id.map(String::from),
                operator: operator.map(String::from),
            },
        };

        // Call analyzer with timeout.
        let timeout = std::time::Duration::from_millis(analyzer.config.timeout_ms);
        match tokio::time::timeout(timeout, analyzer.client.call(&request)).await {
            Ok(Ok(response)) => {
                analyzer.circuit_breaker.record_success();

                // Cache the response.
                if let Some(ref cache) = analyzer.cache {
                    cache.put(cache_key, response.clone());
                }

                convert_findings(&response.findings)
            }
            Ok(Err(e)) => {
                tracing::warn!(
                    analyzer = %analyzer.config.name,
                    error = %e,
                    "analyzer HTTP call failed"
                );
                analyzer.circuit_breaker.record_failure();
                self.fail_behavior(&analyzer.config)
            }
            Err(_) => {
                tracing::warn!(
                    analyzer = %analyzer.config.name,
                    timeout_ms = analyzer.config.timeout_ms,
                    "analyzer HTTP call timed out"
                );
                analyzer.circuit_breaker.record_failure();
                self.fail_behavior(&analyzer.config)
            }
        }
    }

    /// Determine findings to return on failure, based on `on_error` policy.
    fn fail_behavior(
        &self,
        config: &HttpAnalyzerConfig,
    ) -> Vec<forculus_inspect::InspectionFinding> {
        match config.on_error {
            config::OnError::FailOpen => Vec::new(),
            config::OnError::FailClosed => {
                vec![forculus_inspect::InspectionFinding {
                    rule_id: format!("http-analyzer-{}-unavailable", config.name),
                    description: format!(
                        "HTTP analyzer '{}' is unavailable (fail_closed policy)",
                        config.name
                    ),
                    severity: forculus_inspect::Severity::High,
                    category: forculus_inspect::FindingCategory::Custom(
                        "analyzer_unavailable".to_string(),
                    ),
                    location: forculus_inspect::FindingLocation::Unknown,
                    snippet: None,
                    action: forculus_inspect::FindingAction::Block,
                }]
            }
        }
    }
}

/// Convert analyzer protocol findings to inspection findings.
fn convert_findings(
    findings: &[protocol::AnalyzerFinding],
) -> Vec<forculus_inspect::InspectionFinding> {
    findings
        .iter()
        .map(|f| {
            let severity = match f.severity.to_lowercase().as_str() {
                "critical" => forculus_inspect::Severity::Critical,
                "high" => forculus_inspect::Severity::High,
                "medium" => forculus_inspect::Severity::Medium,
                "low" => forculus_inspect::Severity::Low,
                _ => forculus_inspect::Severity::Info,
            };

            let action = match f.action.as_deref().unwrap_or("flag") {
                "deny" | "block" => forculus_inspect::FindingAction::Block,
                "redact" => forculus_inspect::FindingAction::Redact,
                _ => forculus_inspect::FindingAction::Log,
            };

            forculus_inspect::InspectionFinding {
                rule_id: format!("http-analyzer:{}", f.finding_type),
                description: f.detail.clone().unwrap_or_else(|| f.finding_type.clone()),
                severity,
                category: forculus_inspect::FindingCategory::Custom(f.finding_type.clone()),
                location: forculus_inspect::FindingLocation::Unknown,
                snippet: None,
                action,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convert_findings_maps_severity() {
        let findings = vec![
            protocol::AnalyzerFinding {
                finding_type: "test".into(),
                severity: "critical".into(),
                detail: Some("detail".into()),
                action: Some("block".into()),
            },
            protocol::AnalyzerFinding {
                finding_type: "test2".into(),
                severity: "low".into(),
                detail: None,
                action: Some("flag".into()),
            },
        ];

        let result = convert_findings(&findings);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].severity, forculus_inspect::Severity::Critical);
        assert_eq!(result[0].action, forculus_inspect::FindingAction::Block);
        assert_eq!(result[1].severity, forculus_inspect::Severity::Low);
        assert_eq!(result[1].action, forculus_inspect::FindingAction::Log);
    }

    #[test]
    fn convert_findings_redact_action() {
        let findings = vec![protocol::AnalyzerFinding {
            finding_type: "pii".into(),
            severity: "high".into(),
            detail: Some("contains PII".into()),
            action: Some("redact".into()),
        }];

        let result = convert_findings(&findings);
        assert_eq!(result[0].action, forculus_inspect::FindingAction::Redact);
    }

    #[test]
    fn pipeline_new_empty() {
        let pipeline = HttpAnalyzerPipeline::new(&[]);
        assert!(pipeline.analyzers.is_empty());
    }
}
