//! Integration tests for the HTTP callout analyzer pipeline.

use forculus_inspect_http::HttpAnalyzerPipeline;
use forculus_inspect_http::config::{
    AnalyzerCondition, CacheConfig, CircuitBreakerConfig, HttpAnalyzerConfig, OnError,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn test_config(endpoint: &str) -> HttpAnalyzerConfig {
    HttpAnalyzerConfig {
        name: "test-analyzer".into(),
        endpoint: endpoint.to_string(),
        timeout_ms: 2000,
        on_error: OnError::FailOpen,
        circuit_breaker: CircuitBreakerConfig {
            failure_threshold: 5,
            cooldown_seconds: 30,
        },
        cache: CacheConfig {
            enabled: false,
            ttl_seconds: 60,
            max_entries: 100,
        },
        condition: AnalyzerCondition::default(),
    }
}

#[tokio::test]
async fn successful_callout_returns_findings() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/analyze"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "findings": [
                {
                    "type": "pii_detected",
                    "severity": "high",
                    "detail": "Contains email addresses",
                    "action": "redact"
                }
            ],
            "verdict": "transform"
        })))
        .mount(&mock_server)
        .await;

    let config = test_config(&format!("{}/analyze", mock_server.uri()));
    let pipeline = HttpAnalyzerPipeline::new(&[config]);

    let findings = pipeline
        .analyze(
            "outbound",
            b"test body content",
            None,
            None,
            None,
            None,
            None,
        )
        .await;

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].action, forculus_inspect::FindingAction::Redact);
    assert_eq!(findings[0].severity, forculus_inspect::Severity::High);
}

#[tokio::test]
async fn timeout_triggers_fail_open() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/analyze"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"findings": [], "verdict": "allow"}))
                .set_delay(std::time::Duration::from_secs(5)),
        )
        .mount(&mock_server)
        .await;

    let mut config = test_config(&format!("{}/analyze", mock_server.uri()));
    config.timeout_ms = 50; // 50ms timeout

    let pipeline = HttpAnalyzerPipeline::new(&[config]);

    let findings = pipeline
        .analyze("outbound", b"test body", None, None, None, None, None)
        .await;

    // fail_open: empty findings on timeout
    assert!(findings.is_empty());
}

#[tokio::test]
async fn fail_closed_on_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/analyze"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock_server)
        .await;

    let mut config = test_config(&format!("{}/analyze", mock_server.uri()));
    config.on_error = OnError::FailClosed;

    let pipeline = HttpAnalyzerPipeline::new(&[config]);

    let findings = pipeline
        .analyze("outbound", b"test body", None, None, None, None, None)
        .await;

    // fail_closed: synthetic deny finding
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].action, forculus_inspect::FindingAction::Block);
    assert!(findings[0].rule_id.contains("unavailable"));
}

#[tokio::test]
async fn multiple_analyzers_merge_findings() {
    let mock1 = MockServer::start().await;
    let mock2 = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/analyze"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "findings": [
                {"type": "finding_a", "severity": "low", "action": "flag"}
            ],
            "verdict": "allow"
        })))
        .mount(&mock1)
        .await;

    Mock::given(method("POST"))
        .and(path("/analyze"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "findings": [
                {"type": "finding_b", "severity": "medium", "action": "flag"},
                {"type": "finding_c", "severity": "high", "action": "redact"}
            ],
            "verdict": "transform"
        })))
        .mount(&mock2)
        .await;

    let config1 = test_config(&format!("{}/analyze", mock1.uri()));
    let mut config2 = test_config(&format!("{}/analyze", mock2.uri()));
    config2.name = "analyzer-2".into();

    let pipeline = HttpAnalyzerPipeline::new(&[config1, config2]);

    let findings = pipeline
        .analyze("outbound", b"test body", None, None, None, None, None)
        .await;

    // Should merge findings from both analyzers
    assert_eq!(findings.len(), 3);
}

#[tokio::test]
async fn condition_content_type_filter() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/analyze"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "findings": [{"type": "test", "severity": "low"}],
            "verdict": "allow"
        })))
        .expect(0) // Should NOT be called
        .mount(&mock_server)
        .await;

    let mut config = test_config(&format!("{}/analyze", mock_server.uri()));
    config.condition.content_types = vec!["application/json".to_string()];

    let pipeline = HttpAnalyzerPipeline::new(&[config]);

    // Send with text/plain content type — should not match
    let findings = pipeline
        .analyze(
            "outbound",
            b"body",
            None,
            None,
            Some("text/plain"),
            None,
            None,
        )
        .await;

    assert!(findings.is_empty());
}

#[tokio::test]
async fn condition_min_body_bytes_filter() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/analyze"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "findings": [{"type": "test", "severity": "low"}],
            "verdict": "allow"
        })))
        .expect(0) // Should NOT be called
        .mount(&mock_server)
        .await;

    let mut config = test_config(&format!("{}/analyze", mock_server.uri()));
    config.condition.min_body_bytes = 1000;

    let pipeline = HttpAnalyzerPipeline::new(&[config]);

    // Body is too small
    let findings = pipeline
        .analyze("outbound", b"small", None, None, None, None, None)
        .await;

    assert!(findings.is_empty());
}
