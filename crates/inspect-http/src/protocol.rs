//! Analyzer protocol — request/response types for HTTP callout analyzers.

use serde::{Deserialize, Serialize};

/// Request sent to an HTTP callout analyzer.
#[derive(Debug, Clone, Serialize)]
pub struct AnalyzerRequest {
    /// Unique request ID for correlation.
    pub request_id: String,
    /// Direction: `"outbound"` (request to upstream) or `"inbound"` (response from upstream).
    pub direction: String,
    /// The semantic tool name (if resolved).
    pub tool: Option<String>,
    /// The action being performed.
    pub action: Option<String>,
    /// Content type of the body.
    pub content_type: Option<String>,
    /// Base64-encoded request/response body.
    pub body: String,
    /// Additional metadata for the analyzer.
    pub metadata: AnalyzerMetadata,
}

/// Metadata sent alongside the analyzer request.
#[derive(Debug, Clone, Serialize)]
pub struct AnalyzerMetadata {
    /// Session ID (if a session is active).
    pub session_id: Option<String>,
    /// Operator who created the session.
    pub operator: Option<String>,
}

/// Response returned from an HTTP callout analyzer.
#[derive(Debug, Clone, Deserialize)]
pub struct AnalyzerResponse {
    /// Findings from the analyzer.
    pub findings: Vec<AnalyzerFinding>,
    /// Overall verdict: `"allow"`, `"deny"`, or `"transform"`.
    pub verdict: Option<String>,
}

/// A single finding from an analyzer.
#[derive(Debug, Clone, Deserialize)]
pub struct AnalyzerFinding {
    /// Type of finding (e.g. `"pii_detected"`, `"toxicity"`).
    #[serde(rename = "type")]
    pub finding_type: String,
    /// Severity: `"low"`, `"medium"`, `"high"`, `"critical"`.
    pub severity: String,
    /// Human-readable detail about the finding.
    pub detail: Option<String>,
    /// Recommended action: `"deny"`, `"redact"`, `"flag"`.
    pub action: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyzer_request_serializes() {
        let req = AnalyzerRequest {
            request_id: "req-123".into(),
            direction: "outbound".into(),
            tool: Some("slack".into()),
            action: Some("chat.postMessage".into()),
            content_type: Some("application/json".into()),
            body: "aGVsbG8=".into(),
            metadata: AnalyzerMetadata {
                session_id: Some("fcl_sess_abc".into()),
                operator: Some("alice@acme.com".into()),
            },
        };

        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["request_id"], "req-123");
        assert_eq!(json["direction"], "outbound");
        assert_eq!(json["tool"], "slack");
        assert_eq!(json["body"], "aGVsbG8=");
        assert_eq!(json["metadata"]["operator"], "alice@acme.com");
    }

    #[test]
    fn analyzer_response_deserializes() {
        let json = r#"{
            "findings": [
                {
                    "type": "pii_detected",
                    "severity": "high",
                    "detail": "Contains email addresses",
                    "action": "redact"
                }
            ],
            "verdict": "transform"
        }"#;

        let resp: AnalyzerResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.findings.len(), 1);
        assert_eq!(resp.findings[0].finding_type, "pii_detected");
        assert_eq!(resp.findings[0].severity, "high");
        assert_eq!(resp.verdict, Some("transform".into()));
    }

    #[test]
    fn analyzer_response_optional_fields() {
        let json = r#"{"findings": [], "verdict": null}"#;
        let resp: AnalyzerResponse = serde_json::from_str(json).unwrap();
        assert!(resp.findings.is_empty());
        assert!(resp.verdict.is_none());
    }

    #[test]
    fn analyzer_response_missing_verdict() {
        let json = r#"{"findings": []}"#;
        let resp: AnalyzerResponse = serde_json::from_str(json).unwrap();
        assert!(resp.findings.is_empty());
        assert!(resp.verdict.is_none());
    }

    #[test]
    fn analyzer_finding_missing_optional_fields() {
        let json = r#"{"type": "test", "severity": "low"}"#;
        let finding: AnalyzerFinding = serde_json::from_str(json).unwrap();
        assert_eq!(finding.finding_type, "test");
        assert!(finding.detail.is_none());
        assert!(finding.action.is_none());
    }
}
