//! Audit event types — the core data model for the audit log.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A single audit event — the atomic unit of the audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique event ID (UUID v4).
    pub id: String,
    /// When the event occurred.
    pub timestamp: DateTime<Utc>,
    /// What kind of event this is.
    pub event_type: EventType,
    /// The outcome of the event.
    pub outcome: EventOutcome,
    /// Which channel this event came through.
    pub channel: Channel,
    /// Session information (if a session was active).
    pub session: Option<SessionInfo>,
    /// Request information.
    pub request: Option<RequestInfo>,
    /// Policy evaluation information (if policy was evaluated).
    pub policy: Option<PolicyInfo>,
    /// Credential information (if a credential was involved).
    pub credential: Option<CredentialInfo>,
    /// Error information (if the event represents an error).
    pub error: Option<ErrorInfo>,
    /// Content inspection information (if inspection occurred).
    pub inspection: Option<InspectionInfo>,
    /// Wall-clock duration of the operation in microseconds.
    pub duration_us: Option<u64>,
    /// Blake3 hash of this event (computed at insert time for tamper detection).
    pub event_hash: Option<String>,
    /// Hash of the previous event in the chain (`"genesis"` for the first event).
    pub prev_hash: Option<String>,
}

/// The type of event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// A tool call or HTTP request was processed.
    RequestProcessed,
    /// A policy evaluation occurred.
    PolicyDecision,
    /// A credential was injected into an outbound request.
    CredentialInjected,
    /// A session was created.
    SessionCreated,
    /// A session was revoked.
    SessionRevoked,
    /// A session validation failed (invalid/expired/revoked token).
    SessionValidationFailed,
    /// An upstream server started or restarted.
    UpstreamLifecycle,
    /// A request was denied due to rate limiting.
    RateLimited,
    /// A request was denied because a cost budget was exceeded.
    BudgetExceeded,
    /// A request was denied because a tool definition violated hash pinning.
    ToolPinViolation,
    /// A CONNECT tunnel bypassed TLS MITM (passthrough mode).
    TlsPassthrough,
    /// A session was created via OIDC authentication.
    OidcSessionCreated,
    /// An error occurred during processing.
    Error,
}

/// The outcome of the event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventOutcome {
    /// The operation succeeded.
    Success,
    /// The operation was denied by policy.
    Denied,
    /// The operation requires human escalation.
    Escalated,
    /// The operation failed due to an error.
    Failed,
}

/// Which channel the event originated from.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    /// HTTP forward proxy.
    HttpProxy,
    /// HTTPS CONNECT tunnel.
    HttpsProxy,
    /// MCP gateway tool call.
    McpGateway,
    /// CLI command.
    Cli,
    /// Internal system event.
    System,
}

/// Session information attached to an event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    /// Session ID.
    pub session_id: String,
    /// Operator who created the session.
    pub operator: String,
    /// Team scope.
    pub team: Option<String>,
    /// Project scope.
    pub project: Option<String>,
    /// Environment scope.
    pub environment: Option<String>,
    /// Agent type.
    pub agent_type: Option<String>,
}

/// Request information attached to an event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestInfo {
    /// The tool or host being accessed.
    pub tool: String,
    /// The action being performed.
    pub action: String,
    /// The resource being acted on.
    pub resource: Option<String>,
    /// For HTTP: the full URL. For MCP: the namespaced tool name.
    pub target: String,
}

/// Policy evaluation information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyInfo {
    /// The verdict.
    pub verdict: String,
    /// The rule that matched.
    pub matched_rule: Option<String>,
    /// The policy file that contained the rule.
    pub matched_policy: Option<String>,
    /// The scope of the matched rule.
    pub scope: Option<String>,
    /// Human-readable reason.
    pub reason: String,
    /// Evaluation time in microseconds.
    pub evaluation_time_us: u64,
}

/// Credential usage information (never contains the secret itself).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialInfo {
    /// Name of the credential used.
    pub credential_name: String,
    /// Type of credential.
    pub credential_type: String,
    /// The binding that resolved this credential.
    pub binding_tool_pattern: Option<String>,
}

/// Error information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorInfo {
    /// Error category.
    pub category: String,
    /// Error message.
    pub message: String,
}

/// Content inspection information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectionInfo {
    /// Number of findings.
    pub finding_count: u64,
    /// Action taken: "blocked", "redacted", or "logged".
    pub action_taken: String,
    /// Maximum severity found (if any).
    pub max_severity: Option<String>,
}

impl AuditEvent {
    /// Start building an event.
    pub fn builder(event_type: EventType, channel: Channel) -> AuditEventBuilder {
        AuditEventBuilder {
            event: AuditEvent {
                id: String::new(),
                timestamp: Utc::now(),
                event_type,
                outcome: EventOutcome::Success,
                channel,
                session: None,
                request: None,
                policy: None,
                credential: None,
                error: None,
                inspection: None,
                duration_us: None,
                event_hash: None,
                prev_hash: None,
            },
        }
    }
}

/// Builder for ergonomic audit event construction.
pub struct AuditEventBuilder {
    event: AuditEvent,
}

impl AuditEventBuilder {
    /// Set the event outcome.
    pub fn outcome(mut self, outcome: EventOutcome) -> Self {
        self.event.outcome = outcome;
        self
    }

    /// Attach session information.
    pub fn session(mut self, info: SessionInfo) -> Self {
        self.event.session = Some(info);
        self
    }

    /// Attach request information.
    pub fn request(mut self, info: RequestInfo) -> Self {
        self.event.request = Some(info);
        self
    }

    /// Attach policy evaluation information.
    pub fn policy(mut self, info: PolicyInfo) -> Self {
        self.event.policy = Some(info);
        self
    }

    /// Attach credential information (never the secret!).
    pub fn credential(mut self, info: CredentialInfo) -> Self {
        self.event.credential = Some(info);
        self
    }

    /// Attach error information.
    pub fn error(mut self, info: ErrorInfo) -> Self {
        self.event.error = Some(info);
        self
    }

    /// Attach content inspection information.
    pub fn inspection(mut self, info: InspectionInfo) -> Self {
        self.event.inspection = Some(info);
        self
    }

    /// Set the operation duration in microseconds.
    pub fn duration_us(mut self, us: u64) -> Self {
        self.event.duration_us = Some(us);
        self
    }

    /// Build the event, auto-generating the ID and timestamp.
    pub fn build(mut self) -> AuditEvent {
        self.event.id = uuid::Uuid::new_v4().to_string();
        self.event.timestamp = Utc::now();
        self.event
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_produces_event_with_id_and_timestamp() {
        let event = AuditEvent::builder(EventType::RequestProcessed, Channel::HttpProxy).build();
        assert!(!event.id.is_empty());
        assert_eq!(event.event_type, EventType::RequestProcessed);
        assert_eq!(event.channel, Channel::HttpProxy);
        assert_eq!(event.outcome, EventOutcome::Success);
    }

    #[test]
    fn builder_with_all_optional_fields() {
        let event = AuditEvent::builder(EventType::RequestProcessed, Channel::McpGateway)
            .outcome(EventOutcome::Denied)
            .session(SessionInfo {
                session_id: "sid".into(),
                operator: "alice".into(),
                team: Some("eng".into()),
                project: None,
                environment: Some("staging".into()),
                agent_type: None,
            })
            .request(RequestInfo {
                tool: "github".into(),
                action: "push".into(),
                resource: None,
                target: "github__push".into(),
            })
            .policy(PolicyInfo {
                verdict: "deny".into(),
                matched_rule: Some("deny-all".into()),
                matched_policy: Some("global".into()),
                scope: Some("global".into()),
                reason: "blocked".into(),
                evaluation_time_us: 42,
            })
            .credential(CredentialInfo {
                credential_name: "gh-token".into(),
                credential_type: "bearer_token".into(),
                binding_tool_pattern: Some("github__*".into()),
            })
            .error(ErrorInfo {
                category: "policy".into(),
                message: "denied".into(),
            })
            .duration_us(1234)
            .build();

        assert_eq!(event.outcome, EventOutcome::Denied);
        assert!(event.session.is_some());
        assert!(event.request.is_some());
        assert!(event.policy.is_some());
        assert!(event.credential.is_some());
        assert!(event.error.is_some());
        assert_eq!(event.duration_us, Some(1234));
    }

    #[test]
    fn builder_minimal_event() {
        let event = AuditEvent::builder(EventType::Error, Channel::System).build();
        assert!(event.session.is_none());
        assert!(event.request.is_none());
        assert!(event.policy.is_none());
        assert!(event.credential.is_none());
        assert!(event.error.is_none());
        assert!(event.duration_us.is_none());
    }

    #[test]
    fn event_type_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&EventType::RequestProcessed).unwrap(),
            "\"request_processed\""
        );
        assert_eq!(
            serde_json::to_string(&EventType::CredentialInjected).unwrap(),
            "\"credential_injected\""
        );
        assert_eq!(
            serde_json::to_string(&EventType::SessionValidationFailed).unwrap(),
            "\"session_validation_failed\""
        );
    }

    #[test]
    fn oidc_session_created_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&EventType::OidcSessionCreated).unwrap(),
            "\"oidc_session_created\""
        );
    }

    #[test]
    fn event_outcome_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&EventOutcome::Success).unwrap(),
            "\"success\""
        );
        assert_eq!(
            serde_json::to_string(&EventOutcome::Denied).unwrap(),
            "\"denied\""
        );
    }

    #[test]
    fn audit_event_roundtrip() {
        let event = AuditEvent::builder(EventType::RequestProcessed, Channel::HttpProxy)
            .outcome(EventOutcome::Success)
            .duration_us(500)
            .build();
        let json = serde_json::to_string(&event).unwrap();
        let back: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, event.id);
        assert_eq!(back.event_type, EventType::RequestProcessed);
        assert_eq!(back.outcome, EventOutcome::Success);
        assert_eq!(back.duration_us, Some(500));
    }
}
