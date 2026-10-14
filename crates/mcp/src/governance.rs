//! Governance metadata — attached to every tool call response.
//!
//! This establishes the wire format from day one.  Agents that understand
//! the `_meta.governance` field can use it; others ignore it.

use forculus_policy::verdict::PolicyEvaluation;

/// Return governance metadata based on a real policy evaluation.
pub fn governance_metadata(evaluation: &PolicyEvaluation) -> serde_json::Value {
    serde_json::json!({
        "governance": {
            "version": "0.2.0",
            "verdict": serde_json::to_value(&evaluation.verdict).unwrap_or_default(),
            "matched_rule": evaluation.matched_rule,
            "matched_policy": evaluation.matched_policy,
            "scope": serde_json::to_value(evaluation.scope).unwrap_or_default(),
            "reason": evaluation.reason,
            "evaluation_time_us": evaluation.evaluation_time.as_micros(),
        }
    })
}

/// Return stub governance metadata for a tool call response (no policy engine).
pub fn governance_metadata_stub() -> serde_json::Value {
    serde_json::json!({
        "governance": {
            "version": "0.2.0",
            "verdict": "allow",
            "policy_version": null,
            "session_id": null,
            "inspection_results": null,
            "audit_event_id": null
        }
    })
}
