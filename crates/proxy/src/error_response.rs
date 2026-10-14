//! Structured JSON error responses for the HTTP proxy.

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Response, StatusCode};
use serde::Serialize;

use crate::forward::BoxBody;

/// Structured error body returned as JSON in all proxy error responses.
#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub error: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub governance: Option<GovernanceInfo>,
}

/// Governance context attached to policy and inspection denials.
#[derive(Debug, Serialize)]
pub struct GovernanceInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
}

fn json_response(status: StatusCode, body: &ErrorBody) -> Response<BoxBody> {
    use http_body_util::BodyExt;
    let json = serde_json::to_string(body).expect("ErrorBody is always serializable");
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(
            Full::new(Bytes::from(json))
                .map_err(|never| match never {})
                .boxed(),
        )
        .expect("valid error response")
}

/// 401 — session required but not provided.
pub fn session_required() -> Response<BoxBody> {
    json_response(
        StatusCode::UNAUTHORIZED,
        &ErrorBody {
            error: "session_required".into(),
            message: "Session token required. Set X-Forculus-Session header.".into(),
            details: None,
            governance: None,
        },
    )
}

/// 401 — session token present but invalid/expired/revoked.
pub fn session_invalid() -> Response<BoxBody> {
    json_response(
        StatusCode::UNAUTHORIZED,
        &ErrorBody {
            error: "session_invalid".into(),
            message: "Invalid or expired session token".into(),
            details: None,
            governance: None,
        },
    )
}

/// 403 — policy evaluation denied the request.
pub fn policy_denied(
    eval: &forculus_policy::verdict::PolicyEvaluation,
    tool: &str,
    action: &str,
) -> Response<BoxBody> {
    json_response(
        StatusCode::FORBIDDEN,
        &ErrorBody {
            error: "policy_denied".into(),
            message: format!("Policy denied: {}", eval.reason),
            details: None,
            governance: Some(GovernanceInfo {
                matched_rule: eval.matched_rule.clone(),
                matched_policy: eval.matched_policy.clone(),
                scope: Some(serde_json::to_value(eval.scope).map_or_else(
                    |_| "unknown".into(),
                    |v| v.as_str().unwrap_or("unknown").to_string(),
                )),
                tool: Some(tool.to_string()),
                action: Some(action.to_string()),
            }),
        },
    )
}

/// 403 — content inspection blocked the request.
pub fn content_blocked(reason: &str) -> Response<BoxBody> {
    json_response(
        StatusCode::FORBIDDEN,
        &ErrorBody {
            error: "content_blocked".into(),
            message: reason.to_string(),
            details: None,
            governance: None,
        },
    )
}

/// 429 — rate limit exceeded.
pub fn rate_limited(rule_name: &str, retry_after_secs: Option<f64>) -> Response<BoxBody> {
    let details = retry_after_secs.map(|secs| serde_json::json!({ "retry_after_seconds": secs }));
    let mut resp = json_response(
        StatusCode::TOO_MANY_REQUESTS,
        &ErrorBody {
            error: "rate_limited".into(),
            message: format!("Rate limited: {rule_name}"),
            details,
            governance: None,
        },
    );
    if let Some(secs) = retry_after_secs {
        if let Ok(val) = format!("{}", secs.ceil() as u64).parse::<hyper::header::HeaderValue>() {
            resp.headers_mut().insert("retry-after", val);
        }
    }
    resp
}

/// 502 — upstream response blocked by content inspection.
pub fn response_blocked(reason: &str) -> Response<BoxBody> {
    json_response(
        StatusCode::BAD_GATEWAY,
        &ErrorBody {
            error: "response_blocked".into(),
            message: reason.to_string(),
            details: None,
            governance: None,
        },
    )
}

/// 502 — upstream connection or request failed.
pub fn upstream_error(message: &str) -> Response<BoxBody> {
    json_response(
        StatusCode::BAD_GATEWAY,
        &ErrorBody {
            error: "upstream_error".into(),
            message: message.to_string(),
            details: None,
            governance: None,
        },
    )
}

/// 400 — bad request from the client.
pub fn bad_request(message: &str) -> Response<BoxBody> {
    json_response(
        StatusCode::BAD_REQUEST,
        &ErrorBody {
            error: "bad_request".into(),
            message: message.to_string(),
            details: None,
            governance: None,
        },
    )
}

/// 500 — internal server error.
pub fn internal_error(message: &str) -> Response<BoxBody> {
    json_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        &ErrorBody {
            error: "internal_error".into(),
            message: message.to_string(),
            details: None,
            governance: None,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    async fn body_json(resp: Response<BoxBody>) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn session_required_returns_401_json() {
        let resp = session_required();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/json"
        );
        let json = body_json(resp).await;
        assert_eq!(json["error"], "session_required");
        assert!(json.get("governance").is_none());
    }

    #[tokio::test]
    async fn session_invalid_returns_401_json() {
        let resp = session_invalid();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(resp).await;
        assert_eq!(json["error"], "session_invalid");
    }

    #[tokio::test]
    async fn policy_denied_includes_governance() {
        let eval = forculus_policy::verdict::PolicyEvaluation {
            verdict: forculus_policy::verdict::Verdict::Deny,
            matched_rule: Some("block-destructive".into()),
            matched_policy: Some("prod-guard.yaml".into()),
            scope: forculus_policy::verdict::PolicyScope::Project,
            reason: "destructive ops blocked".into(),
            evaluation_time: std::time::Duration::from_micros(50),
        };
        let resp = policy_denied(&eval, "github", "delete_repo");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/json"
        );
        let json = body_json(resp).await;
        assert_eq!(json["error"], "policy_denied");
        assert!(
            json["message"]
                .as_str()
                .unwrap()
                .contains("destructive ops blocked")
        );
        let gov = &json["governance"];
        assert_eq!(gov["matched_rule"], "block-destructive");
        assert_eq!(gov["matched_policy"], "prod-guard.yaml");
        assert_eq!(gov["scope"], "project");
        assert_eq!(gov["tool"], "github");
        assert_eq!(gov["action"], "delete_repo");
    }

    #[tokio::test]
    async fn content_blocked_returns_403() {
        let resp = content_blocked("Request blocked by content inspection");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let json = body_json(resp).await;
        assert_eq!(json["error"], "content_blocked");
    }

    #[tokio::test]
    async fn rate_limited_returns_429_with_retry_after() {
        let resp = rate_limited("api-rate-limit", Some(30.5));
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(resp.headers().get("retry-after").unwrap(), "31");
        let json = body_json(resp).await;
        assert_eq!(json["error"], "rate_limited");
        assert_eq!(json["details"]["retry_after_seconds"], 30.5);
    }

    #[tokio::test]
    async fn rate_limited_without_retry_after_omits_header_and_details() {
        let resp = rate_limited("burst-limit", None);
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp.headers().get("retry-after").is_none());
        let json = body_json(resp).await;
        assert_eq!(json["error"], "rate_limited");
        assert!(json.get("details").is_none());
    }

    #[tokio::test]
    async fn response_blocked_returns_502() {
        let resp = response_blocked("upstream response contained secrets");
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        let json = body_json(resp).await;
        assert_eq!(json["error"], "response_blocked");
    }

    #[tokio::test]
    async fn upstream_error_returns_502() {
        let resp = upstream_error("connection refused");
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        let json = body_json(resp).await;
        assert_eq!(json["error"], "upstream_error");
    }

    #[tokio::test]
    async fn governance_absent_when_not_provided() {
        let resp = session_required();
        let json = body_json(resp).await;
        // governance key should not appear in the JSON at all
        assert!(!json.as_object().unwrap().contains_key("governance"));
    }

    #[tokio::test]
    async fn details_absent_when_none() {
        let resp = content_blocked("blocked");
        let json = body_json(resp).await;
        assert!(!json.as_object().unwrap().contains_key("details"));
    }

    #[tokio::test]
    async fn all_responses_are_valid_json() {
        let responses = vec![
            session_required(),
            session_invalid(),
            content_blocked("blocked"),
            rate_limited("test", Some(1.0)),
            response_blocked("blocked"),
            upstream_error("err"),
            bad_request("bad"),
            internal_error("oops"),
        ];
        for resp in responses {
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            assert!(
                serde_json::from_slice::<serde_json::Value>(&bytes).is_ok(),
                "response body must be valid JSON"
            );
        }
    }
}
