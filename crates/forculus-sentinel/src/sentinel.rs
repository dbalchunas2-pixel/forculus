//! Orchestrator: cache -> breaker -> classifier. Every failure path blocks.

use crate::breaker::Breaker;
use crate::cache::{VerdictCache, cache_key};
use crate::classifier::{Classification, Classifier, DynClassifier, LlamaClassifier, LlamaConfig};
use crate::mock::MockClassifier;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, serde::Serialize)]
pub struct SentinelVerdict {
    pub allowed: bool,
    /// Which layer decided: "cache", "llm", "rate-limit", "breaker",
    /// "classifier-error", "low-confidence".
    pub layer: String,
    pub reasoning: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<Classification>,
}

pub struct Sentinel<C: Classifier> {
    classifier: C,
    cache: VerdictCache,
    breaker: Breaker,
    min_confidence: f64,
}

impl<C: Classifier> Sentinel<C> {
    pub fn new(classifier: C) -> Self {
        Self {
            classifier,
            cache: VerdictCache::new(1024, Duration::from_secs(15 * 60)),
            breaker: Breaker::new(10.0, 1.0, 3),
            min_confidence: 0.7,
        }
    }

    pub fn with_cache(mut self, capacity: usize, ttl: Duration) -> Self {
        self.cache = VerdictCache::new(capacity, ttl);
        self
    }

    pub fn with_breaker(
        mut self,
        burst: f64,
        refill_per_sec: f64,
        failure_threshold: usize,
    ) -> Self {
        self.breaker = Breaker::new(burst, refill_per_sec, failure_threshold);
        self
    }

    pub fn with_min_confidence(mut self, min: f64) -> Self {
        self.min_confidence = min;
        self
    }

    pub async fn inspect(&self, method: &str, params: &Value) -> SentinelVerdict {
        // 1. Open breaker: stop calling the model entirely.
        if self.breaker.is_open() {
            return SentinelVerdict {
                allowed: false,
                layer: "breaker".to_string(),
                reasoning: "circuit breaker open: classifier failing, blocking".to_string(),
                classification: None,
            };
        }

        // 2. Cache hit: identical call inside the TTL window.
        let key = cache_key(method, params);
        if let Some(c) = self.cache.get(&key) {
            let allowed = c.verdict == "allow" && c.confidence >= self.min_confidence;
            return SentinelVerdict {
                allowed,
                layer: "cache".to_string(),
                reasoning: c.reasoning.clone(),
                classification: Some(c),
            };
        }

        // 3. Rate limit: no LLM budget left, block without calling.
        if let Some(trip) = self.breaker.try_acquire() {
            return SentinelVerdict {
                allowed: false,
                layer: "rate-limit".to_string(),
                reasoning: format!("LLM budget tripped ({trip:?}), blocking without model call"),
                classification: None,
            };
        }

        // 4. Classify. Any error blocks (fail closed).
        match self.classifier.classify(method, params).await {
            Ok(c) => {
                self.breaker.record_success();
                self.cache.put(&key, c.clone());
                if c.verdict != "allow" {
                    return SentinelVerdict {
                        allowed: false,
                        layer: "llm".to_string(),
                        reasoning: c.reasoning.clone(),
                        classification: Some(c),
                    };
                }
                if c.confidence < self.min_confidence {
                    return SentinelVerdict {
                        allowed: false,
                        layer: "low-confidence".to_string(),
                        reasoning: format!(
                            "confidence {} below minimum {}",
                            c.confidence, self.min_confidence
                        ),
                        classification: Some(c),
                    };
                }
                SentinelVerdict {
                    allowed: true,
                    layer: "llm".to_string(),
                    reasoning: c.reasoning.clone(),
                    classification: Some(c),
                }
            }
            Err(e) => {
                self.breaker.record_failure();
                SentinelVerdict {
                    allowed: false,
                    layer: "classifier-error".to_string(),
                    reasoning: format!("classifier failed, failing closed: {e}"),
                    classification: None,
                }
            }
        }
    }
}

impl Sentinel<DynClassifier> {
    /// Builds the default stack from env: Llama API tier when
    /// FORCULUS_LLAMA_API_KEY is set, otherwise the deterministic mock
    /// tier. Production tuning (cache, breaker, confidence floor) applies.
    pub fn from_env() -> Self {
        match LlamaConfig::from_env() {
            Some(config) => {
                let classifier = LlamaClassifier::new(config).expect("valid reqwest client");
                Sentinel::new(Arc::new(classifier) as DynClassifier)
            }
            None => Sentinel::new(Arc::new(MockClassifier::default()) as DynClassifier),
        }
    }
}

/// A Sentinel running any classifier backend (the gateway-facing type).
pub type DynSentinel = Sentinel<DynClassifier>;
