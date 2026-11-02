//! Verdict cache: dedupe identical tool calls within a TTL window.

use crate::classifier::Classification;
use lru::LruCache;
use parking_lot::Mutex;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
struct Entry {
    classification: Classification,
    at: Instant,
}

pub struct VerdictCache {
    inner: Mutex<LruCache<String, Entry>>,
    ttl: Duration,
}

impl VerdictCache {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        let capacity = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::MIN);
        Self {
            inner: Mutex::new(LruCache::new(capacity)),
            ttl,
        }
    }

    pub fn get(&self, key: &str) -> Option<Classification> {
        let mut cache = self.inner.lock();
        let entry = cache.get(key)?;
        if entry.at.elapsed() > self.ttl {
            return None;
        }
        Some(entry.classification.clone())
    }

    pub fn put(&self, key: &str, classification: Classification) {
        self.inner.lock().put(
            key.to_string(),
            Entry {
                classification,
                at: Instant::now(),
            },
        );
    }
}

/// Stable cache key for a tool call (sha256 of method + canonical params).
pub fn cache_key(method: &str, params: &Value) -> String {
    let mut hasher = Sha256::new();
    hasher.update(method.as_bytes());
    hasher.update(b"\x1f");
    hasher.update(serde_json::to_string(params).unwrap_or_default().as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
