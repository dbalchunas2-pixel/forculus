//! Fail-closed circuit breaker + token bucket: bounds LLM spend and latency
//! impact. When tripped, calls block WITHOUT reaching the model.

use parking_lot::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

#[derive(Debug, PartialEq)]
pub enum Trip {
    RateLimit,
    Open,
}

pub struct Breaker {
    tokens: Mutex<f64>,
    max_tokens: f64,
    refill_per_sec: f64,
    last_refill: Mutex<Instant>,
    consecutive_failures: AtomicUsize,
    failure_threshold: usize,
}

impl Breaker {
    pub fn new(max_tokens: f64, refill_per_sec: f64, failure_threshold: usize) -> Self {
        Self {
            tokens: Mutex::new(max_tokens),
            max_tokens,
            refill_per_sec,
            last_refill: Mutex::new(Instant::now()),
            consecutive_failures: AtomicUsize::new(0),
            failure_threshold,
        }
    }

    /// Returns Some(Trip) when the call should be blocked without an LLM
    /// request; None when the budget allows one.
    pub fn try_acquire(&self) -> Option<Trip> {
        if self.is_open() {
            return Some(Trip::Open);
        }
        let mut tokens = self.tokens.lock();
        let now = Instant::now();
        let mut last = self.last_refill.lock();
        let elapsed = now.duration_since(*last).as_secs_f64();
        *last = now;
        *tokens = (*tokens + elapsed * self.refill_per_sec).min(self.max_tokens);
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            None
        } else {
            Some(Trip::RateLimit)
        }
    }

    pub fn is_open(&self) -> bool {
        self.consecutive_failures.load(Ordering::Relaxed) >= self.failure_threshold
    }

    pub fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
    }

    pub fn record_failure(&self) {
        self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
    }
}
