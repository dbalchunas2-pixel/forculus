//! Forculus Sentinel: LLM-as-sensor classification for MCP tool calls.
//!
//! Layered defense ported from the Warden gateway pattern: deterministic
//! rule tier (mock), verdict cache, token bucket + circuit breaker, and the
//! Llama API classifier behind one Classifier trait. Every failure path
//! blocks (fail closed).

pub mod breaker;
pub mod cache;
pub mod classifier;
pub mod mock;
pub mod sentinel;

pub use breaker::Breaker;
pub use cache::{VerdictCache, cache_key};
pub use classifier::{Classification, Classifier, LlamaClassifier, LlamaConfig};
pub use mock::MockClassifier;
pub use sentinel::{Sentinel, SentinelVerdict};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SentinelError {
    #[error("classifier HTTP error: {0}")]
    Http(String),
    #[error("classifier response parse error: {0}")]
    Parse(String),
}
