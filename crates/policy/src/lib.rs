//! Forculus policy — YAML-based policy engine for governing AI agent actions.
//!
//! Every tool call and HTTP request is evaluated against rules defined in YAML
//! files.  The engine is synchronous and lock-free for evaluations, with
//! hot-reload support via `ArcSwap`.
#![forbid(unsafe_code)]

pub mod context;
pub mod engine;
pub mod glob;
pub mod loader;
pub mod parser;
pub mod precedence;
pub mod schema;
pub mod validation;
pub mod verdict;
