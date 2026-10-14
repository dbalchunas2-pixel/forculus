//! Forculus audit — structured event logging and persistence.
//!
//! Provides a fire-and-forget [`logger::AuditLogger`] backed by SQLite for
//! recording every tool call, policy decision, and credential injection.
#![forbid(unsafe_code)]

pub mod event;
pub mod logger;
pub mod query;
pub mod retention;
pub mod store;
