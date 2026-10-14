//! Forculus vault — credential storage, session management, and credential injection.
//!
//! The vault provides:
//! - Encrypted credential storage using age encryption
//! - Session token creation and validation
//! - Credential-to-tool binding resolution
//! - Credential injection strategies for HTTP and MCP
#![forbid(unsafe_code)]

pub mod binding;
pub mod credential;
pub mod encryption;
pub mod injection;
pub mod session;
pub mod store;
