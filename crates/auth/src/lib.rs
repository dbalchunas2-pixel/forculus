//! Forculus auth — OAuth 2.1 / OIDC authentication for Forculus sessions.
//!
//! This crate handles OIDC token exchange, JWKS validation, group mapping,
//! and claim extraction. It produces [`MappedClaims`] that the caller uses
//! to create Forculus sessions — session creation itself is not this crate's
//! responsibility.
#![forbid(unsafe_code)]

pub mod claims;
pub mod flows;
pub mod provider;

pub use claims::{GroupMapping, GroupMappingEntry, MappedClaims, ResolvedMapping};
pub use flows::AuthorizationRequest;
pub use provider::AuthProvider;

// Re-export OIDC types needed by callers for the authorization flow.
pub use openidconnect::{Nonce, PkceCodeVerifier};
