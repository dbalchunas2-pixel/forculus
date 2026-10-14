//! Forculus common — shared error types and constants used across all crates.
#![forbid(unsafe_code)]

/// The current version of the Forculus crate, set at compile time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

use thiserror::Error;

/// Top-level error type for the Forculus project.
#[derive(Error, Debug)]
pub enum ForculusError {
    /// A configuration-related error.
    #[error("configuration error: {0}")]
    Config(String),

    /// A TLS-related error.
    #[error("TLS error: {0}")]
    Tls(String),

    /// A proxy-related error.
    #[error("proxy error: {0}")]
    Proxy(String),

    /// An MCP-related error.
    #[error("MCP error: {0}")]
    Mcp(String),

    /// A policy evaluation error.
    #[error("policy error: {0}")]
    Policy(String),

    /// A vault-related error.
    #[error("vault error: {0}")]
    Vault(String),

    /// An audit-related error.
    #[error("audit error: {0}")]
    Audit(String),

    /// An inspection-related error.
    #[error("inspect error: {0}")]
    Inspect(String),

    /// A rate-limiting error.
    #[error("rate limit: {0}")]
    RateLimit(String),

    /// OIDC discovery endpoint unreachable or invalid.
    #[error("OIDC discovery failed: {0}")]
    OidcDiscovery(String),

    /// Authorization code exchange failed.
    #[error("OIDC token exchange failed: {0}")]
    OidcTokenExchange(String),

    /// ID token validation failed (signature, expiry, issuer, etc.).
    #[error("OIDC token validation failed: {0}")]
    OidcTokenValidation(String),

    /// Required claim missing or invalid.
    #[error("OIDC claim extraction failed: {0}")]
    OidcClaimExtraction(String),

    /// Auth configuration invalid (bad issuer URL, missing client_id, etc.).
    #[error("OIDC configuration error: {0}")]
    OidcConfiguration(String),

    /// An I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A catch-all error variant.
    #[error("{0}")]
    Other(String),
}

/// Convenience result type alias using [`ForculusError`].
pub type Result<T> = std::result::Result<T, ForculusError>;
