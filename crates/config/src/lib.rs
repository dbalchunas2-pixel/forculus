//! Forculus config — configuration loading and validation.
//!
//! Loads [`ForculusConfig`] from a YAML file, falling back to sensible defaults
//! when the file does not exist.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Top-level Forculus configuration.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ForculusConfig {
    /// Proxy server settings.
    pub proxy: ProxyConfig,
    /// Logging settings.
    pub logging: LoggingConfig,
    /// MCP gateway settings.
    pub mcp_gateway: McpGatewayConfig,
    /// Policy engine settings.
    pub policy: PolicyConfig,
    /// Vault settings.
    pub vault: VaultConfig,
    /// Audit settings.
    pub audit: AuditConfig,
    /// Content inspection settings.
    pub inspect: forculus_inspect::config::InspectionConfig,
    /// Rate limiting settings.
    pub rate_limit: RateLimitConfig,
    /// Cost estimation settings.
    pub cost_estimation: CostConfig,
    /// Authentication settings (OIDC).
    pub auth: AuthConfig,
}

/// Configuration for the proxy listener.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    /// Address to listen on (e.g. `"127.0.0.1:8080"`).
    pub listen_address: String,
    /// TLS / certificate authority settings.
    pub tls: TlsConfig,
    /// URL-to-tool mappings for semantic policy evaluation.
    pub tool_mappings: Vec<ToolMapping>,
    /// Host patterns that bypass TLS MITM (plain TCP passthrough).
    pub tls_passthrough: Vec<String>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_address: "127.0.0.1:8080".to_string(),
            tls: TlsConfig::default(),
            tool_mappings: Vec::new(),
            tls_passthrough: Vec::new(),
        }
    }
}

/// Maps a URL pattern to a semantic tool name.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ToolMapping {
    /// Glob pattern to match against the URL (host + path).
    pub url_pattern: String,
    /// Semantic tool name to use for policy evaluation.
    pub tool: String,
    /// How to derive the action from the request.
    #[serde(default)]
    pub action_from: ActionFrom,
}

/// How to derive the policy action from an HTTP request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ActionFrom {
    /// Use the URL path as the action (default).
    #[default]
    UrlPath,
    /// Use the HTTP method as the action.
    Method,
    /// Use a specific path segment (0-indexed) as the action.
    PathSegment(usize),
    /// Use a fixed string as the action.
    Static(String),
}

impl Serialize for ActionFrom {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            ActionFrom::UrlPath => serializer.serialize_str("url_path"),
            ActionFrom::Method => serializer.serialize_str("method"),
            ActionFrom::PathSegment(n) => serializer.serialize_str(&format!("path_segment:{n}")),
            ActionFrom::Static(s) => serializer.serialize_str(&format!("static:{s}")),
        }
    }
}

impl<'de> Deserialize<'de> for ActionFrom {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        if s == "url_path" {
            Ok(ActionFrom::UrlPath)
        } else if s == "method" {
            Ok(ActionFrom::Method)
        } else if let Some(rest) = s.strip_prefix("path_segment:") {
            let n: usize = rest.parse().map_err(|e| {
                serde::de::Error::custom(format!("invalid path_segment index: {e}"))
            })?;
            Ok(ActionFrom::PathSegment(n))
        } else if let Some(rest) = s.strip_prefix("static:") {
            Ok(ActionFrom::Static(rest.to_string()))
        } else {
            Err(serde::de::Error::custom(format!(
                "unknown action_from variant: '{s}'. Expected url_path, method, path_segment:N, or static:VALUE"
            )))
        }
    }
}

/// TLS-related configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TlsConfig {
    /// Directory to store the generated CA certificate and key.
    pub ca_dir: String,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            ca_dir: "~/.forculus/ca".to_string(),
        }
    }
}

/// Log output format.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Machine-readable JSON lines.
    #[default]
    Json,
    /// Human-readable pretty output.
    Pretty,
}

/// Logging configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// Output format.
    pub format: LogFormat,
    /// Minimum log level (`trace`, `debug`, `info`, `warn`, `error`).
    pub level: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            format: LogFormat::default(),
            level: "info".to_string(),
        }
    }
}

/// Configuration for the MCP governance gateway.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct McpGatewayConfig {
    /// Upstream MCP tool servers.
    pub upstream_servers: Vec<UpstreamServerConfig>,
    /// HTTP listen address for Streamable HTTP transport (e.g. `"127.0.0.1:3000"`).
    /// `None` means HTTP transport is disabled.
    #[serde(default)]
    pub listen_address: Option<String>,
    /// Allowed origins for DNS rebinding protection. Empty = allow all.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// Path to the tool-definition pin database (F3). `None` disables pinning.
    #[serde(default)]
    pub pins_db_path: Option<String>,
}

/// Configuration for a single upstream MCP tool server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamServerConfig {
    /// Logical name used for tool namespacing.
    pub name: String,
    /// Command to spawn (e.g. `"npx"`).
    pub command: String,
    /// Arguments passed to the command.
    #[serde(default)]
    pub args: Vec<String>,
    /// Environment variables to set for the child process.
    #[serde(default)]
    pub env: HashMap<String, String>,
}

/// Policy engine configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct PolicyConfig {
    /// Directory containing YAML policy files.
    pub policies_dir: String,
    /// Whether to watch for policy file changes and reload automatically.
    pub hot_reload: bool,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            policies_dir: "./policies".to_string(),
            hot_reload: true,
        }
    }
}

/// Credential vault configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct VaultConfig {
    /// Path to the vault key file.
    pub key_path: String,
    /// Path to the credentials directory.
    pub credentials_dir: String,
    /// Path to the bindings file.
    pub bindings_path: String,
    /// Path to the sessions database.
    pub sessions_db_path: String,
    /// Whether sessions are required (strict mode).
    /// If true, requests without a valid session token are rejected.
    /// If false, requests without a session proceed with no operator context.
    pub require_sessions: bool,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            key_path: "~/.forculus/vault-key.age".to_string(),
            credentials_dir: "~/.forculus/credentials".to_string(),
            bindings_path: "~/.forculus/bindings.yaml".to_string(),
            sessions_db_path: "~/.forculus/sessions.db".to_string(),
            require_sessions: false,
        }
    }
}

/// Audit logging configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AuditConfig {
    /// Path to the audit database.
    pub db_path: String,
    /// Whether audit logging is enabled.
    pub enabled: bool,
    /// Retention period in days (0 = no retention, keep everything).
    pub retention_days: u32,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            db_path: "~/.forculus/audit.db".to_string(),
            enabled: true,
            retention_days: 90,
        }
    }
}

/// Rate limiting configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RateLimitConfig {
    /// Whether rate limiting is enabled.
    pub enabled: bool,
    /// Default requests per minute.
    pub default_rpm: u32,
    /// Default burst size.
    pub default_burst: u32,
    /// Rate limit rules.
    pub rules: Vec<RateLimitRule>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_rpm: 60,
            default_burst: 10,
            rules: Vec::new(),
        }
    }
}

/// A single rate limit rule.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimitRule {
    /// Rule name for diagnostics.
    pub name: String,
    /// Tool patterns this rule applies to.
    #[serde(default)]
    pub tools: Vec<String>,
    /// Requests per minute.
    pub rpm: u32,
    /// Burst size.
    pub burst: u32,
    /// Dimensions to rate limit on (e.g. "session", "operator", "tool", "global").
    #[serde(default)]
    pub dimensions: Vec<String>,
}

/// Cost estimation configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CostConfig {
    /// Whether cost estimation is enabled.
    pub enabled: bool,
    /// Default cost per request.
    pub default_cost: f64,
    /// Cost rules.
    pub rules: Vec<CostRule>,
}

impl Default for CostConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_cost: 0.01,
            rules: Vec::new(),
        }
    }
}

/// A single cost rule.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CostRule {
    /// Tool patterns this rule applies to.
    #[serde(default)]
    pub tools: Vec<String>,
    /// Cost per request.
    pub cost: f64,
    /// Monthly budget limit (None = unlimited).
    #[serde(default)]
    pub monthly_budget: Option<f64>,
}

/// Authentication configuration.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct AuthConfig {
    /// OIDC provider configuration.
    pub oidc: Option<AuthOidcConfig>,
    /// Auth management server settings.
    pub server: AuthServerConfig,
}

/// Auth management server configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AuthServerConfig {
    /// Whether the auth management server is enabled.
    pub enabled: bool,
    /// Address for the auth management server (e.g. `"127.0.0.1:9082"`).
    pub listen_address: String,
}

impl Default for AuthServerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_address: "127.0.0.1:9082".to_string(),
        }
    }
}

/// OIDC provider configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthOidcConfig {
    /// Whether OIDC authentication is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// OIDC issuer URL (e.g. `"https://acme.okta.com/oauth2/default"`).
    pub issuer_url: String,
    /// OAuth client ID.
    pub client_id: String,
    /// Where to read the client secret from.
    #[serde(default = "default_secret_source")]
    pub client_secret_source: SecretSource,
    /// Path to client secret file (when `client_secret_source` is `file`).
    pub client_secret_path: Option<String>,
    /// Environment variable name (when `client_secret_source` is `env`).
    #[serde(default = "default_secret_env_var")]
    pub client_secret_env: String,
    /// OAuth redirect URI for the authorization code flow.
    pub redirect_uri: Option<String>,
    /// OAuth scopes to request.
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    /// Claim name containing group memberships.
    #[serde(default = "default_group_claim")]
    pub group_claim: String,
    /// Maps IdP group names to Forculus session fields.
    #[serde(default)]
    pub group_mapping: HashMap<String, GroupMappingEntry>,
    /// Default session TTL in seconds.
    #[serde(default = "default_session_ttl")]
    pub default_session_ttl: u64,
    /// Service account settings.
    #[serde(default)]
    pub service_accounts: ServiceAccountConfig,
}

/// Where to read the OAuth client secret from.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SecretSource {
    /// Read from an environment variable.
    #[default]
    Env,
    /// Read from a file.
    File,
    /// Read from Forculus's credential vault (not yet implemented).
    Vault,
}

/// Service account configuration for client credentials flow.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct ServiceAccountConfig {
    /// Whether service account authentication is enabled.
    pub enabled: bool,
}

/// Maps an IdP group name to Forculus session fields.
#[derive(Debug, Clone, Deserialize)]
pub struct GroupMappingEntry {
    /// Team name to assign.
    pub team: Option<String>,
    /// Environment to assign.
    pub environment: Option<String>,
    /// Agent type to assign.
    pub agent_type: Option<String>,
    /// Additional labels.
    #[serde(default)]
    pub labels: HashMap<String, String>,
}

fn default_secret_source() -> SecretSource {
    SecretSource::Env
}

fn default_secret_env_var() -> String {
    "FORCULUS_OIDC_CLIENT_SECRET".to_string()
}

fn default_scopes() -> Vec<String> {
    vec!["openid".into(), "profile".into(), "groups".into()]
}

fn default_group_claim() -> String {
    "groups".to_string()
}

fn default_session_ttl() -> u64 {
    3600
}

/// Resolve `${VAR_NAME}` references in a string to environment variables.
pub fn resolve_env_vars(value: &str) -> String {
    if let Some(var_name) = value.strip_prefix("${").and_then(|s| s.strip_suffix('}')) {
        std::env::var(var_name).unwrap_or_default()
    } else {
        value.to_string()
    }
}

/// Expand a leading `~` in a path to the user's home directory.
pub fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix('~') {
        if let Some(home) = dirs::home_dir() {
            return format!("{}{rest}", home.display());
        }
    }
    path.to_string()
}

/// Load configuration from the given YAML file path.
///
/// Returns [`ForculusConfig::default()`] when the file does not exist.
/// Returns an error if the file exists but cannot be parsed.
pub fn load_config(path: &Path) -> forculus_common::Result<ForculusConfig> {
    if !path.exists() {
        tracing::info!(?path, "config file not found, using defaults");
        return Ok(ForculusConfig::default());
    }
    let contents = std::fs::read_to_string(path).map_err(|e| {
        forculus_common::ForculusError::Config(format!("failed to read config: {e}"))
    })?;
    let config: ForculusConfig = serde_yaml::from_str(&contents)
        .map_err(|e| forculus_common::ForculusError::Config(format!("invalid YAML: {e}")))?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sensible() {
        let cfg = ForculusConfig::default();
        assert_eq!(cfg.proxy.listen_address, "127.0.0.1:8080");
        assert_eq!(cfg.proxy.tls.ca_dir, "~/.forculus/ca");
        assert_eq!(cfg.logging.format, LogFormat::Json);
        assert_eq!(cfg.logging.level, "info");
    }

    #[test]
    fn expand_tilde_works() {
        let expanded = expand_tilde("~/.forculus/ca");
        assert!(!expanded.starts_with('~'));
        assert!(expanded.ends_with("/.forculus/ca"));
    }

    #[test]
    fn missing_file_returns_defaults() {
        let cfg = load_config(Path::new("/nonexistent/forculus.yaml")).unwrap();
        assert_eq!(cfg.proxy.listen_address, "127.0.0.1:8080");
    }

    #[test]
    fn test_tool_mapping_config() {
        let yaml = r#"
proxy:
  tool_mappings:
    - url_pattern: "api.openai.com/*"
      tool: openai
      action_from: "url_path"
    - url_pattern: "*.github.com/api/*"
      tool: github
      action_from: "method"
"#;
        let cfg: ForculusConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.proxy.tool_mappings.len(), 2);
        assert_eq!(cfg.proxy.tool_mappings[0].tool, "openai");
        assert_eq!(cfg.proxy.tool_mappings[0].action_from, ActionFrom::UrlPath);
        assert_eq!(cfg.proxy.tool_mappings[1].action_from, ActionFrom::Method);
    }

    #[test]
    fn test_rate_limit_config() {
        let yaml = r#"
rate_limit:
  enabled: true
  default_rpm: 120
  default_burst: 20
  rules:
    - name: openai-limit
      tools: ["openai"]
      rpm: 30
      burst: 5
      dimensions: ["session", "operator"]
"#;
        let cfg: ForculusConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(cfg.rate_limit.enabled);
        assert_eq!(cfg.rate_limit.default_rpm, 120);
        assert_eq!(cfg.rate_limit.default_burst, 20);
        assert_eq!(cfg.rate_limit.rules.len(), 1);
        assert_eq!(cfg.rate_limit.rules[0].name, "openai-limit");
        assert_eq!(cfg.rate_limit.rules[0].rpm, 30);
        assert_eq!(
            cfg.rate_limit.rules[0].dimensions,
            vec!["session", "operator"]
        );
    }

    #[test]
    fn test_cost_config() {
        let yaml = r#"
cost_estimation:
  enabled: true
  default_cost: 0.05
  rules:
    - tools: ["openai"]
      cost: 0.10
      monthly_budget: 100.0
    - tools: ["github"]
      cost: 0.001
"#;
        let cfg: ForculusConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(cfg.cost_estimation.enabled);
        assert!((cfg.cost_estimation.default_cost - 0.05).abs() < f64::EPSILON);
        assert_eq!(cfg.cost_estimation.rules.len(), 2);
        assert!((cfg.cost_estimation.rules[0].cost - 0.10).abs() < f64::EPSILON);
        assert_eq!(cfg.cost_estimation.rules[0].monthly_budget, Some(100.0));
        assert_eq!(cfg.cost_estimation.rules[1].monthly_budget, None);
    }

    #[test]
    fn test_action_from_variants() {
        // url_path
        let v: ActionFrom = serde_yaml::from_str("\"url_path\"").unwrap();
        assert_eq!(v, ActionFrom::UrlPath);

        // method
        let v: ActionFrom = serde_yaml::from_str("\"method\"").unwrap();
        assert_eq!(v, ActionFrom::Method);

        // path_segment:2
        let v: ActionFrom = serde_yaml::from_str("\"path_segment:2\"").unwrap();
        assert_eq!(v, ActionFrom::PathSegment(2));

        // static:read
        let v: ActionFrom = serde_yaml::from_str("\"static:read\"").unwrap();
        assert_eq!(v, ActionFrom::Static("read".to_string()));

        // invalid
        let result: Result<ActionFrom, _> = serde_yaml::from_str("\"bogus\"");
        assert!(result.is_err());
    }

    #[test]
    fn test_tls_passthrough_config() {
        let yaml = r#"
proxy:
  tls_passthrough:
    - "*.pinned-service.com"
    - "vault.internal:8200"
    - "mtls.example.org"
"#;
        let cfg: ForculusConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.proxy.tls_passthrough.len(), 3);
        assert_eq!(cfg.proxy.tls_passthrough[0], "*.pinned-service.com");
        assert_eq!(cfg.proxy.tls_passthrough[1], "vault.internal:8200");
        assert_eq!(cfg.proxy.tls_passthrough[2], "mtls.example.org");
    }

    #[test]
    fn test_mcp_http_config() {
        let yaml = r#"
mcp_gateway:
  listen_address: "0.0.0.0:4000"
  allowed_origins:
    - "https://example.com"
    - "https://app.example.com"
  upstream_servers: []
"#;
        let cfg: ForculusConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            cfg.mcp_gateway.listen_address.as_deref(),
            Some("0.0.0.0:4000")
        );
        assert_eq!(cfg.mcp_gateway.allowed_origins.len(), 2);
        assert_eq!(cfg.mcp_gateway.allowed_origins[0], "https://example.com");
    }

    #[test]
    fn test_mcp_http_config_defaults() {
        let yaml = r#"
mcp_gateway:
  upstream_servers: []
"#;
        let cfg: ForculusConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(cfg.mcp_gateway.listen_address.is_none());
        assert!(cfg.mcp_gateway.allowed_origins.is_empty());
    }

    #[test]
    fn test_tls_passthrough_defaults_to_empty() {
        let yaml = r#"
proxy:
  listen_address: "0.0.0.0:9090"
"#;
        let cfg: ForculusConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(cfg.proxy.tls_passthrough.is_empty());
    }

    #[test]
    fn test_auth_oidc_full_config() {
        let yaml = r#"
auth:
  oidc:
    enabled: true
    issuer_url: "https://acme.okta.com/oauth2/default"
    client_id: "0oa1234567890"
    client_secret_source: env
    client_secret_env: "MY_SECRET"
    redirect_uri: "http://localhost:9090/callback"
    scopes: ["openid", "profile", "groups", "email"]
    group_claim: "groups"
    group_mapping:
      "okta-engineering":
        team: "engineering"
      "okta-platform":
        team: "platform"
        environment: "production"
    default_session_ttl: 7200
    service_accounts:
      enabled: true
"#;
        let cfg: ForculusConfig = serde_yaml::from_str(yaml).unwrap();
        let oidc = cfg.auth.oidc.expect("oidc should be present");
        assert!(oidc.enabled);
        assert_eq!(oidc.issuer_url, "https://acme.okta.com/oauth2/default");
        assert_eq!(oidc.client_id, "0oa1234567890");
        assert_eq!(oidc.client_secret_env, "MY_SECRET");
        assert_eq!(
            oidc.redirect_uri.as_deref(),
            Some("http://localhost:9090/callback")
        );
        assert_eq!(oidc.scopes.len(), 4);
        assert_eq!(oidc.group_claim, "groups");
        assert_eq!(oidc.group_mapping.len(), 2);
        assert_eq!(
            oidc.group_mapping["okta-engineering"].team.as_deref(),
            Some("engineering")
        );
        assert_eq!(
            oidc.group_mapping["okta-platform"].environment.as_deref(),
            Some("production")
        );
        assert_eq!(oidc.default_session_ttl, 7200);
        assert!(oidc.service_accounts.enabled);
    }

    #[test]
    fn test_auth_oidc_minimal_config() {
        let yaml = r#"
auth:
  oidc:
    issuer_url: "https://login.microsoftonline.com/tenant/v2.0"
    client_id: "abc123"
"#;
        let cfg: ForculusConfig = serde_yaml::from_str(yaml).unwrap();
        let oidc = cfg.auth.oidc.expect("oidc should be present");
        assert!(!oidc.enabled);
        assert_eq!(
            oidc.issuer_url,
            "https://login.microsoftonline.com/tenant/v2.0"
        );
        assert_eq!(oidc.client_id, "abc123");
        assert_eq!(oidc.client_secret_env, "FORCULUS_OIDC_CLIENT_SECRET");
        assert_eq!(oidc.scopes, vec!["openid", "profile", "groups"]);
        assert_eq!(oidc.group_claim, "groups");
        assert!(oidc.group_mapping.is_empty());
        assert_eq!(oidc.default_session_ttl, 3600);
        assert!(!oidc.service_accounts.enabled);
    }

    #[test]
    fn test_auth_missing_section_backward_compatible() {
        let yaml = r#"
proxy:
  listen_address: "0.0.0.0:8080"
"#;
        let cfg: ForculusConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(cfg.auth.oidc.is_none());
    }

    #[test]
    fn test_secret_source_variants() {
        let env: SecretSource = serde_yaml::from_str("\"env\"").unwrap();
        assert!(matches!(env, SecretSource::Env));

        let file: SecretSource = serde_yaml::from_str("\"file\"").unwrap();
        assert!(matches!(file, SecretSource::File));

        let vault: SecretSource = serde_yaml::from_str("\"vault\"").unwrap();
        assert!(matches!(vault, SecretSource::Vault));
    }

    #[test]
    fn test_group_mapping_deserialization() {
        let yaml = r#"
auth:
  oidc:
    issuer_url: "https://example.com"
    client_id: "test"
    group_mapping:
      "admin-group":
        team: "platform"
        environment: "production"
        agent_type: "claude-code"
        labels:
          tier: "admin"
      "dev-group":
        team: "engineering"
"#;
        let cfg: ForculusConfig = serde_yaml::from_str(yaml).unwrap();
        let oidc = cfg.auth.oidc.unwrap();
        assert_eq!(oidc.group_mapping.len(), 2);

        let admin = &oidc.group_mapping["admin-group"];
        assert_eq!(admin.team.as_deref(), Some("platform"));
        assert_eq!(admin.environment.as_deref(), Some("production"));
        assert_eq!(admin.agent_type.as_deref(), Some("claude-code"));
        assert_eq!(admin.labels.get("tier").map(|s| s.as_str()), Some("admin"));

        let dev = &oidc.group_mapping["dev-group"];
        assert_eq!(dev.team.as_deref(), Some("engineering"));
        assert!(dev.environment.is_none());
        assert!(dev.agent_type.is_none());
        assert!(dev.labels.is_empty());
    }

    #[test]
    fn test_auth_server_config_defaults() {
        let cfg = AuthServerConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.listen_address, "127.0.0.1:9082");
    }

    #[test]
    fn test_auth_server_config_full() {
        let yaml = r#"
auth:
  server:
    enabled: true
    listen_address: "0.0.0.0:9999"
  oidc:
    issuer_url: "https://example.com"
    client_id: "test"
"#;
        let cfg: ForculusConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(cfg.auth.server.enabled);
        assert_eq!(cfg.auth.server.listen_address, "0.0.0.0:9999");
    }

    #[test]
    fn test_auth_config_without_server_backward_compat() {
        let yaml = r#"
auth:
  oidc:
    issuer_url: "https://example.com"
    client_id: "test"
"#;
        let cfg: ForculusConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(!cfg.auth.server.enabled);
        assert_eq!(cfg.auth.server.listen_address, "127.0.0.1:9082");
    }

    #[test]
    fn test_default_session_ttl_defaults_to_3600() {
        let yaml = r#"
auth:
  oidc:
    issuer_url: "https://example.com"
    client_id: "test"
"#;
        let cfg: ForculusConfig = serde_yaml::from_str(yaml).unwrap();
        let oidc = cfg.auth.oidc.unwrap();
        assert_eq!(oidc.default_session_ttl, 3600);
    }
}
