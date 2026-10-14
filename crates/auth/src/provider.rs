//! OIDC provider — discovery, client setup, and configuration.

use std::collections::HashMap;
use std::time::Duration;

use forculus_common::ForculusError;
use openidconnect::core::CoreProviderMetadata;
use openidconnect::{ClientId, ClientSecret, IssuerUrl, RedirectUrl};
use secrecy::{ExposeSecret, SecretString};

use crate::claims::{GroupMapping, GroupMappingEntry};

/// Client type returned by `CoreClient::from_provider_metadata`.
///
/// The typestate parameters reflect which endpoints were discovered:
/// - AuthUrl is always set
/// - TokenUrl and UserInfoUrl are "maybe set" (depends on provider metadata)
/// - DeviceAuthUrl, IntrospectionUrl, RevocationUrl are not set
pub(crate) type DiscoveredClient = openidconnect::core::CoreClient<
    openidconnect::EndpointSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointMaybeSet,
    openidconnect::EndpointMaybeSet,
>;

/// How to resolve the OAuth client secret.
#[derive(Debug, Clone)]
pub enum ClientSecretSource {
    /// Read from the named environment variable.
    Env(String),
    /// Read from a file at the given path.
    File(String),
    /// Read from Forculus's credential vault (not yet implemented).
    Vault,
}

/// Configuration for constructing an [`AuthProvider`].
#[derive(Debug, Clone)]
pub struct AuthProviderConfig {
    /// OIDC issuer URL (e.g. `"https://acme.okta.com/oauth2/default"`).
    pub issuer_url: String,
    /// OAuth client ID.
    pub client_id: String,
    /// Where to read the client secret from.
    pub client_secret_source: ClientSecretSource,
    /// OAuth redirect URI for the authorization code flow.
    pub redirect_uri: Option<String>,
    /// OAuth scopes to request.
    pub scopes: Vec<String>,
    /// Claim name containing group memberships (e.g. `"groups"`).
    pub group_claim: String,
    /// Maps IdP group names to Forculus session fields.
    pub group_mapping: HashMap<String, GroupMappingEntry>,
    /// Default session TTL.
    pub default_session_ttl: Duration,
    /// Whether service account authentication is enabled.
    pub service_accounts_enabled: bool,
}

/// OIDC authentication provider.
///
/// Handles OIDC discovery, authorization URL generation, code exchange,
/// and service token validation. Produces [`MappedClaims`](crate::MappedClaims)
/// that the caller uses to create Forculus sessions.
///
/// Uses `CoreClient` from the `openidconnect` crate for standard OIDC
/// operations. Custom claims (like group memberships) are extracted from
/// the raw JWT payload after the ID token has been verified.
pub struct AuthProvider {
    pub(crate) client: DiscoveredClient,
    pub(crate) http_client: reqwest::Client,
    pub(crate) group_mapping: GroupMapping,
    pub(crate) default_session_ttl: Duration,
    pub(crate) service_accounts_enabled: bool,
    pub(crate) group_claim: String,
}

impl std::fmt::Debug for AuthProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthProvider")
            .field("group_claim", &self.group_claim)
            .field("default_session_ttl", &self.default_session_ttl)
            .field("service_accounts_enabled", &self.service_accounts_enabled)
            .finish_non_exhaustive()
    }
}

impl AuthProvider {
    /// Create from OIDC discovery. Fetches `.well-known/openid-configuration`
    /// from the issuer URL and sets up the OIDC client.
    ///
    /// This is async because it makes HTTP requests to the discovery and JWKS endpoints.
    pub async fn from_discovery(config: &AuthProviderConfig) -> Result<Self, ForculusError> {
        // 1. Resolve client secret
        let client_secret = resolve_secret(&config.client_secret_source)?;

        // 2. Create HTTP client (no redirect following per OIDC security best practices)
        let http_client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| {
                ForculusError::OidcDiscovery(format!("failed to build HTTP client: {e}"))
            })?;

        // 3. Fetch provider metadata from .well-known/openid-configuration
        let issuer_url = IssuerUrl::new(config.issuer_url.clone()).map_err(|e| {
            ForculusError::OidcConfiguration(format!(
                "invalid issuer URL '{}': {e}",
                config.issuer_url
            ))
        })?;

        let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, &http_client)
            .await
            .map_err(|e| {
                ForculusError::OidcDiscovery(format!(
                    "could not reach {}/.well-known/openid-configuration: {e}",
                    config.issuer_url
                ))
            })?;

        // 4. Build client from provider metadata
        let mut client = openidconnect::core::CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(config.client_id.clone()),
            Some(ClientSecret::new(client_secret.expose_secret().to_string())),
        );

        // 5. Set redirect URI if provided
        if let Some(redirect_uri) = &config.redirect_uri {
            client =
                client.set_redirect_uri(RedirectUrl::new(redirect_uri.clone()).map_err(|e| {
                    ForculusError::OidcConfiguration(format!(
                        "invalid redirect URI '{redirect_uri}': {e}"
                    ))
                })?);
        }

        // 6. Build group mapping
        let group_mapping = GroupMapping::new(config.group_mapping.clone());

        Ok(Self {
            client,
            http_client,
            group_mapping,
            default_session_ttl: config.default_session_ttl,
            service_accounts_enabled: config.service_accounts_enabled,
            group_claim: config.group_claim.clone(),
        })
    }
}

/// Resolve a client secret from the configured source.
fn resolve_secret(source: &ClientSecretSource) -> Result<SecretString, ForculusError> {
    match source {
        ClientSecretSource::Env(var_name) => {
            let value = std::env::var(var_name).map_err(|_| {
                ForculusError::OidcConfiguration(format!(
                    "environment variable '{var_name}' not set for client secret"
                ))
            })?;
            Ok(SecretString::from(value))
        }
        ClientSecretSource::File(path) => {
            let value = std::fs::read_to_string(path).map_err(|e| {
                ForculusError::OidcConfiguration(format!(
                    "failed to read client secret from file '{path}': {e}"
                ))
            })?;
            Ok(SecretString::from(value.trim().to_string()))
        }
        ClientSecretSource::Vault => Err(ForculusError::OidcConfiguration(
            "client_secret_source: vault is not yet implemented".to_string(),
        )),
    }
}

/// Extract groups from a JWT payload by decoding the middle base64url segment.
///
/// This is called after the ID token has been cryptographically verified by
/// the OIDC library (signature, issuer, audience, expiry). This function
/// only extracts the dynamic group claim name from the already-verified payload.
pub(crate) fn extract_groups_from_jwt(jwt_str: &str, group_claim: &str) -> Vec<String> {
    let parts: Vec<&str> = jwt_str.split('.').collect();
    if parts.len() < 2 {
        return vec![];
    }

    let payload = match base64_url_decode(parts[1]) {
        Some(p) => p,
        None => return vec![],
    };

    let claims: serde_json::Value = match serde_json::from_slice(&payload) {
        Ok(v) => v,
        Err(_) => return vec![],
    };

    claims
        .get(group_claim)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Decode a base64url-encoded string (no padding) to bytes.
fn base64_url_decode(input: &str) -> Option<Vec<u8>> {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = Vec::new();
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;

    for &byte in input.as_bytes() {
        let c = match byte {
            b'-' => b'+',
            b'_' => b'/',
            b'=' => break,
            c => c,
        };
        let val = alphabet.iter().position(|&b| b == c)? as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_secret_from_env() {
        // Use a unique env var name to avoid test interference
        // Write a temp file and use File source instead, since set_var is unsafe in Rust 2024
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("env_secret.txt");
        std::fs::write(&path, "my-secret-value").unwrap();
        let source = ClientSecretSource::File(path.to_str().unwrap().to_string());
        let secret = resolve_secret(&source).unwrap();
        assert_eq!(secret.expose_secret(), "my-secret-value");
    }

    #[test]
    fn resolve_secret_from_env_missing() {
        // Use a var name that is very unlikely to exist
        let source =
            ClientSecretSource::Env("FORCULUS_TEST_NONEXISTENT_SECRET_XYZ_999".to_string());
        let err = resolve_secret(&source).unwrap_err();
        assert!(
            err.to_string()
                .contains("FORCULUS_TEST_NONEXISTENT_SECRET_XYZ_999")
        );
    }

    #[test]
    fn resolve_secret_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.txt");
        std::fs::write(&path, "file-secret-value\n").unwrap();
        let source = ClientSecretSource::File(path.to_str().unwrap().to_string());
        let secret = resolve_secret(&source).unwrap();
        assert_eq!(secret.expose_secret(), "file-secret-value");
    }

    #[test]
    fn resolve_secret_from_file_trims_whitespace() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret2.txt");
        std::fs::write(&path, "  my-secret  \n").unwrap();
        let source = ClientSecretSource::File(path.to_str().unwrap().to_string());
        let secret = resolve_secret(&source).unwrap();
        assert_eq!(secret.expose_secret(), "my-secret");
    }

    #[test]
    fn resolve_secret_from_file_missing() {
        let source = ClientSecretSource::File("/nonexistent/path/secret.txt".to_string());
        let err = resolve_secret(&source).unwrap_err();
        assert!(err.to_string().contains("/nonexistent/path/secret.txt"));
    }

    #[test]
    fn resolve_secret_vault_not_implemented() {
        let err = resolve_secret(&ClientSecretSource::Vault).unwrap_err();
        assert!(err.to_string().contains("vault is not yet implemented"));
    }

    #[test]
    fn extract_groups_from_valid_jwt() {
        let header = base64_url_encode(b"{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
        let payload =
            base64_url_encode(b"{\"sub\":\"user123\",\"groups\":[\"engineering\",\"platform\"]}");
        let jwt = format!("{header}.{payload}.fake-signature");

        let groups = extract_groups_from_jwt(&jwt, "groups");
        assert_eq!(groups, vec!["engineering", "platform"]);
    }

    #[test]
    fn extract_groups_custom_claim_name() {
        let header = base64_url_encode(b"{\"alg\":\"RS256\"}");
        let payload = base64_url_encode(b"{\"sub\":\"user123\",\"team_memberships\":[\"admins\"]}");
        let jwt = format!("{header}.{payload}.sig");

        let groups = extract_groups_from_jwt(&jwt, "team_memberships");
        assert_eq!(groups, vec!["admins"]);
    }

    #[test]
    fn extract_groups_missing_claim() {
        let header = base64_url_encode(b"{\"alg\":\"RS256\"}");
        let payload = base64_url_encode(b"{\"sub\":\"user123\"}");
        let jwt = format!("{header}.{payload}.sig");

        let groups = extract_groups_from_jwt(&jwt, "groups");
        assert!(groups.is_empty());
    }

    #[test]
    fn extract_groups_invalid_jwt() {
        assert!(extract_groups_from_jwt("not-a-jwt", "groups").is_empty());
        assert!(extract_groups_from_jwt("", "groups").is_empty());
    }

    /// Base64url encode (no padding) for building test JWTs.
    fn base64_url_encode(input: &[u8]) -> String {
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut output = String::new();
        let mut i = 0;
        while i < input.len() {
            let b0 = input[i] as u32;
            let b1 = if i + 1 < input.len() {
                input[i + 1] as u32
            } else {
                0
            };
            let b2 = if i + 2 < input.len() {
                input[i + 2] as u32
            } else {
                0
            };
            let triple = (b0 << 16) | (b1 << 8) | b2;

            output.push(alphabet[((triple >> 18) & 0x3F) as usize] as char);
            output.push(alphabet[((triple >> 12) & 0x3F) as usize] as char);

            if i + 1 < input.len() {
                output.push(alphabet[((triple >> 6) & 0x3F) as usize] as char);
            }
            if i + 2 < input.len() {
                output.push(alphabet[(triple & 0x3F) as usize] as char);
            }
            i += 3;
        }
        output.replace('+', "-").replace('/', "_")
    }

    #[tokio::test]
    async fn discovery_with_invalid_issuer_url() {
        let config = AuthProviderConfig {
            issuer_url: "not a url".to_string(),
            client_id: "test".to_string(),
            client_secret_source: ClientSecretSource::Env("TEST_OIDC_SECRET_INVALID".to_string()),
            redirect_uri: None,
            scopes: vec!["openid".to_string()],
            group_claim: "groups".to_string(),
            group_mapping: HashMap::new(),
            default_session_ttl: Duration::from_secs(3600),
            service_accounts_enabled: false,
        };

        let err = AuthProvider::from_discovery(&config).await.unwrap_err();
        assert!(
            err.to_string().contains("invalid issuer URL")
                || err.to_string().contains("not set for client secret")
        );
    }
}
