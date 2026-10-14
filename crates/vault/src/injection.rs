//! Credential injection strategies for HTTP and MCP.
//!
//! This module defines HOW credentials are injected into outbound requests.
//! It provides the logic for what headers to set — actual injection is done
//! by the proxy and MCP crates.

use secrecy::{ExposeSecret, SecretString};

use crate::credential::Credential;

/// Instructions for injecting a credential into an HTTP request.
#[derive(Debug, Clone)]
pub struct HttpInjection {
    /// Headers to add to the outbound request.
    pub headers: Vec<(String, SecretString)>,
    /// Headers to remove from the original request (strip agent's auth attempts).
    pub strip_headers: Vec<String>,
}

/// Compute the HTTP injection for a credential.
pub fn http_injection(credential: &Credential) -> HttpInjection {
    let mut headers = Vec::new();
    let strip = vec![
        "authorization".to_string(),
        "proxy-authorization".to_string(),
        "x-forculus-session".to_string(),
    ];

    match credential {
        Credential::BearerToken(token) => {
            headers.push((
                "authorization".to_string(),
                SecretString::from(format!("Bearer {}", token.expose_secret())),
            ));
        }
        Credential::BasicAuth { username, password } => {
            use base64::Engine;
            let encoded = base64::engine::general_purpose::STANDARD.encode(format!(
                "{}:{}",
                username,
                password.expose_secret()
            ));
            headers.push((
                "authorization".to_string(),
                SecretString::from(format!("Basic {encoded}")),
            ));
        }
        Credential::ApiKey { header_name, key } => {
            headers.push((header_name.to_lowercase(), key.clone()));
        }
        Credential::CustomHeader { header_name, value } => {
            headers.push((header_name.to_lowercase(), value.clone()));
        }
    }

    HttpInjection {
        headers,
        strip_headers: strip,
    }
}

/// Compute the environment variable to set for an upstream MCP server.
///
/// Returns `(env_var_name, secret_value)`.
pub fn mcp_env_injection(credential: &Credential, env_var_name: &str) -> (String, String) {
    match credential {
        Credential::BearerToken(token) => {
            (env_var_name.to_string(), token.expose_secret().to_string())
        }
        Credential::BasicAuth { password, .. } => (
            env_var_name.to_string(),
            password.expose_secret().to_string(),
        ),
        Credential::ApiKey { key, .. } => {
            (env_var_name.to_string(), key.expose_secret().to_string())
        }
        Credential::CustomHeader { value, .. } => {
            (env_var_name.to_string(), value.expose_secret().to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_token_injection() {
        let cred = Credential::BearerToken(SecretString::from("tok123".to_string()));
        let inj = http_injection(&cred);
        assert_eq!(inj.headers.len(), 1);
        assert_eq!(inj.headers[0].0, "authorization");
        assert_eq!(inj.headers[0].1.expose_secret(), "Bearer tok123");
    }

    #[test]
    fn basic_auth_injection() {
        let cred = Credential::BasicAuth {
            username: "user".to_string(),
            password: SecretString::from("pass".to_string()),
        };
        let inj = http_injection(&cred);
        assert_eq!(inj.headers.len(), 1);
        assert_eq!(inj.headers[0].0, "authorization");

        use base64::Engine;
        let expected = base64::engine::general_purpose::STANDARD.encode("user:pass");
        assert_eq!(
            inj.headers[0].1.expose_secret(),
            &format!("Basic {expected}")
        );
    }

    #[test]
    fn api_key_injection() {
        let cred = Credential::ApiKey {
            header_name: "X-Api-Key".to_string(),
            key: SecretString::from("secret123".to_string()),
        };
        let inj = http_injection(&cred);
        assert_eq!(inj.headers.len(), 1);
        assert_eq!(inj.headers[0].0, "x-api-key");
        assert_eq!(inj.headers[0].1.expose_secret(), "secret123");
    }

    #[test]
    fn strip_headers_always_present() {
        let cred = Credential::BearerToken(SecretString::from("tok".to_string()));
        let inj = http_injection(&cred);
        assert!(inj.strip_headers.contains(&"authorization".to_string()));
        assert!(
            inj.strip_headers
                .contains(&"x-forculus-session".to_string())
        );
    }

    #[test]
    fn mcp_env_injection_bearer() {
        let cred = Credential::BearerToken(SecretString::from("my-token".to_string()));
        let (name, value) = mcp_env_injection(&cred, "GITHUB_TOKEN");
        assert_eq!(name, "GITHUB_TOKEN");
        assert_eq!(value, "my-token");
    }
}
