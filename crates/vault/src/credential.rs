//! Credential types and metadata for the vault.

use chrono::{DateTime, Utc};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

/// A credential that can be injected into outbound requests.
#[derive(Debug, Clone)]
pub enum Credential {
    /// Bearer token: `Authorization: Bearer <token>`
    BearerToken(SecretString),

    /// Basic auth: `Authorization: Basic base64(user:pass)`
    BasicAuth {
        /// The username.
        username: String,
        /// The password.
        password: SecretString,
    },

    /// API key in a custom header: `<header_name>: <key>`
    ApiKey {
        /// The header name.
        header_name: String,
        /// The API key value.
        key: SecretString,
    },

    /// Custom header: `<header_name>: <value>`
    CustomHeader {
        /// The header name.
        header_name: String,
        /// The header value.
        value: SecretString,
    },
}

/// Metadata about a stored credential (does not contain the secret itself).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialEntry {
    /// Unique name for this credential.
    pub name: String,
    /// What type of credential this is.
    pub credential_type: CredentialType,
    /// When this credential was added.
    pub created_at: DateTime<Utc>,
    /// When this credential was last rotated.
    pub updated_at: DateTime<Utc>,
    /// Optional description.
    pub description: Option<String>,
}

/// The type of credential stored.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialType {
    /// Bearer token.
    BearerToken,
    /// Basic auth (username + password).
    BasicAuth,
    /// API key in a custom header.
    ApiKey,
    /// Custom header value.
    CustomHeader,
}

/// Serialize a credential to bytes for encryption.
pub fn credential_to_bytes(credential: &Credential) -> Vec<u8> {
    use secrecy::ExposeSecret;

    match credential {
        Credential::BearerToken(token) => token.expose_secret().as_bytes().to_vec(),
        Credential::BasicAuth { username, password } => {
            let json = serde_json::json!({
                "username": username,
                "password": password.expose_secret(),
            });
            serde_json::to_vec(&json).expect("serialize basic auth")
        }
        Credential::ApiKey { header_name, key } => {
            let json = serde_json::json!({
                "header_name": header_name,
                "key": key.expose_secret(),
            });
            serde_json::to_vec(&json).expect("serialize api key")
        }
        Credential::CustomHeader { header_name, value } => {
            let json = serde_json::json!({
                "header_name": header_name,
                "value": value.expose_secret(),
            });
            serde_json::to_vec(&json).expect("serialize custom header")
        }
    }
}

/// Deserialize a credential from decrypted bytes.
pub fn credential_from_bytes(
    credential_type: &CredentialType,
    bytes: &[u8],
) -> forculus_common::Result<Credential> {
    match credential_type {
        CredentialType::BearerToken => {
            let token = String::from_utf8(bytes.to_vec())
                .map_err(|e| forculus_common::ForculusError::Vault(format!("invalid UTF-8: {e}")))?;
            Ok(Credential::BearerToken(SecretString::from(token)))
        }
        CredentialType::BasicAuth => {
            let json: serde_json::Value = serde_json::from_slice(bytes)
                .map_err(|e| forculus_common::ForculusError::Vault(format!("invalid JSON: {e}")))?;
            let username = json["username"]
                .as_str()
                .ok_or_else(|| {
                    forculus_common::ForculusError::Vault("missing username field".into())
                })?
                .to_string();
            let password = json["password"]
                .as_str()
                .ok_or_else(|| {
                    forculus_common::ForculusError::Vault("missing password field".into())
                })?
                .to_string();
            Ok(Credential::BasicAuth {
                username,
                password: SecretString::from(password),
            })
        }
        CredentialType::ApiKey => {
            let json: serde_json::Value = serde_json::from_slice(bytes)
                .map_err(|e| forculus_common::ForculusError::Vault(format!("invalid JSON: {e}")))?;
            let header_name = json["header_name"]
                .as_str()
                .ok_or_else(|| {
                    forculus_common::ForculusError::Vault("missing header_name field".into())
                })?
                .to_string();
            let key = json["key"]
                .as_str()
                .ok_or_else(|| forculus_common::ForculusError::Vault("missing key field".into()))?
                .to_string();
            Ok(Credential::ApiKey {
                header_name,
                key: SecretString::from(key),
            })
        }
        CredentialType::CustomHeader => {
            let json: serde_json::Value = serde_json::from_slice(bytes)
                .map_err(|e| forculus_common::ForculusError::Vault(format!("invalid JSON: {e}")))?;
            let header_name = json["header_name"]
                .as_str()
                .ok_or_else(|| {
                    forculus_common::ForculusError::Vault("missing header_name field".into())
                })?
                .to_string();
            let value = json["value"]
                .as_str()
                .ok_or_else(|| forculus_common::ForculusError::Vault("missing value field".into()))?
                .to_string();
            Ok(Credential::CustomHeader {
                header_name,
                value: SecretString::from(value),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_entry_serde_roundtrip() {
        let entry = CredentialEntry {
            name: "test-cred".to_string(),
            credential_type: CredentialType::BearerToken,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            description: Some("A test credential".to_string()),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: CredentialEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "test-cred");
        assert_eq!(back.credential_type, CredentialType::BearerToken);
    }

    #[test]
    fn credential_type_snake_case() {
        assert_eq!(
            serde_json::to_string(&CredentialType::BearerToken).unwrap(),
            r#""bearer_token""#
        );
        assert_eq!(
            serde_json::to_string(&CredentialType::BasicAuth).unwrap(),
            r#""basic_auth""#
        );
        assert_eq!(
            serde_json::to_string(&CredentialType::ApiKey).unwrap(),
            r#""api_key""#
        );
        assert_eq!(
            serde_json::to_string(&CredentialType::CustomHeader).unwrap(),
            r#""custom_header""#
        );
    }

    #[test]
    fn all_credential_variants_roundtrip_bytes() {
        use secrecy::ExposeSecret;

        let bearer = Credential::BearerToken(SecretString::from("tok123".to_string()));
        let bytes = credential_to_bytes(&bearer);
        let back = credential_from_bytes(&CredentialType::BearerToken, &bytes).unwrap();
        match back {
            Credential::BearerToken(t) => assert_eq!(t.expose_secret(), "tok123"),
            _ => panic!("wrong variant"),
        }

        let basic = Credential::BasicAuth {
            username: "user".to_string(),
            password: SecretString::from("pass".to_string()),
        };
        let bytes = credential_to_bytes(&basic);
        let back = credential_from_bytes(&CredentialType::BasicAuth, &bytes).unwrap();
        match back {
            Credential::BasicAuth { username, password } => {
                assert_eq!(username, "user");
                assert_eq!(password.expose_secret(), "pass");
            }
            _ => panic!("wrong variant"),
        }

        let apikey = Credential::ApiKey {
            header_name: "X-Api-Key".to_string(),
            key: SecretString::from("secret".to_string()),
        };
        let bytes = credential_to_bytes(&apikey);
        let back = credential_from_bytes(&CredentialType::ApiKey, &bytes).unwrap();
        match back {
            Credential::ApiKey { header_name, key } => {
                assert_eq!(header_name, "X-Api-Key");
                assert_eq!(key.expose_secret(), "secret");
            }
            _ => panic!("wrong variant"),
        }

        let custom = Credential::CustomHeader {
            header_name: "X-Custom".to_string(),
            value: SecretString::from("val".to_string()),
        };
        let bytes = credential_to_bytes(&custom);
        let back = credential_from_bytes(&CredentialType::CustomHeader, &bytes).unwrap();
        match back {
            Credential::CustomHeader { header_name, value } => {
                assert_eq!(header_name, "X-Custom");
                assert_eq!(value.expose_secret(), "val");
            }
            _ => panic!("wrong variant"),
        }
    }
}
