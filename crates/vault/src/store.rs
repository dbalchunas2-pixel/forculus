//! Vault store — brings together credentials, bindings, sessions, and encryption.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use chrono::Utc;

use crate::binding::{CredentialBinding, load_bindings, resolve_binding};
use crate::credential::{
    Credential, CredentialEntry, CredentialType, credential_from_bytes, credential_to_bytes,
};
use crate::encryption::VaultKey;
use crate::session::{CreateSessionParams, Session, SessionStore};

/// The top-level vault — manages credentials, bindings, and sessions.
pub struct Vault {
    vault_key: VaultKey,
    credentials_dir: PathBuf,
    entries: HashMap<String, CredentialEntry>,
    bindings: Vec<CredentialBinding>,
    session_store: SessionStore,
    bindings_path: PathBuf,
    require_sessions: bool,
}

impl Vault {
    /// Open a vault from the given configuration.
    pub fn open(config: &forculus_config::VaultConfig) -> forculus_common::Result<Self> {
        let key_path = PathBuf::from(forculus_config::expand_tilde(&config.key_path));
        let credentials_dir = PathBuf::from(forculus_config::expand_tilde(&config.credentials_dir));
        let bindings_path = PathBuf::from(forculus_config::expand_tilde(&config.bindings_path));
        let sessions_db_path =
            PathBuf::from(forculus_config::expand_tilde(&config.sessions_db_path));

        let vault_key = VaultKey::load_or_generate(&key_path)?;
        std::fs::create_dir_all(&credentials_dir).map_err(|e| {
            forculus_common::ForculusError::Vault(format!(
                "failed to create credentials directory: {e}"
            ))
        })?;

        let entries = load_credential_entries(&credentials_dir)?;
        let bindings = load_bindings(&bindings_path)?;
        let pepper = vault_key.derive_key("forculus session token pepper v1");
        let session_store = SessionStore::open(&sessions_db_path, pepper)?;

        Ok(Self {
            vault_key,
            credentials_dir,
            entries,
            bindings,
            session_store,
            bindings_path,
            require_sessions: config.require_sessions,
        })
    }

    /// Whether sessions are required (strict mode).
    pub fn require_sessions(&self) -> bool {
        self.require_sessions
    }

    /// Add a new credential. Encrypts and stores it.
    pub fn add_credential(
        &mut self,
        name: &str,
        credential: &Credential,
        credential_type: &CredentialType,
        description: Option<&str>,
    ) -> forculus_common::Result<()> {
        let plaintext = credential_to_bytes(credential);
        let ciphertext = self.vault_key.encrypt(&plaintext)?;

        let age_path = self.credentials_dir.join(format!("{name}.age"));
        std::fs::write(&age_path, &ciphertext).map_err(|e| {
            forculus_common::ForculusError::Vault(format!("failed to write credential file: {e}"))
        })?;

        let now = Utc::now();
        let entry = CredentialEntry {
            name: name.to_string(),
            credential_type: credential_type.clone(),
            created_at: now,
            updated_at: now,
            description: description.map(String::from),
        };

        let meta_path = self.credentials_dir.join(format!("{name}.meta.json"));
        let meta_json = serde_json::to_string_pretty(&entry).map_err(|e| {
            forculus_common::ForculusError::Vault(format!("failed to serialize metadata: {e}"))
        })?;
        std::fs::write(&meta_path, meta_json).map_err(|e| {
            forculus_common::ForculusError::Vault(format!("failed to write metadata file: {e}"))
        })?;

        self.entries.insert(name.to_string(), entry);
        Ok(())
    }

    /// Retrieve and decrypt a credential by name.
    pub fn get_credential(&self, name: &str) -> forculus_common::Result<Credential> {
        let entry = self.entries.get(name).ok_or_else(|| {
            forculus_common::ForculusError::Vault(format!("credential not found: {name}"))
        })?;

        let age_path = self.credentials_dir.join(format!("{name}.age"));
        let ciphertext = std::fs::read(&age_path).map_err(|e| {
            forculus_common::ForculusError::Vault(format!("failed to read credential file: {e}"))
        })?;

        let plaintext = self.vault_key.decrypt(&ciphertext)?;
        credential_from_bytes(&entry.credential_type, &plaintext)
    }

    /// Remove a credential (deletes both the encrypted file and metadata).
    pub fn remove_credential(&mut self, name: &str) -> forculus_common::Result<()> {
        if !self.entries.contains_key(name) {
            return Err(forculus_common::ForculusError::Vault(format!(
                "credential not found: {name}"
            )));
        }

        let age_path = self.credentials_dir.join(format!("{name}.age"));
        let meta_path = self.credentials_dir.join(format!("{name}.meta.json"));

        if age_path.exists() {
            std::fs::remove_file(&age_path).map_err(|e| {
                forculus_common::ForculusError::Vault(format!(
                    "failed to remove credential file: {e}"
                ))
            })?;
        }
        if meta_path.exists() {
            std::fs::remove_file(&meta_path).map_err(|e| {
                forculus_common::ForculusError::Vault(format!(
                    "failed to remove metadata file: {e}"
                ))
            })?;
        }

        self.entries.remove(name);
        Ok(())
    }

    /// List all credential entries (metadata only, no secrets).
    pub fn list_credentials(&self) -> Vec<&CredentialEntry> {
        self.entries.values().collect()
    }

    /// Resolve a credential for a tool + session combination.
    ///
    /// Returns `None` if no binding matches.
    pub fn resolve_credential(
        &self,
        tool: &str,
        session: &Session,
    ) -> forculus_common::Result<Option<Credential>> {
        if let Some(cred_name) = resolve_binding(&self.bindings, tool, session) {
            let credential = self.get_credential(&cred_name)?;
            Ok(Some(credential))
        } else {
            Ok(None)
        }
    }

    /// Create a session.
    pub fn create_session(&self, params: CreateSessionParams) -> forculus_common::Result<Session> {
        self.session_store.create(params)
    }

    /// Validate a session token.
    pub fn validate_session(&self, token: &str) -> forculus_common::Result<Option<Session>> {
        self.session_store.validate(token)
    }

    /// Revoke a session.
    pub fn revoke_session(&self, session_id: &str) -> forculus_common::Result<()> {
        self.session_store.revoke(session_id)
    }

    /// List sessions.
    pub fn list_sessions(&self, include_revoked: bool) -> forculus_common::Result<Vec<Session>> {
        self.session_store.list(include_revoked)
    }

    /// Reload bindings from file.
    pub fn reload_bindings(&mut self) -> forculus_common::Result<()> {
        self.bindings = load_bindings(&self.bindings_path)?;
        Ok(())
    }
}

/// Load credential entry metadata from `.meta.json` sidecar files.
fn load_credential_entries(
    dir: &Path,
) -> forculus_common::Result<HashMap<String, CredentialEntry>> {
    let mut entries = HashMap::new();

    if !dir.exists() {
        return Ok(entries);
    }

    let read_dir = std::fs::read_dir(dir).map_err(|e| {
        forculus_common::ForculusError::Vault(format!("failed to read credentials directory: {e}"))
    })?;

    for entry in read_dir {
        let entry = entry.map_err(|e| {
            forculus_common::ForculusError::Vault(format!("directory entry error: {e}"))
        })?;
        let path = entry.path();

        if path.extension().and_then(|e| e.to_str()) == Some("json")
            && path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".meta.json"))
        {
            let contents = std::fs::read_to_string(&path).map_err(|e| {
                forculus_common::ForculusError::Vault(format!(
                    "failed to read {}: {e}",
                    path.display()
                ))
            })?;
            let cred_entry: CredentialEntry = serde_json::from_str(&contents).map_err(|e| {
                forculus_common::ForculusError::Vault(format!(
                    "invalid metadata in {}: {e}",
                    path.display()
                ))
            })?;
            entries.insert(cred_entry.name.clone(), cred_entry);
        }
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::{ExposeSecret, SecretString};

    fn test_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let config = forculus_config::VaultConfig {
            key_path: dir
                .path()
                .join("vault-key.age")
                .to_str()
                .unwrap()
                .to_string(),
            credentials_dir: dir.path().join("credentials").to_str().unwrap().to_string(),
            bindings_path: dir
                .path()
                .join("bindings.yaml")
                .to_str()
                .unwrap()
                .to_string(),
            sessions_db_path: dir.path().join("sessions.db").to_str().unwrap().to_string(),
            require_sessions: false,
        };
        let vault = Vault::open(&config).unwrap();
        (dir, vault)
    }

    #[test]
    fn add_and_retrieve_bearer_token() {
        let (_dir, mut vault) = test_vault();
        let cred = Credential::BearerToken(SecretString::from("my-secret-token".to_string()));

        vault
            .add_credential(
                "github-token",
                &cred,
                &CredentialType::BearerToken,
                Some("test"),
            )
            .unwrap();

        let retrieved = vault.get_credential("github-token").unwrap();
        match retrieved {
            Credential::BearerToken(t) => {
                assert_eq!(t.expose_secret(), "my-secret-token");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn add_and_retrieve_basic_auth() {
        let (_dir, mut vault) = test_vault();
        let cred = Credential::BasicAuth {
            username: "admin".to_string(),
            password: SecretString::from("p@ss".to_string()),
        };

        vault
            .add_credential("db-cred", &cred, &CredentialType::BasicAuth, None)
            .unwrap();

        let retrieved = vault.get_credential("db-cred").unwrap();
        match retrieved {
            Credential::BasicAuth { username, password } => {
                assert_eq!(username, "admin");
                assert_eq!(password.expose_secret(), "p@ss");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn remove_credential() {
        let (_dir, mut vault) = test_vault();
        let cred = Credential::BearerToken(SecretString::from("tok".to_string()));
        vault
            .add_credential("temp", &cred, &CredentialType::BearerToken, None)
            .unwrap();

        vault.remove_credential("temp").unwrap();
        assert!(vault.get_credential("temp").is_err());
    }

    #[test]
    fn list_credentials_metadata() {
        let (_dir, mut vault) = test_vault();
        let cred = Credential::BearerToken(SecretString::from("tok".to_string()));
        vault
            .add_credential(
                "cred-a",
                &cred,
                &CredentialType::BearerToken,
                Some("desc A"),
            )
            .unwrap();
        vault
            .add_credential(
                "cred-b",
                &cred,
                &CredentialType::BearerToken,
                Some("desc B"),
            )
            .unwrap();

        let list = vault.list_credentials();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn resolve_credential_with_binding() {
        let (_dir, mut vault) = test_vault();

        // Add a credential.
        let cred = Credential::BearerToken(SecretString::from("gh-token".to_string()));
        vault
            .add_credential("github-pat", &cred, &CredentialType::BearerToken, None)
            .unwrap();

        // Write bindings file.
        let bindings_yaml = r#"
bindings:
  - credential: github-pat
    tool: "github__*"
"#;
        std::fs::write(&vault.bindings_path, bindings_yaml).unwrap();
        vault.reload_bindings().unwrap();

        // Create a session.
        let session = vault
            .create_session(CreateSessionParams {
                operator: "alice".to_string(),
                team: None,
                project: None,
                environment: None,
                agent_type: None,
                ttl_seconds: None,
                description: None,
            })
            .unwrap();

        // Resolve.
        let resolved = vault.resolve_credential("github__push", &session).unwrap();
        assert!(resolved.is_some());
        match resolved.unwrap() {
            Credential::BearerToken(t) => assert_eq!(t.expose_secret(), "gh-token"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn resolve_credential_no_match() {
        let (_dir, vault) = test_vault();

        let session = vault
            .create_session(CreateSessionParams {
                operator: "alice".to_string(),
                team: None,
                project: None,
                environment: None,
                agent_type: None,
                ttl_seconds: None,
                description: None,
            })
            .unwrap();

        let resolved = vault.resolve_credential("unknown-tool", &session).unwrap();
        assert!(resolved.is_none());
    }
}
