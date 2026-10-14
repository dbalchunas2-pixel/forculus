//! Age encryption/decryption and vault key management.

use std::io::{Read, Write};
use std::path::Path;

use age::secrecy::ExposeSecret;

/// The vault master key, used to encrypt/decrypt all credentials.
pub struct VaultKey {
    identity: age::x25519::Identity,
    recipient: age::x25519::Recipient,
}

impl VaultKey {
    /// Generate a new vault key.
    pub fn generate() -> forculus_common::Result<Self> {
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public();
        Ok(Self {
            identity,
            recipient,
        })
    }

    /// Load a vault key from a file.
    pub fn load(path: &Path) -> forculus_common::Result<Self> {
        let contents = std::fs::read_to_string(path).map_err(|e| {
            forculus_common::ForculusError::Vault(format!(
                "failed to read vault key from {}: {e}",
                path.display()
            ))
        })?;

        let identity: age::x25519::Identity = contents.trim().parse().map_err(|e| {
            forculus_common::ForculusError::Vault(format!("invalid vault key format: {e}"))
        })?;
        let recipient = identity.to_public();

        Ok(Self {
            identity,
            recipient,
        })
    }

    /// Save the vault key to a file. Sets restrictive permissions (0600) on Unix.
    pub fn save(&self, path: &Path) -> forculus_common::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                forculus_common::ForculusError::Vault(format!(
                    "failed to create directory {}: {e}",
                    parent.display()
                ))
            })?;
        }

        let key_str = self.identity.to_string();
        std::fs::write(path, key_str.expose_secret()).map_err(|e| {
            forculus_common::ForculusError::Vault(format!(
                "failed to write vault key to {}: {e}",
                path.display()
            ))
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(
                |e| {
                    forculus_common::ForculusError::Vault(format!(
                        "failed to set permissions on {}: {e}",
                        path.display()
                    ))
                },
            )?;
        }

        Ok(())
    }

    /// Load a vault key if the file exists, otherwise generate and save a new one.
    pub fn load_or_generate(path: &Path) -> forculus_common::Result<Self> {
        if path.exists() {
            Self::load(path)
        } else {
            let key = Self::generate()?;
            key.save(path)?;
            Ok(key)
        }
    }

    /// Encrypt plaintext bytes. Returns the age-encrypted ciphertext.
    pub fn encrypt(&self, plaintext: &[u8]) -> forculus_common::Result<Vec<u8>> {
        let recipient: &dyn age::Recipient = &self.recipient;
        let encryptor =
            age::Encryptor::with_recipients(std::iter::once(recipient)).map_err(|e| {
                forculus_common::ForculusError::Vault(format!("failed to create encryptor: {e}"))
            })?;

        let mut encrypted = vec![];
        let mut writer = encryptor.wrap_output(&mut encrypted).map_err(|e| {
            forculus_common::ForculusError::Vault(format!("encryption wrap error: {e}"))
        })?;
        writer.write_all(plaintext).map_err(|e| {
            forculus_common::ForculusError::Vault(format!("encryption write error: {e}"))
        })?;
        writer.finish().map_err(|e| {
            forculus_common::ForculusError::Vault(format!("encryption finish error: {e}"))
        })?;

        Ok(encrypted)
    }

    /// Derive a 32-byte key for a specific purpose using blake3 key derivation.
    ///
    /// The vault identity secret is used as input key material.
    pub fn derive_key(&self, context: &str) -> [u8; 32] {
        let secret_str = self.identity.to_string();
        blake3::derive_key(context, secret_str.expose_secret().as_bytes())
    }

    /// Decrypt age-encrypted ciphertext. Returns the plaintext bytes.
    pub fn decrypt(&self, ciphertext: &[u8]) -> forculus_common::Result<Vec<u8>> {
        let decryptor = age::Decryptor::new(ciphertext).map_err(|e| {
            forculus_common::ForculusError::Vault(format!("decryption init error: {e}"))
        })?;

        let mut reader = decryptor
            .decrypt(std::iter::once(&self.identity as &dyn age::Identity))
            .map_err(|e| forculus_common::ForculusError::Vault(format!("decryption error: {e}")))?;

        let mut plaintext = vec![];
        reader.read_to_end(&mut plaintext).map_err(|e| {
            forculus_common::ForculusError::Vault(format!("decryption read error: {e}"))
        })?;

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = VaultKey::generate().unwrap();
        let plaintext = b"super secret token 12345";
        let ciphertext = key.encrypt(plaintext).unwrap();
        let decrypted = key.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_produces_different_ciphertext() {
        let key = VaultKey::generate().unwrap();
        let plaintext = b"same data";
        let ct1 = key.encrypt(plaintext).unwrap();
        let ct2 = key.encrypt(plaintext).unwrap();
        assert_ne!(ct1, ct2, "ciphertext should differ due to random nonce");
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let key1 = VaultKey::generate().unwrap();
        let key2 = VaultKey::generate().unwrap();
        let ciphertext = key1.encrypt(b"secret").unwrap();
        let result = key2.decrypt(&ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault-key.age");

        let key = VaultKey::generate().unwrap();
        key.save(&path).unwrap();

        let loaded = VaultKey::load(&path).unwrap();

        // Verify by encrypting with original and decrypting with loaded.
        let plaintext = b"test data";
        let ciphertext = key.encrypt(plaintext).unwrap();
        let decrypted = loaded.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn load_or_generate_creates_then_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault-key.age");

        // First call generates.
        let key1 = VaultKey::load_or_generate(&path).unwrap();
        assert!(path.exists());

        // Encrypt with key1.
        let ciphertext = key1.encrypt(b"data").unwrap();

        // Second call loads.
        let key2 = VaultKey::load_or_generate(&path).unwrap();
        let decrypted = key2.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, b"data");
    }
}
