//! `forculus cred` — credential management commands.

use std::path::Path;

use anyhow::{Context, Result, bail};
use forculus_config::load_config;
use forculus_vault::credential::{Credential, CredentialType};
use forculus_vault::store::Vault;
use secrecy::SecretString;

/// Add a credential to the vault.
pub fn add(
    config_path: &Path,
    name: &str,
    cred_type: &str,
    description: Option<&str>,
    header: Option<&str>,
    username: Option<&str>,
) -> Result<()> {
    let config = load_config(config_path).context("loading configuration")?;
    let mut vault = Vault::open(&config.vault).context("opening vault")?;

    let (credential, credential_type) = match cred_type {
        "bearer" => {
            let secret = read_secret("Enter bearer token: ")?;
            (
                Credential::BearerToken(SecretString::from(secret)),
                CredentialType::BearerToken,
            )
        }
        "basic" => {
            let user = username.map(String::from).unwrap_or_else(|| {
                eprint!("Username: ");
                let mut buf = String::new();
                std::io::stdin().read_line(&mut buf).unwrap();
                buf.trim().to_string()
            });
            let password = read_secret("Enter password: ")?;
            (
                Credential::BasicAuth {
                    username: user,
                    password: SecretString::from(password),
                },
                CredentialType::BasicAuth,
            )
        }
        "api-key" => {
            let header_name =
                header.ok_or_else(|| anyhow::anyhow!("--header is required for api-key type"))?;
            let key = read_secret("Enter API key: ")?;
            (
                Credential::ApiKey {
                    header_name: header_name.to_string(),
                    key: SecretString::from(key),
                },
                CredentialType::ApiKey,
            )
        }
        "custom-header" => {
            let header_name = header
                .ok_or_else(|| anyhow::anyhow!("--header is required for custom-header type"))?;
            let value = read_secret("Enter header value: ")?;
            (
                Credential::CustomHeader {
                    header_name: header_name.to_string(),
                    value: SecretString::from(value),
                },
                CredentialType::CustomHeader,
            )
        }
        other => {
            bail!("Unknown credential type: {other}. Use: bearer, basic, api-key, custom-header")
        }
    };

    vault
        .add_credential(name, &credential, &credential_type, description)
        .context("adding credential")?;

    println!("Credential '{name}' added to vault.");
    Ok(())
}

/// List all credentials in the vault.
pub fn list(config_path: &Path) -> Result<()> {
    let config = load_config(config_path).context("loading configuration")?;
    let vault = Vault::open(&config.vault).context("opening vault")?;

    let entries = vault.list_credentials();
    if entries.is_empty() {
        println!("No credentials in vault.");
        return Ok(());
    }

    println!("{:<20} {:<15} DESCRIPTION", "NAME", "TYPE");
    println!("{}", "-".repeat(60));
    for entry in entries {
        let desc = entry.description.as_deref().unwrap_or("");
        println!(
            "{:<20} {:<15} {}",
            entry.name,
            format!("{:?}", entry.credential_type),
            desc
        );
    }
    Ok(())
}

/// Remove a credential from the vault.
pub fn remove(config_path: &Path, name: &str) -> Result<()> {
    let config = load_config(config_path).context("loading configuration")?;
    let mut vault = Vault::open(&config.vault).context("opening vault")?;

    vault
        .remove_credential(name)
        .context("removing credential")?;

    println!("Credential '{name}' removed.");
    Ok(())
}

/// Test credential resolution for a tool + session.
pub fn test_resolve(config_path: &Path, tool: &str, session_token: &str) -> Result<()> {
    let config = load_config(config_path).context("loading configuration")?;
    let vault = Vault::open(&config.vault).context("opening vault")?;

    let session = vault
        .validate_session(session_token)
        .context("validating session")?
        .ok_or_else(|| anyhow::anyhow!("Invalid or expired session token"))?;

    match vault.resolve_credential(tool, &session)? {
        Some(_) => {
            println!(
                "Credential resolved for tool '{tool}' with session '{}'.",
                session.id
            );
        }
        None => {
            println!("No credential binding matches tool '{tool}'.");
        }
    }
    Ok(())
}

/// Read a secret from stdin without echoing.
fn read_secret(prompt: &str) -> Result<String> {
    rpassword::prompt_password(prompt).context("reading secret input")
}
