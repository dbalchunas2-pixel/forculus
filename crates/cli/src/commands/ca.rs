//! `forculus ca` — CA certificate management commands.

use std::path::Path;

use anyhow::{Context, Result};
use forculus_config::{expand_tilde, load_config};

use crate::ca_trust;

/// Resolve the CA PEM path from config.
pub fn resolve_ca_pem_path(config_path: &Path) -> Result<std::path::PathBuf> {
    let config = load_config(config_path).context("loading configuration")?;
    let ca_dir = expand_tilde(&config.proxy.tls.ca_dir);
    Ok(std::path::PathBuf::from(ca_dir).join("ca.pem"))
}

/// Export the CA certificate PEM to stdout.
pub fn export(config_path: &Path) -> Result<()> {
    let ca_pem_path = resolve_ca_pem_path(config_path)?;

    if !ca_pem_path.exists() {
        anyhow::bail!(
            "No CA certificate found at {}. Run `forculus init` or `forculus proxy start` first.",
            ca_pem_path.display()
        );
    }

    let pem = std::fs::read_to_string(&ca_pem_path)
        .with_context(|| format!("reading {}", ca_pem_path.display()))?;

    print!("{pem}");
    Ok(())
}

/// Print the absolute path to the CA certificate PEM file.
pub fn path(config_path: &Path) -> Result<()> {
    let ca_pem_path = resolve_ca_pem_path(config_path)?;

    if !ca_pem_path.exists() {
        eprintln!("CA certificate not found. Run 'forculus init' first.");
        std::process::exit(1);
    }

    let absolute = ca_pem_path
        .canonicalize()
        .with_context(|| format!("resolving absolute path for {}", ca_pem_path.display()))?;

    println!("{}", absolute.display());
    Ok(())
}

/// Install the Forculus CA certificate as a trusted root in the system store.
pub fn install(config_path: &Path, skip_confirm: bool) -> Result<()> {
    let ca_pem_path = resolve_ca_pem_path(config_path)?;

    if !ca_pem_path.exists() {
        anyhow::bail!("CA certificate not found. Run `forculus init` first.");
    }

    let platform = ca_trust::detect_platform();
    eprintln!("Detected platform: {platform}");

    // Confirmation prompt (unless --yes was passed).
    if !skip_confirm {
        eprintln!();
        eprintln!("This will install the Forculus CA certificate as a trusted root.");
        eprintln!("Forculus will be able to intercept HTTPS traffic on this machine.");
        eprint!("Continue? [y/N] ");

        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .context("reading confirmation")?;
        let input = input.trim().to_lowercase();
        if input != "y" && input != "yes" {
            eprintln!("Aborted.");
            return Ok(());
        }
    }

    let trust_cmd =
        ca_trust::install_command(&platform, &ca_pem_path).map_err(|e| anyhow::anyhow!("{e}"))?;

    eprintln!("  {}", trust_cmd.description);

    match ca_trust::execute_trust_command(trust_cmd) {
        Ok(()) => {
            eprintln!();
            eprintln!("CA certificate installed successfully.");
            eprintln!(
                "The Forculus CA is now trusted system-wide. HTTPS MITM inspection is active."
            );
            Ok(())
        }
        Err(e) => {
            anyhow::bail!(
                "Failed to install CA certificate.\n\n{e}\n\n\
                 Hint: try running with elevated privileges:\n  \
                 sudo forculus ca install --yes"
            );
        }
    }
}

/// Remove the Forculus CA certificate from the system trust store.
pub fn uninstall(config_path: &Path, skip_confirm: bool) -> Result<()> {
    let ca_pem_path = resolve_ca_pem_path(config_path)?;

    if !ca_pem_path.exists() {
        anyhow::bail!("CA certificate not found. Run `forculus init` first.");
    }

    let platform = ca_trust::detect_platform();
    eprintln!("Detected platform: {platform}");

    if !skip_confirm {
        eprintln!();
        eprintln!("This will remove the Forculus CA certificate from the system trust store.");
        eprintln!("HTTPS MITM inspection will no longer work until the CA is reinstalled.");
        eprint!("Continue? [y/N] ");

        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .context("reading confirmation")?;
        let input = input.trim().to_lowercase();
        if input != "y" && input != "yes" {
            eprintln!("Aborted.");
            return Ok(());
        }
    }

    let trust_cmd =
        ca_trust::uninstall_command(&platform, &ca_pem_path).map_err(|e| anyhow::anyhow!("{e}"))?;

    eprintln!("  {}", trust_cmd.description);

    match ca_trust::execute_trust_command(trust_cmd) {
        Ok(()) => {
            eprintln!();
            eprintln!("CA certificate removed successfully.");
            Ok(())
        }
        Err(e) => {
            anyhow::bail!(
                "Failed to remove CA certificate.\n\n{e}\n\n\
                 Hint: try running with elevated privileges:\n  \
                 sudo forculus ca uninstall --yes"
            );
        }
    }
}

/// Run the CA install flow non-interactively (used by `forculus init`).
/// Returns Ok(true) if installed, Ok(false) if skipped.
pub fn try_install_from_init(ca_pem_path: &Path) -> Result<bool> {
    let platform = ca_trust::detect_platform();

    let trust_cmd = match ca_trust::install_command(&platform, ca_pem_path) {
        Ok(cmd) => cmd,
        Err(e) => {
            eprintln!("  Cannot auto-install CA on this platform: {e}");
            return Ok(false);
        }
    };

    eprintln!("  {}", trust_cmd.description);

    match ca_trust::execute_trust_command(trust_cmd) {
        Ok(()) => {
            eprintln!("  CA certificate installed system-wide.");
            Ok(true)
        }
        Err(e) => {
            eprintln!("  Could not install CA automatically: {e}");
            eprintln!("  You can install it manually later with: sudo forculus ca install");
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_path_returns_pem_path() {
        let dir = tempfile::tempdir().unwrap();
        let ca_dir = dir.path().join("ca");
        std::fs::create_dir_all(&ca_dir).unwrap();

        // Write a dummy ca.pem.
        let ca_pem = ca_dir.join("ca.pem");
        std::fs::write(
            &ca_pem,
            "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n",
        )
        .unwrap();

        // Write a config pointing to this CA dir.
        let config_path = dir.path().join("forculus.yaml");
        std::fs::write(
            &config_path,
            format!(
                "proxy:\n  listen_address: \"127.0.0.1:0\"\n  tls:\n    ca_dir: \"{}\"\n",
                ca_dir.display()
            ),
        )
        .unwrap();

        // Resolve the path.
        let resolved = resolve_ca_pem_path(&config_path).unwrap();
        assert!(resolved.exists(), "resolved path should exist on disk");
        assert!(
            resolved.to_str().unwrap().ends_with("ca.pem"),
            "path should end with ca.pem, got: {}",
            resolved.display()
        );

        // Verify canonicalize works (the path handler uses it).
        let absolute = resolved.canonicalize().unwrap();
        assert!(absolute.is_absolute(), "path should be absolute");
        assert!(
            absolute.to_str().unwrap().ends_with("ca.pem"),
            "absolute path should end with ca.pem"
        );
    }
}
