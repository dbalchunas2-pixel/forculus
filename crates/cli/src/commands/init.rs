//! `forculus init [path]` — scaffold a new Forculus project directory.

use std::path::Path;

use anyhow::{Context, Result};

/// Prompt the user to install the CA system-wide. Returns `true` if installed.
fn offer_ca_install(ca_cert: &Path) -> bool {
    if !ca_cert.exists() {
        return false;
    }

    eprintln!();
    eprint!(
        "Install CA certificate system-wide? This allows Forculus to inspect HTTPS traffic. [y/N] "
    );

    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    let input = input.trim().to_lowercase();
    if input != "y" && input != "yes" {
        return false;
    }

    match super::ca::try_install_from_init(ca_cert) {
        Ok(installed) => installed,
        Err(e) => {
            eprintln!("  Warning: CA install failed: {e}");
            false
        }
    }
}

/// Run the `init` command: create project scaffolding in the target directory.
pub fn run(path: Option<&Path>) -> Result<()> {
    let target = path.unwrap_or_else(|| Path::new("."));

    std::fs::create_dir_all(target)
        .with_context(|| format!("creating directory {}", target.display()))?;

    // Write default config.
    let config_path = target.join("forculus.yaml");
    if !config_path.exists() {
        std::fs::write(&config_path, include_str!("../../../../forculus.yaml"))
            .context("writing forculus.yaml")?;
        println!("  created {}", config_path.display());
    }

    // Create policies directory with placeholder.
    let policies_dir = target.join("policies");
    std::fs::create_dir_all(&policies_dir).context("creating policies/")?;
    let global_policy = policies_dir.join("global.yaml");
    if !global_policy.exists() {
        std::fs::write(
            &global_policy,
            r#"# Forculus global policy — starter template
#
# This policy allows all read operations and denies everything else.
# Customize the rules below to match your governance requirements.

metadata:
  name: global
  description: Default global policy
  scope: global

rules:
  # Allow read-only operations by default.
  - name: allow-reads
    verdict: allow
    reason: "Read operations are safe"
    priority: 10
    match:
      actions: ["read_*", "list_*", "get_*", "GET *", "HEAD *", "OPTIONS *"]

  # Default deny — catches everything not explicitly allowed above.
  - name: default-deny
    verdict: deny
    reason: "No matching allow rule"
"#,
        )
        .context("writing global.yaml")?;
        println!("  created {}", global_policy.display());
    }

    // Create secrets directory.
    let secrets_dir = target.join("secrets");
    std::fs::create_dir_all(&secrets_dir).context("creating secrets/")?;
    let gitkeep = secrets_dir.join(".gitkeep");
    if !gitkeep.exists() {
        std::fs::write(&gitkeep, "").context("writing .gitkeep")?;
    }

    // Generate CA if it doesn't already exist.
    let ca_dir = forculus_config::expand_tilde("~/.forculus/ca");
    let ca_cert = Path::new(&ca_dir).join("ca.pem");
    if !ca_cert.exists() {
        // Generating the CA has the side-effect of writing the files.
        forculus_proxy::tls::TlsState::new("~/.forculus/ca").context("generating CA")?;
        println!("  generated CA in {ca_dir}");
    }

    // Generate vault key if it doesn't already exist.
    let vault_key_path = forculus_config::expand_tilde("~/.forculus/vault-key.age");
    if !Path::new(&vault_key_path).exists() {
        forculus_vault::encryption::VaultKey::load_or_generate(Path::new(&vault_key_path))
            .context("generating vault key")?;
        println!("  generated vault key at {vault_key_path}");
    }

    // Create credentials directory.
    let creds_dir = forculus_config::expand_tilde("~/.forculus/credentials");
    std::fs::create_dir_all(&creds_dir).context("creating credentials directory")?;

    // Create empty bindings file if it doesn't exist.
    let bindings_path = forculus_config::expand_tilde("~/.forculus/bindings.yaml");
    if !Path::new(&bindings_path).exists() {
        std::fs::write(
            &bindings_path,
            r#"# Credential bindings — maps tools to credentials.
#
# Example:
#   bindings:
#     - credential: github-token
#       tool: "github__*"
#       scope:
#         teams: [engineering]
#         environments: [production]
bindings: []
"#,
        )
        .context("writing bindings.yaml")?;
        println!("  created {bindings_path}");
    }

    // Offer to install the CA system-wide.
    let ca_installed = offer_ca_install(&ca_cert);

    println!();
    println!("Forculus project initialised in {}", target.display());
    println!();
    println!("Next steps:");
    println!("  1. Edit forculus.yaml to configure the proxy");
    if !ca_installed {
        println!("  2. Trust the CA: forculus ca install  (or set env vars manually)");
        println!("     export NODE_EXTRA_CA_CERTS=\"{}/ca.pem\"", ca_dir);
        println!("     export REQUESTS_CA_BUNDLE=\"{}/ca.pem\"", ca_dir);
        println!("     export SSL_CERT_FILE=\"{}/ca.pem\"", ca_dir);
    } else {
        println!("  2. CA is already trusted system-wide");
    }
    println!(
        "  {}. Add credentials with `forculus cred add <name>`",
        if ca_installed { 2 } else { 3 }
    );
    println!(
        "  {}. Run `forculus proxy start` to launch the proxy",
        if ca_installed { 3 } else { 4 }
    );

    Ok(())
}
