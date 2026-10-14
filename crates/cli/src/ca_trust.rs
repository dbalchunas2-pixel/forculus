//! Platform detection and system trust-store command construction for the
//! Forculus CA certificate.
//!
//! Command construction is separated from execution so that unit tests can
//! verify the correct program and arguments without running privileged
//! system commands.

use std::path::Path;

/// Detected operating system / distro family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Platform {
    MacOS,
    LinuxDebian,
    LinuxRedHat,
    Unsupported(String),
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Platform::MacOS => write!(f, "macOS"),
            Platform::LinuxDebian => write!(f, "Linux (Debian/Ubuntu)"),
            Platform::LinuxRedHat => write!(f, "Linux (RHEL/Fedora)"),
            Platform::Unsupported(os) => write!(f, "Unsupported ({os})"),
        }
    }
}

/// Detect the current platform.
///
/// On Linux, probes well-known files to distinguish Debian-family from
/// RHEL-family, with a fallback to `/etc/os-release`.
pub fn detect_platform() -> Platform {
    match std::env::consts::OS {
        "macos" => Platform::MacOS,
        "linux" => detect_linux_distro(),
        other => Platform::Unsupported(other.to_string()),
    }
}

/// Probe Linux distro family via filesystem markers.
fn detect_linux_distro() -> Platform {
    // Debian / Ubuntu
    if Path::new("/etc/debian_version").exists() {
        return Platform::LinuxDebian;
    }

    // RHEL / Fedora / CentOS
    if Path::new("/etc/redhat-release").exists() || Path::new("/etc/fedora-release").exists() {
        return Platform::LinuxRedHat;
    }

    // Fallback: parse /etc/os-release for ID_LIKE
    if let Ok(contents) = std::fs::read_to_string("/etc/os-release") {
        for line in contents.lines() {
            if let Some(value) = line.strip_prefix("ID_LIKE=") {
                let value = value.trim_matches('"').to_lowercase();
                if value.contains("debian") || value.contains("ubuntu") {
                    return Platform::LinuxDebian;
                }
                if value.contains("rhel") || value.contains("fedora") || value.contains("centos") {
                    return Platform::LinuxRedHat;
                }
            }
            // Also check bare ID= for direct matches
            if let Some(value) = line.strip_prefix("ID=") {
                let value = value.trim_matches('"').to_lowercase();
                if value == "debian" || value == "ubuntu" {
                    return Platform::LinuxDebian;
                }
                if value == "rhel" || value == "fedora" || value == "centos" {
                    return Platform::LinuxRedHat;
                }
            }
        }
    }

    Platform::Unsupported("linux (unknown distro)".to_string())
}

/// Describes a system command to execute, composed of a primary command
/// and an optional follow-up command (e.g., copy + update-ca-certificates).
#[derive(Debug)]
pub struct TrustCommand {
    /// The primary command to execute.
    pub primary: std::process::Command,
    /// An optional follow-up command (e.g., `update-ca-certificates`).
    pub followup: Option<std::process::Command>,
    /// Human-readable description of what this does.
    pub description: String,
}

/// The well-known destination path on Debian-family systems.
const DEBIAN_CERT_PATH: &str = "/usr/local/share/ca-certificates/forculus-ca.crt";

/// The well-known destination path on RHEL-family systems.
const REDHAT_CERT_PATH: &str = "/etc/pki/ca-trust/source/anchors/forculus-ca.crt";

/// Construct the command(s) to install the CA certificate into the system
/// trust store. Returns an error for unsupported platforms.
pub fn install_command(platform: &Platform, ca_path: &Path) -> Result<TrustCommand, String> {
    let ca_str = ca_path
        .to_str()
        .ok_or_else(|| "CA path contains non-UTF-8 characters".to_string())?;

    match platform {
        Platform::MacOS => {
            let mut cmd = std::process::Command::new("security");
            cmd.args([
                "add-trusted-cert",
                "-d",
                "-r",
                "trustRoot",
                "-k",
                "/Library/Keychains/System.keychain",
                ca_str,
            ]);
            Ok(TrustCommand {
                primary: cmd,
                followup: None,
                description: "Add CA to macOS System Keychain".to_string(),
            })
        }
        Platform::LinuxDebian => {
            let mut cp = std::process::Command::new("cp");
            cp.args([ca_str, DEBIAN_CERT_PATH]);
            let mut update = std::process::Command::new("update-ca-certificates");
            // no extra args needed
            let _ = &mut update;
            Ok(TrustCommand {
                primary: cp,
                followup: Some(update),
                description: format!("Copy CA to {DEBIAN_CERT_PATH} and update trust store"),
            })
        }
        Platform::LinuxRedHat => {
            let mut cp = std::process::Command::new("cp");
            cp.args([ca_str, REDHAT_CERT_PATH]);
            let mut update = std::process::Command::new("update-ca-trust");
            let _ = &mut update;
            Ok(TrustCommand {
                primary: cp,
                followup: Some(update),
                description: format!("Copy CA to {REDHAT_CERT_PATH} and update trust store"),
            })
        }
        Platform::Unsupported(os) => Err(format!(
            "Automatic CA installation is not supported on {os}.\n\
             Please install the CA certificate manually:\n  {}",
            ca_str
        )),
    }
}

/// Construct the command(s) to uninstall the CA certificate from the system
/// trust store. Returns an error for unsupported platforms.
pub fn uninstall_command(platform: &Platform, ca_path: &Path) -> Result<TrustCommand, String> {
    let ca_str = ca_path
        .to_str()
        .ok_or_else(|| "CA path contains non-UTF-8 characters".to_string())?;

    match platform {
        Platform::MacOS => {
            let mut cmd = std::process::Command::new("security");
            cmd.args(["remove-trusted-cert", "-d", ca_str]);
            Ok(TrustCommand {
                primary: cmd,
                followup: None,
                description: "Remove CA from macOS System Keychain".to_string(),
            })
        }
        Platform::LinuxDebian => {
            let mut rm = std::process::Command::new("rm");
            rm.args(["-f", DEBIAN_CERT_PATH]);
            let mut update = std::process::Command::new("update-ca-certificates");
            update.arg("--fresh");
            Ok(TrustCommand {
                primary: rm,
                followup: Some(update),
                description: format!("Remove {DEBIAN_CERT_PATH} and refresh trust store"),
            })
        }
        Platform::LinuxRedHat => {
            let mut rm = std::process::Command::new("rm");
            rm.args(["-f", REDHAT_CERT_PATH]);
            let mut update = std::process::Command::new("update-ca-trust");
            let _ = &mut update;
            Ok(TrustCommand {
                primary: rm,
                followup: Some(update),
                description: format!("Remove {REDHAT_CERT_PATH} and refresh trust store"),
            })
        }
        Platform::Unsupported(os) => Err(format!(
            "Automatic CA uninstallation is not supported on {os}.\n\
             Please remove the CA certificate manually:\n  {}",
            ca_str
        )),
    }
}

/// Execute a `TrustCommand`, returning a user-friendly error message on failure.
pub fn execute_trust_command(mut trust_cmd: TrustCommand) -> Result<(), String> {
    // Run primary command.
    let output = trust_cmd
        .primary
        .output()
        .map_err(|e| format_exec_error(&e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(suggest_sudo(&stderr));
    }

    // Run follow-up if present.
    if let Some(mut followup) = trust_cmd.followup {
        let output = followup.output().map_err(|e| format_exec_error(&e))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(suggest_sudo(&stderr));
        }
    }

    Ok(())
}

/// Format a command execution error with actionable guidance.
fn format_exec_error(e: &std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        "Permission denied. Try running with sudo:\n  sudo forculus ca install".to_string()
    } else if e.kind() == std::io::ErrorKind::NotFound {
        format!(
            "Required command not found: {e}\n\
             Make sure the necessary system utilities are installed."
        )
    } else {
        format!("Failed to execute command: {e}")
    }
}

/// If stderr contains permission-related text, append a sudo hint.
fn suggest_sudo(stderr: &str) -> String {
    let lower = stderr.to_lowercase();
    if lower.contains("permission")
        || lower.contains("access denied")
        || lower.contains("operation not permitted")
        || lower.contains("eacces")
    {
        format!(
            "{}\n\nPermission denied. Try running with sudo:\n  sudo forculus ca install",
            stderr.trim()
        )
    } else {
        format!("Command failed:\n{}", stderr.trim())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn detect_platform_returns_valid_variant() {
        let platform = detect_platform();
        // On any CI/local machine, we should get a known variant.
        match &platform {
            Platform::MacOS
            | Platform::LinuxDebian
            | Platform::LinuxRedHat
            | Platform::Unsupported(_) => {}
        }
        // Display impl should not be empty.
        let display = format!("{platform}");
        assert!(!display.is_empty());
    }

    #[test]
    fn install_command_macos() {
        let path = PathBuf::from("/tmp/test-ca.pem");
        let trust_cmd = install_command(&Platform::MacOS, &path).unwrap();
        let cmd = &trust_cmd.primary;
        assert_eq!(cmd.get_program(), "security");
        let args: Vec<&std::ffi::OsStr> = cmd.get_args().collect();
        assert_eq!(
            args,
            &[
                "add-trusted-cert",
                "-d",
                "-r",
                "trustRoot",
                "-k",
                "/Library/Keychains/System.keychain",
                "/tmp/test-ca.pem",
            ]
        );
        assert!(trust_cmd.followup.is_none());
    }

    #[test]
    fn install_command_linux_debian() {
        let path = PathBuf::from("/tmp/test-ca.pem");
        let trust_cmd = install_command(&Platform::LinuxDebian, &path).unwrap();

        // Primary: cp
        let cmd = &trust_cmd.primary;
        assert_eq!(cmd.get_program(), "cp");
        let args: Vec<&std::ffi::OsStr> = cmd.get_args().collect();
        assert_eq!(args, &["/tmp/test-ca.pem", DEBIAN_CERT_PATH,]);

        // Followup: update-ca-certificates
        let followup = trust_cmd.followup.as_ref().unwrap();
        assert_eq!(followup.get_program(), "update-ca-certificates");
        let followup_args: Vec<&std::ffi::OsStr> = followup.get_args().collect();
        assert!(followup_args.is_empty());
    }

    #[test]
    fn install_command_linux_redhat() {
        let path = PathBuf::from("/tmp/test-ca.pem");
        let trust_cmd = install_command(&Platform::LinuxRedHat, &path).unwrap();

        // Primary: cp
        let cmd = &trust_cmd.primary;
        assert_eq!(cmd.get_program(), "cp");
        let args: Vec<&std::ffi::OsStr> = cmd.get_args().collect();
        assert_eq!(args, &["/tmp/test-ca.pem", REDHAT_CERT_PATH,]);

        // Followup: update-ca-trust
        let followup = trust_cmd.followup.as_ref().unwrap();
        assert_eq!(followup.get_program(), "update-ca-trust");
    }

    #[test]
    fn install_command_unsupported_returns_error() {
        let path = PathBuf::from("/tmp/test-ca.pem");
        let result = install_command(&Platform::Unsupported("freebsd".into()), &path);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("not supported"), "error: {err}");
        assert!(
            err.contains("/tmp/test-ca.pem"),
            "error should contain CA path: {err}"
        );
    }

    #[test]
    fn uninstall_command_macos() {
        let path = PathBuf::from("/tmp/test-ca.pem");
        let trust_cmd = uninstall_command(&Platform::MacOS, &path).unwrap();
        let cmd = &trust_cmd.primary;
        assert_eq!(cmd.get_program(), "security");
        let args: Vec<&std::ffi::OsStr> = cmd.get_args().collect();
        assert_eq!(args, &["remove-trusted-cert", "-d", "/tmp/test-ca.pem",]);
        assert!(trust_cmd.followup.is_none());
    }

    #[test]
    fn uninstall_command_linux_debian() {
        let path = PathBuf::from("/tmp/test-ca.pem");
        let trust_cmd = uninstall_command(&Platform::LinuxDebian, &path).unwrap();

        // Primary: rm -f
        let cmd = &trust_cmd.primary;
        assert_eq!(cmd.get_program(), "rm");
        let args: Vec<&std::ffi::OsStr> = cmd.get_args().collect();
        assert_eq!(args, &["-f", DEBIAN_CERT_PATH,]);

        // Followup: update-ca-certificates --fresh
        let followup = trust_cmd.followup.as_ref().unwrap();
        assert_eq!(followup.get_program(), "update-ca-certificates");
        let followup_args: Vec<&std::ffi::OsStr> = followup.get_args().collect();
        assert_eq!(followup_args, &["--fresh"]);
    }

    #[test]
    fn uninstall_command_linux_redhat() {
        let path = PathBuf::from("/tmp/test-ca.pem");
        let trust_cmd = uninstall_command(&Platform::LinuxRedHat, &path).unwrap();

        let cmd = &trust_cmd.primary;
        assert_eq!(cmd.get_program(), "rm");
        let args: Vec<&std::ffi::OsStr> = cmd.get_args().collect();
        assert_eq!(args, &["-f", REDHAT_CERT_PATH,]);

        let followup = trust_cmd.followup.as_ref().unwrap();
        assert_eq!(followup.get_program(), "update-ca-trust");
    }

    #[test]
    fn uninstall_command_unsupported_returns_error() {
        let path = PathBuf::from("/tmp/test-ca.pem");
        let result = uninstall_command(&Platform::Unsupported("windows".into()), &path);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("not supported"), "error: {err}");
    }

    #[test]
    fn ca_not_found_error_message() {
        // Simulate the "CA not found" path that ca.rs would check.
        let missing = PathBuf::from("/nonexistent/path/ca.pem");
        assert!(!missing.exists());
        // The error message is generated by the caller (ca.rs), but we can
        // verify the install_command still works with any valid path string.
        let result = install_command(&Platform::MacOS, &missing);
        assert!(
            result.is_ok(),
            "command construction should succeed even if file doesn't exist"
        );
    }

    #[test]
    fn platform_display_is_meaningful() {
        assert_eq!(format!("{}", Platform::MacOS), "macOS");
        assert_eq!(
            format!("{}", Platform::LinuxDebian),
            "Linux (Debian/Ubuntu)"
        );
        assert_eq!(format!("{}", Platform::LinuxRedHat), "Linux (RHEL/Fedora)");
        assert_eq!(
            format!("{}", Platform::Unsupported("haiku".into())),
            "Unsupported (haiku)"
        );
    }

    #[test]
    fn suggest_sudo_detects_permission_errors() {
        let msg = suggest_sudo("Error: operation not permitted");
        assert!(msg.contains("sudo"), "should suggest sudo: {msg}");

        let msg = suggest_sudo("something else went wrong");
        assert!(!msg.contains("sudo"), "should not suggest sudo: {msg}");
    }
}
