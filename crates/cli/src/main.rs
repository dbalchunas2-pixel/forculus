//! Forculus CLI — binary entry point for the `forculus` command.

use std::path::PathBuf;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};

mod ca_trust;
mod commands;

/// Governance layer for AI agents.
#[derive(Parser)]
#[command(name = "forculus", about = "Governance layer for AI agents", version)]
struct Cli {
    /// Path to config file.
    #[arg(long, default_value = "forculus.yaml", global = true)]
    config: PathBuf,

    /// Override the log level (trace, debug, info, warn, error).
    #[arg(long, global = true)]
    log_level: Option<String>,

    /// Disable colored output.
    #[arg(long, global = true)]
    no_color: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage the governance proxy.
    Proxy {
        #[command(subcommand)]
        action: ProxyAction,
    },
    /// Initialize a new Forculus project.
    Init {
        /// Directory to initialize (defaults to current directory).
        path: Option<PathBuf>,
    },
    /// Manage the Forculus CA certificate.
    Ca {
        #[command(subcommand)]
        action: CaAction,
    },
    /// Run the MCP governance gateway.
    Mcp {
        #[command(subcommand)]
        action: McpAction,
    },
    /// Manage policies.
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
    /// Manage vault credentials.
    Cred {
        #[command(subcommand)]
        action: CredAction,
    },
    /// Manage sessions.
    Session {
        #[command(subcommand)]
        action: SessionAction,
    },
    /// Query and manage the audit log.
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },
    /// Test content inspection.
    Inspect {
        #[command(subcommand)]
        action: InspectAction,
    },
    /// OIDC authentication management.
    Auth {
        #[command(subcommand)]
        action: AuthAction,
    },
    /// Diagnose common setup issues.
    Doctor {
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show health dashboard of all subsystems.
    Status {
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Generate shell completions.
    Completions {
        /// Shell to generate completions for.
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
}

#[derive(Subcommand)]
enum CaAction {
    /// Print the CA certificate PEM to stdout.
    Export,
    /// Print the absolute path to the CA certificate PEM file.
    Path,
    /// Install the CA certificate as a trusted root in the system store.
    Install {
        /// Skip the confirmation prompt.
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Remove the CA certificate from the system trust store.
    Uninstall {
        /// Skip the confirmation prompt.
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum McpAction {
    /// Start the MCP gateway (stdio mode).
    Start,
    /// Start the MCP gateway over HTTP (Streamable HTTP transport).
    Serve {
        /// Override the listen address (e.g. 127.0.0.1:3000).
        #[arg(long)]
        listen: Option<String>,
    },
}

#[derive(Subcommand)]
enum PolicyAction {
    /// Validate policy files in a directory.
    Validate {
        /// Path to the policies directory.
        #[arg(default_value = "./policies")]
        path: PathBuf,
    },
    /// Test policies by replaying audit events.
    Test {
        /// Directory containing policies to test.
        #[arg(long)]
        dir: PathBuf,
        /// Only replay events since this time (e.g. 1h, 24h, 7d).
        #[arg(long)]
        since: Option<String>,
        /// Maximum events to replay.
        #[arg(long, default_value = "1000")]
        limit: usize,
        /// Show events where verdict didn't change.
        #[arg(long)]
        show_unchanged: bool,
    },
}

#[derive(Subcommand)]
enum ProxyAction {
    /// Start the proxy server.
    Start {
        /// Override the listen address (e.g. 127.0.0.1:9090).
        #[arg(long)]
        listen: Option<String>,
    },
}

#[derive(Subcommand)]
enum CredAction {
    /// Add a new credential to the vault.
    Add {
        /// Credential name (e.g. github-token).
        name: String,
        /// Credential type: bearer, basic, api-key, custom-header.
        #[arg(long, default_value = "bearer")]
        r#type: String,
        /// Description of this credential.
        #[arg(long)]
        description: Option<String>,
        /// For api-key / custom-header: the header name.
        #[arg(long)]
        header: Option<String>,
        /// For basic auth: the username.
        #[arg(long)]
        username: Option<String>,
    },
    /// List all credentials in the vault.
    List,
    /// Remove a credential from the vault.
    Remove {
        /// Credential name to remove.
        name: String,
    },
    /// Test credential resolution for a tool + session.
    Test {
        /// Tool name (e.g. github__push).
        tool: String,
        /// Session token.
        #[arg(long)]
        session: String,
    },
}

#[derive(Subcommand)]
enum AuditAction {
    /// Search audit events.
    Search {
        /// Filter by event type (e.g. request_processed, policy_decision).
        #[arg(long)]
        event_type: Option<String>,
        /// Filter by outcome (e.g. success, denied, failed).
        #[arg(long)]
        outcome: Option<String>,
        /// Filter by operator name.
        #[arg(long)]
        operator: Option<String>,
        /// Filter by tool name (supports * wildcard).
        #[arg(long)]
        tool: Option<String>,
        /// Show events since (e.g. 1h, 24h, 7d).
        #[arg(long)]
        since: Option<String>,
        /// Maximum number of results.
        #[arg(long, default_value = "50")]
        limit: Option<usize>,
    },
    /// Show the most recent audit events.
    Tail {
        /// Number of events to show.
        #[arg(default_value = "20")]
        count: usize,
    },
    /// Show aggregate audit statistics.
    Stats {
        /// Show stats since (e.g. 1h, 24h, 7d).
        #[arg(long)]
        since: Option<String>,
    },
    /// Export audit events as JSON lines.
    Export {
        /// Export events since (e.g. 1h, 24h, 7d).
        #[arg(long)]
        since: Option<String>,
    },
    /// Run retention cleanup on old events.
    Cleanup {
        /// Override retention period (days).
        #[arg(long)]
        days: Option<u32>,
    },
    /// Verify the integrity of the audit hash chain.
    Verify,
}

#[derive(Subcommand)]
enum InspectAction {
    /// Scan text or a file for sensitive content.
    Scan {
        /// Text to scan (if omitted, reads from stdin).
        #[arg(long)]
        text: Option<String>,
        /// File to scan.
        #[arg(long)]
        file: Option<PathBuf>,
        /// Output format (table, json).
        #[arg(long, default_value = "table")]
        format: String,
    },
    /// List all inspection rules.
    Rules {
        /// Show disabled rules too.
        #[arg(long)]
        all: bool,
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum AuthAction {
    /// Start the auth management server (OIDC endpoints).
    Serve {
        /// Override the listen address (e.g. 127.0.0.1:9082).
        #[arg(long)]
        listen: Option<String>,
    },
    /// Show OIDC configuration and connectivity status.
    Status,
}

#[derive(Subcommand)]
enum SessionAction {
    /// Create a new session.
    Create {
        /// Operator name (required unless --oidc is used).
        #[arg(long, required_unless_present = "oidc")]
        operator: Option<String>,
        /// Team.
        #[arg(long)]
        team: Option<String>,
        /// Project.
        #[arg(long)]
        project: Option<String>,
        /// Environment (e.g. staging, production).
        #[arg(long)]
        environment: Option<String>,
        /// Agent type (e.g. coding, research).
        #[arg(long)]
        agent_type: Option<String>,
        /// Time-to-live in seconds.
        #[arg(long)]
        ttl: Option<u64>,
        /// Description.
        #[arg(long)]
        description: Option<String>,
        /// Use OIDC browser authentication to create the session.
        #[arg(long)]
        oidc: bool,
    },
    /// List active sessions.
    List {
        /// Include revoked sessions.
        #[arg(long)]
        all: bool,
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Revoke a session.
    Revoke {
        /// Session ID to revoke.
        id: String,
    },
    /// Show detailed activity timeline for a session.
    Inspect {
        /// Session ID to inspect.
        id: String,
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Respect NO_COLOR env var and --no-color flag.
    if cli.no_color || std::env::var("NO_COLOR").is_ok() {
        colored::control::set_override(false);
    }

    match cli.command {
        Commands::Proxy { action } => match action {
            ProxyAction::Start { listen } => {
                commands::proxy::start(&cli.config, cli.log_level.as_deref(), listen.as_deref())
            }
        },
        Commands::Init { path } => commands::init::run(path.as_deref()),
        Commands::Ca { action } => match action {
            CaAction::Export => commands::ca::export(&cli.config),
            CaAction::Path => commands::ca::path(&cli.config),
            CaAction::Install { yes } => commands::ca::install(&cli.config, yes),
            CaAction::Uninstall { yes } => commands::ca::uninstall(&cli.config, yes),
        },
        Commands::Mcp { action } => match action {
            McpAction::Start => commands::mcp::start(&cli.config, cli.log_level.as_deref()),
            McpAction::Serve { listen } => {
                commands::mcp::serve(&cli.config, cli.log_level.as_deref(), listen.as_deref())
            }
        },
        Commands::Policy { action } => match action {
            PolicyAction::Validate { path } => commands::policy::validate(&path),
            PolicyAction::Test {
                dir,
                since,
                limit,
                show_unchanged,
            } => commands::policy::test_replay(
                &cli.config,
                &dir,
                since.as_deref(),
                limit,
                show_unchanged,
            ),
        },
        Commands::Cred { action } => match action {
            CredAction::Add {
                name,
                r#type,
                description,
                header,
                username,
            } => commands::cred::add(
                &cli.config,
                &name,
                &r#type,
                description.as_deref(),
                header.as_deref(),
                username.as_deref(),
            ),
            CredAction::List => commands::cred::list(&cli.config),
            CredAction::Remove { name } => commands::cred::remove(&cli.config, &name),
            CredAction::Test { tool, session } => {
                commands::cred::test_resolve(&cli.config, &tool, &session)
            }
        },
        Commands::Audit { action } => match action {
            AuditAction::Search {
                event_type,
                outcome,
                operator,
                tool,
                since,
                limit,
            } => commands::audit::search(
                &cli.config,
                event_type.as_deref(),
                outcome.as_deref(),
                operator.as_deref(),
                tool.as_deref(),
                since.as_deref(),
                limit,
            ),
            AuditAction::Tail { count } => commands::audit::tail(&cli.config, count),
            AuditAction::Stats { since } => commands::audit::stats(&cli.config, since.as_deref()),
            AuditAction::Export { since } => commands::audit::export(&cli.config, since.as_deref()),
            AuditAction::Cleanup { days } => commands::audit::cleanup(&cli.config, days),
            AuditAction::Verify => commands::audit::verify(&cli.config),
        },
        Commands::Inspect { action } => match action {
            InspectAction::Scan { text, file, format } => {
                commands::inspect::scan(&cli.config, text.as_deref(), file.as_deref(), &format)
            }
            InspectAction::Rules { all, json } => commands::inspect::rules(&cli.config, all, json),
        },
        Commands::Auth { action } => match action {
            AuthAction::Serve { listen } => {
                commands::auth::serve(&cli.config, cli.log_level.as_deref(), listen.as_deref())
            }
            AuthAction::Status => commands::auth::status(&cli.config),
        },
        Commands::Session { action } => match action {
            SessionAction::Create {
                operator,
                team,
                project,
                environment,
                agent_type,
                ttl,
                description,
                oidc,
            } => {
                if oidc {
                    commands::auth::session_create_oidc(&cli.config)
                } else {
                    commands::session::create(
                        &cli.config,
                        operator.as_deref().unwrap_or(""),
                        team.as_deref(),
                        project.as_deref(),
                        environment.as_deref(),
                        agent_type.as_deref(),
                        ttl,
                        description.as_deref(),
                    )
                }
            }
            SessionAction::List { all, json } => commands::session::list(&cli.config, all, json),
            SessionAction::Revoke { id } => commands::session::revoke(&cli.config, &id),
            SessionAction::Inspect { id, json } => {
                commands::session::inspect(&cli.config, &id, json)
            }
        },
        Commands::Doctor { json } => commands::doctor::run(&cli.config, json),
        Commands::Status { json } => commands::status::run(&cli.config, json),
        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            clap_complete::generate(shell, &mut cmd, "forculus", &mut std::io::stdout());
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_color_flag_parses() {
        let cli = Cli::try_parse_from(["forculus", "--no-color", "inspect", "rules"]).unwrap();
        assert!(cli.no_color);
    }

    #[test]
    fn completions_bash_generates_output() {
        let mut cmd = Cli::command();
        let mut buf = Vec::new();
        clap_complete::generate(clap_complete::Shell::Bash, &mut cmd, "forculus", &mut buf);
        let output = String::from_utf8(buf).unwrap();
        assert!(!output.is_empty());
        assert!(output.contains("forculus"));
    }

    #[test]
    fn ca_install_subcommand_parses() {
        let cli = Cli::try_parse_from(["forculus", "ca", "install", "--yes"]).unwrap();
        match cli.command {
            Commands::Ca {
                action: CaAction::Install { yes },
            } => assert!(yes),
            _ => panic!("expected Ca Install"),
        }
    }

    #[test]
    fn ca_install_default_no_yes() {
        let cli = Cli::try_parse_from(["forculus", "ca", "install"]).unwrap();
        match cli.command {
            Commands::Ca {
                action: CaAction::Install { yes },
            } => assert!(!yes),
            _ => panic!("expected Ca Install"),
        }
    }

    #[test]
    fn mcp_serve_subcommand_parses() {
        let cli =
            Cli::try_parse_from(["forculus", "mcp", "serve", "--listen", "0.0.0.0:4000"]).unwrap();
        match cli.command {
            Commands::Mcp {
                action: McpAction::Serve { listen },
            } => assert_eq!(listen.as_deref(), Some("0.0.0.0:4000")),
            _ => panic!("expected Mcp Serve"),
        }
    }

    #[test]
    fn mcp_serve_default_no_listen() {
        let cli = Cli::try_parse_from(["forculus", "mcp", "serve"]).unwrap();
        match cli.command {
            Commands::Mcp {
                action: McpAction::Serve { listen },
            } => assert!(listen.is_none()),
            _ => panic!("expected Mcp Serve"),
        }
    }

    #[test]
    fn ca_uninstall_subcommand_parses() {
        let cli = Cli::try_parse_from(["forculus", "ca", "uninstall", "-y"]).unwrap();
        match cli.command {
            Commands::Ca {
                action: CaAction::Uninstall { yes },
            } => assert!(yes),
            _ => panic!("expected Ca Uninstall"),
        }
    }

    #[test]
    fn session_create_oidc_flag_parses() {
        let cli = Cli::try_parse_from(["forculus", "session", "create", "--oidc"]).unwrap();
        match cli.command {
            Commands::Session {
                action: SessionAction::Create { oidc, operator, .. },
            } => {
                assert!(oidc);
                assert!(operator.is_none());
            }
            _ => panic!("expected Session Create with --oidc"),
        }
    }

    #[test]
    fn session_create_operator_still_works() {
        let cli =
            Cli::try_parse_from(["forculus", "session", "create", "--operator", "alice"]).unwrap();
        match cli.command {
            Commands::Session {
                action: SessionAction::Create { oidc, operator, .. },
            } => {
                assert!(!oidc);
                assert_eq!(operator.as_deref(), Some("alice"));
            }
            _ => panic!("expected Session Create with --operator"),
        }
    }

    #[test]
    fn auth_serve_subcommand_parses() {
        let cli = Cli::try_parse_from(["forculus", "auth", "serve"]).unwrap();
        match cli.command {
            Commands::Auth {
                action: AuthAction::Serve { listen },
            } => assert!(listen.is_none()),
            _ => panic!("expected Auth Serve"),
        }
    }

    #[test]
    fn auth_serve_with_listen_parses() {
        let cli =
            Cli::try_parse_from(["forculus", "auth", "serve", "--listen", "0.0.0.0:9082"]).unwrap();
        match cli.command {
            Commands::Auth {
                action: AuthAction::Serve { listen },
            } => assert_eq!(listen.as_deref(), Some("0.0.0.0:9082")),
            _ => panic!("expected Auth Serve"),
        }
    }

    #[test]
    fn auth_status_subcommand_parses() {
        let cli = Cli::try_parse_from(["forculus", "auth", "status"]).unwrap();
        match cli.command {
            Commands::Auth {
                action: AuthAction::Status,
            } => {}
            _ => panic!("expected Auth Status"),
        }
    }
}
