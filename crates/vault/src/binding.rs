//! Credential-to-tool binding resolution.
//!
//! A binding maps a tool pattern + scope constraints to a credential name.
//! When a request is processed, the vault resolves which credential to inject
//! based on the tool being called and the session's scope.

use forculus_policy::glob::GlobPattern;
use serde::{Deserialize, Serialize};

use crate::session::Session;

/// A binding between a tool pattern and a credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialBinding {
    /// Name of the credential this binds to.
    pub credential: String,
    /// Tool pattern (glob). Which tools this binding applies to.
    pub tool: String,
    /// Scope restrictions. All non-empty fields must match the session.
    #[serde(default)]
    pub scope: BindingScope,
}

/// Scope constraints for a binding.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BindingScope {
    /// Only apply for these teams.
    #[serde(default)]
    pub teams: Vec<String>,
    /// Only apply in these environments.
    #[serde(default)]
    pub environments: Vec<String>,
    /// Only apply for these operators.
    #[serde(default)]
    pub operators: Vec<String>,
    /// Only apply within these projects.
    #[serde(default)]
    pub projects: Vec<String>,
}

/// Top-level bindings file structure.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BindingsFile {
    /// The list of credential bindings.
    #[serde(default)]
    pub bindings: Vec<CredentialBinding>,
}

/// Resolve which credential to use for a given tool and session.
///
/// Returns the credential name of the best matching binding, or `None`.
pub fn resolve_binding(
    bindings: &[CredentialBinding],
    tool: &str,
    session: &Session,
) -> Option<String> {
    let mut best: Option<(usize, &CredentialBinding)> = None;

    for binding in bindings {
        // Check tool pattern match.
        let pattern = match GlobPattern::compile(&binding.tool) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if !pattern.matches(tool) {
            continue;
        }

        // Check scope constraints.
        if !scope_matches(&binding.scope, session) {
            continue;
        }

        // Compute specificity (number of non-empty scope fields).
        let specificity = scope_specificity(&binding.scope);

        match &best {
            Some((best_specificity, _)) => {
                if specificity > *best_specificity {
                    best = Some((specificity, binding));
                }
                // On tie: first defined wins (don't replace).
            }
            None => {
                best = Some((specificity, binding));
            }
        }
    }

    best.map(|(_, b)| b.credential.clone())
}

/// Check if all non-empty scope fields in the binding match the session.
fn scope_matches(scope: &BindingScope, session: &Session) -> bool {
    if !scope.teams.is_empty() {
        match &session.team {
            Some(team) => {
                if !scope.teams.iter().any(|t| t.eq_ignore_ascii_case(team)) {
                    return false;
                }
            }
            None => return false,
        }
    }

    if !scope.environments.is_empty() {
        match &session.environment {
            Some(env) => {
                if !scope
                    .environments
                    .iter()
                    .any(|e| e.eq_ignore_ascii_case(env))
                {
                    return false;
                }
            }
            None => return false,
        }
    }

    if !scope.operators.is_empty()
        && !scope
            .operators
            .iter()
            .any(|o| o.eq_ignore_ascii_case(&session.operator))
    {
        return false;
    }

    if !scope.projects.is_empty() {
        match &session.project {
            Some(project) => {
                if !scope
                    .projects
                    .iter()
                    .any(|p| p.eq_ignore_ascii_case(project))
                {
                    return false;
                }
            }
            None => return false,
        }
    }

    true
}

/// Count the number of non-empty scope fields.
fn scope_specificity(scope: &BindingScope) -> usize {
    let mut count = 0;
    if !scope.teams.is_empty() {
        count += 1;
    }
    if !scope.environments.is_empty() {
        count += 1;
    }
    if !scope.operators.is_empty() {
        count += 1;
    }
    if !scope.projects.is_empty() {
        count += 1;
    }
    count
}

/// Load bindings from a YAML file.
pub fn load_bindings(path: &std::path::Path) -> forculus_common::Result<Vec<CredentialBinding>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let contents = std::fs::read_to_string(path).map_err(|e| {
        forculus_common::ForculusError::Vault(format!(
            "failed to read bindings from {}: {e}",
            path.display()
        ))
    })?;
    let file: BindingsFile = serde_yaml::from_str(&contents)
        .map_err(|e| forculus_common::ForculusError::Vault(format!("invalid bindings YAML: {e}")))?;
    Ok(file.bindings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn test_session(
        operator: &str,
        team: Option<&str>,
        env: Option<&str>,
        project: Option<&str>,
    ) -> Session {
        Session {
            id: "test-id".to_string(),
            token: "bwk_sess_0000000000000000".to_string(),
            operator: operator.to_string(),
            team: team.map(String::from),
            project: project.map(String::from),
            environment: env.map(String::from),
            agent_type: None,
            created_at: Utc::now(),
            expires_at: None,
            revoked: false,
            description: None,
        }
    }

    #[test]
    fn exact_tool_match() {
        let bindings = vec![CredentialBinding {
            credential: "github-token".to_string(),
            tool: "github__read".to_string(),
            scope: BindingScope::default(),
        }];
        let session = test_session("alice", None, None, None);
        let result = resolve_binding(&bindings, "github__read", &session);
        assert_eq!(result, Some("github-token".to_string()));
    }

    #[test]
    fn glob_tool_match() {
        let bindings = vec![CredentialBinding {
            credential: "github-token".to_string(),
            tool: "github__*".to_string(),
            scope: BindingScope::default(),
        }];
        let session = test_session("alice", None, None, None);
        assert_eq!(
            resolve_binding(&bindings, "github__push", &session),
            Some("github-token".to_string())
        );
    }

    #[test]
    fn no_match_returns_none() {
        let bindings = vec![CredentialBinding {
            credential: "github-token".to_string(),
            tool: "github__*".to_string(),
            scope: BindingScope::default(),
        }];
        let session = test_session("alice", None, None, None);
        assert_eq!(resolve_binding(&bindings, "slack__post", &session), None);
    }

    #[test]
    fn scope_team_matches() {
        let bindings = vec![CredentialBinding {
            credential: "eng-token".to_string(),
            tool: "github__*".to_string(),
            scope: BindingScope {
                teams: vec!["engineering".to_string()],
                ..Default::default()
            },
        }];
        let session = test_session("alice", Some("engineering"), None, None);
        assert_eq!(
            resolve_binding(&bindings, "github__read", &session),
            Some("eng-token".to_string())
        );
    }

    #[test]
    fn scope_team_no_match() {
        let bindings = vec![CredentialBinding {
            credential: "eng-token".to_string(),
            tool: "github__*".to_string(),
            scope: BindingScope {
                teams: vec!["engineering".to_string()],
                ..Default::default()
            },
        }];
        let session = test_session("alice", Some("marketing"), None, None);
        assert_eq!(resolve_binding(&bindings, "github__read", &session), None);
    }

    #[test]
    fn scope_environment_matches() {
        let bindings = vec![CredentialBinding {
            credential: "staging-token".to_string(),
            tool: "*".to_string(),
            scope: BindingScope {
                environments: vec!["staging".to_string()],
                ..Default::default()
            },
        }];
        let session = test_session("alice", None, Some("staging"), None);
        assert_eq!(
            resolve_binding(&bindings, "any-tool", &session),
            Some("staging-token".to_string())
        );
    }

    #[test]
    fn more_specific_binding_wins() {
        let bindings = vec![
            CredentialBinding {
                credential: "generic".to_string(),
                tool: "github__*".to_string(),
                scope: BindingScope::default(),
            },
            CredentialBinding {
                credential: "specific".to_string(),
                tool: "github__*".to_string(),
                scope: BindingScope {
                    teams: vec!["engineering".to_string()],
                    environments: vec!["staging".to_string()],
                    ..Default::default()
                },
            },
        ];
        let session = test_session("alice", Some("engineering"), Some("staging"), None);
        assert_eq!(
            resolve_binding(&bindings, "github__read", &session),
            Some("specific".to_string())
        );
    }

    #[test]
    fn first_binding_wins_on_tie() {
        let bindings = vec![
            CredentialBinding {
                credential: "first".to_string(),
                tool: "github__*".to_string(),
                scope: BindingScope::default(),
            },
            CredentialBinding {
                credential: "second".to_string(),
                tool: "github__*".to_string(),
                scope: BindingScope::default(),
            },
        ];
        let session = test_session("alice", None, None, None);
        assert_eq!(
            resolve_binding(&bindings, "github__read", &session),
            Some("first".to_string())
        );
    }
}
