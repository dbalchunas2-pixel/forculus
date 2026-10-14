//! Claim extraction and group mapping for OIDC tokens.

use std::collections::HashMap;
use std::time::Duration;

use serde::Deserialize;

/// The output of successful authentication. Contains everything needed
/// to create a Forculus session. The caller (management server or CLI)
/// is responsible for actually creating the session via the Vault.
#[derive(Debug, Clone)]
pub struct MappedClaims {
    /// Operator name (from preferred_username, email, or sub).
    pub operator: String,
    /// Team name (from group mapping).
    pub team: Option<String>,
    /// Environment (from group mapping).
    pub environment: Option<String>,
    /// Agent type (from group mapping).
    pub agent_type: Option<String>,
    /// Additional labels from group mapping.
    pub labels: HashMap<String, String>,
    /// Session TTL from config.
    pub ttl: Duration,
    /// blake3 hash of the raw OIDC subject claim, for audit.
    pub provider_subject_hash: String,
}

/// Maps IdP group names to Forculus session fields.
#[derive(Debug, Clone, Default)]
pub struct GroupMapping {
    mappings: HashMap<String, GroupMappingEntry>,
}

/// A single group mapping entry.
#[derive(Debug, Clone, Deserialize)]
pub struct GroupMappingEntry {
    /// Team name to assign.
    pub team: Option<String>,
    /// Environment to assign.
    pub environment: Option<String>,
    /// Agent type to assign.
    pub agent_type: Option<String>,
    /// Additional labels.
    #[serde(default)]
    pub labels: HashMap<String, String>,
}

/// The result of resolving group mappings against a list of groups.
#[derive(Debug, Clone, Default)]
pub struct ResolvedMapping {
    /// Resolved team name.
    pub team: Option<String>,
    /// Resolved environment.
    pub environment: Option<String>,
    /// Resolved agent type.
    pub agent_type: Option<String>,
    /// Merged labels.
    pub labels: HashMap<String, String>,
}

impl GroupMapping {
    /// Create a new group mapping from a map of group names to entries.
    pub fn new(mappings: HashMap<String, GroupMappingEntry>) -> Self {
        Self { mappings }
    }

    /// Given a list of group names from the IdP token, resolve the session fields.
    /// If multiple groups match, merge the entries. For conflicting fields,
    /// the last match wins (alphabetical order of group names for determinism).
    pub fn resolve(&self, groups: &[String]) -> ResolvedMapping {
        let mut result = ResolvedMapping::default();

        // Sort groups alphabetically for deterministic conflict resolution
        let mut sorted_groups: Vec<&String> = groups.iter().collect();
        sorted_groups.sort();

        for group in sorted_groups {
            if let Some(entry) = self.mappings.get(group.as_str()) {
                if let Some(team) = &entry.team {
                    result.team = Some(team.clone());
                }
                if let Some(env) = &entry.environment {
                    result.environment = Some(env.clone());
                }
                if let Some(agent) = &entry.agent_type {
                    result.agent_type = Some(agent.clone());
                }
                for (k, v) in &entry.labels {
                    result.labels.insert(k.clone(), v.clone());
                }
            }
        }

        result
    }
}

/// Resolve the operator name from OIDC claims.
///
/// Priority: preferred_username > email > sub.
pub fn resolve_operator(
    preferred_username: Option<&str>,
    email: Option<&str>,
    sub: &str,
) -> String {
    if let Some(username) = preferred_username
        && !username.is_empty()
    {
        return username.to_string();
    }
    if let Some(email) = email
        && !email.is_empty()
    {
        return email.to_string();
    }
    sub.to_string()
}

/// Hash the raw OIDC subject claim with blake3 for audit storage.
/// The raw subject must never be stored or logged directly.
pub fn hash_subject(sub: &str) -> String {
    blake3::hash(sub.as_bytes()).to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_mapping() -> GroupMapping {
        let mut mappings = HashMap::new();
        mappings.insert(
            "engineering".to_string(),
            GroupMappingEntry {
                team: Some("eng".to_string()),
                environment: None,
                agent_type: None,
                labels: HashMap::new(),
            },
        );
        mappings.insert(
            "platform".to_string(),
            GroupMappingEntry {
                team: Some("platform".to_string()),
                environment: Some("production".to_string()),
                agent_type: Some("claude-code".to_string()),
                labels: {
                    let mut m = HashMap::new();
                    m.insert("tier".to_string(), "admin".to_string());
                    m
                },
            },
        );
        GroupMapping::new(mappings)
    }

    #[test]
    fn single_group_match() {
        let mapping = make_mapping();
        let result = mapping.resolve(&["engineering".to_string()]);
        assert_eq!(result.team.as_deref(), Some("eng"));
        assert!(result.environment.is_none());
        assert!(result.agent_type.is_none());
    }

    #[test]
    fn multiple_groups_merge_last_alphabetical_wins() {
        let mapping = make_mapping();
        // "engineering" < "platform" alphabetically, so platform wins on team conflict
        let result = mapping.resolve(&["engineering".to_string(), "platform".to_string()]);
        assert_eq!(result.team.as_deref(), Some("platform"));
        assert_eq!(result.environment.as_deref(), Some("production"));
        assert_eq!(result.agent_type.as_deref(), Some("claude-code"));
        assert_eq!(result.labels.get("tier").map(|s| s.as_str()), Some("admin"));
    }

    #[test]
    fn no_matching_groups() {
        let mapping = make_mapping();
        let result = mapping.resolve(&["unknown-group".to_string()]);
        assert!(result.team.is_none());
        assert!(result.environment.is_none());
        assert!(result.agent_type.is_none());
        assert!(result.labels.is_empty());
    }

    #[test]
    fn empty_groups_list() {
        let mapping = make_mapping();
        let result = mapping.resolve(&[]);
        assert!(result.team.is_none());
        assert!(result.environment.is_none());
        assert!(result.agent_type.is_none());
        assert!(result.labels.is_empty());
    }

    #[test]
    fn operator_resolution_preferred_username_first() {
        assert_eq!(
            resolve_operator(Some("alice"), Some("alice@acme.com"), "sub123"),
            "alice"
        );
    }

    #[test]
    fn operator_resolution_falls_to_email() {
        assert_eq!(
            resolve_operator(None, Some("alice@acme.com"), "sub123"),
            "alice@acme.com"
        );
    }

    #[test]
    fn operator_resolution_falls_to_sub() {
        assert_eq!(resolve_operator(None, None, "sub123"), "sub123");
    }

    #[test]
    fn operator_resolution_skips_empty_username() {
        assert_eq!(
            resolve_operator(Some(""), Some("alice@acme.com"), "sub123"),
            "alice@acme.com"
        );
    }

    #[test]
    fn operator_resolution_skips_empty_email() {
        assert_eq!(resolve_operator(None, Some(""), "sub123"), "sub123");
    }

    #[test]
    fn subject_hashing_is_consistent() {
        let h1 = hash_subject("user|abc123");
        let h2 = hash_subject("user|abc123");
        assert_eq!(h1, h2);
        // blake3 hex output is 64 chars
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn subject_hashing_different_inputs() {
        let h1 = hash_subject("user|abc123");
        let h2 = hash_subject("user|xyz789");
        assert_ne!(h1, h2);
    }

    #[test]
    fn mapped_claims_ttl_from_config() {
        let claims = MappedClaims {
            operator: "alice".to_string(),
            team: None,
            environment: None,
            agent_type: None,
            labels: HashMap::new(),
            ttl: Duration::from_secs(7200),
            provider_subject_hash: hash_subject("sub123"),
        };
        assert_eq!(claims.ttl, Duration::from_secs(7200));
    }
}
