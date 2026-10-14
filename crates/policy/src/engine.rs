//! Policy evaluation engine — the core of Forculus policy enforcement.

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;

use crate::context::RequestContext;
use crate::glob::GlobPattern;
use crate::parser::load_policies_from_directory;
use crate::precedence::{RulePrecedence, compare_precedence};
use crate::schema::{Conditions, Rule};
use crate::verdict::{PolicyEvaluation, PolicyScope, Verdict};

/// A compiled rule ready for evaluation.
#[derive(Debug, Clone)]
struct CompiledRule {
    name: String,
    verdict: Verdict,
    reason: String,
    priority: i32,
    scope: PolicyScope,
    policy_name: String,
    load_order: usize,
    tool_patterns: Vec<GlobPattern>,
    action_patterns: Vec<GlobPattern>,
    resource_patterns: Vec<GlobPattern>,
    conditions: Conditions,
}

/// Snapshot of all loaded policy state.
#[derive(Debug)]
struct PolicyState {
    rules: Vec<CompiledRule>,
    source_count: usize,
}

/// The policy engine — evaluates requests against loaded policy rules.
///
/// Uses `ArcSwap` for lock-free hot-reload: in-flight evaluations see
/// a consistent snapshot even while a reload is in progress.
pub struct PolicyEngine {
    state: ArcSwap<PolicyState>,
}

impl PolicyEngine {
    /// Create an empty engine with no rules loaded.
    pub fn new() -> Self {
        Self {
            state: ArcSwap::new(Arc::new(PolicyState {
                rules: Vec::new(),
                source_count: 0,
            })),
        }
    }

    /// Create an engine pre-loaded with policies from a directory.
    pub fn from_directory(dir: &Path) -> Result<Self, String> {
        let engine = Self::new();
        engine.reload(dir)?;
        Ok(engine)
    }

    /// Reload policies from the given directory.
    ///
    /// On success, atomically swaps the rule set. On failure, the previous
    /// state is preserved.
    pub fn reload(&self, dir: &Path) -> Result<(), String> {
        let policies = load_policies_from_directory(dir)?;
        let source_count = policies.len();
        let mut rules = Vec::new();
        let mut load_order = 0usize;

        for (path, policy_file) in &policies {
            let scope = policy_file.metadata.scope;
            let policy_name = if policy_file.metadata.name.is_empty() {
                path.file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown")
                    .to_string()
            } else {
                policy_file.metadata.name.clone()
            };

            for rule in &policy_file.rules {
                if !rule.enabled {
                    tracing::debug!(rule = %rule.name, policy = %policy_name, "skipping disabled rule");
                    continue;
                }
                match compile_rule(rule, scope, &policy_name, load_order) {
                    Ok(compiled) => {
                        rules.push(compiled);
                        load_order += 1;
                    }
                    Err(e) => {
                        return Err(format!(
                            "error compiling rule '{}' in {}: {e}",
                            rule.name,
                            path.display()
                        ));
                    }
                }
            }
        }

        // Sort by precedence (highest precedence last, so we can pop or iterate in reverse).
        rules.sort_by(|a, b| {
            compare_precedence(
                &RulePrecedence {
                    scope: a.scope,
                    verdict: a.verdict.clone(),
                    priority: a.priority,
                    load_order: a.load_order,
                },
                &RulePrecedence {
                    scope: b.scope,
                    verdict: b.verdict.clone(),
                    priority: b.priority,
                    load_order: b.load_order,
                },
            )
        });

        debug_assert!(
            rules.windows(2).all(|w| {
                compare_precedence(
                    &RulePrecedence {
                        scope: w[0].scope,
                        verdict: w[0].verdict.clone(),
                        priority: w[0].priority,
                        load_order: w[0].load_order,
                    },
                    &RulePrecedence {
                        scope: w[1].scope,
                        verdict: w[1].verdict.clone(),
                        priority: w[1].priority,
                        load_order: w[1].load_order,
                    },
                ) != std::cmp::Ordering::Greater
            }),
            "rules must be sorted by precedence after reload"
        );

        tracing::info!(
            rules = rules.len(),
            sources = source_count,
            "policy engine reloaded"
        );

        self.state.store(Arc::new(PolicyState {
            rules,
            source_count,
        }));

        Ok(())
    }

    /// Evaluate a request context against loaded policies.
    ///
    /// Returns `Verdict::Deny` with reason "no matching rule (default deny)"
    /// when no rules match.
    pub fn evaluate(&self, ctx: &RequestContext) -> PolicyEvaluation {
        debug_assert!(
            !ctx.action.is_empty(),
            "RequestContext.action must not be empty"
        );
        debug_assert!(
            !ctx.tool.is_empty(),
            "RequestContext.tool must not be empty"
        );

        let start = Instant::now();
        let state = self.state.load();

        // Find the highest-precedence matching rule.
        // Rules are sorted in ascending precedence order, so iterate in reverse.
        for rule in state.rules.iter().rev() {
            if matches_rule(rule, ctx) {
                return PolicyEvaluation {
                    verdict: rule.verdict.clone(),
                    matched_rule: Some(rule.name.clone()),
                    matched_policy: Some(rule.policy_name.clone()),
                    scope: rule.scope,
                    reason: if rule.reason.is_empty() {
                        format!("matched rule '{}'", rule.name)
                    } else {
                        rule.reason.clone()
                    },
                    evaluation_time: start.elapsed(),
                };
            }
        }

        // Default deny when no rules match.
        PolicyEvaluation {
            verdict: Verdict::Deny,
            matched_rule: None,
            matched_policy: None,
            scope: PolicyScope::Global,
            reason: "no matching rule (default deny)".to_string(),
            evaluation_time: start.elapsed(),
        }
    }

    /// Return the number of active (enabled) rules loaded.
    pub fn rule_count(&self) -> usize {
        self.state.load().rules.len()
    }

    /// Return the number of policy source files loaded.
    pub fn source_count(&self) -> usize {
        self.state.load().source_count
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Compile a parsed rule into a `CompiledRule` with pre-compiled glob patterns.
fn compile_rule(
    rule: &Rule,
    scope: PolicyScope,
    policy_name: &str,
    load_order: usize,
) -> Result<CompiledRule, String> {
    let tool_patterns = compile_patterns(&rule.match_criteria.tools)?;
    let action_patterns = compile_patterns(&rule.match_criteria.actions)?;
    let resource_patterns = compile_patterns(&rule.match_criteria.resources)?;

    Ok(CompiledRule {
        name: rule.name.clone(),
        verdict: rule.verdict.clone(),
        reason: rule.reason.clone(),
        priority: rule.priority,
        scope,
        policy_name: policy_name.to_string(),
        load_order,
        tool_patterns,
        action_patterns,
        resource_patterns,
        conditions: rule.conditions.clone(),
    })
}

/// Compile a list of glob pattern strings.
fn compile_patterns(patterns: &[String]) -> Result<Vec<GlobPattern>, String> {
    patterns.iter().map(|p| GlobPattern::compile(p)).collect()
}

/// Check whether a compiled rule matches the given request context.
///
/// Match logic: all non-empty criteria must match (AND logic).
/// Empty criteria lists are treated as "match anything".
fn matches_rule(rule: &CompiledRule, ctx: &RequestContext) -> bool {
    // Tool patterns: at least one must match (OR within, AND with other criteria).
    if !rule.tool_patterns.is_empty() && !rule.tool_patterns.iter().any(|p| p.matches(&ctx.tool)) {
        return false;
    }

    // Action patterns.
    if !rule.action_patterns.is_empty()
        && !rule.action_patterns.iter().any(|p| p.matches(&ctx.action))
    {
        return false;
    }

    // Resource patterns.
    if !rule.resource_patterns.is_empty() {
        let resource = ctx.resource.as_deref().unwrap_or("");
        if !rule.resource_patterns.iter().any(|p| p.matches(resource)) {
            return false;
        }
    }

    // Conditions — all non-empty lists must match.
    if !matches_conditions(&rule.conditions, ctx) {
        return false;
    }

    true
}

/// Check whether additional conditions match the context.
fn matches_conditions(conditions: &Conditions, ctx: &RequestContext) -> bool {
    // Operators: context operator must be in the list.
    if !conditions.operators.is_empty() {
        match &ctx.operator {
            Some(op) => {
                if !conditions
                    .operators
                    .iter()
                    .any(|o| o.eq_ignore_ascii_case(op))
                {
                    return false;
                }
            }
            None => return false,
        }
    }

    // Teams.
    if !conditions.teams.is_empty() {
        match &ctx.team {
            Some(team) => {
                if !conditions
                    .teams
                    .iter()
                    .any(|t| t.eq_ignore_ascii_case(team))
                {
                    return false;
                }
            }
            None => return false,
        }
    }

    // Environments.
    if !conditions.environments.is_empty() {
        match &ctx.environment {
            Some(env) => {
                if !conditions
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

    // Agent types.
    if !conditions.agent_types.is_empty() {
        match &ctx.agent_type {
            Some(at) => {
                if !conditions
                    .agent_types
                    .iter()
                    .any(|a| a.eq_ignore_ascii_case(at))
                {
                    return false;
                }
            }
            None => return false,
        }
    }

    // Labels: all specified labels must be present and match.
    for (key, value) in &conditions.labels {
        match ctx.labels.get(key) {
            Some(ctx_value) => {
                if !ctx_value.eq_ignore_ascii_case(value) {
                    return false;
                }
            }
            None => return false,
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_policy(dir: &Path, name: &str, content: &str) {
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
    }

    #[test]
    fn empty_engine_denies() {
        let engine = PolicyEngine::new();
        let ctx = RequestContext::new("github", "read_file");
        let eval = engine.evaluate(&ctx);
        assert_eq!(eval.verdict, Verdict::Deny);
        assert!(eval.reason.contains("default deny"));
    }

    #[test]
    fn allow_all_rule() {
        let dir = tempfile::tempdir().unwrap();
        write_policy(
            dir.path(),
            "global.yaml",
            r#"
rules:
  - name: allow-all
    verdict: allow
    match:
      tools: ["*"]
      actions: ["*"]
"#,
        );

        let engine = PolicyEngine::from_directory(dir.path()).unwrap();
        let ctx = RequestContext::new("any-tool", "any-action");
        let eval = engine.evaluate(&ctx);
        assert_eq!(eval.verdict, Verdict::Allow);
        assert_eq!(eval.matched_rule.as_deref(), Some("allow-all"));
    }

    #[test]
    fn deny_specific_action() {
        let dir = tempfile::tempdir().unwrap();
        write_policy(
            dir.path(),
            "policy.yaml",
            r#"
rules:
  - name: allow-reads
    verdict: allow
    priority: 10
    match:
      tools: ["*"]
      actions: ["read_*", "list_*"]
  - name: deny-all
    verdict: deny
    match:
      tools: ["*"]
      actions: ["*"]
"#,
        );

        let engine = PolicyEngine::from_directory(dir.path()).unwrap();

        let read_ctx = RequestContext::new("github", "read_file");
        assert_eq!(engine.evaluate(&read_ctx).verdict, Verdict::Allow);

        let delete_ctx = RequestContext::new("github", "delete_repo");
        assert_eq!(engine.evaluate(&delete_ctx).verdict, Verdict::Deny);
        assert_eq!(
            engine.evaluate(&delete_ctx).matched_rule.as_deref(),
            Some("deny-all")
        );
    }

    #[test]
    fn conditions_filter() {
        let dir = tempfile::tempdir().unwrap();
        write_policy(
            dir.path(),
            "policy.yaml",
            r#"
rules:
  - name: team-only
    verdict: allow
    priority: 10
    match:
      tools: ["*"]
    conditions:
      teams: ["engineering"]
  - name: deny-all
    verdict: deny
"#,
        );

        let engine = PolicyEngine::from_directory(dir.path()).unwrap();

        let eng_ctx = RequestContext::new("github", "push").with_team("engineering");
        assert_eq!(engine.evaluate(&eng_ctx).verdict, Verdict::Allow);

        let other_ctx = RequestContext::new("github", "push").with_team("marketing");
        assert_eq!(engine.evaluate(&other_ctx).verdict, Verdict::Deny);

        let no_team_ctx = RequestContext::new("github", "push");
        assert_eq!(engine.evaluate(&no_team_ctx).verdict, Verdict::Deny);
    }

    #[test]
    fn scope_precedence() {
        let dir = tempfile::tempdir().unwrap();
        write_policy(
            dir.path(),
            "global.yaml",
            r#"
metadata:
  scope: global
rules:
  - name: global-deny
    verdict: deny
    match:
      tools: ["*"]
"#,
        );
        write_policy(
            dir.path(),
            "override.yaml",
            r#"
metadata:
  scope: override
rules:
  - name: override-allow
    verdict: allow
    match:
      tools: ["*"]
"#,
        );

        let engine = PolicyEngine::from_directory(dir.path()).unwrap();
        let ctx = RequestContext::new("github", "push");
        let eval = engine.evaluate(&ctx);
        assert_eq!(eval.verdict, Verdict::Allow);
        assert_eq!(eval.matched_rule.as_deref(), Some("override-allow"));
    }

    #[test]
    fn deny_beats_allow_same_scope() {
        let dir = tempfile::tempdir().unwrap();
        write_policy(
            dir.path(),
            "policy.yaml",
            r#"
rules:
  - name: allow-all
    verdict: allow
    match:
      tools: ["*"]
  - name: deny-all
    verdict: deny
    match:
      tools: ["*"]
"#,
        );

        let engine = PolicyEngine::from_directory(dir.path()).unwrap();
        let ctx = RequestContext::new("github", "push");
        let eval = engine.evaluate(&ctx);
        assert_eq!(eval.verdict, Verdict::Deny);
    }

    #[test]
    fn priority_ordering() {
        let dir = tempfile::tempdir().unwrap();
        write_policy(
            dir.path(),
            "policy.yaml",
            r#"
rules:
  - name: low-priority-deny
    verdict: deny
    priority: 1
    match:
      tools: ["github"]
  - name: high-priority-allow
    verdict: allow
    priority: 100
    match:
      tools: ["github"]
"#,
        );

        let engine = PolicyEngine::from_directory(dir.path()).unwrap();
        let ctx = RequestContext::new("github", "push");
        // higher priority wins over deny-beats-allow
        let eval = engine.evaluate(&ctx);
        assert_eq!(eval.verdict, Verdict::Allow);
    }

    #[test]
    fn disabled_rules_skipped() {
        let dir = tempfile::tempdir().unwrap();
        write_policy(
            dir.path(),
            "policy.yaml",
            r#"
rules:
  - name: disabled-allow
    verdict: allow
    enabled: false
    match:
      tools: ["*"]
  - name: deny-all
    verdict: deny
    match:
      tools: ["*"]
"#,
        );

        let engine = PolicyEngine::from_directory(dir.path()).unwrap();
        assert_eq!(engine.rule_count(), 1);
        let ctx = RequestContext::new("github", "push");
        assert_eq!(engine.evaluate(&ctx).verdict, Verdict::Deny);
    }

    #[test]
    fn reload_updates_rules() {
        let dir = tempfile::tempdir().unwrap();
        write_policy(
            dir.path(),
            "policy.yaml",
            "rules:\n  - name: deny-all\n    verdict: deny\n",
        );

        let engine = PolicyEngine::from_directory(dir.path()).unwrap();
        let ctx = RequestContext::new("x", "y");
        assert_eq!(engine.evaluate(&ctx).verdict, Verdict::Deny);

        // Rewrite to allow.
        write_policy(
            dir.path(),
            "policy.yaml",
            r#"
rules:
  - name: allow-all
    verdict: allow
    match:
      tools: ["*"]
"#,
        );
        engine.reload(dir.path()).unwrap();
        assert_eq!(engine.evaluate(&ctx).verdict, Verdict::Allow);
    }

    #[test]
    fn resource_matching() {
        let dir = tempfile::tempdir().unwrap();
        write_policy(
            dir.path(),
            "policy.yaml",
            r#"
rules:
  - name: allow-docs
    verdict: allow
    priority: 10
    match:
      tools: ["*"]
      resources: ["docs/*"]
  - name: deny-all
    verdict: deny
"#,
        );

        let engine = PolicyEngine::from_directory(dir.path()).unwrap();

        let doc_ctx = RequestContext::new("github", "read").with_resource("docs/readme.md");
        assert_eq!(engine.evaluate(&doc_ctx).verdict, Verdict::Allow);

        let src_ctx = RequestContext::new("github", "read").with_resource("src/main.rs");
        assert_eq!(engine.evaluate(&src_ctx).verdict, Verdict::Deny);
    }

    #[test]
    fn empty_match_criteria_matches_anything() {
        let dir = tempfile::tempdir().unwrap();
        write_policy(
            dir.path(),
            "policy.yaml",
            r#"
rules:
  - name: catch-all
    verdict: allow
"#,
        );

        let engine = PolicyEngine::from_directory(dir.path()).unwrap();
        let ctx = RequestContext::new("any", "thing");
        assert_eq!(engine.evaluate(&ctx).verdict, Verdict::Allow);
    }

    #[test]
    fn environment_condition() {
        let dir = tempfile::tempdir().unwrap();
        write_policy(
            dir.path(),
            "policy.yaml",
            r#"
rules:
  - name: prod-only
    verdict: deny
    priority: 10
    match:
      tools: ["*"]
    conditions:
      environments: ["production"]
  - name: allow-all
    verdict: allow
    match:
      tools: ["*"]
"#,
        );

        let engine = PolicyEngine::from_directory(dir.path()).unwrap();

        let prod_ctx = RequestContext::new("db", "drop").with_environment("production");
        assert_eq!(engine.evaluate(&prod_ctx).verdict, Verdict::Deny);

        let dev_ctx = RequestContext::new("db", "drop").with_environment("development");
        assert_eq!(engine.evaluate(&dev_ctx).verdict, Verdict::Allow);
    }

    #[test]
    fn label_conditions() {
        let dir = tempfile::tempdir().unwrap();
        write_policy(
            dir.path(),
            "policy.yaml",
            r#"
rules:
  - name: high-risk
    verdict: escalate
    priority: 10
    match:
      tools: ["*"]
    conditions:
      labels:
        risk: high
  - name: allow-all
    verdict: allow
    match:
      tools: ["*"]
"#,
        );

        let engine = PolicyEngine::from_directory(dir.path()).unwrap();

        let risky = RequestContext::new("tool", "act").with_label("risk", "high");
        assert_eq!(engine.evaluate(&risky).verdict, Verdict::Escalate);

        let safe = RequestContext::new("tool", "act").with_label("risk", "low");
        assert_eq!(engine.evaluate(&safe).verdict, Verdict::Allow);
    }

    #[test]
    fn agent_type_condition() {
        let dir = tempfile::tempdir().unwrap();
        write_policy(
            dir.path(),
            "policy.yaml",
            r#"
rules:
  - name: coding-allow
    verdict: allow
    priority: 10
    match:
      tools: ["*"]
    conditions:
      agent_types: ["coding"]
  - name: deny-all
    verdict: deny
"#,
        );

        let engine = PolicyEngine::from_directory(dir.path()).unwrap();

        let coding = RequestContext::new("gh", "push").with_agent_type("coding");
        assert_eq!(engine.evaluate(&coding).verdict, Verdict::Allow);

        let research = RequestContext::new("gh", "push").with_agent_type("research");
        assert_eq!(engine.evaluate(&research).verdict, Verdict::Deny);
    }

    #[test]
    fn rule_count_and_source_count() {
        let dir = tempfile::tempdir().unwrap();
        write_policy(
            dir.path(),
            "a.yaml",
            "rules:\n  - name: r1\n    verdict: allow\n  - name: r2\n    verdict: deny\n",
        );
        write_policy(
            dir.path(),
            "b.yaml",
            "rules:\n  - name: r3\n    verdict: allow\n",
        );

        let engine = PolicyEngine::from_directory(dir.path()).unwrap();
        assert_eq!(engine.rule_count(), 3);
        assert_eq!(engine.source_count(), 2);
    }

    #[test]
    fn invalid_glob_errors() {
        let dir = tempfile::tempdir().unwrap();
        write_policy(
            dir.path(),
            "policy.yaml",
            r#"
rules:
  - name: bad
    verdict: allow
    match:
      tools: ["[unclosed"]
"#,
        );

        let result = PolicyEngine::from_directory(dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn escalate_verdict() {
        let dir = tempfile::tempdir().unwrap();
        write_policy(
            dir.path(),
            "policy.yaml",
            r#"
rules:
  - name: escalate-deletes
    verdict: escalate
    reason: "Deletions require approval"
    priority: 10
    match:
      actions: ["delete_*"]
  - name: allow-all
    verdict: allow
    match:
      tools: ["*"]
"#,
        );

        let engine = PolicyEngine::from_directory(dir.path()).unwrap();

        let del_ctx = RequestContext::new("github", "delete_repo");
        let eval = engine.evaluate(&del_ctx);
        assert_eq!(eval.verdict, Verdict::Escalate);
        assert_eq!(eval.reason, "Deletions require approval");
    }

    #[test]
    fn evaluation_time_is_set() {
        let engine = PolicyEngine::new();
        let ctx = RequestContext::new("x", "y");
        let eval = engine.evaluate(&ctx);
        // Just check it doesn't panic and produces a valid duration.
        let _ = eval.evaluation_time.as_nanos();
    }

    #[test]
    fn multiple_tool_patterns_or() {
        let dir = tempfile::tempdir().unwrap();
        write_policy(
            dir.path(),
            "policy.yaml",
            r#"
rules:
  - name: allow-gh-or-fs
    verdict: allow
    priority: 10
    match:
      tools: ["github", "filesystem"]
  - name: deny-all
    verdict: deny
"#,
        );

        let engine = PolicyEngine::from_directory(dir.path()).unwrap();

        assert_eq!(
            engine.evaluate(&RequestContext::new("github", "x")).verdict,
            Verdict::Allow
        );
        assert_eq!(
            engine
                .evaluate(&RequestContext::new("filesystem", "x"))
                .verdict,
            Verdict::Allow
        );
        assert_eq!(
            engine
                .evaluate(&RequestContext::new("database", "x"))
                .verdict,
            Verdict::Deny
        );
    }

    #[test]
    fn operator_condition() {
        let dir = tempfile::tempdir().unwrap();
        write_policy(
            dir.path(),
            "policy.yaml",
            r#"
rules:
  - name: alice-only
    verdict: allow
    priority: 10
    match:
      tools: ["*"]
    conditions:
      operators: ["alice"]
  - name: deny-all
    verdict: deny
"#,
        );

        let engine = PolicyEngine::from_directory(dir.path()).unwrap();

        let alice = RequestContext::new("tool", "act").with_operator("alice");
        assert_eq!(engine.evaluate(&alice).verdict, Verdict::Allow);

        let bob = RequestContext::new("tool", "act").with_operator("bob");
        assert_eq!(engine.evaluate(&bob).verdict, Verdict::Deny);
    }

    #[test]
    fn default_reason_when_empty() {
        let dir = tempfile::tempdir().unwrap();
        write_policy(
            dir.path(),
            "policy.yaml",
            "rules:\n  - name: my-rule\n    verdict: allow\n",
        );

        let engine = PolicyEngine::from_directory(dir.path()).unwrap();
        let eval = engine.evaluate(&RequestContext::new("x", "y"));
        assert!(eval.reason.contains("my-rule"));
    }

    #[test]
    fn policy_name_from_metadata() {
        let dir = tempfile::tempdir().unwrap();
        write_policy(
            dir.path(),
            "policy.yaml",
            r#"
metadata:
  name: "My Policy"
rules:
  - name: r1
    verdict: allow
"#,
        );

        let engine = PolicyEngine::from_directory(dir.path()).unwrap();
        let eval = engine.evaluate(&RequestContext::new("x", "y"));
        assert_eq!(eval.matched_policy.as_deref(), Some("My Policy"));
    }

    #[test]
    fn policy_name_from_filename() {
        let dir = tempfile::tempdir().unwrap();
        write_policy(
            dir.path(),
            "custom-name.yaml",
            "rules:\n  - name: r1\n    verdict: allow\n",
        );

        let engine = PolicyEngine::from_directory(dir.path()).unwrap();
        let eval = engine.evaluate(&RequestContext::new("x", "y"));
        assert_eq!(eval.matched_policy.as_deref(), Some("custom-name"));
    }

    // -- Precondition tests --

    #[test]
    fn empty_engine_always_denies() {
        let engine = PolicyEngine::new();
        let ctx = RequestContext::new("some-tool", "some-action");
        let eval = engine.evaluate(&ctx);
        // Empty engine → default deny.
        assert_eq!(eval.verdict, Verdict::Deny);
    }

    #[test]
    fn evaluate_is_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        write_policy(
            dir.path(),
            "test.yaml",
            r#"
rules:
  - name: allow-get
    verdict: allow
    match:
      actions: ["GET *"]
  - name: deny-all
    verdict: deny
"#,
        );
        let engine = PolicyEngine::from_directory(dir.path()).unwrap();
        let ctx = RequestContext::new("host", "GET /path");
        let v1 = engine.evaluate(&ctx);
        let v2 = engine.evaluate(&ctx);
        assert_eq!(format!("{:?}", v1.verdict), format!("{:?}", v2.verdict));
        assert_eq!(v1.matched_rule, v2.matched_rule);
    }

    #[test]
    fn loaded_rules_are_sorted_by_precedence() {
        let dir = tempfile::tempdir().unwrap();
        write_policy(
            dir.path(),
            "test.yaml",
            r#"
rules:
  - name: low-priority
    verdict: allow
    priority: 1
  - name: high-priority
    verdict: deny
    priority: 100
"#,
        );
        let engine = PolicyEngine::from_directory(dir.path()).unwrap();
        // Verify ordering is consistent: higher-precedence rules should win.
        let ctx = RequestContext::new("x", "y");
        let eval = engine.evaluate(&ctx);
        assert_eq!(eval.verdict, Verdict::Deny);
        assert_eq!(eval.matched_rule.as_deref(), Some("high-priority"));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn arb_request_context() -> impl Strategy<Value = RequestContext> {
        ("[a-z_]{1,20}", "[a-z_]{1,20}")
            .prop_map(|(tool, action)| RequestContext::new(tool, action))
    }

    proptest! {
        #[test]
        fn evaluate_never_panics(ctx in arb_request_context()) {
            let engine = PolicyEngine::new();
            let _verdict = engine.evaluate(&ctx);
        }

        #[test]
        fn empty_engine_always_denies_prop(ctx in arb_request_context()) {
            let engine = PolicyEngine::new();
            let eval = engine.evaluate(&ctx);
            prop_assert!(matches!(eval.verdict, Verdict::Deny));
        }
    }
}
