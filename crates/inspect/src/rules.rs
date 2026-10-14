//! Inspection rules — configured patterns with enable/disable support.

use crate::config::InspectionConfig;
use crate::patterns::{PatternMatcher, builtin_patterns};

/// A configured inspection rule.
#[derive(Debug, Clone)]
pub struct InspectionRule {
    /// The underlying pattern matcher.
    pub matcher: PatternMatcher,
    /// Whether this rule is enabled.
    pub enabled: bool,
}

/// The full set of inspection rules — built-in plus custom.
#[derive(Debug, Clone)]
pub struct InspectionRuleSet {
    rules: Vec<InspectionRule>,
}

impl InspectionRuleSet {
    /// Create a rule set with only the built-in patterns (all enabled).
    pub fn builtin() -> Self {
        let rules = builtin_patterns()
            .into_iter()
            .map(|matcher| InspectionRule {
                matcher,
                enabled: true,
            })
            .collect();
        Self { rules }
    }

    /// Create a rule set from configuration.
    ///
    /// Applies overrides (enable/disable, severity changes) and adds custom patterns.
    pub fn from_config(config: &InspectionConfig) -> forculus_common::Result<Self> {
        let mut rules: Vec<InspectionRule> = builtin_patterns()
            .into_iter()
            .map(|mut matcher| {
                let enabled = !config.disabled_rules.contains(&matcher.id);

                // Apply overrides.
                if let Some(ovr) = config
                    .rule_overrides
                    .iter()
                    .find(|o| o.rule_id == matcher.id)
                {
                    if let Some(severity) = ovr.severity {
                        matcher.severity = severity;
                    }
                    if let Some(ref action) = ovr.action {
                        matcher.action = action.clone();
                    }
                }

                InspectionRule { matcher, enabled }
            })
            .collect();

        // Add custom patterns.
        for cp in &config.custom_patterns {
            let matcher = PatternMatcher::new(
                &cp.id,
                &cp.description,
                &cp.pattern,
                cp.severity,
                cp.category.clone(),
                cp.action.clone(),
            )?;
            rules.push(InspectionRule {
                matcher,
                enabled: true,
            });
        }

        Ok(Self { rules })
    }

    /// Get all enabled rules.
    pub fn enabled_rules(&self) -> impl Iterator<Item = &InspectionRule> {
        self.rules.iter().filter(|r| r.enabled)
    }

    /// Get all rules (enabled and disabled).
    pub fn all_rules(&self) -> &[InspectionRule] {
        &self.rules
    }

    /// Get a rule by ID.
    pub fn get_rule(&self, id: &str) -> Option<&InspectionRule> {
        self.rules.iter().find(|r| r.matcher.id == id)
    }

    /// Get the total number of rules (enabled + disabled).
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Get the number of enabled rules.
    pub fn enabled_count(&self) -> usize {
        self.rules.iter().filter(|r| r.enabled).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CustomPattern, RuleOverride};
    use crate::finding::{FindingAction, FindingCategory, Severity};

    #[test]
    fn builtin_creates_expected_rules() {
        let set = InspectionRuleSet::builtin();
        assert_eq!(set.rule_count(), 13);
        assert_eq!(set.enabled_count(), 13);
    }

    #[test]
    fn from_config_disabled_rules() {
        let config = InspectionConfig {
            disabled_rules: vec!["email-address".into(), "us-phone".into()],
            ..Default::default()
        };
        let set = InspectionRuleSet::from_config(&config).unwrap();
        assert_eq!(set.enabled_count(), 11);
        assert!(!set.get_rule("email-address").unwrap().enabled);
        assert!(!set.get_rule("us-phone").unwrap().enabled);
        assert!(set.get_rule("aws-access-key").unwrap().enabled);
    }

    #[test]
    fn from_config_rule_overrides() {
        let config = InspectionConfig {
            rule_overrides: vec![RuleOverride {
                rule_id: "generic-api-key".into(),
                severity: Some(Severity::Medium),
                action: Some(FindingAction::Log),
            }],
            ..Default::default()
        };
        let set = InspectionRuleSet::from_config(&config).unwrap();
        let rule = set.get_rule("generic-api-key").unwrap();
        assert_eq!(rule.matcher.severity, Severity::Medium);
        assert_eq!(rule.matcher.action, FindingAction::Log);
    }

    #[test]
    fn from_config_custom_patterns() {
        let config = InspectionConfig {
            custom_patterns: vec![CustomPattern {
                id: "internal-code".into(),
                description: "Internal project codes".into(),
                pattern: r"PROJ-\d{4,}".into(),
                severity: Severity::Medium,
                category: FindingCategory::Custom("internal".into()),
                action: FindingAction::Log,
            }],
            ..Default::default()
        };
        let set = InspectionRuleSet::from_config(&config).unwrap();
        assert_eq!(set.rule_count(), 14); // 13 builtin + 1 custom
        let custom = set.get_rule("internal-code").unwrap();
        assert!(custom.enabled);
        assert_eq!(custom.matcher.severity, Severity::Medium);
    }

    #[test]
    fn enabled_count_reflects_disabling() {
        let config = InspectionConfig {
            disabled_rules: vec!["email-address".into()],
            ..Default::default()
        };
        let set = InspectionRuleSet::from_config(&config).unwrap();
        assert_eq!(set.rule_count(), 13);
        assert_eq!(set.enabled_count(), 12);
    }
}
