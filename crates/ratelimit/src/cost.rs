//! Cost tracking — estimates and tracks per-operator costs with budget enforcement.

use std::collections::HashMap;
use std::fmt;

use forculus_policy::glob::GlobPattern;

/// A compiled cost rule.
#[derive(Debug)]
struct CompiledCostRule {
    tool_patterns: Vec<GlobPattern>,
    cost: f64,
    monthly_budget: Option<f64>,
}

/// Budget exceeded error.
#[derive(Debug, Clone)]
pub struct BudgetExceeded {
    /// The operator who exceeded their budget.
    pub operator: String,
    /// Current accumulated cost.
    pub current: f64,
    /// Budget limit.
    pub limit: f64,
}

impl fmt::Display for BudgetExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "operator '{}' exceeded monthly budget: ${:.2} / ${:.2}",
            self.operator, self.current, self.limit
        )
    }
}

/// Tracks costs per operator and enforces monthly budgets.
pub struct CostTracker {
    state: parking_lot::Mutex<CostState>,
}

struct CostState {
    rules: Vec<CompiledCostRule>,
    default_cost: f64,
    /// Accumulated cost per operator.
    spend: HashMap<String, f64>,
}

impl CostTracker {
    /// Create a cost tracker from config rules.
    pub fn new(default_cost: f64, rules: Vec<forculus_config::CostRule>) -> Result<Self, String> {
        let compiled = rules
            .into_iter()
            .map(|r| {
                let patterns: Result<Vec<GlobPattern>, String> =
                    r.tools.iter().map(|p| GlobPattern::compile(p)).collect();
                Ok(CompiledCostRule {
                    tool_patterns: patterns?,
                    cost: r.cost,
                    monthly_budget: r.monthly_budget,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;

        Ok(Self {
            state: parking_lot::Mutex::new(CostState {
                rules: compiled,
                default_cost,
                spend: HashMap::new(),
            }),
        })
    }

    /// Estimate the cost for a tool invocation.
    pub fn estimate_cost(&self, tool: &str) -> f64 {
        let state = self.state.lock();
        for rule in &state.rules {
            let matches =
                rule.tool_patterns.is_empty() || rule.tool_patterns.iter().any(|p| p.matches(tool));
            if matches {
                return rule.cost;
            }
        }
        state.default_cost
    }

    /// Record a cost for an operator. Returns `Err(BudgetExceeded)` if the
    /// operator's monthly budget has been exceeded.
    pub fn record_cost(&self, operator: &str, cost: f64) -> Result<(), BudgetExceeded> {
        let mut state = self.state.lock();
        let current = state.spend.entry(operator.to_string()).or_insert(0.0);
        *current += cost;
        let current_val = *current;

        // Check budgets.
        for rule in &state.rules {
            if let Some(budget) = rule.monthly_budget {
                if current_val > budget {
                    return Err(BudgetExceeded {
                        operator: operator.to_string(),
                        current: current_val,
                        limit: budget,
                    });
                }
            }
        }

        Ok(())
    }

    /// Get the current spend for an operator.
    pub fn get_spend(&self, operator: &str) -> f64 {
        let state = self.state.lock();
        state.spend.get(operator).copied().unwrap_or(0.0)
    }

    /// Reset all spend tracking (e.g. at the start of a new month).
    pub fn reset_spend(&self) {
        let mut state = self.state.lock();
        state.spend.clear();
    }
}

impl fmt::Debug for CostTracker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CostTracker").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use forculus_config::CostRule;

    fn cost_rule(tools: &[&str], cost: f64, budget: Option<f64>) -> CostRule {
        CostRule {
            tools: tools.iter().map(|s| s.to_string()).collect(),
            cost,
            monthly_budget: budget,
        }
    }

    #[test]
    fn default_cost_when_no_rules() {
        let tracker = CostTracker::new(0.05, vec![]).unwrap();
        assert!((tracker.estimate_cost("anything") - 0.05).abs() < f64::EPSILON);
    }

    #[test]
    fn matching_rule_cost() {
        let tracker = CostTracker::new(0.01, vec![cost_rule(&["openai*"], 0.10, None)]).unwrap();
        assert!((tracker.estimate_cost("openai") - 0.10).abs() < f64::EPSILON);
        assert!((tracker.estimate_cost("github") - 0.01).abs() < f64::EPSILON);
    }

    #[test]
    fn record_and_get_spend() {
        let tracker = CostTracker::new(0.01, vec![]).unwrap();
        tracker.record_cost("alice", 0.50).unwrap();
        tracker.record_cost("alice", 0.25).unwrap();
        assert!((tracker.get_spend("alice") - 0.75).abs() < f64::EPSILON);
        assert!((tracker.get_spend("bob") - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn budget_exceeded() {
        let tracker = CostTracker::new(0.01, vec![cost_rule(&["*"], 1.0, Some(5.0))]).unwrap();
        for _ in 0..5 {
            tracker.record_cost("alice", 1.0).unwrap();
        }
        // 6th should exceed.
        let result = tracker.record_cost("alice", 1.0);
        assert!(result.is_err());
        let exceeded = result.unwrap_err();
        assert_eq!(exceeded.operator, "alice");
        assert!((exceeded.current - 6.0).abs() < f64::EPSILON);
        assert!((exceeded.limit - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn reset_spend_clears_all() {
        let tracker = CostTracker::new(0.01, vec![]).unwrap();
        tracker.record_cost("alice", 10.0).unwrap();
        tracker.reset_spend();
        assert!((tracker.get_spend("alice") - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn separate_operators() {
        let tracker = CostTracker::new(0.01, vec![cost_rule(&["*"], 1.0, Some(3.0))]).unwrap();
        tracker.record_cost("alice", 3.0).unwrap();
        // Alice is at limit.
        assert!(tracker.record_cost("alice", 1.0).is_err());
        // Bob is fine.
        assert!(tracker.record_cost("bob", 2.0).is_ok());
    }

    #[test]
    fn first_matching_rule_wins() {
        let tracker = CostTracker::new(
            0.01,
            vec![
                cost_rule(&["openai"], 0.10, None),
                cost_rule(&["*"], 0.50, None),
            ],
        )
        .unwrap();
        // openai matches the first rule.
        assert!((tracker.estimate_cost("openai") - 0.10).abs() < f64::EPSILON);
        // github matches the second rule.
        assert!((tracker.estimate_cost("github") - 0.50).abs() < f64::EPSILON);
    }

    #[test]
    fn no_budget_means_unlimited() {
        let tracker = CostTracker::new(0.01, vec![cost_rule(&["*"], 1.0, None)]).unwrap();
        for _ in 0..100 {
            assert!(tracker.record_cost("alice", 1.0).is_ok());
        }
    }
}
