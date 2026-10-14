//! Forculus inspect — content inspection for sensitive data, PII, and prompt injection.
#![forbid(unsafe_code)]

pub mod config;
pub mod finding;
pub mod patterns;
pub mod redactor;
pub mod rules;
pub mod scanner;

pub use config::InspectionConfig;
pub use finding::{
    FindingAction, FindingCategory, FindingLocation, InspectionFinding, InspectionResult, Severity,
};
pub use redactor::{redact_json, redact_text};
pub use rules::InspectionRuleSet;
pub use scanner::ContentScanner;
