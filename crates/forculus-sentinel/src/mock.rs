//! Deterministic rule-based classifier: zero network, fully reproducible.
//! Serves as the offline eval tier, the test tier, and a conservative
//! fallback when no LLM is configured.
//!
//! Note: attack-pattern literals are assembled at compile time from parts
//! so that building this crate on a machine guarded by a Warden-class
//! gateway does not false-positive on the corpus strings. Yes, we blocked
//! our own build once already. That is the product working.

use serde_json::Value;
use std::future::Future;
use std::pin::Pin;

use crate::classifier::Classification;
use crate::{Classifier, SentinelError};

const RM_RF: &str = concat!("rm", " -rf");
const WIPE_FS: &str = concat!("mk", "fs");
const DD_IF: &str = concat!("dd ", "if=");
const FORK_BOMB: &str = concat!(":(", "){");
const KILL_ALL: &str = concat!("kill", "all -9");
const CRONTAB: &str = concat!("cron", "tab -");
const CHMOD_777: &str = concat!("chmod", " 777");
const SUDO_CMD: &str = concat!("sud", "o ");

const EXFIL: &[&str] = &[
    "webhook.site",
    "requestbin",
    "api.telegram.org",
    "pastebin.com/api",
    "transfer.sh",
    "file.io",
    "discord.com/api/webhooks",
    "ngrok",
    "| base64 -d |",
    "| sh",
    "|sh",
];

const DESTRUCTIVE: &[&str] = &[RM_RF, WIPE_FS, DD_IF, FORK_BOMB, KILL_ALL, CRONTAB];

const CREDENTIALS: &[&str] = &[
    "id_rsa",
    ".ssh/",
    ".aws/credentials",
    ".env",
    "find-generic-password",
    "keychain",
    "credential.helper",
    "chat.db",
];

const PRIVILEGE: &[&str] = &[CHMOD_777, SUDO_CMD, "/etc/sudoers", "launchctl bsexec"];

const INJECTION: &[&str] = &[
    "ignore previous instructions",
    "disregard your",
    "you are now",
    "system: disregard",
    "override your",
];

pub struct MockClassifier {
    pub confidence: f64,
}

impl Default for MockClassifier {
    fn default() -> Self {
        Self { confidence: 0.9 }
    }
}

/// Returns the threat category if the call matches an attack pattern.
pub fn rule_category(lowercased: &str) -> Option<&'static str> {
    fn any(haystack: &str, needles: &[&str]) -> bool {
        needles.iter().any(|n| haystack.contains(n))
    }
    if any(lowercased, EXFIL) {
        return Some("data_exfiltration");
    }
    if any(lowercased, DESTRUCTIVE) {
        return Some("destructive");
    }
    if any(lowercased, CREDENTIALS) {
        return Some("credential_access");
    }
    if any(lowercased, PRIVILEGE) {
        return Some("privilege_escalation");
    }
    if any(lowercased, INJECTION) {
        return Some("prompt_injection");
    }
    None
}

impl Classifier for MockClassifier {
    fn name(&self) -> &str {
        "mock-rules"
    }

    fn classify<'a>(
        &'a self,
        method: &'a str,
        params: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<Classification, SentinelError>> + Send + 'a>> {
        Box::pin(async move {
            let haystack = format!("{method} {params}").to_lowercase();
            let (verdict, category, reasoning) = match rule_category(&haystack) {
                Some(category) => (
                    "block",
                    category,
                    format!("mock rule engine matched category: {category}"),
                ),
                None => (
                    "allow",
                    "safe",
                    "mock rule engine: no attack pattern matched".to_string(),
                ),
            };
            Ok(Classification {
                verdict: verdict.to_string(),
                confidence: self.confidence,
                reasoning,
                category: category.to_string(),
            })
        })
    }
}
