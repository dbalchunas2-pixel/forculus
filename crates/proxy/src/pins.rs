//! F3: tool-definition hash pinning.
//!
//! Pins a SHA-256 hash over each MCP server's tool definitions at first
//! connection. On later connections, any tool whose canonical definition
//! changed (or was added) is reported so the proxy can block it and alert.
//! Changed tools are never silently re-pinned: refreshing a pin is an
//! explicit operator action.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Clone)]
pub struct ToolDef {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub input_schema: serde_json::Value,
}

#[derive(Debug, PartialEq, Clone)]
pub enum PinVerdict {
    /// All tool definitions match their pins.
    Pinned,
    /// First time this server is seen; pins were created and persisted.
    NewServer,
    /// One or more tool definitions changed or were added since pinning.
    /// Carries the offending tool names. Pins are NOT updated.
    Changed(Vec<String>),
}

pub struct PinStore {
    path: PathBuf,
    pins: BTreeMap<String, BTreeMap<String, String>>, // server -> tool -> hash
}

/// Canonical JSON: object keys sorted recursively so equivalent schemas
/// always hash identically.
fn canonical_json(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Object(map) => {
            let sorted: BTreeMap<&String, &serde_json::Value> = map.iter().collect();
            let inner: Vec<String> = sorted
                .iter()
                .map(|(k, val)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap_or_else(|_| "\"\"".into()),
                        canonical_json(val)
                    )
                })
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        serde_json::Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(canonical_json).collect();
            format!("[{}]", inner.join(","))
        }
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

impl PinStore {
    pub fn load(path: PathBuf) -> Result<Self, std::io::Error> {
        let mut pins = BTreeMap::new();
        if path.exists() {
            let content = std::fs::read_to_string(&path)?;
            if !content.trim().is_empty() {
                pins = serde_json::from_str(&content)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            }
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        Ok(Self { path, pins })
    }

    pub fn save(&self) -> std::io::Result<()> {
        let content = serde_json::to_string_pretty(&self.pins)?;
        std::fs::write(&self.path, content)
    }

    /// SHA-256 (hex) over the canonical tool definition:
    /// name, description and canonically-serialized input schema.
    pub fn hash_tool(t: &ToolDef) -> String {
        let canonical = format!(
            "{}|{}|{}",
            t.name,
            t.description,
            canonical_json(&t.input_schema)
        );
        let digest = Sha256::digest(canonical.as_bytes());
        digest.iter().map(|b| format!("{:02x}", b)).collect::<String>()
    }

    pub fn verify(&mut self, server: &str, tools: &[ToolDef]) -> PinVerdict {
        match self.pins.get(server) {
            None => {
                let mut server_pins = BTreeMap::new();
                for tool in tools {
                    server_pins.insert(tool.name.clone(), Self::hash_tool(tool));
                }
                self.pins.insert(server.to_string(), server_pins);
                let _ = self.save();
                PinVerdict::NewServer
            }
            Some(server_pins) => {
                let changed: Vec<String> = tools
                    .iter()
                    .filter(|t| {
                        server_pins
                            .get(&t.name)
                            .map(|h| h != &Self::hash_tool(t))
                            .unwrap_or(true) // new tool on a pinned server = a change
                    })
                    .map(|t| t.name.clone())
                    .collect();
                if changed.is_empty() {
                    PinVerdict::Pinned
                } else {
                    PinVerdict::Changed(changed)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "forculus_pins_test_{}_{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn tool(name: &str, desc: &str) -> ToolDef {
        ToolDef {
            name: name.into(),
            description: desc.into(),
            input_schema: serde_json::json!({"type": "object", "properties": {}}),
        }
    }

    #[test]
    fn hash_is_stable_and_canonical() {
        let a = ToolDef {
            name: "t".into(),
            description: "d".into(),
            input_schema: serde_json::json!({"properties": {"x": 1}, "type": "object"}),
        };
        let b = ToolDef {
            name: "t".into(),
            description: "d".into(),
            input_schema: serde_json::json!({"type": "object", "properties": {"x": 1}}),
        };
        // Key order in the schema must not change the hash.
        assert_eq!(PinStore::hash_tool(&a), PinStore::hash_tool(&b));
        let mut c = b.clone();
        c.description = "other".into();
        assert_ne!(PinStore::hash_tool(&a), PinStore::hash_tool(&c));
    }

    #[test]
    fn round_trip() {
        let path = tmp_path();
        let mut store = PinStore::load(path.clone()).expect("load failed");
        assert_eq!(store.verify("srv", &[tool("a", "x")]), PinVerdict::NewServer);
        let loaded = PinStore::load(path.clone()).expect("reload failed");
        assert_eq!(store.pins, loaded.pins);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn changed_detection() {
        let path = tmp_path();
        let mut store = PinStore::load(path.clone()).expect("load failed");
        assert_eq!(
            store.verify("srv", &[tool("a", "x"), tool("b", "y")]),
            PinVerdict::NewServer
        );
        assert_eq!(
            store.verify("srv", &[tool("a", "x"), tool("b", "y")]),
            PinVerdict::Pinned
        );
        assert_eq!(
            store.verify("srv", &[tool("a", "CHANGED"), tool("b", "y")]),
            PinVerdict::Changed(vec!["a".into()])
        );
        // A new tool on a pinned server is also a change.
        assert_eq!(
            store.verify("srv", &[tool("a", "x"), tool("b", "y"), tool("c", "z")]),
            PinVerdict::Changed(vec!["c".into()])
        );
        // Pins must NOT have been silently refreshed by the Changed verdicts.
        assert_eq!(
            store.verify("srv", &[tool("a", "CHANGED"), tool("b", "y")]),
            PinVerdict::Changed(vec!["a".into()])
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn servers_are_independent() {
        let path = tmp_path();
        let mut store = PinStore::load(path.clone()).expect("load failed");
        assert_eq!(store.verify("s1", &[tool("a", "x")]), PinVerdict::NewServer);
        assert_eq!(store.verify("s2", &[tool("a", "x")]), PinVerdict::NewServer);
        assert_eq!(store.verify("s1", &[tool("a", "x")]), PinVerdict::Pinned);
        assert_eq!(store.verify("s2", &[tool("a", "x")]), PinVerdict::Pinned);
        // s1 changed, s2 unaffected.
        assert_eq!(store.verify("s1", &[tool("a", "evil")]), PinVerdict::Changed(vec!["a".into()]));
        assert_eq!(store.verify("s2", &[tool("a", "x")]), PinVerdict::Pinned);
        let _ = std::fs::remove_file(&path);
    }
}
