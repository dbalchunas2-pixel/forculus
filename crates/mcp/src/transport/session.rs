//! MCP HTTP session manager — tracks per-connection MCP sessions.

use std::collections::HashMap;
use std::time::Instant;

use parking_lot::RwLock;
use uuid::Uuid;

/// An MCP session created during HTTP transport initialization.
#[derive(Debug, Clone)]
pub struct McpSession {
    /// The MCP session identifier (UUID).
    pub id: String,
    /// Optional Forculus vault session token for this MCP session.
    pub vault_token: Option<String>,
    /// Whether the client has completed the MCP initialize handshake.
    pub initialized: bool,
    /// When the session was created.
    pub created_at: Instant,
}

/// Manages MCP HTTP sessions.
///
/// Thread-safe via `RwLock` — many concurrent readers, few writers.
pub struct SessionManager {
    sessions: RwLock<HashMap<String, McpSession>>,
}

impl SessionManager {
    /// Create an empty session manager.
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }

    /// Create a new session, returning its ID.
    pub fn create_session(&self) -> String {
        let id = Uuid::new_v4().to_string();
        let session = McpSession {
            id: id.clone(),
            vault_token: None,
            initialized: false,
            created_at: Instant::now(),
        };
        self.sessions.write().insert(id.clone(), session);
        id
    }

    /// Get a clone of a session by ID.
    pub fn get_session(&self, id: &str) -> Option<McpSession> {
        self.sessions.read().get(id).cloned()
    }

    /// Mark a session as initialized (MCP handshake complete).
    pub fn mark_initialized(&self, id: &str) {
        if let Some(session) = self.sessions.write().get_mut(id) {
            session.initialized = true;
        }
    }

    /// Set the vault token for a session.
    pub fn set_vault_token(&self, id: &str, token: String) {
        if let Some(session) = self.sessions.write().get_mut(id) {
            session.vault_token = Some(token);
        }
    }

    /// Remove a session. Returns `true` if it existed.
    pub fn remove_session(&self, id: &str) -> bool {
        self.sessions.write().remove(id).is_some()
    }

    /// Return the number of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.read().len()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_get_session() {
        let mgr = SessionManager::new();
        let id = mgr.create_session();
        let session = mgr.get_session(&id).unwrap();
        assert_eq!(session.id, id);
        assert!(!session.initialized);
        assert!(session.vault_token.is_none());
        assert_eq!(mgr.session_count(), 1);
    }

    #[test]
    fn get_unknown_session_returns_none() {
        let mgr = SessionManager::new();
        assert!(mgr.get_session("nonexistent").is_none());
    }

    #[test]
    fn mark_initialized() {
        let mgr = SessionManager::new();
        let id = mgr.create_session();
        assert!(!mgr.get_session(&id).unwrap().initialized);
        mgr.mark_initialized(&id);
        assert!(mgr.get_session(&id).unwrap().initialized);
    }

    #[test]
    fn set_vault_token() {
        let mgr = SessionManager::new();
        let id = mgr.create_session();
        mgr.set_vault_token(&id, "fcl_sess_abc123".to_string());
        let session = mgr.get_session(&id).unwrap();
        assert_eq!(session.vault_token.as_deref(), Some("fcl_sess_abc123"));
    }

    #[test]
    fn remove_session() {
        let mgr = SessionManager::new();
        let id = mgr.create_session();
        assert_eq!(mgr.session_count(), 1);
        assert!(mgr.remove_session(&id));
        assert_eq!(mgr.session_count(), 0);
        assert!(mgr.get_session(&id).is_none());
    }

    #[test]
    fn remove_unknown_returns_false() {
        let mgr = SessionManager::new();
        assert!(!mgr.remove_session("nonexistent"));
    }
}
