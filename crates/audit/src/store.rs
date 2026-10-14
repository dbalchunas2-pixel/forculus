//! SQLite persistence layer for audit events.

use std::collections::HashMap;
use std::path::Path;

use chrono::{DateTime, Utc};

use crate::event::{
    AuditEvent, Channel, CredentialInfo, ErrorInfo, EventOutcome, EventType, InspectionInfo,
    PolicyInfo, RequestInfo, SessionInfo,
};
use crate::query::{AuditFilter, AuditStats};

/// Persistent store for audit events backed by SQLite.
pub struct AuditStore {
    db: rusqlite::Connection,
}

impl AuditStore {
    /// Open or create the audit database at the given path.
    pub fn open(path: &Path) -> forculus_common::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                forculus_common::ForculusError::Audit(format!(
                    "failed to create directory {}: {e}",
                    parent.display()
                ))
            })?;
        }

        let db = rusqlite::Connection::open(path).map_err(|e| {
            forculus_common::ForculusError::Audit(format!("failed to open audit database: {e}"))
        })?;

        db.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;",
        )
        .map_err(|e| {
            forculus_common::ForculusError::Audit(format!("failed to set pragmas: {e}"))
        })?;

        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                outcome TEXT NOT NULL,
                channel TEXT NOT NULL,
                session_id TEXT,
                operator TEXT,
                team TEXT,
                project TEXT,
                environment TEXT,
                agent_type TEXT,
                tool TEXT,
                action TEXT,
                resource TEXT,
                target TEXT,
                verdict TEXT,
                matched_rule TEXT,
                matched_policy TEXT,
                policy_scope TEXT,
                reason TEXT,
                evaluation_time_us INTEGER,
                credential_name TEXT,
                credential_type TEXT,
                binding_tool_pattern TEXT,
                error_category TEXT,
                error_message TEXT,
                inspection_finding_count INTEGER,
                inspection_action TEXT,
                inspection_max_severity TEXT,
                duration_us INTEGER,
                event_hash TEXT,
                prev_hash TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_events(event_type);
            CREATE INDEX IF NOT EXISTS idx_audit_outcome ON audit_events(outcome);
            CREATE INDEX IF NOT EXISTS idx_audit_operator ON audit_events(operator);
            CREATE INDEX IF NOT EXISTS idx_audit_tool ON audit_events(tool);
            CREATE INDEX IF NOT EXISTS idx_audit_session_id ON audit_events(session_id);
            CREATE INDEX IF NOT EXISTS idx_audit_channel ON audit_events(channel);",
        )
        .map_err(|e| {
            forculus_common::ForculusError::Audit(format!("failed to create audit table: {e}"))
        })?;

        Ok(Self { db })
    }

    /// Insert a single event.
    pub fn insert(&self, event: &AuditEvent) -> forculus_common::Result<()> {
        self.insert_inner(&self.db, event)
    }

    /// Insert a batch of events in a single transaction.
    pub fn insert_batch(&self, events: &[AuditEvent]) -> forculus_common::Result<usize> {
        let tx = self.db.unchecked_transaction().map_err(|e| {
            forculus_common::ForculusError::Audit(format!("failed to begin transaction: {e}"))
        })?;
        let mut count = 0;
        for event in events {
            self.insert_inner(&tx, event)?;
            count += 1;
        }
        tx.commit().map_err(|e| {
            forculus_common::ForculusError::Audit(format!("failed to commit transaction: {e}"))
        })?;
        Ok(count)
    }

    /// Query events with filters.
    pub fn query(&self, filter: &AuditFilter) -> forculus_common::Result<Vec<AuditEvent>> {
        let (where_clause, params) = filter.to_sql();
        let order_limit = filter.order_limit_sql();
        let sql = format!("SELECT * FROM audit_events {where_clause} {order_limit}");

        let param_refs: Vec<&dyn rusqlite::types::ToSql> = params
            .iter()
            .map(|p| p as &dyn rusqlite::types::ToSql)
            .collect();

        let mut stmt = self.db.prepare(&sql).map_err(|e| {
            forculus_common::ForculusError::Audit(format!("query prepare error: {e}"))
        })?;

        let rows = stmt
            .query_map(param_refs.as_slice(), |row| self.row_to_event(row))
            .map_err(|e| forculus_common::ForculusError::Audit(format!("query error: {e}")))?;

        let mut events = Vec::new();
        for row in rows {
            events.push(row.map_err(|e| {
                forculus_common::ForculusError::Audit(format!("row read error: {e}"))
            })?);
        }
        Ok(events)
    }

    /// Count events matching a filter.
    pub fn count(&self, filter: &AuditFilter) -> forculus_common::Result<u64> {
        let (where_clause, params) = filter.to_sql();
        let sql = format!("SELECT COUNT(*) FROM audit_events {where_clause}");

        let param_refs: Vec<&dyn rusqlite::types::ToSql> = params
            .iter()
            .map(|p| p as &dyn rusqlite::types::ToSql)
            .collect();

        let count: i64 = self
            .db
            .query_row(&sql, param_refs.as_slice(), |row| row.get(0))
            .map_err(|e| forculus_common::ForculusError::Audit(format!("count error: {e}")))?;

        Ok(count as u64)
    }

    /// Get aggregate statistics.
    pub fn stats(&self, since: Option<DateTime<Utc>>) -> forculus_common::Result<AuditStats> {
        let time_filter = since
            .map(|t| format!("WHERE timestamp >= '{}'", t.to_rfc3339()))
            .unwrap_or_default();

        let total_events: i64 = self
            .db
            .query_row(
                &format!("SELECT COUNT(*) FROM audit_events {time_filter}"),
                [],
                |row| row.get(0),
            )
            .map_err(|e| forculus_common::ForculusError::Audit(format!("stats error: {e}")))?;

        let by_event_type = self.count_by_column("event_type", &time_filter)?;
        let by_outcome = self.count_by_column("outcome", &time_filter)?;
        let by_channel = self.count_by_column("channel", &time_filter)?;
        let top_operators = self.top_by_column("operator", &time_filter, 10)?;
        let top_tools = self.top_by_column("tool", &time_filter, 10)?;

        let now = Utc::now();
        let last_hour = self.count_since(now - chrono::Duration::hours(1))?;
        let last_day = self.count_since(now - chrono::Duration::days(1))?;
        let last_week = self.count_since(now - chrono::Duration::weeks(1))?;

        Ok(AuditStats {
            total_events: total_events as u64,
            by_event_type,
            by_outcome,
            by_channel,
            top_operators,
            top_tools,
            last_hour,
            last_day,
            last_week,
        })
    }

    /// Delete events older than the given timestamp.
    pub fn delete_before(&self, before: DateTime<Utc>) -> forculus_common::Result<u64> {
        let count = self
            .db
            .execute(
                "DELETE FROM audit_events WHERE timestamp < ?1",
                rusqlite::params![before.to_rfc3339()],
            )
            .map_err(|e| forculus_common::ForculusError::Audit(format!("delete error: {e}")))?;
        Ok(count as u64)
    }

    /// Get the most recent N events.
    pub fn recent(&self, limit: usize) -> forculus_common::Result<Vec<AuditEvent>> {
        self.query(&AuditFilter {
            limit: Some(limit),
            ..Default::default()
        })
    }

    // -- Private helpers --

    fn insert_inner(
        &self,
        conn: &rusqlite::Connection,
        event: &AuditEvent,
    ) -> forculus_common::Result<()> {
        let event_type_str = serde_json::to_value(&event.event_type)
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        let outcome_str = serde_json::to_value(&event.outcome)
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        let channel_str = serde_json::to_value(&event.channel)
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();

        // Hash chain: get the previous event's hash (or "genesis" for the first event).
        let prev_hash: String = conn
            .query_row(
                "SELECT event_hash FROM audit_events ORDER BY rowid DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap_or_else(|_| "genesis".to_string());

        // Compute this event's hash from prev_hash + event content.
        let event_hash = compute_event_hash(&prev_hash, event);

        conn.execute(
            "INSERT INTO audit_events (
                id, timestamp, event_type, outcome, channel,
                session_id, operator, team, project, environment, agent_type,
                tool, action, resource, target,
                verdict, matched_rule, matched_policy, policy_scope, reason, evaluation_time_us,
                credential_name, credential_type, binding_tool_pattern,
                error_category, error_message,
                inspection_finding_count, inspection_action, inspection_max_severity,
                duration_us,
                event_hash, prev_hash
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5,
                ?6, ?7, ?8, ?9, ?10, ?11,
                ?12, ?13, ?14, ?15,
                ?16, ?17, ?18, ?19, ?20, ?21,
                ?22, ?23, ?24,
                ?25, ?26,
                ?27, ?28, ?29,
                ?30,
                ?31, ?32
            )",
            rusqlite::params![
                event.id,
                event.timestamp.to_rfc3339(),
                event_type_str,
                outcome_str,
                channel_str,
                event.session.as_ref().map(|s| &s.session_id),
                event.session.as_ref().map(|s| &s.operator),
                event.session.as_ref().and_then(|s| s.team.as_ref()),
                event.session.as_ref().and_then(|s| s.project.as_ref()),
                event.session.as_ref().and_then(|s| s.environment.as_ref()),
                event.session.as_ref().and_then(|s| s.agent_type.as_ref()),
                event.request.as_ref().map(|r| &r.tool),
                event.request.as_ref().map(|r| &r.action),
                event.request.as_ref().and_then(|r| r.resource.as_ref()),
                event.request.as_ref().map(|r| &r.target),
                event.policy.as_ref().map(|p| &p.verdict),
                event.policy.as_ref().and_then(|p| p.matched_rule.as_ref()),
                event
                    .policy
                    .as_ref()
                    .and_then(|p| p.matched_policy.as_ref()),
                event.policy.as_ref().and_then(|p| p.scope.as_ref()),
                event.policy.as_ref().map(|p| &p.reason),
                event.policy.as_ref().map(|p| p.evaluation_time_us as i64),
                event.credential.as_ref().map(|c| &c.credential_name),
                event.credential.as_ref().map(|c| &c.credential_type),
                event
                    .credential
                    .as_ref()
                    .and_then(|c| c.binding_tool_pattern.as_ref()),
                event.error.as_ref().map(|e| &e.category),
                event.error.as_ref().map(|e| &e.message),
                event.inspection.as_ref().map(|i| i.finding_count as i64),
                event.inspection.as_ref().map(|i| &i.action_taken),
                event
                    .inspection
                    .as_ref()
                    .and_then(|i| i.max_severity.as_ref()),
                event.duration_us.map(|d| d as i64),
                event_hash,
                prev_hash,
            ],
        )
        .map_err(|e| forculus_common::ForculusError::Audit(format!("insert error: {e}")))?;
        Ok(())
    }

    fn row_to_event(&self, row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditEvent> {
        let id: String = row.get("id")?;
        let timestamp_str: String = row.get("timestamp")?;
        let event_type_str: String = row.get("event_type")?;
        let outcome_str: String = row.get("outcome")?;
        let channel_str: String = row.get("channel")?;

        let timestamp = DateTime::parse_from_rfc3339(&timestamp_str)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        let event_type: EventType =
            serde_json::from_value(serde_json::Value::String(event_type_str))
                .unwrap_or(EventType::Error);
        let outcome: EventOutcome = serde_json::from_value(serde_json::Value::String(outcome_str))
            .unwrap_or(EventOutcome::Failed);
        let channel: Channel = serde_json::from_value(serde_json::Value::String(channel_str))
            .unwrap_or(Channel::System);

        let session_id: Option<String> = row.get("session_id")?;
        let operator: Option<String> = row.get("operator")?;
        let session = match (session_id, operator) {
            (Some(sid), Some(op)) => Some(SessionInfo {
                session_id: sid,
                operator: op,
                team: row.get("team")?,
                project: row.get("project")?,
                environment: row.get("environment")?,
                agent_type: row.get("agent_type")?,
            }),
            _ => None,
        };

        let tool: Option<String> = row.get("tool")?;
        let action: Option<String> = row.get("action")?;
        let request = match (tool, action) {
            (Some(t), Some(a)) => Some(RequestInfo {
                tool: t,
                action: a,
                resource: row.get("resource")?,
                target: row.get::<_, Option<String>>("target")?.unwrap_or_default(),
            }),
            _ => None,
        };

        let verdict: Option<String> = row.get("verdict")?;
        let policy = verdict.map(|v| PolicyInfo {
            verdict: v,
            matched_rule: row.get("matched_rule").unwrap_or(None),
            matched_policy: row.get("matched_policy").unwrap_or(None),
            scope: row.get("policy_scope").unwrap_or(None),
            reason: row
                .get::<_, Option<String>>("reason")
                .unwrap_or(None)
                .unwrap_or_default(),
            evaluation_time_us: row
                .get::<_, Option<i64>>("evaluation_time_us")
                .unwrap_or(None)
                .unwrap_or(0) as u64,
        });

        let cred_name: Option<String> = row.get("credential_name")?;
        let credential = cred_name.map(|name| CredentialInfo {
            credential_name: name,
            credential_type: row
                .get::<_, Option<String>>("credential_type")
                .unwrap_or(None)
                .unwrap_or_default(),
            binding_tool_pattern: row.get("binding_tool_pattern").unwrap_or(None),
        });

        let error_category: Option<String> = row.get("error_category")?;
        let error = error_category.map(|cat| ErrorInfo {
            category: cat,
            message: row
                .get::<_, Option<String>>("error_message")
                .unwrap_or(None)
                .unwrap_or_default(),
        });

        let inspection_action: Option<String> = row.get("inspection_action")?;
        let inspection = inspection_action.map(|action| InspectionInfo {
            finding_count: row
                .get::<_, Option<i64>>("inspection_finding_count")
                .unwrap_or(None)
                .unwrap_or(0) as u64,
            action_taken: action,
            max_severity: row.get("inspection_max_severity").unwrap_or(None),
        });

        let duration_us: Option<i64> = row.get("duration_us")?;
        let event_hash: Option<String> = row.get("event_hash")?;
        let prev_hash: Option<String> = row.get("prev_hash")?;

        Ok(AuditEvent {
            id,
            timestamp,
            event_type,
            outcome,
            channel,
            session,
            request,
            policy,
            credential,
            error,
            inspection,
            duration_us: duration_us.map(|d| d as u64),
            event_hash,
            prev_hash,
        })
    }

    fn count_by_column(
        &self,
        column: &str,
        time_filter: &str,
    ) -> forculus_common::Result<HashMap<String, u64>> {
        let sql =
            format!("SELECT {column}, COUNT(*) FROM audit_events {time_filter} GROUP BY {column}");
        let mut stmt = self.db.prepare(&sql).map_err(|e| {
            forculus_common::ForculusError::Audit(format!("stats query error: {e}"))
        })?;
        let rows = stmt
            .query_map([], |row| {
                let key: Option<String> = row.get(0)?;
                let count: i64 = row.get(1)?;
                Ok((key.unwrap_or_else(|| "unknown".to_string()), count as u64))
            })
            .map_err(|e| forculus_common::ForculusError::Audit(format!("stats row error: {e}")))?;

        let mut map = HashMap::new();
        for row in rows {
            let (key, count) = row.map_err(|e| {
                forculus_common::ForculusError::Audit(format!("stats read error: {e}"))
            })?;
            map.insert(key, count);
        }
        Ok(map)
    }

    fn top_by_column(
        &self,
        column: &str,
        time_filter: &str,
        limit: usize,
    ) -> forculus_common::Result<Vec<(String, u64)>> {
        let sql = format!(
            "SELECT {column}, COUNT(*) as cnt FROM audit_events {time_filter} \
             WHERE {column} IS NOT NULL GROUP BY {column} ORDER BY cnt DESC LIMIT {limit}"
        );
        let mut stmt = self
            .db
            .prepare(&sql)
            .map_err(|e| forculus_common::ForculusError::Audit(format!("top query error: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                let key: String = row.get(0)?;
                let count: i64 = row.get(1)?;
                Ok((key, count as u64))
            })
            .map_err(|e| forculus_common::ForculusError::Audit(format!("top row error: {e}")))?;

        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(|e| {
                forculus_common::ForculusError::Audit(format!("top read error: {e}"))
            })?);
        }
        Ok(result)
    }

    fn count_since(&self, since: DateTime<Utc>) -> forculus_common::Result<u64> {
        let count: i64 = self
            .db
            .query_row(
                "SELECT COUNT(*) FROM audit_events WHERE timestamp >= ?1",
                rusqlite::params![since.to_rfc3339()],
                |row| row.get(0),
            )
            .map_err(|e| {
                forculus_common::ForculusError::Audit(format!("count since error: {e}"))
            })?;
        Ok(count as u64)
    }

    /// Verify the integrity of the audit hash chain.
    ///
    /// Re-computes each event's hash and checks that:
    /// 1. The first event's `prev_hash` is `"genesis"`.
    /// 2. Each subsequent event's `prev_hash` equals the previous event's `event_hash`.
    /// 3. Each event's stored `event_hash` matches the re-computed hash.
    ///
    /// Returns a [`ChainVerification`] with the result.
    pub fn verify_chain(&self) -> forculus_common::Result<ChainVerification> {
        let mut stmt = self
            .db
            .prepare("SELECT * FROM audit_events ORDER BY rowid ASC")
            .map_err(|e| {
                forculus_common::ForculusError::Audit(format!("verify prepare error: {e}"))
            })?;

        let rows = stmt
            .query_map([], |row| self.row_to_event(row))
            .map_err(|e| {
                forculus_common::ForculusError::Audit(format!("verify query error: {e}"))
            })?;

        let mut events = Vec::new();
        for row in rows {
            events.push(row.map_err(|e| {
                forculus_common::ForculusError::Audit(format!("verify row error: {e}"))
            })?);
        }

        if events.is_empty() {
            return Ok(ChainVerification {
                valid: true,
                events_checked: 0,
                first_invalid_index: None,
                error: None,
            });
        }

        let mut expected_prev = "genesis".to_string();

        for (i, event) in events.iter().enumerate() {
            let stored_hash = match &event.event_hash {
                Some(h) => h,
                None => {
                    return Ok(ChainVerification {
                        valid: false,
                        events_checked: i as u64,
                        first_invalid_index: Some(i as u64),
                        error: Some(format!("event {} has no event_hash", event.id)),
                    });
                }
            };

            let stored_prev = match &event.prev_hash {
                Some(h) => h,
                None => {
                    return Ok(ChainVerification {
                        valid: false,
                        events_checked: i as u64,
                        first_invalid_index: Some(i as u64),
                        error: Some(format!("event {} has no prev_hash", event.id)),
                    });
                }
            };

            // Check chain linkage.
            if *stored_prev != expected_prev {
                return Ok(ChainVerification {
                    valid: false,
                    events_checked: i as u64,
                    first_invalid_index: Some(i as u64),
                    error: Some(format!(
                        "event {} prev_hash mismatch: expected {}, got {}",
                        event.id, expected_prev, stored_prev
                    )),
                });
            }

            // Re-compute hash and compare.
            let recomputed = compute_event_hash(&expected_prev, event);
            if recomputed != *stored_hash {
                return Ok(ChainVerification {
                    valid: false,
                    events_checked: i as u64,
                    first_invalid_index: Some(i as u64),
                    error: Some(format!(
                        "event {} hash mismatch: expected {}, stored {}",
                        event.id, recomputed, stored_hash
                    )),
                });
            }

            expected_prev = stored_hash.clone();
        }

        Ok(ChainVerification {
            valid: true,
            events_checked: events.len() as u64,
            first_invalid_index: None,
            error: None,
        })
    }
}

/// Result of verifying the audit hash chain.
#[derive(Debug, Clone)]
pub struct ChainVerification {
    /// Whether the chain is valid (no tampering detected).
    pub valid: bool,
    /// Number of events that were checked.
    pub events_checked: u64,
    /// Index of the first invalid event (if any).
    pub first_invalid_index: Option<u64>,
    /// Description of the first error found.
    pub error: Option<String>,
}

/// Compute the blake3 hash for an audit event.
///
/// The hash covers `prev_hash` + all event content (excluding the hash fields
/// themselves). Uses JSON serialization with hash fields set to `None` for
/// deterministic, order-preserving content representation.
pub fn compute_event_hash(prev_hash: &str, event: &AuditEvent) -> String {
    let mut event_for_hash = event.clone();
    event_for_hash.event_hash = None;
    event_for_hash.prev_hash = None;
    let content = serde_json::to_string(&event_for_hash).unwrap();

    let mut hasher = blake3::Hasher::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(content.as_bytes());
    hasher.finalize().to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::AuditEvent;

    fn temp_store() -> (tempfile::TempDir, AuditStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(&dir.path().join("audit.db")).unwrap();
        (dir, store)
    }

    fn sample_event(event_type: EventType, outcome: EventOutcome) -> AuditEvent {
        AuditEvent::builder(event_type, Channel::HttpProxy)
            .outcome(outcome)
            .request(RequestInfo {
                tool: "example.com".into(),
                action: "GET /test".into(),
                resource: None,
                target: "http://example.com/test".into(),
            })
            .build()
    }

    fn sample_event_with_session(operator: &str) -> AuditEvent {
        AuditEvent::builder(EventType::RequestProcessed, Channel::McpGateway)
            .outcome(EventOutcome::Success)
            .session(SessionInfo {
                session_id: "sess-1".into(),
                operator: operator.into(),
                team: Some("eng".into()),
                project: None,
                environment: None,
                agent_type: None,
            })
            .request(RequestInfo {
                tool: "github".into(),
                action: "push".into(),
                resource: None,
                target: "github__push".into(),
            })
            .build()
    }

    #[test]
    fn insert_and_query_single() {
        let (_dir, store) = temp_store();
        let event = sample_event(EventType::RequestProcessed, EventOutcome::Success);
        let event_id = event.id.clone();
        store.insert(&event).unwrap();

        let results = store.query(&AuditFilter::default()).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, event_id);
        assert_eq!(results[0].event_type, EventType::RequestProcessed);
    }

    #[test]
    fn insert_batch_and_query() {
        let (_dir, store) = temp_store();
        let events: Vec<AuditEvent> = (0..5)
            .map(|_| sample_event(EventType::RequestProcessed, EventOutcome::Success))
            .collect();
        let count = store.insert_batch(&events).unwrap();
        assert_eq!(count, 5);

        let results = store.query(&AuditFilter::default()).unwrap();
        assert_eq!(results.len(), 5);
    }

    #[test]
    fn query_with_event_type_filter() {
        let (_dir, store) = temp_store();
        store
            .insert(&sample_event(
                EventType::RequestProcessed,
                EventOutcome::Success,
            ))
            .unwrap();
        store
            .insert(&sample_event(EventType::Error, EventOutcome::Failed))
            .unwrap();

        let filter = AuditFilter {
            event_types: vec![EventType::Error],
            ..Default::default()
        };
        let results = store.query(&filter).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].event_type, EventType::Error);
    }

    #[test]
    fn query_with_outcome_filter() {
        let (_dir, store) = temp_store();
        store
            .insert(&sample_event(
                EventType::RequestProcessed,
                EventOutcome::Success,
            ))
            .unwrap();
        store
            .insert(&sample_event(
                EventType::RequestProcessed,
                EventOutcome::Denied,
            ))
            .unwrap();

        let filter = AuditFilter {
            outcomes: vec![EventOutcome::Denied],
            ..Default::default()
        };
        let results = store.query(&filter).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].outcome, EventOutcome::Denied);
    }

    #[test]
    fn query_with_operator_filter() {
        let (_dir, store) = temp_store();
        store.insert(&sample_event_with_session("alice")).unwrap();
        store.insert(&sample_event_with_session("bob")).unwrap();

        let filter = AuditFilter {
            operators: vec!["alice".into()],
            ..Default::default()
        };
        let results = store.query(&filter).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].session.as_ref().unwrap().operator, "alice");
    }

    #[test]
    fn query_with_tool_wildcard() {
        let (_dir, store) = temp_store();
        store.insert(&sample_event_with_session("alice")).unwrap();
        store
            .insert(&sample_event(
                EventType::RequestProcessed,
                EventOutcome::Success,
            ))
            .unwrap();

        let filter = AuditFilter {
            tool: Some("git*".into()),
            ..Default::default()
        };
        let results = store.query(&filter).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].request.as_ref().unwrap().tool, "github");
    }

    #[test]
    fn query_with_limit_and_offset() {
        let (_dir, store) = temp_store();
        for _ in 0..10 {
            store
                .insert(&sample_event(
                    EventType::RequestProcessed,
                    EventOutcome::Success,
                ))
                .unwrap();
        }

        let filter = AuditFilter {
            limit: Some(3),
            offset: Some(2),
            ..Default::default()
        };
        let results = store.query(&filter).unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn count_matches_filter() {
        let (_dir, store) = temp_store();
        for _ in 0..5 {
            store
                .insert(&sample_event(
                    EventType::RequestProcessed,
                    EventOutcome::Success,
                ))
                .unwrap();
        }
        store
            .insert(&sample_event(EventType::Error, EventOutcome::Failed))
            .unwrap();

        let count = store
            .count(&AuditFilter {
                event_types: vec![EventType::RequestProcessed],
                ..Default::default()
            })
            .unwrap();
        assert_eq!(count, 5);
    }

    #[test]
    fn recent_returns_newest_first() {
        let (_dir, store) = temp_store();
        let e1 = sample_event(EventType::RequestProcessed, EventOutcome::Success);
        let e1_id = e1.id.clone();
        store.insert(&e1).unwrap();

        // Insert a second event slightly later.
        let e2 = sample_event(EventType::Error, EventOutcome::Failed);
        let e2_id = e2.id.clone();
        store.insert(&e2).unwrap();

        let recent = store.recent(1).unwrap();
        assert_eq!(recent.len(), 1);
        // The second event should be most recent.
        assert_eq!(recent[0].id, e2_id);

        let _ = e1_id; // suppress unused warning
    }

    #[test]
    fn delete_before_removes_old_events() {
        let (_dir, store) = temp_store();
        // Insert two events with current timestamps.
        store
            .insert(&sample_event(
                EventType::RequestProcessed,
                EventOutcome::Success,
            ))
            .unwrap();
        store
            .insert(&sample_event(
                EventType::RequestProcessed,
                EventOutcome::Success,
            ))
            .unwrap();

        // Delete events before the far future → deletes everything.
        let deleted = store
            .delete_before(Utc::now() + chrono::Duration::hours(1))
            .unwrap();
        assert_eq!(deleted, 2);
        assert_eq!(store.count(&AuditFilter::default()).unwrap(), 0);
    }

    #[test]
    fn stats_with_empty_db() {
        let (_dir, store) = temp_store();
        let stats = store.stats(None).unwrap();
        assert_eq!(stats.total_events, 0);
        assert_eq!(stats.last_hour, 0);
    }

    // -- Hash chain tests --

    #[test]
    fn hash_chain_empty_db_is_valid() {
        let (_dir, store) = temp_store();
        let result = store.verify_chain().unwrap();
        assert!(result.valid);
        assert_eq!(result.events_checked, 0);
    }

    #[test]
    fn hash_chain_single_event_is_valid() {
        let (_dir, store) = temp_store();
        store
            .insert(&sample_event(
                EventType::RequestProcessed,
                EventOutcome::Success,
            ))
            .unwrap();
        let result = store.verify_chain().unwrap();
        assert!(result.valid);
        assert_eq!(result.events_checked, 1);
    }

    #[test]
    fn hash_chain_multiple_events_is_valid() {
        let (_dir, store) = temp_store();
        for _ in 0..10 {
            store
                .insert(&sample_event(
                    EventType::RequestProcessed,
                    EventOutcome::Success,
                ))
                .unwrap();
        }
        let result = store.verify_chain().unwrap();
        assert!(result.valid);
        assert_eq!(result.events_checked, 10);
    }

    #[test]
    fn hash_chain_detects_tampered_event() {
        let (_dir, store) = temp_store();
        store
            .insert(&sample_event(
                EventType::RequestProcessed,
                EventOutcome::Success,
            ))
            .unwrap();
        store
            .insert(&sample_event(EventType::Error, EventOutcome::Failed))
            .unwrap();

        // Tamper: change the outcome of the first event directly in the DB.
        store
            .db
            .execute(
                "UPDATE audit_events SET outcome = 'denied' WHERE rowid = 1",
                [],
            )
            .unwrap();

        let result = store.verify_chain().unwrap();
        assert!(!result.valid, "tampered chain must be detected");
        assert_eq!(result.first_invalid_index, Some(0));
        assert!(result.error.unwrap().contains("hash mismatch"));
    }

    #[test]
    fn hash_chain_detects_broken_linkage() {
        let (_dir, store) = temp_store();
        store
            .insert(&sample_event(
                EventType::RequestProcessed,
                EventOutcome::Success,
            ))
            .unwrap();
        store
            .insert(&sample_event(EventType::Error, EventOutcome::Failed))
            .unwrap();

        // Tamper: change the prev_hash of the second event.
        store
            .db
            .execute(
                "UPDATE audit_events SET prev_hash = 'tampered' WHERE rowid = 2",
                [],
            )
            .unwrap();

        let result = store.verify_chain().unwrap();
        assert!(!result.valid, "broken linkage must be detected");
        assert_eq!(result.first_invalid_index, Some(1));
        assert!(result.error.unwrap().contains("prev_hash mismatch"));
    }

    #[test]
    fn hash_chain_first_event_has_genesis_prev() {
        let (_dir, store) = temp_store();
        store
            .insert(&sample_event(
                EventType::RequestProcessed,
                EventOutcome::Success,
            ))
            .unwrap();

        let events = store.query(&AuditFilter::default()).unwrap();
        assert_eq!(events[0].prev_hash.as_deref(), Some("genesis"));
    }

    #[test]
    fn hash_chain_batch_insert_maintains_chain() {
        let (_dir, store) = temp_store();
        let events: Vec<AuditEvent> = (0..5)
            .map(|_| sample_event(EventType::RequestProcessed, EventOutcome::Success))
            .collect();
        store.insert_batch(&events).unwrap();

        let result = store.verify_chain().unwrap();
        assert!(result.valid);
        assert_eq!(result.events_checked, 5);
    }

    #[test]
    fn stats_with_mixed_events() {
        let (_dir, store) = temp_store();
        store
            .insert(&sample_event(
                EventType::RequestProcessed,
                EventOutcome::Success,
            ))
            .unwrap();
        store
            .insert(&sample_event(
                EventType::RequestProcessed,
                EventOutcome::Denied,
            ))
            .unwrap();
        store
            .insert(&sample_event(EventType::Error, EventOutcome::Failed))
            .unwrap();

        let stats = store.stats(None).unwrap();
        assert_eq!(stats.total_events, 3);
        assert_eq!(stats.by_event_type.get("request_processed"), Some(&2));
        assert_eq!(stats.by_event_type.get("error"), Some(&1));
        assert_eq!(stats.by_outcome.get("success"), Some(&1));
        assert_eq!(stats.by_outcome.get("denied"), Some(&1));
        assert_eq!(stats.last_hour, 3);
    }
}
