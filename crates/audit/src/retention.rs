//! Retention — age-based cleanup of old audit events.

use chrono::{Duration, Utc};

use crate::store::AuditStore;

/// Delete audit events older than `max_age_days` days.
///
/// Returns the number of events deleted.
pub fn run_retention(store: &AuditStore, max_age_days: u32) -> forculus_common::Result<u64> {
    if max_age_days == 0 {
        return Ok(0);
    }
    let cutoff = Utc::now() - Duration::days(max_age_days as i64);
    let deleted = store.delete_before(cutoff)?;
    if deleted > 0 {
        tracing::info!(deleted, max_age_days, "audit retention cleanup");
    }
    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{AuditEvent, Channel, EventType};
    use crate::query::AuditFilter;

    #[test]
    fn retention_zero_days_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(&dir.path().join("audit.db")).unwrap();
        store
            .insert(&AuditEvent::builder(EventType::RequestProcessed, Channel::HttpProxy).build())
            .unwrap();
        let deleted = run_retention(&store, 0).unwrap();
        assert_eq!(deleted, 0);
        assert_eq!(store.count(&AuditFilter::default()).unwrap(), 1);
    }

    #[test]
    fn retention_deletes_nothing_when_events_are_recent() {
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(&dir.path().join("audit.db")).unwrap();
        store
            .insert(&AuditEvent::builder(EventType::RequestProcessed, Channel::HttpProxy).build())
            .unwrap();
        let deleted = run_retention(&store, 90).unwrap();
        assert_eq!(deleted, 0);
    }
}
