//! Async audit logger — fire-and-forget event logging that never blocks the
//! request path.
//!
//! Events are sent through an unbounded mpsc channel to a background writer
//! that flushes them to SQLite in batches (every 1 second or 100 events,
//! whichever comes first).

use std::path::Path;

use tokio::sync::mpsc;

use crate::event::AuditEvent;
use crate::store::AuditStore;

/// Fire-and-forget handle for the async audit logger.
///
/// Cloning is cheap (just an `mpsc::UnboundedSender`).
#[derive(Clone)]
pub struct AuditLogger {
    tx: mpsc::UnboundedSender<AuditCommand>,
}

enum AuditCommand {
    Log(Box<AuditEvent>),
    Flush(tokio::sync::oneshot::Sender<()>),
    Shutdown(tokio::sync::oneshot::Sender<()>),
}

impl AuditLogger {
    /// Create and start a new audit logger.
    ///
    /// Opens (or creates) the SQLite database at `db_path` and spawns a
    /// background writer task on the current tokio runtime.
    pub fn new(db_path: &Path) -> forculus_common::Result<Self> {
        debug_assert!(
            db_path.extension().is_some_and(|ext| ext == "db"),
            "audit db_path should have .db extension"
        );
        let store = AuditStore::open(db_path)?;
        let (tx, rx) = mpsc::unbounded_channel();

        tokio::spawn(background_writer(store, rx));

        Ok(Self { tx })
    }

    /// Log an audit event without blocking.
    ///
    /// Returns immediately. Events are buffered and flushed in the background.
    pub fn log(&self, event: AuditEvent) {
        if self.tx.send(AuditCommand::Log(Box::new(event))).is_err() {
            tracing::warn!("audit logger channel closed, event dropped");
        }
    }

    /// Flush all buffered events to disk and wait for completion.
    pub async fn flush(&self) {
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        if self.tx.send(AuditCommand::Flush(done_tx)).is_ok() {
            let _ = done_rx.await;
        }
    }

    /// Gracefully shut down the logger: flush remaining events and stop.
    pub async fn shutdown(&self) {
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        if self.tx.send(AuditCommand::Shutdown(done_tx)).is_ok() {
            let _ = done_rx.await;
        }
    }
}

/// Background task that receives events and writes them to SQLite in batches.
async fn background_writer(store: AuditStore, mut rx: mpsc::UnboundedReceiver<AuditCommand>) {
    const BATCH_SIZE: usize = 100;
    const FLUSH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

    let mut buffer: Vec<AuditEvent> = Vec::with_capacity(BATCH_SIZE);
    let mut interval = tokio::time::interval(FLUSH_INTERVAL);
    // The first tick completes immediately; consume it.
    interval.tick().await;

    loop {
        tokio::select! {
            cmd = rx.recv() => {
                match cmd {
                    Some(AuditCommand::Log(event)) => {
                        buffer.push(*event);
                        if buffer.len() >= BATCH_SIZE {
                            flush_buffer(&store, &mut buffer);
                        }
                    }
                    Some(AuditCommand::Flush(done)) => {
                        flush_buffer(&store, &mut buffer);
                        let _ = done.send(());
                    }
                    Some(AuditCommand::Shutdown(done)) => {
                        flush_buffer(&store, &mut buffer);
                        let _ = done.send(());
                        break;
                    }
                    None => {
                        // Channel closed — flush and exit.
                        flush_buffer(&store, &mut buffer);
                        break;
                    }
                }
            }
            _ = interval.tick() => {
                if !buffer.is_empty() {
                    flush_buffer(&store, &mut buffer);
                }
            }
        }
    }
}

/// Flush the buffer to SQLite. On error, log and discard.
fn flush_buffer(store: &AuditStore, buffer: &mut Vec<AuditEvent>) {
    if buffer.is_empty() {
        return;
    }

    let count = buffer.len();
    match store.insert_batch(buffer) {
        Ok(n) => {
            tracing::trace!(events = n, "audit events flushed");
        }
        Err(e) => {
            tracing::error!(error = %e, events = count, "failed to flush audit events");
        }
    }
    buffer.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{AuditEvent, Channel, EventType};
    use crate::query::AuditFilter;

    #[tokio::test]
    async fn logger_writes_events() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("audit.db");
        let logger = AuditLogger::new(&db_path).unwrap();

        let event = AuditEvent::builder(EventType::RequestProcessed, Channel::HttpProxy).build();
        logger.log(event);
        logger.flush().await;

        let store = AuditStore::open(&db_path).unwrap();
        let events = store.query(&AuditFilter::default()).unwrap();
        assert_eq!(events.len(), 1);
    }

    #[tokio::test]
    async fn logger_handles_batch() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("audit.db");
        let logger = AuditLogger::new(&db_path).unwrap();

        for _ in 0..50 {
            let event =
                AuditEvent::builder(EventType::RequestProcessed, Channel::McpGateway).build();
            logger.log(event);
        }
        logger.flush().await;

        let store = AuditStore::open(&db_path).unwrap();
        assert_eq!(store.count(&AuditFilter::default()).unwrap(), 50);
    }

    #[tokio::test]
    async fn logger_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("audit.db");
        let logger = AuditLogger::new(&db_path).unwrap();

        let event = AuditEvent::builder(EventType::Error, Channel::System).build();
        logger.log(event);
        logger.shutdown().await;

        let store = AuditStore::open(&db_path).unwrap();
        assert_eq!(store.count(&AuditFilter::default()).unwrap(), 1);
    }

    #[tokio::test]
    async fn logger_clone_shares_channel() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("audit.db");
        let logger = AuditLogger::new(&db_path).unwrap();
        let logger2 = logger.clone();

        logger.log(AuditEvent::builder(EventType::RequestProcessed, Channel::HttpProxy).build());
        logger2.log(AuditEvent::builder(EventType::PolicyDecision, Channel::McpGateway).build());
        logger.flush().await;

        let store = AuditStore::open(&db_path).unwrap();
        assert_eq!(store.count(&AuditFilter::default()).unwrap(), 2);
    }
}
