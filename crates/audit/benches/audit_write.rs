//! Benchmarks for audit event writes — single insert and batch throughput.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use forculus_audit::event::{AuditEvent, Channel, EventOutcome, EventType, RequestInfo};
use forculus_audit::store::AuditStore;

fn sample_event() -> AuditEvent {
    AuditEvent::builder(EventType::RequestProcessed, Channel::HttpProxy)
        .outcome(EventOutcome::Success)
        .request(RequestInfo {
            tool: "example.com".into(),
            action: "GET /test".into(),
            resource: None,
            target: "http://example.com/test".into(),
        })
        .duration_us(500)
        .build()
}

fn bench_single_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("audit_write/single_insert");

    group.bench_function("insert_one", |b| {
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(&dir.path().join("bench.db")).unwrap();
        b.iter(|| {
            let event = sample_event();
            store.insert(&event).unwrap();
        });
    });

    group.finish();
}

fn bench_batch_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("audit_write/batch_insert");

    for batch_size in [10, 50, 100, 500] {
        group.bench_with_input(
            BenchmarkId::from_parameter(batch_size),
            &batch_size,
            |b, &size| {
                let dir = tempfile::tempdir().unwrap();
                let store = AuditStore::open(&dir.path().join("bench.db")).unwrap();
                b.iter(|| {
                    let events: Vec<AuditEvent> = (0..size).map(|_| sample_event()).collect();
                    store.insert_batch(&events).unwrap();
                });
            },
        );
    }

    group.finish();
}

fn bench_hash_chain_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("audit_write/hash_chain");

    // Measure how insert cost grows as chain length increases.
    for preload in [0, 100, 1000] {
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(&dir.path().join("bench.db")).unwrap();

        // Pre-populate the chain.
        if preload > 0 {
            let events: Vec<AuditEvent> = (0..preload).map(|_| sample_event()).collect();
            store.insert_batch(&events).unwrap();
        }

        let label = format!("after_{preload}_events");
        group.bench_function(&label, |b| {
            b.iter(|| {
                let event = sample_event();
                store.insert(&event).unwrap();
            });
        });
    }

    group.finish();
}

fn bench_query_after_inserts(c: &mut Criterion) {
    let mut group = c.benchmark_group("audit_write/query");

    for count in [100, 1000] {
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(&dir.path().join("bench.db")).unwrap();

        let events: Vec<AuditEvent> = (0..count).map(|_| sample_event()).collect();
        store.insert_batch(&events).unwrap();

        group.bench_with_input(BenchmarkId::new("recent_10", count), &count, |b, _| {
            b.iter(|| {
                let _ = store.recent(10).unwrap();
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_single_insert,
    bench_batch_insert,
    bench_hash_chain_overhead,
    bench_query_after_inserts,
);
criterion_main!(benches);
