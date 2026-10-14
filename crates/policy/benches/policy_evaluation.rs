//! Benchmarks for policy evaluation at various rule counts.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use forculus_policy::context::RequestContext;
use forculus_policy::engine::PolicyEngine;

fn generate_policy_yaml(rule_count: usize) -> String {
    let mut rules = String::new();
    for i in 0..rule_count {
        rules.push_str(&format!(
            "  - name: rule-{i}\n    verdict: allow\n    priority: {}\n    match:\n      tools: [\"tool-{i}\"]\n      actions: [\"action-{i}\"]\n",
            i + 1
        ));
    }
    format!("metadata:\n  name: bench\n  scope: global\nrules:\n{rules}")
}

fn engine_with_rules(rule_count: usize) -> PolicyEngine {
    let dir = tempfile::tempdir().unwrap();
    let yaml = generate_policy_yaml(rule_count);
    std::fs::write(dir.path().join("bench.yaml"), &yaml).unwrap();
    PolicyEngine::from_directory(dir.path()).unwrap()
}

fn bench_rule_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("policy_evaluation/rule_scaling");

    for count in [10, 50, 100, 500, 1000] {
        let engine = engine_with_rules(count);
        // Match the middle rule to benchmark actual traversal.
        let mid = count / 2;
        let ctx = RequestContext::new(format!("tool-{mid}"), format!("action-{mid}"));

        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, _| {
            b.iter(|| {
                let _ = engine.evaluate(&ctx);
            });
        });
    }

    group.finish();
}

fn bench_glob_matching(c: &mut Criterion) {
    let mut group = c.benchmark_group("policy_evaluation/glob_matching");

    // Exact match.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("exact.yaml"),
        "metadata:\n  name: exact\n  scope: global\nrules:\n  - name: exact\n    verdict: allow\n    priority: 1\n    match:\n      tools: [\"github\"]\n",
    )
    .unwrap();
    let engine = PolicyEngine::from_directory(dir.path()).unwrap();
    let ctx = RequestContext::new("github", "push");
    group.bench_function("exact", |b| {
        b.iter(|| engine.evaluate(&ctx));
    });

    // Wildcard.
    let dir2 = tempfile::tempdir().unwrap();
    std::fs::write(
        dir2.path().join("wild.yaml"),
        "metadata:\n  name: wild\n  scope: global\nrules:\n  - name: wild\n    verdict: allow\n    priority: 1\n    match:\n      tools: [\"git*\"]\n",
    )
    .unwrap();
    let engine2 = PolicyEngine::from_directory(dir2.path()).unwrap();
    group.bench_function("wildcard", |b| {
        b.iter(|| engine2.evaluate(&ctx));
    });

    // Complex pattern.
    let dir3 = tempfile::tempdir().unwrap();
    std::fs::write(
        dir3.path().join("complex.yaml"),
        "metadata:\n  name: complex\n  scope: global\nrules:\n  - name: complex\n    verdict: allow\n    priority: 1\n    match:\n      tools: [\"{github,gitlab,bitbucket}\"]\n      actions: [\"*push*\"]\n",
    )
    .unwrap();
    let engine3 = PolicyEngine::from_directory(dir3.path()).unwrap();
    group.bench_function("complex_pattern", |b| {
        b.iter(|| engine3.evaluate(&ctx));
    });

    group.finish();
}

criterion_group!(benches, bench_rule_scaling, bench_glob_matching);
criterion_main!(benches);
