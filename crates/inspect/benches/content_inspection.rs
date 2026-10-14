//! Benchmarks for content inspection at various sizes and pattern counts.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use forculus_inspect::config::InspectionConfig;
use forculus_inspect::scanner::ContentScanner;

fn generate_text(size: usize) -> String {
    let base = "The quick brown fox jumps over the lazy dog. ";
    base.repeat(size / base.len() + 1)[..size].to_string()
}

fn bench_scan_by_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("content_inspection/scan_by_size");
    let scanner = ContentScanner::builtin();

    for size in [1_000, 10_000, 100_000, 1_000_000] {
        let text = generate_text(size);
        let label = match size {
            1_000 => "1KB",
            10_000 => "10KB",
            100_000 => "100KB",
            1_000_000 => "1MB",
            _ => "?",
        };
        group.bench_with_input(BenchmarkId::from_parameter(label), &text, |b, text| {
            b.iter(|| scanner.scan_text(text));
        });
    }

    group.finish();
}

fn bench_scan_json_depth(c: &mut Criterion) {
    let mut group = c.benchmark_group("content_inspection/json_depth");
    let scanner = ContentScanner::builtin();

    for depth in [1, 5, 10] {
        let json = nested_json(depth);
        group.bench_with_input(BenchmarkId::from_parameter(depth), &json, |b, json| {
            b.iter(|| scanner.scan_json(json));
        });
    }

    group.finish();
}

fn nested_json(depth: usize) -> serde_json::Value {
    let mut val = serde_json::json!({"leaf": "value with some text content here"});
    for i in (0..depth).rev() {
        val = serde_json::json!({format!("level_{i}"): val});
    }
    val
}

fn bench_clean_vs_dirty(c: &mut Criterion) {
    let mut group = c.benchmark_group("content_inspection/clean_vs_dirty");
    let scanner = ContentScanner::builtin();

    let clean = generate_text(10_000);
    let dirty = format!(
        "{}AKIAIOSFODNN7EXAMPLE and user@example.com and 123-45-6789{}",
        &clean[..5000],
        &clean[5000..]
    );

    group.bench_function("clean_10kb", |b| {
        b.iter(|| scanner.scan_text(&clean));
    });
    group.bench_function("dirty_10kb", |b| {
        b.iter(|| scanner.scan_text(&dirty));
    });

    group.finish();
}

fn bench_pattern_count(c: &mut Criterion) {
    let mut group = c.benchmark_group("content_inspection/pattern_count");
    let text = generate_text(10_000);

    // Default 13 built-in patterns.
    let scanner_default = ContentScanner::builtin();
    group.bench_function("13_patterns", |b| {
        b.iter(|| scanner_default.scan_text(&text));
    });

    // With extra custom patterns.
    let config = InspectionConfig {
        custom_patterns: (0..12)
            .map(|i| forculus_inspect::config::CustomPattern {
                id: format!("custom-{i}"),
                description: format!("Custom pattern {i}"),
                pattern: format!("CUSTOM_PATTERN_{i}_[0-9]+"),
                severity: forculus_inspect::Severity::Low,
                category: forculus_inspect::FindingCategory::Custom("custom".into()),
                action: forculus_inspect::FindingAction::Log,
            })
            .collect(),
        ..Default::default()
    };
    let scanner_25 = ContentScanner::from_config(&config).unwrap();
    group.bench_function("25_patterns", |b| {
        b.iter(|| scanner_25.scan_text(&text));
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_scan_by_size,
    bench_scan_json_depth,
    bench_clean_vs_dirty,
    bench_pattern_count,
);
criterion_main!(benches);
