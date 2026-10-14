# Contributing to Forculus

Thank you for your interest in contributing to Forculus! This document provides guidelines for contributing.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/forculus.git`
3. Create a branch: `git checkout -b my-feature`
4. Make your changes
5. Run the checks (see below)
6. Commit and push
7. Open a Pull Request

## Development Setup

**Prerequisites:**
- Rust 1.85+ (edition 2024)
- SQLite development libraries (bundled via `rusqlite`)

**Build:**
```bash
cargo build --workspace
```

**Test:**
```bash
cargo test --workspace
```

**Lint:**
```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

**Benchmarks:**
```bash
./scripts/bench.sh
```

## Code Style

- Run `cargo fmt` before committing
- All code must pass `cargo clippy` with `-D warnings`
- Use `#![forbid(unsafe_code)]` in all crates
- Follow existing patterns for error handling (`ForculusError` variants)
- Use the builder pattern (`with_*()` methods) for optional subsystem integration
- All new fields should use `Option<Arc<T>>` with `None` = passthrough for backward compatibility

## Testing

- Unit tests go in `#[cfg(test)] mod tests {}` within source files
- Integration tests go in `crates/<crate>/tests/`
- Use `tempfile::tempdir()` for any test that needs filesystem state
- All PRs must maintain or increase test count

## Pull Request Process

1. Ensure all checks pass: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all -- --check`
2. Update documentation if you change public APIs
3. Add tests for new functionality
4. Keep PRs focused on a single change

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
