# Merlon Fork Report — F0 Baseline Audit

**Date:** October 14, 2026
**Upstream:** claudius-ars/bulwark (Apache-2.0), cloned to `~/merlon`
**Upstream commit:** `7563549ed042534e24cab83a9404f7a8e214f7b7` (2026-02-25, "fix: use v0.2.0 tag to match Docker image")
**Plan phase:** F0 of spec v0.4 Section 10 (baseline audit clone → build+test → this report)

## Build result

- Command: `cargo build --release` (stable toolchain, rustup at `~/.cargo/bin`)
- Result: SEE BUILD SECTION BELOW (filled after completion)

## Test result

- Command: `cargo test --release`
- Result: SEE TEST SECTION BELOW

## Crate inventory (12 crates)

| Crate | Role | Merlon relevance |
|---|---|---|
| bulwark-policy | Policy engine (decision core) | Core; F2 audit target |
| bulwark-audit | Audit writer | Shared crate candidate with Ad Populum node agent |
| bulwark-proxy | MITM/forwarding proxy (incl. TLS) | Core interception path |
| bulwark-mcp | MCP protocol handling | Core |
| bulwark-cli | CLI entrypoint | Stays (GUI wraps this layer later) |
| bulwark-auth | Auth flows (OAuth/OIDC, PKCE, claims mapping) | Core |
| bulwark-vault | Credential vault/injection | Core |
| bulwark-ratelimit | Rate limiting | Core |
| bulwark-inspect / bulwark-inspect-http | Request/response inspection | Core |
| bulwark-config | Configuration | Core |
| bulwark-common | Shared types | Core |

## Engine capability survey

- Policy enforcement: present (bulwark-policy)
- Credential injection: present (bulwark-vault)
- Secret scanning: present (per upstream docs — verify in F2)
- Hash-chained audit: present (bulwark-audit)
- **Tool-definition hash pinning: ABSENT (confirmed).** All `sha256`/hash references in source are TLS cert generation (`rcgen` ECDSA P-256), PKCE verifiers, subject-hash claims mapping, and an FNV-1a hash in the proxy — none pin tool definitions. F3 (add tool-def hash pinning) is genuine new work.

## Red flags in inherited code

- `unsafe` blocks: 1 total across all crates (locate in F2)
- Dependencies: many current deps (serde 1.0.228, indexmap 2.13, aws-lc-sys 0.37.1 look recent); full `cargo audit` to run in F2
- Engine dormant since Feb 25 2026 (~8 months) — expect dep drift vs crates.io latest; Cargo.lock pins are internally consistent

## F1 rename checklist (NOT yet executed, per plan)

- Rename `bulwark-*` crates → `merlon-*`, update workspace `Cargo.toml`
- Preserve Apache-2.0 attribution: NOTICE file + CHANGES.md per section 4(b)
- Keep upstream commit recorded above as fork base
