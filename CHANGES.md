# CHANGES.md - Forculus

Change record since the fork of claudius-ars/bulwark @ `7563549` (Apache-2.0).
Maintained per Apache License 2.0 Section 4; see NOTICE for attribution.

## [0.1.0-forculus.1] - 2026-10-14

### Changed
- Renamed project from Bulwark to Forculus: all 12 crates (`bulwark-*` -> `forculus-*`),
  binary name, config file (`bulwark.yaml` -> `forculus.yaml`), and Homebrew formula.
  502 tests pass post-rename.
- Updated spec: `docs/forculus-spec-v1.2.md` (12-pillar product scope, approved via
  Council review, Linear DBA-6).

### Added
- Governance documentation: `docs/COUNCIL-DOCKET.md` (adversarial review transcript),
  `docs/LEGAL-GATES.md`, `docs/SCAFFOLDING.md`, `docs/KEY-INVENTORY.md`.
- ADRs: `docs/adr/ADR-0001-telemetry-stance.md` (zero telemetry by default; structural
  no-egress for arguments/credentials/payloads), `docs/adr/ADR-0002-license-keys.md`
  (Ed25519 offline license files, gentle enforcement).
- CI: `.github/workflows/ci.yml` (fmt, clippy, build, full test suite, cargo audit,
  cargo deny, SBOM via cargo-auditable; ubuntu + macos).
- Security policy: `SECURITY.md` (disclosure process and response SLAs).
- Key generation script: `scripts/generate-signing-keys.sh` (update-signing and
  license-signing keypairs; see KEY-INVENTORY.md).

### Planned (12-pillar scope, build in progress)
- Pillars 1-12 per `docs/forculus-spec-v1.2.md` section 2: Tauri GUI, tool-definition
  hash pinning, poisoning detection, sandbox profiles, agent identity, desktop
  approvals, threat feed, offline mode, cost awareness, provenance, scoped tokens,
  compliance export.
