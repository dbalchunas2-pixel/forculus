# Dev Report - 2026-10-15: Rebrand completion, provenance hygiene, security audit

**Type:** Dev report (retrospective; backfilled 2026-10-16)
**Session date:** 2026-10-15 (late session, ~01:50-02:30 UTC)
**Status:** Completed

## Summary

The rename started on the 14th was finished properly: session token prefixes rebranded in code and tests (where a timing test caught a real asymmetry), README install paths fixed to point at this repository with correct fork provenance, a 13-fixture torture-test corpus landed for the sandbox and content-scanning phases, and the second-reviewer adversarial audit passed 7/7 with a go for Checkpoint A.

## Work completed

**Token prefix rebrand.** The session token prefix changed from the upstream prefix to `fcl_sess_` in the vault crate (15 occurrences), then swept through tests and docs. Notable: the timing test caught a prefix-validated fast-fail asymmetry, so the completion sweep fixed a real behavioral inconsistency, not just a string.

**README provenance fix.** Install paths had pointed at the upstream owner; corrected to this repository. Nonexistent install instructions (brew/docker) removed. Fork provenance documented per Apache-2.0 section 4(b) via NOTICE and CHANGES.md.

**Torture-test corpus.** 13 fixtures (7 malicious, 6 benign) with a manifest and validator, built as the acceptance harness for the sandbox and content-scanning phases.

**Second-reviewer adversarial audit.** Directly answers the Council's process revision (solo review is a process risk for a security product). Result: 7/7 sections PASS, GO for Checkpoint A.

### Commits

- `716ed62` - docs: fix README provenance and install paths to this repo
- `7ee65f6` - fix: rebrand session token prefix (vault session crate, 15 occurrences)
- `aa28488` - test: torture-test corpus for F3/F4 - 13 fixtures (7 malicious, 6 benign), manifest, validator
- `9ba93b5` - docs(f2): second-reviewer adversarial audit - 7/7 sections PASS, GO for Checkpoint A
- `22f93be` - fix: complete token-prefix rebrand sweep in tests + docs (timing test caught prefix-validated fast-fail asymmetry)

## What changed since the last report

All user-visible strings, token formats, and docs now refer to Forculus rather than the upstream name. The rebrand is complete at the code level, pending the remaining test-verification pass.
