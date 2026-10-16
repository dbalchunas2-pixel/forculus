# Dev Report - 2026-10-16: Documentation and proof of need

**Type:** Dev report (written same day)
**Session date:** 2026-10-16
**Status:** Completed

## Summary

This session produced the project's proof-of-need artifact and established the reporting cadence. 47 real incidents from the maintainer's own MCP fleet history were compiled, anonymized, and mapped to the Forculus pillars that would have prevented each one.

## Work completed

**Case studies (47, across 7 categories):**

1. Destructive commands without approval (placeholder-content file destruction, recursive deletes, permission resets, port squatting)
2. Credential and token lifecycle failures (plaintext tokens, expired OAuth, hardcoded secrets, unauthenticated daemons)
3. Runaway loops and resource thrashing (infinite retry loops, GPU contention, runaway save loops, model-task mismatches)
4. Unrestricted access and blast radius (unrestricted shell execution, scripts on authenticated pages, permission checks disabled)
5. Silent data corruption (transport mojibake, silent field drops, config loss, divergent data stores)
6. Supply chain and tool definition drift (endpoint moves, SDK breakage, known-vulnerable upstream tools, access-control exposure)
7. Network and environment issues (registry blocks, stale service definitions, permission-path fragility)

Each entry covers the problem, what actually happened, why Forculus is the right solution (referenced by pillar), and a technical walkthrough of the interception, inspection, approval, and audit trail that would have caught it.

**Project tracking.** A Forculus project was created in Linear (P-DBA-1), with the case-studies commit and the reporting cadence tracked as issues under the spec parent issue (DBA-6).

**Reporting cadence.** This `docs/dev-reports/` series was established. The 2026-10-14 and 2026-10-15 reports were backfilled from the commit history and project records; each backfill discloses its status at the top.

## Decisions

- **Reporting split.** Dev reports (this directory) are retrospective and factual; anything forward-looking will be labeled separately. The distinction matters: these files are evidence of completed work, not a diary of intentions.
- **Distribution posture.** Everything stays in the private repository for now. When the repository goes public (after the LLC + E&O conditions recorded on 2026-10-14), the case studies and this dev-report trail become the public proof-of-need and credibility record.

## Next

- Commit the case-studies document as `docs/case-studies.md` (tracked in Linear).
- Resume the build plan at Checkpoint A (cleared by the 2026-10-15 audit).
