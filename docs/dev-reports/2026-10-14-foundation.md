# Dev Report - 2026-10-14: Foundation

**Type:** Dev report (retrospective; backfilled 2026-10-16)
**Session date:** 2026-10-14
**Status:** Completed

## Summary

Forculus was established as a standalone product: the 12-pillar specification passed a full adversarial review with modifications, the inherited codebase was renamed end to end, the private repository was created, and the full test suite was verified green (502/502).

## Work completed

**Specification review.** The 12-pillar MCP firewall/permission broker spec went through a full product-venture review covering architecture, business strategy, competitive positioning, build plan, and legal and financial exposure. Verdict: proceed with modification, with six priority revisions recorded as tracked issues (DBA-7 through DBA-12):

1. **MVP cut-line.** A dogfoodable product needs 3-4 pillars, not 12: hash pinning + sandbox + approvals, inheriting the policy/audit/vault core.
2. **Legal.** File the LLC and obtain an E&O quote before the repository goes public. Liability attaches at repo visibility, not at paid tier. Private dogfooding approved immediately.
3. **Marketing language.** No inflated maturity claims anywhere in the product or its copy.
4. **Threat feed.** Reframed as a cold-start challenge with network-effect potential, not a day-one moat.
5. **Opportunity cost.** Named explicitly against the Ad Populum Gate 0 deadline (2026-12-31); Forculus runs as a background build with no fixed timeline.
6. **Process.** Hour estimates per build phase, and a named second reviewer for the security audit.

**Naming collision sweep.** The working name (Merlon) collided with an in-category company. Renamed to **Forculus** - the Roman god of the door: he decides when it opens. Fallback name on record: Limentinus.

**Repository.** Created as a private repo, forked from claudius-ars/bulwark (Apache-2.0). Upstream history retained and credited.

### Commits

- `ba60bec` - Pre-rename checkpoint: scaffolding docs, ADRs, CI, SECURITY
- `b98bc0e` - Rename Merlon/Bulwark -> Forculus: crates, binary, docs, configs (502 tests green)
- `246a732` - Correct rename provenance note in SCAFFOLDING
- `a06ce0e` - F0.5 verification: dependency refresh (185 crates), audit/deny configs aligned, formatting applied; 502/502 tests green

## Decisions

- **Business strategy committed:** dogfood Forculus on the maintainer's own MCP fleet (~25 servers), ship as a paid Pro/Team service, then make it free when the companion compute-marketplace project launches.
- **Repo stays private** until the LLC + E&O conditions above are met.

## Metrics

- Tests: 502/502 passing
- Workspace crates: 12
- Dependencies refreshed: 185 crates
