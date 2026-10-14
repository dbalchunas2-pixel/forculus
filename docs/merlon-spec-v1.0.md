# Forculus — MCP Firewall & Permission Broker

**Version:** 1.2 (Founder Revision)
**Status:** Design — Full 12-Pillar Scope Approved (Founder veto of MVP cut, Oct 14 2026)
**Author:** David Joseph Balchunas Jr.
**Date:** October 14, 2026
**Council ruling:** PROCEED WITH MODIFICATION — see docs/COUNCIL-DOCKET.md and Linear DBA-6
**v1.1 change summary:** Council revisions applied (hour estimates, F2 second reviewer, background-build posture, threat feed reframed, language rule, legal gates section).
**v1.2 change summary:** FOUNDER VETO of revision 1 — MVP cut-line rejected; all 12 pillars in scope with preserved build order and honest full-scope sizing (158-226 hrs). Dogfood checkpoints replace the cut-line.
**Fork base:** claudius-ars/bulwark @ `7563549` (Apache-2.0, Feb 25 2026)
**Repo:** `dbalchunas2-pixel/merlon` (to be wired)

---

## 0. What Changed From the Forked Engine

The forked Bulwark engine provides a solid CLI core: policy enforcement, credential vault, content inspection, hash-chained audit, rate limiting, and MCP/HTTP gateway modes. Forculus does NOT throw this away — it wraps it in a desktop product and adds 7 new subsystems the engine lacks entirely.

### Inherited (from Bulwark fork, rename to merlon-* in F1)

| Subsystem | Crate | What It Does | Forculus Role |
|---|---|---|---|
| Policy engine | `policy` | YAML rules, glob matching, scope hierarchy, hot-reload, default-deny | Core governance — extended with sandbox profiles + agent identity conditions |
| Credential vault | `vault` | age encryption, bindings, injection, session store | Core — extended with scoped-token issuance |
| Content inspector | `inspect` | 13 built-in patterns, custom rules, block/redact/log | Core — extended with tool-definition poisoning scanner |
| Audit log | `audit` | SQLite, blake3 hash chain, query/export/verify | Core — extended with compliance template exporter |
| Rate limiter | `ratelimit` | Token bucket, per-session/operator/tool/global, cost tracking | Core — extended with GUI dashboard + budget enforcement UI |
| MCP gateway | `mcp` | stdio JSON-RPC, session handling, tool name extraction | Core |
| HTTP proxy | `proxy` | Forward proxy, TLS MITM, ephemeral certs | Core |
| Auth | `auth` | OAuth/OIDC, PKCE, claims mapping | Core — extended with agent identity signing |
| Config | `config` | YAML loading, validation | Core — extended with sandbox profiles + trust cards |
| CLI | `cli` | Full CLI (init, doctor, session, cred, audit, inspect, policy, proxy, mcp) | Stays as headless mode; GUI wraps it |
| Common | `common` | Shared types | Core |

### New (Forculus-only, not in the fork)

| Pillar | New Subsystem | Built On |
|---|---|---|
| 1. Desktop-first | Tauri GUI (Rust + webview) | New crate `merlon-gui` |
| 2. Tool-def hash pinning | Tool definition registrar | New crate `merlon-toolguard` |
| 3. Tool poisoning detection | Poisoning scanner (extends `inspect`) | Extends `merlon-inspect` |
| 4. Sandbox / blast radius | Capability profile engine | New crate `merlon-sandbox` |
| 5. Agent identity | Agent identity provider | Extends `merlon-auth` |
| 6. Desktop approvals | Approval workflow + Tauri notifications | New crate `merlon-approve` |
| 7. Shared threat feed | Threat feed client/server | New crate `merlon-threatfeed` |
| 8. Offline / air-gapped | Offline mode controller | Extends `merlon-config` |
| 9. Cost / token awareness | Cost dashboard + budget enforcement | Extends `merlon-ratelimit` + GUI |
| 10. Supply chain verification | MCP provenance verifier | New crate `merlon-provenance` |
| 11. Scoped credential vault | Token issuer (extends `vault`) | Extends `merlon-vault` |
| 12. Compliance export | Template engine (extends `audit`) | Extends `merlon-audit` |

---

## 1. Architecture: The Forculus Governance Pipeline

The existing Bulwark pipeline is 10 stages: Session -> Tool Mapping -> Rate Limit -> Content Inspect (req) -> Policy -> Credential Inject -> Forward -> Content Inspect (resp) -> Cost Record -> Audit.

Forculus inserts 5 NEW stages into this pipeline (shown with **):

```
Agent (Untrusted)
  |
  v
[1] Session Validation (inherited)
  |
  v
[1a] **Agent Identity Verification** (NEW — pillar 5)
     |- Verify agent's signed identity token
     |- Per-call revalidation (not just connection-time)
     |- Reject if identity revoked or stale
  |
  v
[1b] **Tool Definition Integrity Check** (NEW — pillar 2)
     |- Hash-compare current tool definitions against pinned baseline
     |- If mismatch: block + alert + trigger poisoning scan
  |
  v
[2] Tool Mapping (inherited)
  |
  v
[2a] **Supply Chain Verification** (NEW — pillar 10)
     |- Look up tool/server provenance from trust registry
     |- Check publisher signature, reputation, change history
     |- Display trust card in GUI; block if untrusted + strict mode
  |
  v
[3] Rate Limiting (inherited)
  |
  v
[3a] **Cost Budget Check** (ENHANCED — pillar 9)
     |- Per-tool-call cost lookup
     |- Per-agent session budget enforcement
     |- Block if budget exceeded; GUI dashboard shows real-time spend
  |
  v
[4] Content Inspection — Request (inherited)
  |
  v
[4a] **Tool Poisoning Scan** (NEW — pillar 3)
     |- Scan tool definitions for injection patterns
     |- Pattern DB sourced from shared threat feed
     |- Block + alert if injection patterns detected
  |
  v
[5] Policy Evaluation (inherited, ENHANCED)
     |- **Sandbox profile check** (NEW — pillar 4): verify call is within
     |  per-server capability profile (filesystem paths, network endpoints, env vars)
     |- Existing rule evaluation (glob matching, scope precedence)
     |- If verdict = escalate -> **Approval Workflow** (NEW — pillar 6)
  |
  v
[5a] **Approval Workflow** (NEW — pillar 6)
     |- If policy verdict = escalate or risk classifier flags high-risk:
     |  - Send Tauri desktop notification
     |  - Include: agent identity, tool, action, arguments summary
     |  - Approve / Deny buttons
     |  - Configurable timeout (default 10s -> auto-deny)
     |  - Log decision to audit chain
  |
  v
[6] Credential Injection (inherited, ENHANCED — pillar 11)
     |- **Scoped token issuance**: instead of injecting raw API key,
     |  issue a short-lived scoped token (TTL = call duration + N min)
     |  Agent never sees the underlying secret
  |
  v
[7] Forward to Upstream (inherited)
  |
  v
[8] Content Inspection — Response (inherited)
  |
  v
[9] Cost Recording (inherited, ENHANCED)
     |- Record actual cost (from response metadata if available)
     |- Update GUI dashboard in real-time
  |
  v
[10] Audit Logging (inherited, ENHANCED — pillar 12)
     |- blake3 hash chain (inherited)
     |- **Compliance metadata**: tag events with framework-relevant fields
     |  (SOC 2: who/what/when/verdict; GDPR: data category/access basis;
     |   HIPAA: PHI flag/access context; EU AI Act: risk tier/oversight)
  |
  v
Agent receives response (or 403/429/error)
```

### Offline Mode (Pillar 8)

The entire pipeline runs without internet. The only features that need network:
- Shared threat feed updates (pillar 7) -> manual import of signed bundles
- Supply chain verification lookups (pillar 10) -> local cache + manual refresh
- Everything else is local: policies, vault, audit, sandbox, approvals, poisoning scan (with local pattern DB)

Config flag:
```yaml
offline_mode: true
threat_feed:
  source: manual  # auto | manual
  import_path: "~/.merlon/threat-feed/"
```

---

## 2. The 12 Pillars — Detailed Spec

### Pillar 1: Desktop-First / Local-First (Tauri GUI)

**Crate:** `merlon-gui` (new)

The GUI is not a thin wrapper — it is the product. The CLI engine runs as a sidecar process; the Tauri app talks to it over a local socket.

**GUI surfaces:**
- **Dashboard** — live view of all connected MCP servers, their health, call volume, cost burn, blocked-call count
- **Server inspector** — per-server: tool list, pinned hashes, capability profile, provenance trust card, recent calls
- **Policy editor** — visual YAML editor with live validation and policy-replay preview (engine already has `policy test`)
- **Approval center** — pending + historical approval requests
- **Audit explorer** — searchable audit log with hash-chain verify button, one-click compliance export
- **Threat feed** — subscribed feeds, last update, blocked threats sourced from feed
- **Cost center** — per-agent/per-server spend, budgets, alerts

**Onboarding (zero-config):** On first launch, Forculus auto-discovers MCP servers from known client configs (Claude Desktop `claude_desktop_config.json`, Cursor, Claude Code `~/.claude.json`, etc.), pins their current tool definitions, generates default-deny + safe-read-allow starter policies, and shows a "review and arm" screen. 5 minutes to protected.

### Pillar 2: Tool Definition Hash Pinning

**Crate:** `merlon-toolguard` (new) — CONFIRMED absent in fork (FORK-REPORT.md)

- On first connection to an MCP server, capture `tools/list` response and compute a canonical hash per tool (name + description + input schema + annotations), plus a server-level aggregate hash.
- Store in `~/.merlon/toolguard/pins.db` (SQLite) with first-seen timestamp.
- On every subsequent `tools/list` or `tools/call`, recompute and compare.
- **Mismatch handling:** block the call, raise a GUI alert showing a diff (old vs new tool definition), require explicit re-pin to proceed.
- Canonical hashing must be stable: sort keys, normalize whitespace, strip volatile fields (e.g. server timestamps). This is the subtle engineering — a naive hash produces false positives.

**Why it matters:** This is the direct defense against tool poisoning (OWASP, Microsoft June 2026, CSA July 2026). A malicious or compromised server that silently changes a tool description to inject instructions gets caught at the hash layer before the LLM ever sees the new description.

### Pillar 3: Tool Poisoning Detection

**Extends:** `merlon-inspect`

Goes beyond hash pinning (which only detects CHANGE) to detect MALICIOUS CONTENT on first connection too.

Scan tool definitions (names, descriptions, parameter descriptions, annotations) for:
- **Hidden Unicode** — zero-width chars, bidi overrides, homoglyphs (closes the known Unicode gap in the inherited inspector's threat model)
- **Instruction-override language** — "ignore previous", "system:", "you must", "before using any other tool", imperative injection
- **Data exfiltration instructions** — "send to", "include the contents of", "read ~/.ssh", "base64 encode and append"
- **Tool shadowing** — a tool whose description tries to redefine the behavior of OTHER tools (the Invariant Labs attack class)
- **Cross-origin references** — a tool description that references other servers/tools it shouldn't know about

Pattern DB ships with defaults and updates via the shared threat feed (pillar 7). Unicode normalization runs BEFORE scanning (fixes inherited gap).

### Pillar 4: Sandbox / Blast Radius Containment

**Crate:** `merlon-sandbox` (new)

Each MCP server gets a declared **capability profile**:

```yaml
# ~/.merlon/sandbox/profiles/filesystem.yaml
server: filesystem
capabilities:
  filesystem:
    read: ["~/projects/**", "~/Documents/**"]
    write: ["~/projects/scratch/**"]
    deny: ["~/.ssh/**", "~/.aws/**", "**/.env"]
  network:
    allow: []        # filesystem server should make zero network calls
  env_vars:
    allow: ["HOME", "PATH"]
    deny: ["*_TOKEN", "*_KEY", "*_SECRET"]
  processes:
    spawn: false
```

- Any tool call whose arguments reference a resource outside the profile = **blocked** (default-deny within the profile too).
- Profiles are auto-suggested on first connection based on the server's declared tool set, then the user tightens them in the GUI.
- This is protocol-layer sandboxing (vs obstalabs/bulwark's kernel-level read gate). It cannot stop a server binary from doing arbitrary syscalls, but it CAN stop the agent from instructing it to — which is the actual MCP threat model (a compromised agent chaining tool calls).
- Profiles compose with policy rules; sandbox is evaluated inside the policy stage.

### Pillar 5: Agent Identity / Non-Human Identity

**Extends:** `merlon-auth`

- Each agent (Claude Code, Dismas, Littlebird, a custom script) gets a cryptographic identity: an Ed25519 keypair issued by Forculus.
- Agent presents a signed identity token on connection AND signs each `tools/call` (or a rolling nonce) for per-call revalidation.
- Audit events are attributed to a verified agent identity, not just a session token (which can be replayed — a known gap in the inherited threat model).
- Policy conditions can match on `agent_identity` (e.g. "only the deployment-bot identity may call github delete tools").
- Identity revocation is instant: revoke in GUI, next call fails.
- Closes the inherited gap: "session tokens have no client binding." The signature binds each call to the holder of the private key.

### Pillar 6: Human-in-the-Loop Approval Workflows

**Crate:** `merlon-approve` (new)

- Triggered when policy verdict = `escalate` OR a risk classifier flags the call.
- **Risk classification** is configurable per tool + per argument pattern:
  - High-risk defaults: filesystem writes/deletes, shell exec, payment APIs (Stripe), outbound email/messages, credential tools, anything matching a destructive glob (`delete_*`, `drop_*`, `force_*`, `terminate_*`)
- **Native Tauri/macOS notification** with: agent identity, server, tool, action, a human-readable argument summary, and Approve / Deny.
- Configurable timeout (default 10s -> auto-deny). Timeout action configurable per risk tier.
- Zero external dependency — no Slack, no Teams, no webhook (the Peta differentiator).
- All decisions logged to the audit chain with the approver identity.
- Finally implements the `escalate` verdict that the inherited engine accepts but treats as `allow` (known limitation #10 in fork threat model).

### Pillar 7: Shared Threat Feed

**Crate:** `merlon-threatfeed` (new)

- Community-sourced intelligence: malicious MCP server fingerprints, known poisoning patterns, bad publisher signatures, CVE-tagged tool versions.
- **Opt-in telemetry:** users can share anonymized signals — blocked calls (hashed), suspicious tool-def changes, poisoning-scan hits. Never shares arguments, credentials, or user data.
- Feed auto-updates the poisoning scanner (pillar 3) pattern DB and the provenance verifier (pillar 10) reputation data.
- **Cold-start challenge, not a moat (Council ruling, DBA-8):** a network effect does not exist at zero users. The feed is an *intended* moat; today it is an unproven trust problem. The binding constraint is trust: a credible feed requires a hosting and trust architecture that answers why a stranger would send it telemetry, before it can compound into an advantage.
- Offline mode (pillar 8): feed delivered as signed bundles the user imports manually.
- Architecture: a lightweight server (Railway or a dedicated host — NOT the homelab, which fails the availability expectation) aggregates and signs feed bundles; clients pull or import. The hosting + trust plan must be written before any user-facing telemetry ships.

### Pillar 8: Offline / Air-Gapped Operation

**Extends:** `merlon-config`

- Full governance with zero network dependency. Government, defense, healthcare, regulated environments.
- Threat feed via signed manual bundles. Provenance via local cache. Everything else is already local.
- No telemetry required (telemetry is strictly opt-in, pillar 7).
- This single capability eliminates every cloud gateway (MintMCP, TrueFoundry, Traefik, Azure) from the regulated-industry conversation. Pro/Enterprise tier feature.

### Pillar 9: Cost / Token Awareness

**Extends:** `merlon-ratelimit` (inherited cost tracking) + GUI

- Inherited engine already tracks per-operator cost and enforces monthly budgets. Forculus adds:
  - **Per-agent AND per-server** budgets (not just per-operator)
  - **Real-time GUI dashboard** of spend by agent/server/time window
  - **Both token AND call-count limits** (for David's own stack: Claude Code Bridge, Dismas, Littlebird all share API budgets)
  - **Throttle-then-block** escalation: warn at 80%, throttle at 95%, block at 100%
- Prevents runaway agent credit burn — a real problem for a 25-server solo stack.

### Pillar 10: MCP Server Supply Chain Verification

**Crate:** `merlon-provenance` (new)

- On new server connection, build a **trust card**:
  - Publisher identity + signature (if the server ships one)
  - Registry reputation (from threat feed + public MCP registries)
  - First-seen date, binary/version hash, change history
  - Declared vs observed capability (does it ask for more than it declares?)
- Like an SBOM for MCP servers. Directly addresses the CSA finding: ~8,000 MCP servers exposed with no provenance.
- Strict mode: block servers below a trust threshold until the user explicitly approves.

### Pillar 11: Time-Limited Scoped Credential Vault

**Extends:** `merlon-vault`

- Inherited vault injects credentials per-call (age-encrypted at rest). Forculus upgrades injection:
  - Instead of injecting the raw long-lived API key, issue a **short-lived scoped token** minted per call.
  - Token TTL = call duration + small grace (configurable, e.g. 2 min).
  - Agent and upstream never hold the underlying secret beyond the call window.
  - Where the upstream API supports token exchange (OAuth OBO), use it; where it doesn't, Forculus acts as the token broker and the "scoped token" is a Forculus-issued handle it swaps for the real key at the last millimeter.
- Closes inherited gap: credentials currently sit in process memory between decrypt and inject; scoped tokens shrink the exposure window and remove long-lived secrets from the agent side entirely.

### Pillar 12: Compliance Export Templates

**Extends:** `merlon-audit`

- Inherited audit log is the raw material (blake3 hash chain, rich events).
- Add one-click export templates formatting the chain into:
  - **SOC 2** — access control + change management evidence (who/what/when/verdict per control)
  - **GDPR** — data access records (data category, access basis, data subject if detectable)
  - **HIPAA** — PHI access log (access context, minimum-necessary justification)
  - **EU AI Act** — high-risk system logging (risk tier, human oversight events, the Aug 2026 enforceable provisions)
- Events get tagged with compliance metadata at audit time (pipeline stage 10) so export is a formatting step, not a reconstruction.
- For solo devs / small teams who can't afford a compliance consultant — turns the audit log into audit-ready evidence.

---

## 3. Updated Configuration Schema

```yaml
# merlon.yaml — full Forculus config (extends bulwark.yaml)

# === INHERITED (from fork) ===
proxy:
  listen_address: "127.0.0.1:8080"
  tls:
    ca_dir: "~/.merlon/ca"

policy:
  policies_dir: "./policies"
  hot_reload: true

vault:
  require_sessions: false

audit:
  enabled: true
  db_path: "~/.merlon/audit.db"
  retention_days: 90

inspect:
  enabled: true
  inspect_requests: true
  inspect_responses: true
  max_content_size: 1048576

rate_limit:
  enabled: false
  default_rpm: 60
  default_burst: 10

mcp_gateway:
  listen_address: "127.0.0.1:3000"
  allowed_origins: []

# === NEW (Forculus) ===

# Pillar 1: GUI
gui:
  enabled: true
  port: 0          # 0 = auto-select; Tauri uses its own webview
  theme: "auto"    # auto | light | dark
  onboarding: auto # auto-discover MCP servers from known client configs

# Pillar 2: Tool definition hash pinning
toolguard:
  enabled: true
  pins_db: "~/.merlon/toolguard/pins.db"
  on_mismatch: block   # block | alert | log
  canonical_hash: true # sort keys, normalize whitespace, strip volatile fields

# Pillar 3: Tool poisoning detection
poisoning_scan:
  enabled: true
  scan_on_first_connect: true
  scan_on_definition_change: true
  unicode_normalize: true       # fix inherited gap
  pattern_source: builtin        # builtin | threatfeed | both
  custom_patterns: []

# Pillar 4: Sandbox / blast radius
sandbox:
  enabled: true
  profiles_dir: "~/.merlon/sandbox/profiles"
  auto_suggest: true             # suggest profiles from server's declared tools
  default_deny_outside_profile: true

# Pillar 5: Agent identity
agent_identity:
  enabled: true
  keypair_dir: "~/.merlon/identities"
  per_call_signing: true
  revocation_check: true

# Pillar 6: Approval workflows
approvals:
  enabled: true
  timeout_seconds: 10
  timeout_action: deny           # deny | allow (deny is fail-safe)
  risk_classifier:
    high_risk_tools:
      - "filesystem:write_*"
      - "filesystem:delete_*"
      - "terminal:exec"
      - "stripe:*"
      - "gmail:send"
      - "imessage:send"
      - "*:delete_*"
      - "*:drop_*"
      - "*:force_*"
      - "*:terminate_*"
    high_risk_args:
      - pattern: "~/.ssh/**"
        reason: "SSH key access"
      - pattern: "**/.env"
        reason: "Credential file access"

# Pillar 7: Shared threat feed
threat_feed:
  enabled: false                 # opt-in
  source: auto                   # auto | manual
  server_url: ""                 # Forculus threat feed server (empty = manual only)
  import_path: "~/.merlon/threat-feed/"
  share_telemetry: false         # anonymized blocked-call signals
  update_interval_hours: 6

# Pillar 8: Offline mode
offline_mode: false              # true = no network calls, manual feed import only

# Pillar 9: Cost / token awareness (extends inherited cost_tracking)
cost_tracking:
  enabled: true
  per_agent_budgets: true
  per_server_budgets: true
  throttle_at_percent: 80
  block_at_percent: 100
  default_monthly_budget: 50.00
  agent_budgets: {}
  server_budgets: {}

# Pillar 10: Supply chain verification
provenance:
  enabled: true
  strict_mode: false             # true = block untrusted servers until approved
  cache_dir: "~/.merlon/provenance/"
  trust_threshold: 50            # 0-100 score; below = warn, below 25 = block in strict

# Pillar 11: Scoped credential vault
scoped_tokens:
  enabled: true
  default_ttl_seconds: 120       # 2 min grace after call completes
  token_strategy: prefer_exchange  # prefer_exchange (OBO if available) | broker (Forculus issues handle)
  
# Pillar 12: Compliance export
compliance:
  templates_dir: "~/.merlon/compliance/templates"
  frameworks:
    - soc2
    - gdpr
    - hipaa
    - eu_ai_act
  auto_tag_events: true          # tag audit events with compliance metadata at write time
```

---

## 4. Build Plan — Full 12-Pillar Scope (v1.2, Founder Veto of MVP Cut)

### 4.0 Timeline posture

Forculus is a **background build with no fixed timeline**. Ad Populum owns priority through its Gate 0 deadline (Dec 31, 2026). Forculus gets at most ~1hr/day, and only after Ad Populum's daily work is done. No shippable-by-date claim is made anywhere.

### 4.1 Founder direction (Oct 14 2026)

**FOUNDER VETO of Council revision 1 (DBA-7).** The MVP cut-line is rejected. The point of Forculus is precisely that it is cheap and does SO much so well — all 12 pillars stay in scope. The build ORDER from the Council phases is preserved (it was never the objection), so the highest-risk defenses still land first. Nothing is cut; everything is sequenced.

### 4.2 Phases with hour estimates (all 12 pillars, DBA-12)

All estimates assume 1hr sessions. "Sessions" = working hours, not calendar days.

| Phase | Scope | Est. hours |
|---|---|---|
| F0 Baseline audit | Fork clone, FORK-REPORT.md, crate inventory | DONE |
| F0.5 Build verification | Full `cargo build` + 487-test run on the Mac, fix any env issues | 2-4 |
| F1 Rename & attribution | Rename 12 `bulwark-*` crates -> `merlon-*`, NOTICE + CHANGES.md (Apache-2.0 4(b)), wire `dbalchunas2-pixel/merlon`, re-verify 487 tests | 5-7 |
| F2 Security audit | `cargo audit`, the 1 `unsafe` block, threat-model gap mapping. Second reviewer required — see 4.4 | 3-5 (+reviewer) |
| F3 Tool-def hash pinning (pillar 2) | New crate `merlon-toolguard`: canonical hashing, SQLite pins store, mismatch -> block + alert + diff view | 7-10 |
| F4 Sandbox + Poisoning + Provenance (pillars 3, 4, 10) | `merlon-sandbox` capability profiles (10-14); poisoning scanner in `merlon-inspect` with Unicode normalization (8-12); `merlon-provenance` trust cards (12-16) | 30-42 |
| F5 Agent Identity + Approvals + Scoped Tokens (pillars 5, 6, 11) | Ed25519 identity + per-call signing in `merlon-auth` (12-16); `merlon-approve` risk classifier + native notifications + timeout/deny (8-12); scoped-token issuance in `merlon-vault` (10-14) | 30-42 |
| F6 GUI + Threat Feed + Compliance + Cost + Offline (pillars 1, 7, 8, 9, 12) | Tauri GUI, all surfaces, zero-config onboarding (40-60); `merlon-threatfeed` client/server + signed bundles (15-20); compliance templates in `merlon-audit` (10-14); cost dashboard + budgets (8-12); offline-mode polish (3-5) | 76-111 |
| Dogfood burn-in | Wire David's own 25 servers, run weeks of real traffic, fix what breaks | 5 + passive |
| **FULL VISION TOTAL** | | **158-226 hrs** |

At 1hr/day that is **~8-11 months**. That is the honest price of full scope, stated plainly. Compression levers if wanted later: delegate whole-crate scaffolding to Claude Code Bridge (cuts F4-F6 substantially), and treat GUI polish as iterative.

### 4.3 Dogfood checkpoints (replaces the MVP cut-line)

Since nothing is cut, dogfooding happens along the way instead of at a cut-line:
- **Checkpoint A (after F3):** hash pinning live on David's 25 servers — poisoning defense active.
- **Checkpoint B (after F4):** sandbox + poisoning scan + trust cards active.
- **Checkpoint C (after F5):** full runtime governance — identity, approvals, scoped tokens.
- **Checkpoint D (after F6):** the product — GUI, feed, compliance, cost, offline.

### 4.4 F2 second reviewer (DBA-12)

Named: **Claude Code Bridge performs an independent adversarial review pass of the inherited code** (fresh-context review, not David-authored review of David's work), output filed as `docs/f2-review.md`. At public-repo launch, an additional external/community reviewer is recruited. For a security product, solo review is a process risk; this closes it as far as a solo founder can.

### 4.5 Why this order

Hash pinning first because tool poisoning is the hottest documented threat (OWASP, Microsoft June 2026, CSA July 2026) and it is the simplest high-impact defense. Sandbox, poisoning scan, and provenance form the supply-chain security layer. Identity, approvals, and scoped tokens complete the runtime governance layer. The GUI, threat feed, compliance export, cost dashboard, and offline polish are the product surface — built last because the engine must be real before the surface exists, and CLI-mode dogfooding at Checkpoints A-C proves the engine all along the way. The inherited `escalate`-treated-as-`allow` limitation (fork threat model, limitation #10) is closed by F5, not left open.

### 4.6 Structured Timeline (dated Oct 14 2026)

**Assumptions:** first session Mon Oct 19, 2026. **4 sessions/wk Oct 19 - Dec 31** (Ad Populum Gate 0 owns priority; Forculus gets evenings after Ad Populum work is done). **5 sessions/wk from Jan 1, 2027** (post-Gate 0). School-year evening sessions throughout.

| Window | Work | Cumulative sessions |
|---|---|---|
| Oct 19 - Nov 6 | F0.5 build verify + F1 rename & attribution | 7-11 |
| Nov 1 - Nov 14 | F2 security audit (Claude Code Bridge review pass runs in parallel) | 10-16 |
| **Checkpoint A: Nov 16 - Dec 1** | **Hash pinning live on the 25-server stack** | 17-26 |
| Dec 1 - Dec 31 | F4 underway (sandbox first); Forculus holds at 4/wk through the Gate 0 crunch — the optional throttle to 3/wk costs ~1-2 wks downstream, not baked in | ~26-42 |
| **Checkpoint B: Jan 5 - Feb 3** | **Sandbox + poisoning scan + trust cards active** | 47-68 |
| Feb 3 - Feb 16 | F5 begins (agent identity first) | — |
| **Checkpoint C: Feb 16 - Apr 2** | **Full runtime governance: identity, approvals, scoped tokens** | 77-110 |
| Apr 2 - Jun 9 | F6: Tauri GUI build-out (largest block, 40-60 hrs) | — |
| **Checkpoint D: Jun 9 - Sep 13** | **The product: GUI, threat feed, compliance export, cost dashboard, offline** — lands around graduation (June 2027) | 158-226 |

**Reading the ranges:** the left edge of each window assumes minimum-hour phases; the right edge assumes maximum-hour phases. Every checkpoint is a real dogfood milestone — if a checkpoint slips past its window by more than ~2 weeks, that is the signal to delegate crate scaffolding to Claude Code Bridge rather than let the timeline drift.

**Hard external anchors:** Ad Populum Gate 0 = Dec 31, 2026 (owns December priority). High school graduation = June 2027 (Checkpoint D is designed to land at/after it, not before). LLC + E&O formation (G2 gate) has no Forculus timeline dependency for private dogfooding but blocks Checkpoint D from ever being public.

---

## 5. Competitive Position Summary

| Capability | Forculus | MintMCP | Peta | TrueFoundry | Bulwark OSS | Aembit |
|---|---|---|---|---|---|---|
| Desktop GUI, zero infra | YES | No | No | No | No | No |
| Offline / air-gapped | YES | No | No | No | YES | No |
| Tool-def hash pinning | YES | No | No | No | No | No |
| Tool poisoning scan | YES | No | No | No | No | No |
| Per-server sandbox | YES | Rules | Policy | No | No | No |
| Agent crypto identity | YES | Agent ID | No | No | No | YES |
| Desktop approvals | YES | Slack/Teams | Slack/Teams | No | No | No |
| Shared threat feed | YES | No | No | No | No | No |
| Cost budget enforcement | YES | Track | No | No | No | No |
| Supply chain verification | YES | Curation | No | No | No | No |
| Scoped token vault | YES | No | YES (vault) | No | No | No |
| Compliance templates | YES | SOC2 audit | No | No | No | No |
| Price | Lifetime license | Ent SaaS | Ent SaaS | Ent SaaS | Free | Ent SaaS |

**One-sentence pitch:** Forculus is the only MCP security tool that a single developer can install in 5 minutes, run entirely on their own machine, and get tool-poisoning defense, credential vaulting, blast-radius containment, and audit trails — without routing a single MCP call through someone else's cloud.

**Language rule (Council ruling, DBA-10):** never claim 'enterprise-grade' anywhere user-facing. The inherited fork ships 12 known limitations with HIGH residual risks; the phrase would erode developer trust the first time a limitation is discovered. Describe what the product does, not a grade it has not earned.

---

## 6. Open Questions

1. **Threat feed server hosting** — David's homelab? Railway? Separate domain? Needs to survive if homelab goes down.
2. **Tauri cross-platform** — macOS first (David's Mac), but Windows/Linux for market? Tauri supports all three natively.
3. **Lifetime license pricing** — what number? Needs to be high enough to signal value, low enough for solo devs. $49? $99? $149?
4. **Free tier scope** — when Forculus goes free post-Ad Populum, what stays paid (Pro/Enterprise)? Likely: offline mode, compliance templates, team sync.
5. **Threat feed privacy** — what exactly gets shared in opt-in telemetry? Need to be crystal clear in the UI. Blocked-call hashes + poisoning-scan hits only; never arguments, credentials, or user data.
6. **Ad Populum crate sharing** — the policy engine + audit writer are the shared crate. Does Ad Populum consume the Rust crate directly, or via a protocol? Needs an ADR.
7. **Pricing hypothesis (DBA-11)** — working hypothesis: **100 lifetime founder licenses at $99 = $9,900** conversion floor. If fewer than ~100 are sellable at $99, the paid tier is not viable as a solo product and Forculus stays a dogfood tool + free funnel for Ad Populum. TAM for MCP security tooling is unproven and treated as an estimate, not a fact.
8. **Free tier scope post-Ad Populum** — likely paid keepers: offline mode, compliance templates, team sync. Decide when the MVP is dogfooded.

---

## 7. Legal Gates (Council ruling, DBA-9)

Liability attaches at repo visibility and third-party use, NOT at sale — and NOT at private self-dogfooding. Therefore:

| Gate | Requirement | Status |
|---|---|---|
| G1 | Private self-dogfood on David's own credentials + private repo | ALLOWED NOW |
| G2 | Public repo (`dbalchunas2-pixel/merlon` -> public) | BLOCKED until: LLC formed + E&O/liability insurance quoted (or declined deliberately, documented) + ToS/Privacy/disclaimers drafted |
| G3 | Any paid tier | BLOCKED until G2 satisfied |
| G4 | Any external communication on counsel/insurance engagement | Requires David's explicit per-message approval |

Rationale: Forculus handles high-value secrets (API keys) for other people the moment the repo is public. The Apache-2.0 license does not waive tort liability for a security product that fails to secure. Full checklist: docs/LEGAL-GATES.md.

Pre-build scaffolding (identity, release engineering, key inventory, telemetry/license ADRs, repo hygiene): docs/SCAFFOLDING.md.
