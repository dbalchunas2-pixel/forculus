# Threat Model

This document describes the threats Forculus is designed to defend against, the mitigations it provides today, and the limitations operators should be aware of when deploying it.

## Trust Boundaries

Forculus defines three trust zones separated by two enforcement boundaries.

```
 Untrusted            Enforcement Boundary 1           Trusted (config only)          Enforcement Boundary 2            Untrusted
┌──────────┐         ┌──────────────────────────────────────────────────────┐         ┌──────────────────┐
│  Agent   │ ──────> │                   Forculus Gateway                    │ ──────> │  Upstream Tool   │
│          │ <────── │  (proxy, policy, vault, inspect, audit, ratelimit)   │ <────── │                  │
└──────────┘         └──────────────────────────────────────────────────────┘         └──────────────────┘
```

| Component | Trust Level | Rationale |
|-----------|-------------|-----------|
| Operator (human) | **Trusted** | Creates sessions, writes policies, manages credentials. All actions are audited. |
| Configuration files | **Trusted** | Policies, bindings, and inspector rules are authored by the operator and read from the local filesystem. |
| Forculus process | **Trusted** | Assumed to run on infrastructure the operator controls. Compromise of the process is out of scope for runtime mitigations. |
| Agent (AI system) | **Untrusted** | May be compromised, buggy, or intentionally malicious. Must authenticate with a session token. Every request is evaluated. |
| Upstream tool / API | **Untrusted** | May return malicious payloads, leak data, or be compromised. Responses are inspected before being returned to the agent. |

### What crosses each boundary

| Boundary | Inbound Data | Outbound Data |
|----------|-------------|---------------|
| Agent to Forculus | HTTP request or JSON-RPC message, session token, tool name header | HTTP response or JSON-RPC result (potentially redacted) |
| Forculus to Upstream | Forwarded request with injected credentials | Upstream response (raw) |

## Threat Actors

| Actor | Motivation | Capabilities |
|-------|-----------|--------------|
| **Malicious agent** | Exfiltrate credentials, access unauthorized tools, bypass policies | Crafts arbitrary HTTP requests or JSON-RPC messages; controls all content sent to Forculus |
| **Compromised upstream tool** | Steal injected credentials from requests, inject malicious content into responses | Controls response bodies, headers, and timing |
| **Insider (rogue operator)** | Abuse privileged access to extract credentials or tamper with audit trail | Has filesystem access, can read config files and databases |
| **Network attacker** | Intercept credentials in transit, session hijack | Can observe or modify traffic between agent and Forculus if TLS is not used or CA is compromised |
| **Supply-chain attacker** | Inject malicious code via dependencies | Compromises a crate in the dependency tree at build time |

## Attack Surfaces

### 1. Session Token Theft and Replay

**Threat**: An attacker obtains a valid `fcl_sess_` token and replays it to impersonate the associated operator.

**How tokens work today**:
- Format: `fcl_sess_` + 32 random hex characters (128 bits of entropy)
- Stored as keyed blake3 hashes in SQLite (never stored in plaintext after creation)
- Passed via `X-Forculus-Session` header (HTTP) or `initialize` params (MCP)

| Attack Vector | Mitigation | Residual Risk |
|--------------|------------|---------------|
| Token leaked in agent logs or environment variables | Operator responsibility to handle tokens securely | Forculus cannot control how agents store tokens |
| Token intercepted on the network (agent to Forculus) | HTTP proxy mode uses plaintext by default for the agent-to-proxy hop; HTTPS CONNECT uses TLS MITM | Agent-to-proxy hop is **not encrypted** unless the agent connects via HTTPS CONNECT |
| Token brute-force | 128-bit entropy makes brute-force infeasible; keyed blake3 hashing in the session store | None |
| Stolen token reused after session expiry | Sessions have configurable TTL; expired sessions are rejected on validation | Tokens are valid until TTL expires; no per-request nonce or binding to client identity |

### 2. Policy Bypass

**Threat**: An agent circumvents policy rules to access tools or actions it should not.

| Attack Vector | Mitigation | Residual Risk |
|--------------|------------|---------------|
| Glob pattern edge cases (e.g., `github:*` not matching `github::nested:tool`) | Glob patterns are compiled to regex with well-defined semantics; case-insensitive matching | Complex glob patterns may not cover all tool naming conventions; operators must test policies |
| Race condition during hot-reload | `ArcSwap` provides atomic pointer swap; in-flight evaluations complete against the old policy, new requests see the new policy | A brief window exists where a request may be evaluated against a policy that is about to be replaced; this is by design (no request is ever evaluated against a partially loaded policy) |
| Missing tool name header | Default-deny when no rules match; missing `X-Tool-Name` means no rules match, so the request is denied | Agents that omit `X-Tool-Name` are blocked but also cannot receive credential injection |
| Scope/priority confusion | Precedence is deterministic: scope > priority > deny-beats-allow > load-order | Policy misconfiguration by the operator can create unintended gaps |
| Override scope abuse | Override policies require filesystem access (operator-level trust) | If the operator's filesystem is compromised, policies can be overwritten |

### 3. Credential Exfiltration

**Threat**: An attacker extracts decrypted credential material from memory, disk, or network traffic.

| Attack Vector | Mitigation | Residual Risk |
|--------------|------------|---------------|
| Reading `.age` files from disk | Credentials are encrypted with age; attacker needs the age private key to decrypt | If the age identity key is on the same filesystem, disk compromise exposes both |
| Memory scraping of the Forculus process | Credentials use `SecretString` (from the `secrecy` crate) which attempts to zeroize on drop | Rust does not guarantee zeroization; the compiler or OS may copy secret bytes to other memory locations (stack spills, page swaps) |
| Credential in transit (Forculus to upstream) | Forculus re-establishes TLS to upstream endpoints and validates server certificates | Credentials are present in plaintext in the Forculus process memory between decryption and injection |
| Agent inspecting injected credentials in upstream responses | Content inspector scans responses for secret patterns (API keys, tokens) and can redact before returning to agent | Response scanning is regex-based and may miss obfuscated or novel credential formats |
| Side-channel timing attacks on credential decryption | age decryption happens on every injection (or cached after first use depending on config) | No constant-time guarantees on the credential lookup path; cache hit/miss may be observable |
| Credential binding bypass (agent requests wrong tool to get a credential injected into a request it controls) | Bindings use glob matching against the tool name; scope constraints restrict which operators can use which credentials | If tool name extraction is manipulable (e.g., agent sets `X-Tool-Name` to a tool that has credentials bound), credentials could be injected into attacker-controlled requests |

### 4. Content Inspection Evasion

**Threat**: An agent or upstream tool crafts content to evade secret/PII detection.

| Attack Vector | Mitigation | Residual Risk |
|--------------|------------|---------------|
| Base64 or other encoding of secrets | Built-in `base64-secret` pattern detects common encoded secrets | Double-encoding, custom encodings, or compression will evade detection |
| Unicode homoglyphs (e.g., replacing ASCII `A` in `AKIA` with Cyrillic `A`) | Not currently mitigated | **Known gap**: Unicode normalization is not performed before scanning |
| Chunked transfer encoding / streaming | Content is inspected as a whole body after reassembly | Very large bodies may be truncated at `max_body_size`; content split across multiple requests is not correlated |
| Splitting secrets across JSON fields | JSON scanner traverses all values recursively | Secrets split across multiple fields (e.g., first half in field A, second half in field B) will not be detected |
| Novel secret formats | 13 built-in patterns cover common providers; custom patterns can be added | Zero-day credential formats or proprietary tokens may not match any built-in rule |
| Prompt injection via indirect means | Built-in `prompt-injection` pattern detects common phrasing | Adversarial prompt injection is an open research problem; regex-based detection has fundamental limits |

### 5. Audit Log Tampering

**Threat**: An attacker modifies or deletes audit records to cover their tracks.

| Attack Vector | Mitigation | Residual Risk |
|--------------|------------|---------------|
| Direct modification of `audit.db` | blake3 hash chain links each event to its predecessor; any modification breaks the chain and is detectable via `forculus audit verify` | Tamper-**evident**, not tamper-**proof**: an attacker with filesystem access can recompute the entire chain after modification |
| Deleting the audit database | Operator should restrict filesystem permissions on `audit.db` | No built-in replication or remote backup; if the file is deleted before export, events are lost |
| Inserting false events | Events are appended by the Forculus process; insertion requires process-level access | If the Forculus process is compromised, false events can be injected with valid hashes |
| Truncating old events via retention policy | Retention is operator-configured; critical events can have longer retention | Retention cleanup removes events permanently; no soft-delete or archival mechanism |

### 6. TLS MITM CA Key Compromise

**Threat**: The Forculus CA private key (`ca-key.pem`) is stolen, allowing an attacker to impersonate any HTTPS endpoint to the agent.

| Attack Vector | Mitigation | Residual Risk |
|--------------|------------|---------------|
| Reading `ca-key.pem` from disk | Generated with ECDSA P-256; file should be permission-restricted by the operator | **Forculus does not enforce file permissions on the CA key**; it is the operator's responsibility |
| Using a compromised CA to MITM traffic outside Forculus | The CA is only trusted by agents explicitly configured to use it | If agents trust the CA system-wide, any process on the network could use the stolen key to MITM their traffic |
| Ephemeral leaf certificate forgery | Leaf certs are cached in an in-memory LRU cache (capacity 1000); no persistence | Cache is process-scoped; compromise requires process memory access |

### 7. Rate Limit Bypass

**Threat**: An agent circumvents rate limits to overwhelm upstream tools or exhaust budgets.

| Attack Vector | Mitigation | Residual Risk |
|--------------|------------|---------------|
| Session rotation (creating many sessions to get fresh rate-limit buckets) | Per-operator and global rate limits apply regardless of session; session creation is an operator-level action | If an attacker can create sessions (compromised operator credentials), they can multiply per-session limits |
| Distributed agents sharing a single operator identity | Per-operator limits cap aggregate traffic; per-session limits cap each instance | Operator-level limits may be set too high for the downstream API; operators must align limits with upstream quotas |
| Clock manipulation to accelerate token bucket refill | Token buckets use `std::time::Instant` (monotonic clock) | On systems where monotonic clock is unreliable (rare), refill timing could be skewed |
| Exploiting tool name variations to avoid per-tool limits | Tool names are extracted from `X-Tool-Name` header or MCP method; no normalization beyond what the agent provides | Agent can vary tool name casing or formatting to potentially create separate rate-limit buckets (glob matching is case-insensitive, but bucket keys may not normalize) |

### 8. MCP Protocol-Level Attacks

**Threat**: Attacks exploiting the JSON-RPC / MCP protocol layer between agent and Forculus or Forculus and the upstream MCP server.

| Attack Vector | Mitigation | Residual Risk |
|--------------|------------|---------------|
| Malformed JSON-RPC payloads | Forculus parses JSON-RPC strictly; malformed messages are rejected | Parser bugs in `serde_json` could theoretically be exploited, though this is unlikely given the crate's maturity |
| Method name spoofing (calling `tools/call` with a tool name that maps to a different tool) | Policy evaluation uses the tool name from the parsed `tools/call` params, not a separate header | No secondary verification that the MCP server actually implements the claimed tool |
| Notification flooding (JSON-RPC notifications do not require responses) | Notifications are logged but not forwarded to upstream by default | Large volumes of notifications could consume audit log storage |
| Injecting extra fields in JSON-RPC params to manipulate upstream server behavior | Forculus forwards params as-is after policy check and credential injection | Forculus does not validate or sanitize individual tool parameters beyond content inspection |
| Response manipulation by compromised MCP server | Content inspector scans MCP responses | MCP stdio transport has no authentication or integrity checking between Forculus and the upstream server |

## Known Limitations

The following are honest assessments of what Forculus does **not** protect against today.

1. **No encryption of agent-to-proxy traffic in HTTP mode**. The `X-Forculus-Session` header is sent in plaintext when the agent uses `http://` to reach the proxy. Only HTTPS CONNECT requests benefit from TLS.

2. **No client authentication beyond session tokens**. There is no mutual TLS, IP allowlisting, or cryptographic client binding. Any process that knows the session token can make requests.

3. **No hardware-backed key storage**. The CA private key and age identity keys are stored as PEM files on disk. There is no HSM, TPM, or secure enclave integration.

4. **No distributed audit replication**. The audit log is a local SQLite file. If the host is compromised, the attacker can destroy or rewrite the log. There is no streaming to a remote append-only store.

5. **No Unicode normalization in content inspection**. Homoglyph attacks and alternative encodings can evade regex-based detection patterns.

6. **No cross-request correlation**. Content inspection operates on individual requests and responses. Secrets split across multiple requests, or exfiltrated incrementally over time, will not be detected.

7. **Session tokens have no client binding**. A stolen token can be used from any network location until it expires. There is no IP pinning, user-agent binding, or device fingerprinting.

8. **`ca-key.pem` permissions are not enforced**. Forculus does not check or set filesystem permissions on the CA private key. Operators must do this manually.

9. **No request/response body storage**. The audit log stores blake3 hashes of request and response bodies, not the bodies themselves. Forensic reconstruction of what was actually sent or received is not possible from the audit log alone.

10. **`transform` verdict is not fully implemented**. The policy engine accepts `transform` as a verdict but currently treats it as `allow`. Request transformation logic is not yet in place.

11. **Rate-limit buckets are in-memory only**. If the Forculus process restarts, all rate-limit state is lost and buckets reset to full capacity.

12. **No credential rotation automation**. Credential rotation is a manual CLI operation. There is no automatic rotation, grace period, or dual-credential overlap.

## Recommendations for Operators

### Network and Transport

- **Run Forculus on localhost or a private network**. The agent-to-proxy hop is not encrypted in HTTP mode. Do not expose the proxy port to untrusted networks.
- **Restrict `ca-key.pem` permissions** to `0600` owned by the Forculus process user. Audit access to this file.
- **Use HTTPS CONNECT** for all agent traffic where possible, so the session token is transmitted inside the TLS tunnel.
- **Rotate the CA key periodically** and re-distribute the new `ca.pem` to agents.

### Session Management

- **Set short TTLs** on sessions (hours, not days) and create new sessions for each agent run.
- **Revoke sessions immediately** when an agent is decommissioned or an operator's access is removed.
- **Monitor session creation events** in the audit log for unexpected or bulk session creation.

### Policy Configuration

- **Test policies in a staging environment** before deploying to production. Use `forculus audit query` to verify that the expected verdicts are being produced.
- **Prefer explicit allow-lists** over broad globs. A rule matching `tools: ["*"]` should be rare and well-justified.
- **Review override-scope policies regularly**. These bypass all other rules and should be time-limited.
- **Version-control all policy files** and require code review for changes.

### Credential Security

- **Store age identity keys separately** from the credential vault. Ideally on a different host or in a secrets manager.
- **Audit `CredentialInjected` events** weekly to verify credentials are only used by expected tools and operators.
- **Rotate credentials every 90 days** or immediately after any suspected compromise.
- **Minimize credential bindings**: bind each credential to the narrowest possible tool glob and operator set.

### Audit and Monitoring

- **Run `forculus audit verify`** on a schedule (daily or on each startup) to detect hash chain breaks.
- **Export audit logs** to a remote, append-only store (S3 with Object Lock, a SIEM, or similar). The local SQLite database should not be the only copy.
- **Alert on anomalous events**: `ContentInspectionTriggered` with Critical severity, `RateLimitExceeded` spikes, and unexpected `PolicyDecision` denials.
- **Restrict filesystem access** to `audit.db` and `sessions.db` to the Forculus process user only.

### Content Inspection

- **Enable response scanning** (`scan_responses: true`) to catch credential leaks from upstream tools.
- **Add custom patterns** for organization-specific secrets (internal API keys, proprietary token formats).
- **Set `max_body_size` appropriately**. Scanning is truncated beyond this limit; large payloads may contain unscanned sensitive data.
- **Layer content inspection with policy rules**. Use policies to block access to dangerous tools, and content inspection as a second line of defense.

### Deployment Hardening

- **Run Forculus as a dedicated, unprivileged user** with minimal filesystem access.
- **Use process isolation** (containers, VMs, or sandboxing) to limit the impact of a Forculus process compromise.
- **Pin dependency versions** and audit the supply chain with `cargo audit` and `cargo deny`.
- **Enable Rust's hardening flags** in production builds (`-C overflow-checks=yes`, panic=abort).
- **Monitor Forculus process memory usage** to detect potential denial-of-service via large payloads or cache exhaustion.

## Summary Table

| Threat | Severity | Mitigated | Residual Risk Level |
|--------|----------|-----------|-------------------|
| Session token replay | High | Partial | Medium (no client binding) |
| Policy bypass via glob edge cases | Medium | Yes | Low (default-deny covers gaps) |
| Policy race on hot-reload | Low | Yes | Negligible (atomic swap) |
| Credential exfiltration from disk | High | Yes (age encryption) | Medium (key co-location) |
| Credential exfiltration from memory | High | Partial (SecretString) | Medium (no guaranteed zeroization) |
| Content inspection evasion | Medium | Partial (13 built-in rules) | Medium (encoding, unicode, chunking) |
| Audit log tampering | High | Partial (hash chain) | Medium (no remote replication) |
| CA key compromise | Critical | Partial (ephemeral leaf certs) | High (PEM on disk, no HSM) |
| Rate limit bypass via session rotation | Medium | Partial (per-operator limits) | Low (operator limits are session-independent) |
| MCP protocol injection | Medium | Partial (strict parsing) | Medium (no param-level validation) |
| Prompt injection | High | Partial (regex detection) | High (open research problem) |
| Supply-chain compromise | High | External (`cargo audit`) | Medium (large dependency tree) |
