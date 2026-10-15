# Architecture Overview

Forculus is a governance layer that sits between AI agents and their tools, enforcing policies, managing credentials, inspecting content, and maintaining an immutable audit trail. This document explains how Forculus works under the hood.

## The Governance Pipeline

Every request flows through a multi-stage pipeline. Each stage can allow, deny, or modify the request before it reaches the upstream tool.

```
┌─────────────┐
│   Agent     │
│  (Untrusted)│
└──────┬──────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│                     Forculus Gateway                          │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ 1. Session Validation                                 │  │
│  │    ├─ Verify X-Forculus-Session header or init params │  │
│  │    ├─ Load operator identity from session store      │  │
│  │    └─ Reject if invalid/revoked                      │  │
│  └──────────────────────────────────────────────────────┘  │
│                          ▼                                   │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ 2. Tool Mapping                                       │  │
│  │    ├─ Extract tool name from X-Tool-Name or method   │  │
│  │    ├─ Normalize to canonical form                    │  │
│  │    └─ Look up credential bindings for this tool      │  │
│  └──────────────────────────────────────────────────────┘  │
│                          ▼                                   │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ 3. Rate Limiting                                      │  │
│  │    ├─ Check token buckets (session/operator/tool)    │  │
│  │    ├─ Consume tokens if available                    │  │
│  │    └─ Reject with 429 if rate exceeded               │  │
│  └──────────────────────────────────────────────────────┘  │
│                          ▼                                   │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ 4. Content Inspection (Request)                       │  │
│  │    ├─ Scan for secrets (API keys, tokens, etc.)      │  │
│  │    ├─ Scan for PII (emails, SSNs, credit cards)      │  │
│  │    ├─ Detect prompt injection attempts               │  │
│  │    └─ Redact or block based on config                │  │
│  └──────────────────────────────────────────────────────┘  │
│                          ▼                                   │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ 5. Policy Evaluation                                  │  │
│  │    ├─ Load policies from ArcSwap (lock-free)         │  │
│  │    ├─ Match tool/action/resource against rules       │  │
│  │    ├─ Check conditions (teams, env, labels)          │  │
│  │    ├─ Apply precedence (scope > priority > deny)     │  │
│  │    └─ Return allow/deny/escalate verdict             │  │
│  └──────────────────────────────────────────────────────┘  │
│                          ▼                                   │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ 6. Credential Injection                               │  │
│  │    ├─ If credential binding exists for this tool     │  │
│  │    ├─ Decrypt credential from age-encrypted file     │  │
│  │    └─ Inject via HTTP header or JSON-RPC param       │  │
│  └──────────────────────────────────────────────────────┘  │
│                          ▼                                   │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ 7. Forward to Upstream                                │  │
│  │    ├─ HTTP Proxy: Forward HTTP/HTTPS request         │  │
│  │    └─ MCP Gateway: Invoke real MCP server via stdio  │  │
│  └──────────────────────────────────────────────────────┘  │
│                          ▼                                   │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ 8. Content Inspection (Response)                      │  │
│  │    ├─ Scan response for secrets/PII                  │  │
│  │    └─ Redact based on config                         │  │
│  └──────────────────────────────────────────────────────┘  │
│                          ▼                                   │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ 9. Cost Recording                                     │  │
│  │    ├─ Extract cost metadata from response            │  │
│  │    ├─ Update per-operator cost totals                │  │
│  │    └─ Check budget limits                            │  │
│  └──────────────────────────────────────────────────────┘  │
│                          ▼                                   │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ 10. Audit Logging                                     │  │
│  │    ├─ Record event to SQLite (timestamp, session,    │  │
│  │    │  operator, tool, verdict, req/resp hashes)      │  │
│  │    └─ Link to previous event via blake3 hash chain   │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
       │
       ▼
┌──────────────┐
│  Upstream    │
│  Tool        │
│ (Untrusted)  │
└──────────────┘
```

### Pipeline Characteristics

- **Fail-closed**: If any stage fails, the request is blocked
- **Tamper-evident**: Every decision is logged with cryptographic hash chains
- **Hot-reloadable**: Policies can be updated without restarting the proxy
- **Zero-trust**: Both agent and upstream are untrusted; only operator and config are trusted

## Integration Modes

Forculus supports two integration modes, depending on whether your agent uses MCP (JSON-RPC over stdio) or HTTP.

### Mode 1: MCP Gateway

In MCP mode, Forculus acts as a transparent gateway between an MCP client (the agent) and an MCP server (the real tool provider).

```
┌─────────────┐                  ┌──────────────┐                  ┌─────────────┐
│ MCP Client  │                  │   Forculus    │                  │ MCP Server  │
│  (Agent)    │ <─── stdio ───> │  MCP Gateway │ <─── stdio ───> │   (Tools)   │
└─────────────┘                  └──────────────┘                  └─────────────┘
   JSON-RPC                        Intercept &                       JSON-RPC
   requests                        govern                            responses
```

**How it works**:

1. Agent sends JSON-RPC request via stdin (e.g., `tools/call` method)
2. Forculus parses the request and extracts the tool name from the method
3. Pipeline executes: session validation, policy check, content inspection, etc.
4. If allowed, Forculus forwards the request to the real MCP server via stdio
5. MCP server responds via stdout
6. Forculus logs the event and returns the response to the agent

**Session handling**:

- Session token passed in `initialize` params: `{"session_token": "fcl_sess_..."}`
- Stored in interior mutable state (`parking_lot::Mutex<Option<String>>`)
- Validated on every `tools/call` request

**Best for**: Claude Desktop, Cline, Zed, or any MCP-compatible agent

### Mode 2: HTTP Forward Proxy

In HTTP proxy mode, Forculus acts as a forward proxy that intercepts HTTP and HTTPS requests.

```
┌─────────────┐                  ┌──────────────┐                  ┌─────────────┐
│   Agent     │                  │   Forculus    │                  │  Upstream   │
│ (HTTP/S)    │ ───── HTTP ────> │  HTTP Proxy  │ ───── HTTP ────> │  API/Tool   │
└─────────────┘                  └──────────────┘                  └─────────────┘
   HTTP: direct                   MITM with TLS                     HTTP/HTTPS
   HTTPS: CONNECT tunnel          termination                       requests
```

**How it works**:

1. Agent configures HTTP proxy: `http://localhost:8080`
2. For HTTP requests: Agent sends `GET/POST http://example.com` directly to Forculus
3. For HTTPS requests: Agent sends `CONNECT example.com:443`, Forculus performs TLS MITM
4. Forculus extracts tool name from `X-Tool-Name` header
5. Pipeline executes (same as MCP mode)
6. If allowed, Forculus forwards request to upstream and returns response

**Session handling**:

- Session token passed in every request: `X-Forculus-Session: fcl_sess_...`
- Validated against SQLite session store

**TLS MITM**:

- Forculus generates a root CA on first run (`ca-cert.pem`, `ca-key.pem`)
- Agent must trust this CA
- For each HTTPS host, Forculus signs ephemeral certificates on-the-fly
- Uses `rustls` with `aws_lc_rs` backend (FIPS-compatible crypto)

**Best for**: HTTP-based agents, curl scripts, Python requests, or custom agents

## Subsystem Overview

Forculus is a Rust workspace with 10 crates. Here's what each subsystem does.

### Policy Engine (`crates/policy`)

The policy engine evaluates YAML policies to decide if a request should be allowed, denied, or escalated.

**Key features**:
- **Lock-free hot-reload**: Policies stored in `ArcSwap<PolicyEngine>` for zero-lock reads
- **Glob matching**: Tool patterns like `filesystem:*` or `api:{get,post}` compiled to regex
- **Scope precedence**: Override > Project > Team > Agent > Global
- **Conditions**: Rules can match on operator, team, environment, agent type, or custom labels
- **Default-deny**: If no rules match, verdict is deny

**Data structures**:
- `Policy`: Metadata + list of rules
- `Rule`: Name, verdict, match criteria, conditions, priority
- `PolicyEngine`: Map of scope → policies, pre-sorted by priority

**Evaluated on**: Every request in pipeline stage 5

### Credential Vault (`crates/vault`)

The vault manages encrypted credentials and injects them into requests.

**Key features**:
- **age encryption**: Each credential stored as `.age` file (encrypted) + `.meta.json` (metadata)
- **Recipient-based access**: Each credential encrypted to one or more age recipients (public keys)
- **Session-scoped binding**: Credentials bound to specific tools, with scope constraints (Global, Agent, Team, Project)
- **Automatic injection**: Credentials injected via HTTP header (`Authorization: Bearer ...`) or JSON-RPC param

**Data structures**:
- `Vault`: Map of credential name → encrypted file path
- `CredentialBinding`: Mapping of tool glob → credential name with scope constraints
- `SessionStore`: SQLite database of session token → operator identity

**Storage**:
- Credentials: `credentials/<name>.age` and `credentials/<name>.meta.json`
- Bindings: `credentials/bindings.yaml`
- Sessions: `sessions.db` (SQLite)

**Accessed by**: Pipeline stages 1 (session), 2 (mapping), and 6 (injection)

### Audit Log (`crates/audit`)

The audit log records every governed request in a tamper-evident chain.

**Key features**:
- **SQLite storage**: Events stored in `audit.db` with indexed columns
- **Hash chain**: Each event includes blake3 hash of previous event, forming an immutable chain
- **Rich metadata**: Timestamp, session ID, operator, tool, verdict, request/response hashes, cost
- **Query API**: Filter by operator, tool, verdict, time range

**Data structures**:
- `AuditEvent`: Timestamp, session, operator, tool, verdict, hashes, previous hash
- `AuditStore`: SQLite connection with prepared statements

**Schema**:
```sql
CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY,
  timestamp TEXT NOT NULL,
  session_id TEXT NOT NULL,
  operator TEXT NOT NULL,
  tool TEXT NOT NULL,
  verdict TEXT NOT NULL,
  request_hash TEXT,
  response_hash TEXT,
  cost REAL,
  prev_hash TEXT NOT NULL,
  event_hash TEXT NOT NULL
);
```

**Written by**: Pipeline stage 10 (every request)

### Content Inspection (`crates/inspect`)

The content inspector scans requests and responses for sensitive data and malicious patterns.

**Key features**:
- **13 built-in rules**: API keys, AWS keys, SSH keys, JWTs, credit cards, SSNs, emails, phone numbers, IP addresses, URLs, prompt injection, SQL injection, path traversal
- **Regex-based detection**: Fast pattern matching with pre-compiled regexes
- **Redaction modes**: Block request, redact content, or log only
- **Bidirectional**: Scans both request (before forwarding) and response (before returning to agent)

**Data structures**:
- `InspectionRule`: Rule ID, pattern (regex), severity, action (block/redact/log)
- `Inspector`: Pre-compiled rules, configurable severity thresholds
- `InspectionResult`: List of findings (rule ID, matched text, location)

**Invoked by**: Pipeline stages 4 (request) and 8 (response)

### Rate Limiting (`crates/ratelimit`)

The rate limiter enforces token-bucket rate limits to prevent abuse.

**Key features**:
- **Multi-level limits**: Per-session, per-operator, per-tool, and global
- **Token bucket algorithm**: Configurable capacity and refill rate
- **In-memory state**: Buckets stored in `HashMap` with periodic refill
- **Graceful degradation**: If rate limit hit, returns 429 Too Many Requests

**Data structures**:
- `TokenBucket`: Capacity, tokens, refill rate, last refill time
- `RateLimiter`: Map of (session/operator/tool) → bucket

**Configuration example**:
```yaml
rate_limits:
  per_session: {capacity: 100, refill_per_second: 10}
  per_operator: {capacity: 1000, refill_per_second: 100}
  per_tool: {capacity: 50, refill_per_second: 5}
  global: {capacity: 10000, refill_per_second: 1000}
```

**Invoked by**: Pipeline stage 3

## Trust Model

Forculus implements a zero-trust architecture where only the operator and configuration files are trusted.

### Trusted Components

1. **Operator**: The human or system that creates sessions and writes policies
   - Identity verified via session tokens
   - All actions logged to audit trail

2. **Configuration files**: YAML policies, credential bindings, inspector rules
   - Managed by operator
   - Validated on load (syntax, schema, conflicts)
   - Hot-reloadable without restart

### Untrusted Components

1. **Agent**: The AI system making requests
   - May be compromised, malicious, or buggy
   - Must authenticate with session token
   - Every request evaluated against policies
   - Cannot access credentials directly (only injected by vault)

2. **Upstream tools**: External APIs, services, tools
   - May return malicious or sensitive data
   - Responses scanned by content inspector
   - Response hashes logged to audit trail

### Security Guarantees

- **Confidentiality**: Credentials encrypted at rest (age) and in transit (TLS)
- **Integrity**: Audit log tamper-evident via hash chains
- **Availability**: Rate limiting prevents resource exhaustion
- **Accountability**: Every action attributed to an operator via session
- **Least privilege**: Policies enforce fine-grained access control

## Data Flow

Understanding what data goes where is critical for operating Forculus.

### Persistent Storage (Disk)

| Data | Location | Format | Encryption |
|------|----------|--------|------------|
| Policies | `policies/*.yaml` | YAML | No (plaintext) |
| Credentials | `credentials/*.age` | age-encrypted | Yes (age) |
| Credential metadata | `credentials/*.meta.json` | JSON | No (metadata only) |
| Credential bindings | `credentials/bindings.yaml` | YAML | No (tool mappings) |
| Audit log | `audit.db` | SQLite | No (hashes only) |
| Session store | `sessions.db` | SQLite | No (tokens are random) |
| Configuration | `forculus.yaml` | YAML | No (plaintext) |
| CA certificate | `ca-cert.pem` | PEM | No (public cert) |
| CA private key | `ca-key.pem` | PEM | No (private key) |

**Security notes**:
- `ca-key.pem` should have restricted permissions (600) - needed for TLS MITM
- Credential `.age` files are encrypted; even if stolen, attacker needs age private key
- Session tokens are long random strings (`fcl_sess_` + 32 hex characters (128 bits of entropy)); brute-force infeasible
- Audit log stores hashes, not full request/response bodies (privacy + performance)

### In-Memory State

| Data | Storage | Access Pattern |
|------|---------|----------------|
| Policy engine | `ArcSwap<PolicyEngine>` | Lock-free reads, rare writes (hot-reload) |
| Rate limit buckets | `HashMap<Key, TokenBucket>` | Mutex-protected, frequent reads/writes |
| Vault (credential cache) | `parking_lot::Mutex<Vault>` | Sync mutex, reads on every credential injection |
| MCP session token | `parking_lot::Mutex<Option<String>>` | Sync mutex, read on every request, write once on init |

**Performance notes**:
- `ArcSwap` allows zero-lock reads for policy evaluation (hot path)
- `parking_lot::Mutex` is faster than std::sync::Mutex (futex-based, no poisoning)
- Rate limit buckets refilled periodically (e.g., every 100ms) rather than per-request
- Credential decryption is cached in memory after first use (security vs. performance tradeoff)

### Network Traffic

| Direction | Protocol | Data |
|-----------|----------|------|
| Agent → Forculus | HTTP/HTTPS or stdio (JSON-RPC) | Tool invocation requests, session token, tool name |
| Forculus → Upstream | HTTP/HTTPS or stdio (JSON-RPC) | Forwarded requests (with injected credentials) |
| Upstream → Forculus | HTTP/HTTPS or stdio (JSON-RPC) | Tool responses |
| Forculus → Agent | HTTP/HTTPS or stdio (JSON-RPC) | Tool responses (or 403/429 errors) |

**TLS security**:
- Agent → Forculus: TLS terminated by Forculus (MITM with self-signed CA)
- Forculus → Upstream: TLS re-established by Forculus (validates upstream certs)
- Forculus never sees agent's TLS private keys (not a transparent proxy)

### Data Lifecycle

1. **Operator creates session**: `forculus session create` → session token stored in `sessions.db`
2. **Agent makes request**: Includes session token → Forculus validates against `sessions.db`
3. **Policy evaluated**: Policies loaded from `ArcSwap<PolicyEngine>` (in-memory, lock-free)
4. **Credential injected**: Decrypted from `.age` file, injected into request
5. **Request forwarded**: Sent to upstream tool via HTTP or stdio
6. **Response inspected**: Scanned for secrets/PII by content inspector
7. **Cost recorded**: Extracted from response metadata, added to per-operator totals
8. **Audit logged**: Event written to `audit.db` with blake3 hash chain
9. **Response returned**: Sent back to agent (or 403/429 if blocked/rate-limited)

## Crate Dependency Graph

```
cli
 ├─ proxy
 │   ├─ policy
 │   ├─ vault
 │   ├─ audit
 │   ├─ inspect
 │   ├─ ratelimit
 │   └─ common
 ├─ mcp
 │   ├─ policy
 │   ├─ vault
 │   ├─ audit
 │   ├─ inspect
 │   ├─ ratelimit
 │   └─ common
 └─ config
     └─ common

common: Shared types (error, result, etc.)
config: YAML parsing and validation
policy: Policy engine with ArcSwap hot-reload
vault: age encryption, session store, credential injection
audit: SQLite audit log with blake3 hash chains
inspect: Content inspection with 13 built-in rules
ratelimit: Token-bucket rate limiting
proxy: HTTP forward proxy with TLS MITM
mcp: MCP gateway (stdio JSON-RPC)
cli: Command-line interface (forculus binary)
```

## Configuration Files

### Main Config: `forculus.yaml`

```yaml
# Server configuration
proxy:
  host: "127.0.0.1"
  port: 8080
  tls_mitm: true

# Policy engine
policies:
  directory: "policies"
  hot_reload: true
  default_verdict: deny

# Credential vault
vault:
  directory: "credentials"
  bindings: "credentials/bindings.yaml"

# Audit log
audit:
  database: "audit.db"
  retention_days: 90

# Session store
sessions:
  database: "sessions.db"
  ttl_hours: 24

# Content inspection
inspect:
  enabled: true
  redact_secrets: true
  block_on_injection: true

# Rate limiting
rate_limits:
  per_session:
    capacity: 100
    refill_per_second: 10
  per_operator:
    capacity: 1000
    refill_per_second: 100
  per_tool:
    capacity: 50
    refill_per_second: 5
  global:
    capacity: 10000
    refill_per_second: 1000

# Cost tracking
cost_tracking:
  enabled: true
  budget_currency: "USD"
  monthly_budget_per_operator: 1000.0
```

## Performance Characteristics

| Operation | Latency | Throughput | Scalability |
|-----------|---------|------------|-------------|
| Policy evaluation | ~10μs | 100k ops/sec | Lock-free, CPU-bound |
| Session validation | ~100μs | 10k ops/sec | SQLite read, disk I/O |
| Credential decryption | ~1ms (first time), ~10μs (cached) | 1k ops/sec | age decryption, CPU-bound |
| Content inspection | ~100μs per KB | 10 MB/sec | Regex matching, CPU-bound |
| Audit logging | ~500μs | 2k events/sec | SQLite write, disk I/O |
| Rate limit check | ~10μs | 100k ops/sec | HashMap lookup, memory-bound |

**Bottlenecks**:
- SQLite writes (audit log): Use WAL mode, batch writes, or async logging for higher throughput
- TLS MITM (HTTPS): Certificate signing on-the-fly; cache ephemeral certs per host
- Content inspection: Regex matching scales linearly with payload size; use streaming for large responses

**Optimization tips**:
- Enable policy hot-reload only in dev; use static policies in prod
- Increase SQLite cache size: `PRAGMA cache_size = 10000;`
- Use async audit logging: Queue events and flush in background
- Disable content inspection for trusted tools (configure per-tool)

## Design Principles

1. **Fail-closed**: If any stage fails, request is blocked (no fail-open fallback)
2. **Zero-trust**: Treat agent and upstream as hostile
3. **Tamper-evident**: Audit log uses cryptographic hash chains (like blockchain)
4. **Lock-free hot path**: Policy evaluation uses `ArcSwap` for zero-lock reads
5. **Operator-centric**: All actions attributed to an operator (accountability)
6. **YAML-first**: Configuration and policies in human-readable YAML
7. **Rust safety**: Memory safety, no undefined behavior, no data races
8. **Modular**: Each subsystem is a separate crate, can be used independently

## Future Architecture

Planned improvements:
- **Distributed audit log**: Replicate audit events to remote store (S3, Kafka)
- **Policy as code**: Rego (OPA) or CEL for more expressive policies
- **Credential rotation**: Automatic rotation with grace periods
- **Multi-tenancy**: Isolate sessions/policies/credentials by tenant
- **Observability**: Prometheus metrics, OpenTelemetry traces
- **Horizontal scaling**: Shared session store (Redis) and audit log (Kafka)
- **Plugin system**: WebAssembly plugins for custom inspectors/policies

## Further Reading

- [Getting Started Guide](getting-started.md) - Install and run Forculus in 10 minutes
- [Policy Reference](policy-reference.md) - Full policy schema and examples
- [Credential Vault Guide](credential-vault.md) - Manage encrypted credentials
- [Content Inspection Guide](content-inspection.md) - Configure secret/PII scanning
- [MCP Gateway Guide](mcp-gateway.md) - Use Forculus with MCP agents
- [Deployment Guide](deployment.md) - Run Forculus in production
- [Contributing Guide](../CONTRIBUTING.md) - Contribute to Forculus
