# Configuration Reference

Forculus is configured via a YAML file (typically `forculus.yaml` or `/etc/forculus/config.yaml`). This document describes all available configuration options.

## Table of Contents

- [Configuration File Location](#configuration-file-location)
- [Proxy](#proxy)
- [Logging](#logging)
- [MCP Gateway](#mcp-gateway)
- [Policy](#policy)
- [Vault](#vault)
- [Audit](#audit)
- [Content Inspection](#content-inspection)
- [Rate Limiting](#rate-limiting)
- [Cost Estimation](#cost-estimation)
- [Complete Example](#complete-example)

## Configuration File Location

Forculus searches for configuration in this order:

1. Path specified via `--config` flag: `forculus --config /path/to/config.yaml`
2. `./forculus.yaml` (current directory)
3. `/etc/forculus/forculus.yaml` (system-wide)

## Proxy

The proxy section configures Forculus's HTTP/HTTPS forward proxy with TLS MITM capabilities.

```yaml
proxy:
  listen_address: "127.0.0.1:8080"
  tls:
    ca_dir: "/etc/forculus/ca"
  tool_mappings:
    - url_pattern: "https://api.github.com/*"
      tool: "github:api"
      action_from:
        type: method  # or url_path, path_segment, static
```

### Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `listen_address` | String | No | `127.0.0.1:8080` | Address and port for the proxy to listen on |
| `tls.ca_dir` | String | No | `./ca` | Directory containing CA certificate and key for TLS MITM |
| `tool_mappings` | Array | No | `[]` | URL-to-tool mapping rules |

### TLS Configuration

The `tls.ca_dir` directory must contain:
- `ca.crt` - CA certificate in PEM format
- `ca.key` - CA private key in PEM format

Forculus uses this CA to generate certificates on-the-fly for intercepted HTTPS connections. Clients must trust this CA certificate.

To generate a CA:

```bash
openssl req -x509 -newkey rsa:4096 -keyout ca.key -out ca.crt \
  -days 365 -nodes -subj "/CN=Forculus CA"
```

### Tool Mappings

Tool mappings translate HTTP requests into tool/action identifiers for policy evaluation:

```yaml
tool_mappings:
  - url_pattern: "https://api.github.com/repos/*/pulls"
    tool: "github:api"
    action_from:
      type: method  # GET -> read, POST -> write, DELETE -> delete

  - url_pattern: "https://api.slack.com/api/*"
    tool: "slack:api"
    action_from:
      type: url_path  # /api/chat.postMessage -> chat.postMessage

  - url_pattern: "https://example.com/api/v*/users"
    tool: "example:users"
    action_from:
      type: path_segment
      index: 2  # Extract segment at index 2 as action

  - url_pattern: "https://monitoring.example.com/*"
    tool: "monitoring:api"
    action_from:
      type: static
      value: "monitor"  # Always use this action
```

#### `action_from` Types

| Type | Description | Example |
|------|-------------|---------|
| `method` | Derive action from HTTP method | `GET` -> `read`, `POST` -> `write`, `PUT` -> `update`, `DELETE` -> `delete` |
| `url_path` | Use URL path as action | `/api/chat.postMessage` -> `chat.postMessage` |
| `path_segment` | Extract specific path segment | `/api/v1/users` with `index: 2` -> `users` |
| `static` | Always use a fixed action | `value: "monitor"` -> `monitor` |

## Logging

Configure logging format and verbosity:

```yaml
logging:
  format: json  # or text
  level: info   # trace, debug, info, warn, error
```

### Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `format` | String | No | `text` | Log output format: `text` (human-readable) or `json` (structured) |
| `level` | String | No | `info` | Minimum log level: `trace`, `debug`, `info`, `warn`, `error` |

### Log Formats

**Text format** (default):
```
2026-02-15T10:30:45Z INFO forculus::proxy: Request allowed tool=github:api action=read
```

**JSON format**:
```json
{"timestamp":"2026-02-15T10:30:45Z","level":"INFO","target":"forculus::proxy","message":"Request allowed","tool":"github:api","action":"read"}
```

Use JSON format when integrating with log aggregation systems (ELK, Splunk, etc.).

## MCP Gateway

Configure the Model Context Protocol gateway for AI agent communication:

```yaml
mcp_gateway:
  upstream_servers:
    - name: "filesystem"
      command: "npx"
      args: ["-y", "@modelcontextprotocol/server-filesystem", "/workspace"]

    - name: "github"
      command: "npx"
      args: ["-y", "@modelcontextprotocol/server-github"]
      env:
        GITHUB_TOKEN: "${GITHUB_TOKEN}"  # Reference environment variable
```

### Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `upstream_servers` | Array | No | `[]` | List of MCP servers to proxy |

### Upstream Server Configuration

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | String | Yes | Identifier for the upstream server |
| `command` | String | Yes | Command to execute |
| `args` | Array of Strings | No | Command-line arguments |
| `env` | Map of String to String | No | Environment variables (supports `${VAR}` interpolation) |

The MCP gateway spawns each upstream server as a subprocess and forwards MCP requests based on policy evaluation.

## Policy

Configure the policy engine:

```yaml
policy:
  policies_dir: "/etc/forculus/policies"
  hot_reload: true
```

### Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `policies_dir` | String | Yes | - | Directory containing YAML policy files |
| `hot_reload` | Boolean | No | `false` | Automatically reload policies when files change |

### Policy Directory Structure

```
/etc/forculus/policies/
├── 00-global.yaml
├── 10-team-engineering.yaml
├── 20-project-frontend.yaml
├── 30-agent-deploy-bot.yaml
└── 99-overrides.yaml
```

Policies are loaded in lexicographic order. Use numeric prefixes to control load order (which affects precedence for rules with equal scope and priority).

See the [Policy Reference](policy-reference.md) for detailed policy syntax.

## Vault

Configure the credential vault for secure credential storage and session management:

```yaml
vault:
  key_path: "/etc/forculus/vault.key"
  credentials_dir: "/etc/forculus/credentials"
  bindings_path: "/etc/forculus/bindings.yaml"
  sessions_db_path: "/var/lib/forculus/sessions.db"
  require_sessions: true
```

### Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `key_path` | String | Yes | - | Path to age encryption key file |
| `credentials_dir` | String | Yes | - | Directory containing encrypted credentials |
| `bindings_path` | String | Yes | - | Path to credential bindings YAML file |
| `sessions_db_path` | String | No | `./sessions.db` | Path to SQLite session database |
| `require_sessions` | Boolean | No | `false` | Whether to require valid session for all requests |

### Credential Storage

Credentials are stored as age-encrypted files with metadata sidecars:

```
/etc/forculus/credentials/
├── github-token.age           # Encrypted credential data
├── github-token.meta.json     # Metadata (name, description, tags)
├── slack-webhook.age
└── slack-webhook.meta.json
```

### Credential Bindings

The bindings file maps tools to credentials with scope constraints:

```yaml
bindings:
  - credential: github-token
    tools:
      - "github:*"
    scopes:
      - "repo"
      - "workflow"
    environments:
      - "production"
      - "staging"

  - credential: slack-webhook
    tools:
      - "slack:webhook"
    scopes:
      - "chat:write"
```

### Session Management

When `require_sessions` is enabled, all requests must include a valid session token:

```bash
# HTTP Proxy
curl -H "X-Forculus-Session: fcl_sess_abc123..." https://api.github.com/user

# MCP Gateway (session stored per connection)
```

Sessions are stored in a SQLite database and validated on each request.

## Audit

Configure audit logging for compliance and security monitoring:

```yaml
audit:
  enabled: true
  db_path: "/var/lib/forculus/audit.db"
  retention_days: 90
```

### Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `enabled` | Boolean | No | `false` | Enable audit logging |
| `db_path` | String | No | `./audit.db` | Path to SQLite audit database |
| `retention_days` | Integer | No | `90` | Days to retain audit logs (0 = forever) |

### Audit Log Contents

When enabled, Forculus logs all policy decisions to a SQLite database:

- Timestamp
- Tool and action requested
- Resource accessed
- Policy verdict (allow, deny, escalate)
- Session ID (if applicable)
- Operator (if available from context)
- Request/response metadata

Audit logs can be queried for compliance reporting and security investigations.

## Content Inspection

Configure real-time content inspection for secrets, PII, and injection attacks:

```yaml
inspect:
  enabled: true
  inspect_requests: true
  inspect_responses: true
  max_content_size: 1048576  # 1 MB
  disabled_rules:
    - "credit-card"  # Disable specific detection rules
  rule_overrides:
    aws-key:
      action: "redact"  # block, redact, or log
      severity: "critical"
  custom_patterns:
    - name: "internal-ticket-id"
      pattern: "TICKET-\\d{6}"
      action: "log"
      severity: "low"
      description: "Internal ticket reference"
```

### Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `enabled` | Boolean | No | `false` | Enable content inspection |
| `inspect_requests` | Boolean | No | `true` | Inspect request bodies |
| `inspect_responses` | Boolean | No | `true` | Inspect response bodies |
| `max_content_size` | Integer | No | `1048576` | Maximum content size to inspect (bytes) |
| `disabled_rules` | Array of Strings | No | `[]` | Rule IDs to disable |
| `rule_overrides` | Map | No | `{}` | Override default rule behavior |
| `custom_patterns` | Array | No | `[]` | Custom detection patterns |

### Built-in Detection Rules

Forculus includes detectors for:

- **Secrets**: API keys, tokens, private keys, passwords
  - AWS keys, GitHub tokens, Slack tokens, JWT tokens
  - RSA/SSH private keys, database connection strings
- **PII**: Email, phone, credit card, SSN
- **Injection**: SQL injection, command injection, XSS

### Rule Override Actions

| Action | Description |
|--------|-------------|
| `block` | Reject the request/response (default for critical) |
| `redact` | Replace detected content with `[REDACTED]` |
| `log` | Log the detection but allow the content |

### Custom Patterns

Define custom detection patterns using regex:

```yaml
custom_patterns:
  - name: "employee-id"
    pattern: "EMP-\\d{8}"
    action: "redact"
    severity: "medium"
    description: "Internal employee identifier"

  - name: "api-endpoint"
    pattern: "https://internal\\.example\\.com/api/.*"
    action: "log"
    severity: "low"
    description: "Internal API endpoint reference"
```

## Rate Limiting

Configure rate limiting to prevent abuse and control costs:

```yaml
rate_limit:
  enabled: true
  default_rpm: 60     # requests per minute
  default_burst: 10   # burst allowance
  rules:
    - name: "expensive-operations"
      tools:
        - "gpt-4"
        - "claude-opus"
      rpm: 10
      burst: 2
      dimensions:
        - "tool"
        - "operator"

    - name: "high-volume-apis"
      tools:
        - "github:*"
      rpm: 5000
      burst: 100
      dimensions:
        - "tool"
```

### Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `enabled` | Boolean | No | `false` | Enable rate limiting |
| `default_rpm` | Integer | No | `60` | Default requests per minute limit |
| `default_burst` | Integer | No | `10` | Default burst allowance |
| `rules` | Array | No | `[]` | Tool-specific rate limit rules |

### Rate Limit Rules

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | String | Yes | Rule identifier |
| `tools` | Array of Strings | Yes | Tool patterns to match (supports globs) |
| `rpm` | Integer | Yes | Requests per minute limit |
| `burst` | Integer | Yes | Burst allowance |
| `dimensions` | Array of Strings | No | Rate limit dimensions: `tool`, `operator`, `team`, `agent` |

### Rate Limit Dimensions

Dimensions control how rate limits are applied:

- **tool**: Separate limit per tool
- **operator**: Separate limit per user
- **team**: Separate limit per team
- **agent**: Separate limit per agent instance

Multiple dimensions create a composite key. For example, `["tool", "operator"]` creates a separate limit for each tool-operator pair.

## Cost Estimation

Track and limit AI operation costs:

```yaml
cost_estimation:
  enabled: true
  default_cost: 0.001  # Default cost per request in USD
  rules:
    - tools:
        - "gpt-4"
        - "claude-opus-4"
      cost: 0.03
      monthly_budget: 1000.0

    - tools:
        - "gpt-3.5-turbo"
        - "claude-haiku"
      cost: 0.001
      monthly_budget: 100.0
```

### Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `enabled` | Boolean | No | `false` | Enable cost tracking |
| `default_cost` | Float | No | `0.001` | Default cost per request (USD) |
| `rules` | Array | No | `[]` | Tool-specific cost rules |

### Cost Rules

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tools` | Array of Strings | Yes | Tool patterns to match (supports globs) |
| `cost` | Float | Yes | Cost per request in USD |
| `monthly_budget` | Float | No | Monthly budget limit (USD) |

Cost tracking helps:
- Monitor AI usage costs across teams and projects
- Prevent budget overruns with monthly limits
- Identify expensive operations for optimization
- Generate cost reports for chargeback

## Complete Example

Here's a comprehensive configuration demonstrating all sections:

```yaml
# Forculus Configuration
# /etc/forculus/forculus.yaml

proxy:
  listen_address: "0.0.0.0:8080"
  tls:
    ca_dir: "/etc/forculus/ca"
  tool_mappings:
    - url_pattern: "https://api.github.com/*"
      tool: "github:api"
      action_from:
        type: method
    - url_pattern: "https://api.openai.com/v1/*"
      tool: "openai:api"
      action_from:
        type: url_path
    - url_pattern: "https://api.anthropic.com/v1/*"
      tool: "anthropic:api"
      action_from:
        type: url_path

logging:
  format: json
  level: info

mcp_gateway:
  upstream_servers:
    - name: "filesystem"
      command: "npx"
      args: ["-y", "@modelcontextprotocol/server-filesystem", "/workspace"]

    - name: "github"
      command: "npx"
      args: ["-y", "@modelcontextprotocol/server-github"]
      env:
        GITHUB_TOKEN: "${GITHUB_TOKEN}"

    - name: "postgres"
      command: "npx"
      args: ["-y", "@modelcontextprotocol/server-postgres"]
      env:
        DATABASE_URL: "${DATABASE_URL}"

policy:
  policies_dir: "/etc/forculus/policies"
  hot_reload: true

vault:
  key_path: "/etc/forculus/vault.key"
  credentials_dir: "/etc/forculus/credentials"
  bindings_path: "/etc/forculus/bindings.yaml"
  sessions_db_path: "/var/lib/forculus/sessions.db"
  require_sessions: true

audit:
  enabled: true
  db_path: "/var/lib/forculus/audit.db"
  retention_days: 90

inspect:
  enabled: true
  inspect_requests: true
  inspect_responses: true
  max_content_size: 1048576
  disabled_rules: []
  rule_overrides:
    aws-key:
      action: "block"
      severity: "critical"
    email:
      action: "redact"
      severity: "medium"
  custom_patterns:
    - name: "internal-api"
      pattern: "https://internal\\.example\\.com/.*"
      action: "log"
      severity: "low"
      description: "Internal API endpoint reference"

rate_limit:
  enabled: true
  default_rpm: 60
  default_burst: 10
  rules:
    - name: "ai-models"
      tools:
        - "openai:*"
        - "anthropic:*"
      rpm: 30
      burst: 5
      dimensions:
        - "tool"
        - "operator"

    - name: "github-api"
      tools:
        - "github:api"
      rpm: 5000
      burst: 100
      dimensions:
        - "tool"

cost_estimation:
  enabled: true
  default_cost: 0.001
  rules:
    - tools:
        - "openai:api:/v1/chat/completions"
        - "anthropic:api:/v1/messages"
      cost: 0.03
      monthly_budget: 5000.0

    - tools:
        - "openai:api:/v1/embeddings"
      cost: 0.0001
      monthly_budget: 100.0
```

## Environment Variable Interpolation

Configuration values support environment variable interpolation using `${VAR_NAME}` syntax:

```yaml
mcp_gateway:
  upstream_servers:
    - name: "github"
      command: "npx"
      args: ["-y", "@modelcontextprotocol/server-github"]
      env:
        GITHUB_TOKEN: "${GITHUB_TOKEN}"  # Read from environment
        API_BASE_URL: "${API_URL:-https://api.github.com}"  # With default value
```

This allows sensitive values to be stored outside the configuration file.

## Configuration Validation

Forculus validates configuration on startup:

- Required fields must be present
- Paths must exist and be accessible
- Enum values must be valid
- Numeric values must be in valid ranges

Invalid configuration causes Forculus to exit with an error message describing the problem.

## Best Practices

1. **Separate environments**: Use different configuration files for dev, staging, and production
2. **Version control**: Keep configuration in git (except secrets)
3. **Environment variables**: Use `${VAR}` interpolation for secrets and environment-specific values
4. **Minimal permissions**: Run Forculus as a dedicated user with minimal file system access
5. **TLS security**: Protect CA private key with restrictive permissions (0600)
6. **Audit retention**: Balance compliance requirements with storage costs
7. **Rate limits**: Set conservative defaults and tune based on actual usage
8. **Cost budgets**: Start with low budgets and increase as needed
9. **Hot reload**: Enable in production for zero-downtime policy updates
10. **Monitoring**: Use JSON logging format for integration with observability tools

## Troubleshooting

### Configuration Not Found

```
Error: Configuration file not found
```

**Solution**: Specify the config path explicitly:

```bash
forculus --config /etc/forculus/forculus.yaml
```

### Invalid YAML Syntax

```
Error: Failed to parse configuration: invalid YAML at line 42
```

**Solution**: Validate YAML syntax:

```bash
yamllint forculus.yaml
```

### Permission Denied

```
Error: Permission denied: /etc/forculus/ca/ca.key
```

**Solution**: Ensure the Forculus process has read access:

```bash
chmod 600 /etc/forculus/ca/ca.key
chown forculus:forculus /etc/forculus/ca/ca.key
```

### Hot Reload Not Working

**Solution**:
1. Verify `hot_reload: true` in config
2. Check file system notification support
3. Review logs for parsing errors
4. Ensure policies directory is readable

### Session Database Locked

```
Error: database is locked: sessions.db
```

**Solution**: Only one Forculus instance can access the session database. Ensure no other instances are running, or use a different database path per instance.
