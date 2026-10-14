# OpenClaw Integration

OpenClaw is an open-source AI agent framework that uses the Model Context Protocol (MCP) for tool integration. Forculus integrates with OpenClaw via the MCP gateway to add governance, policy enforcement, and audit logging.

## Overview

Forculus provides OpenClaw with:

- **Policy enforcement**: Control which tools OpenClaw can use
- **Credential management**: Securely inject API keys and tokens
- **Audit logging**: Track all tool calls and decisions
- **Content inspection**: Scan for secrets, PII, and security issues
- **Rate limiting**: Control request rates and costs
- **Governance metadata**: Rich policy information in tool responses

## Architecture

```
OpenClaw Agent
    |
    | (MCP stdio/JSON-RPC)
    |
Forculus MCP Gateway
    |
    | (Policy, Credentials, Audit, Content Inspection)
    |
MCP Servers (filesystem, github, slack, database, etc.)
```

OpenClaw connects to Forculus's MCP gateway, which enforces policies and forwards approved requests to the configured MCP servers.

## Configuration

### 1. Configure Forculus MCP Gateway

Create or edit `~/.forculus/forculus.yaml`:

```yaml
mcp:
  enabled: true
  mode: gateway

  # MCP servers to proxy
  servers:
    - name: filesystem
      command: npx
      args:
        - "-y"
        - "@modelcontextprotocol/server-filesystem"
        - "/home/user/workspace"
      env:
        NODE_ENV: production

    - name: github
      command: npx
      args:
        - "-y"
        - "@modelcontextprotocol/server-github"
      env:
        GITHUB_PERSONAL_ACCESS_TOKEN: "{{ credential:github-token }}"

    - name: slack
      command: npx
      args:
        - "-y"
        - "@modelcontextprotocol/server-slack"
      env:
        SLACK_BOT_TOKEN: "{{ credential:slack-token }}"

    - name: postgres
      command: npx
      args:
        - "-y"
        - "@modelcontextprotocol/server-postgres"
      env:
        DATABASE_URL: "{{ credential:postgres-url }}"

# Enable policy enforcement
policy:
  enabled: true
  policy_file: ~/.forculus/policies.yaml

# Enable credential vault
vault:
  enabled: true
  vault_dir: ~/.forculus/vault

# Enable audit logging
audit:
  enabled: true
  database_path: ~/.forculus/audit/audit.db

# Enable content inspection
content_inspection:
  enabled: true
  scan_requests: true
  scan_responses: true
  rules:
    # Block credential leaks
    - id: aws-key
      action: Block
    - id: gcp-key
      action: Block
    - id: github-token
      action: Block
    - id: private-key
      action: Block

    # Redact PII
    - id: ssn
      action: Redact
    - id: credit-card
      action: Redact

# Enable rate limiting
rate_limiting:
  enabled: true
  operator:
    requests_per_minute: 300
    burst: 30
  session:
    requests_per_minute: 100
    burst: 10
```

### 2. Configure OpenClaw

Edit OpenClaw's configuration file (typically `~/.openclaw/config.yaml` or similar):

```yaml
mcp:
  # Connect to Forculus gateway instead of direct MCP servers
  servers:
    - name: forculus
      command: forculus
      args:
        - mcp
        - gateway
      env:
        FORCULUS_SESSION_TOKEN: "bwk_sess_your_session_token_here"

# OpenClaw agent configuration
agent:
  name: openclaw-agent
  model: gpt-4
  temperature: 0.7

  # Tool usage settings
  tools:
    enabled: true
    max_calls_per_turn: 10
    retry_on_error: true
```

### 3. Create Session Token

```bash
# Create a session for OpenClaw
forculus session create --operator openclaw-agent

# Output:
# Session created: bwk_sess_o1p2e3n4c5l6a7w8x9y0z1a2b3c4d5e6
# Store this token securely - it won't be shown again
```

Copy the token into your OpenClaw config (step 2 above).

### 4. Add Credentials

```bash
# Add GitHub token
forculus cred add github-token
# Type: bearer_token
# Secret: ghp_your_github_token_here

# Add Slack token
forculus cred add slack-token
# Type: bearer_token
# Secret: xoxb-your-slack-token-here

# Add PostgreSQL connection string
forculus cred add postgres-url
# Type: custom
# Secret: postgresql://user:password@localhost:5432/dbname
```

### 5. Configure Credential Bindings

Edit `~/.forculus/vault/bindings.yaml`:

```yaml
bindings:
  - credential_id: github-token
    tools:
      - "github::*"
    scopes:
      - repo
      - read:user
      - write:issues
    operators:
      - openclaw-agent

  - credential_id: slack-token
    tools:
      - "slack::*"
    scopes:
      - chat:write
      - channels:read
    operators:
      - openclaw-agent

  - credential_id: postgres-url
    tools:
      - "postgres::*"
    scopes:
      - db:read
      - db:write
    operators:
      - openclaw-agent
```

### 6. Configure Policies

Edit `~/.forculus/policies.yaml`:

```yaml
policies:
  # Filesystem operations
  - scope: "tool:filesystem::read-file"
    action: allow
    priority: 100

  - scope: "tool:filesystem::write-file"
    action: allow
    priority: 100
    require_approval: true

  - scope: "tool:filesystem::delete-file"
    action: deny
    priority: 200

  # GitHub read operations
  - scope: "tool:github::list-*"
    action: allow
    priority: 100

  - scope: "tool:github::get-*"
    action: allow
    priority: 100

  - scope: "tool:github::search-*"
    action: allow
    priority: 100

  # GitHub write operations (require approval)
  - scope: "tool:github::create-*"
    action: allow
    priority: 100
    require_approval: true

  - scope: "tool:github::update-*"
    action: allow
    priority: 100
    require_approval: true

  # Block destructive GitHub operations
  - scope: "tool:github::delete-*"
    action: deny
    priority: 200

  # Slack operations
  - scope: "tool:slack::post-message"
    action: allow
    priority: 100

  - scope: "tool:slack::list-channels"
    action: allow
    priority: 100

  # Database read operations
  - scope: "tool:postgres::query"
    action: allow
    priority: 100
    conditions:
      - type: sql_operation
        value: ["SELECT"]

  # Database write operations (require approval)
  - scope: "tool:postgres::query"
    action: allow
    priority: 100
    require_approval: true
    conditions:
      - type: sql_operation
        value: ["INSERT", "UPDATE", "DELETE"]

  # Block dangerous database operations
  - scope: "tool:postgres::query"
    action: deny
    priority: 200
    conditions:
      - type: sql_operation
        value: ["DROP", "TRUNCATE", "ALTER"]

  # Default deny
  - scope: "*"
    action: deny
    priority: 0
```

## Example Session

Complete example of using OpenClaw with Forculus governance:

### Setup

```bash
# 1. Configure Forculus (see Configuration section)

# 2. Create session
forculus session create --operator openclaw-agent
# Token: bwk_sess_abc123...

# 3. Add token to OpenClaw config
# (See step 2 in Configuration)

# 4. Start Forculus MCP gateway (runs automatically when OpenClaw starts)

# 5. Start OpenClaw
openclaw start
```

### Interaction

```
User: List files in the workspace

OpenClaw: I'll list the files in your workspace.

[MCP Tool Call]
Method: tools/call
Tool: filesystem::list-directory
Parameters:
  path: "/home/user/workspace"

[Forculus Processing]
1. Extract session: openclaw-agent
2. Check policy: allow (filesystem::list-directory)
3. Forward to filesystem MCP server

[MCP Response]
Result:
  files:
    - name: "main.rs"
      type: "file"
    - name: "lib.rs"
      type: "file"
    - name: "tests/"
      type: "directory"

OpenClaw: Your workspace contains:
- main.rs (file)
- lib.rs (file)
- tests/ (directory)

---

User: Read main.rs

OpenClaw: I'll read the contents of main.rs.

[MCP Tool Call]
Tool: filesystem::read-file
Parameters:
  path: "/home/user/workspace/main.rs"

[Forculus Processing]
1. Check policy: allow
2. Forward request

[MCP Response]
Result:
  content: "fn main() {\n    println!(\"Hello, world!\");\n}\n"

OpenClaw: The file contains:
```rust
fn main() {
    println!("Hello, world!");
}
```

---

User: Create a GitHub issue titled "Update README"

OpenClaw: I'll create a GitHub issue, but this requires approval.

[MCP Tool Call]
Tool: github::create-issue
Parameters:
  repo: "owner/repo"
  title: "Update README"
  body: "We need to update the README with installation instructions."

[Forculus Processing]
1. Check policy: allow (require_approval: true)
2. PAUSE - Request approval

[Forculus Response]
Error:
  code: "approval_required"
  message: "This operation requires approval"
  approval_request_id: "appr_xyz"

OpenClaw: This operation requires your approval. Please approve at:
https://forculus.local/approve?request_id=appr_xyz

[User approves via Forculus UI or CLI]

OpenClaw: Approval received. Creating issue...

[MCP Tool Call - Retry]
Tool: github::create-issue
Parameters: (same as above)
Approval: appr_xyz

[Forculus Processing]
1. Verify approval
2. Inject credential: github-token
3. Forward to GitHub MCP server

[MCP Response]
Result:
  issue_number: 123
  url: "https://github.com/owner/repo/issues/123"

OpenClaw: Issue #123 created successfully:
https://github.com/owner/repo/issues/123

---

User: Delete the repository

OpenClaw: I cannot delete the repository because this operation is denied by policy.

[MCP Tool Call]
Tool: github::delete-repo
Parameters:
  repo: "owner/repo"

[Forculus Processing]
1. Check policy: deny (destructive operation)
2. BLOCK

[Forculus Response]
Error:
  code: "policy_denied"
  message: "This operation is denied by policy"
  policy_rule: "deny-github-destructive"

OpenClaw: I'm unable to delete the repository because destructive operations are blocked by governance policy. This is a safety measure to prevent accidental data loss.

If you need to delete the repository, you can:
1. Archive it instead (safer alternative)
2. Contact your administrator to adjust the policy
3. Perform the operation manually

Would you like me to archive the repository instead?

---

User: Query the database for all users

OpenClaw: I'll query the database for all users.

[MCP Tool Call]
Tool: postgres::query
Parameters:
  query: "SELECT * FROM users"

[Forculus Processing]
1. Check policy: allow (SELECT operation)
2. Inject credential: postgres-url
3. Content inspection: Check for PII in response
4. Forward to postgres MCP server

[MCP Response]
Result:
  rows:
    - id: 1, name: "Alice", email: "alice@example.com", ssn: "123-45-6789"
    - id: 2, name: "Bob", email: "bob@example.com", ssn: "987-65-4321"

[Forculus Content Inspection]
- Detected: email addresses (Low severity, Log action)
- Detected: SSNs (High severity, Redact action)
- Redacting SSNs...

[Redacted Response]
Result:
  rows:
    - id: 1, name: "Alice", email: "alice@example.com", ssn: "[REDACTED:SSN]"
    - id: 2, name: "Bob", email: "bob@example.com", ssn: "[REDACTED:SSN]"

OpenClaw: Found 2 users:
1. Alice (alice@example.com)
2. Bob (bob@example.com)

Note: SSNs were redacted by content inspection for security.

---

User: Update user 1's email to alice-new@example.com

OpenClaw: I'll update the email, but this requires approval since it's a database write operation.

[MCP Tool Call]
Tool: postgres::query
Parameters:
  query: "UPDATE users SET email = 'alice-new@example.com' WHERE id = 1"

[Forculus Processing]
1. Check policy: allow (UPDATE operation, require_approval: true)
2. PAUSE - Request approval

[Forculus Response]
Error:
  code: "approval_required"
  message: "Database write operations require approval"

OpenClaw: This operation requires approval. Please approve to proceed.

[After approval]

[MCP Response]
Result:
  rows_affected: 1

OpenClaw: Successfully updated user 1's email to alice-new@example.com.

---

User: Drop the users table

OpenClaw: I cannot drop the users table because this operation is denied by policy.

[MCP Tool Call]
Tool: postgres::query
Parameters:
  query: "DROP TABLE users"

[Forculus Processing]
1. Check policy: deny (DROP operation)
2. BLOCK

[Forculus Response]
Error:
  code: "policy_denied"
  message: "Dangerous database operations are not allowed"

OpenClaw: I'm unable to drop the users table because dangerous database operations (DROP, TRUNCATE, ALTER) are blocked by governance policy.

This is a critical safety measure to prevent accidental data loss. If you need to perform schema changes, please:
1. Use a database migration tool
2. Work with your DBA
3. Contact your administrator for policy exceptions
```

## Audit Trail

All OpenClaw operations are logged:

```bash
# View recent OpenClaw activity
forculus audit query --operator openclaw-agent --since 1h

# Output:
# 2026-02-15 10:30:00 | SessionCreated | openclaw-agent | Created session
# 2026-02-15 10:31:00 | RequestProcessed | openclaw-agent | filesystem::list-directory | 200
# 2026-02-15 10:31:00 | PolicyDecision | openclaw-agent | filesystem::list-directory | allow
# 2026-02-15 10:32:00 | RequestProcessed | openclaw-agent | github::create-issue | 200
# 2026-02-15 10:32:00 | PolicyDecision | openclaw-agent | github::create-issue | allow (approval required)
# 2026-02-15 10:32:00 | CredentialInjected | openclaw-agent | github-token | github::create-issue
# 2026-02-15 10:33:00 | PolicyDecision | openclaw-agent | github::delete-repo | deny
# 2026-02-15 10:34:00 | RequestProcessed | openclaw-agent | postgres::query | 200
# 2026-02-15 10:34:00 | PolicyDecision | openclaw-agent | postgres::query | allow
# 2026-02-15 10:34:00 | ContentInspectionTriggered | openclaw-agent | ssn | Redact
# 2026-02-15 10:35:00 | PolicyDecision | openclaw-agent | postgres::query | deny

# Export for analysis
forculus audit export --operator openclaw-agent --since 24h --output openclaw-audit.jsonl
```

## Best Practices

### 1. Least Privilege Policies

Start with minimal permissions and add as needed:

```yaml
# Week 1: Read-only access
policies:
  - scope: "tool:filesystem::read-file"
    action: allow
  - scope: "tool:github::get-*"
    action: allow
  - scope: "tool:github::list-*"
    action: allow
  - scope: "*"
    action: deny

# Week 2: Add write with approval
policies:
  - scope: "tool:filesystem::write-file"
    action: allow
    require_approval: true
  - scope: "tool:github::create-*"
    action: allow
    require_approval: true
```

### 2. Content Inspection for Database Queries

Always enable content inspection for database tools:

```yaml
content_inspection:
  enabled: true
  scan_responses: true
  rules:
    - id: ssn
      action: Redact
    - id: credit-card
      action: Redact
    - id: email-address
      action: Log
```

### 3. Rate Limiting for Production

Set appropriate rate limits:

```yaml
rate_limiting:
  enabled: true
  operator:
    requests_per_minute: 300
    burst: 30
  tool_overrides:
    "slack::post-message":
      requests_per_minute: 20  # Match Slack's limits
      burst: 5
```

### 4. Monitor for Anomalies

Set up monitoring for unusual patterns:

```bash
#!/bin/bash
# openclaw-monitor.sh

# Alert on high denial rate
DENIALS=$(forculus audit query \
  --operator openclaw-agent \
  --event-type PolicyDecision \
  --since 1h | \
  grep "deny" | wc -l)

if [ "$DENIALS" -gt 50 ]; then
  echo "ALERT: High denial rate for openclaw-agent: $DENIALS in 1 hour"
fi

# Alert on content inspection blocks
BLOCKS=$(forculus audit query \
  --operator openclaw-agent \
  --event-type ContentInspectionTriggered \
  --since 1h | wc -l)

if [ "$BLOCKS" -gt 10 ]; then
  echo "ALERT: High content inspection blocks: $BLOCKS in 1 hour"
fi
```

### 5. Regular Policy Reviews

Review and update policies monthly:

```bash
# Monthly policy review
forculus audit stats --operator openclaw-agent --since 30d

# Identify frequently denied tools
forculus audit export \
  --operator openclaw-agent \
  --event-type PolicyDecision \
  --since 30d \
  --output policy-decisions.jsonl

cat policy-decisions.jsonl | \
  jq -r 'select(.details.decision == "deny") | .details.tool_name' | \
  sort | uniq -c | sort -rn

# Consider allowing if legitimate use cases
```

## Advanced Features

### Tool-Specific Conditions

Apply conditions based on tool parameters:

```yaml
policies:
  # Allow SELECT queries
  - scope: "tool:postgres::query"
    action: allow
    priority: 100
    conditions:
      - type: sql_operation
        value: ["SELECT"]

  # Allow writes to specific tables only
  - scope: "tool:postgres::query"
    action: allow
    priority: 100
    require_approval: true
    conditions:
      - type: sql_operation
        value: ["UPDATE", "INSERT"]
      - type: sql_table
        value: ["logs", "analytics", "temp_data"]

  # Block writes to critical tables
  - scope: "tool:postgres::query"
    action: deny
    priority: 200
    conditions:
      - type: sql_table
        value: ["users", "payments", "credentials"]
```

### Cost Tracking

Track costs per tool:

```yaml
cost_tracking:
  enabled: true
  default_monthly_budget: 100.00

  tool_costs:
    "github::create-issue":
      cost_per_request: 0.001
    "slack::post-message":
      cost_per_request: 0.0005
    "postgres::query":
      cost_per_request: 0.0001
```

Monitor spending:

```bash
forculus cost show --operator openclaw-agent

# Output:
# Operator: openclaw-agent
# Budget: $100.00
# Spent: $45.67
# Remaining: $54.33
#
# Top Tools by Cost:
# 1. github::create-issue: $25.30 (25,300 requests)
# 2. slack::post-message: $12.45 (24,900 requests)
# 3. postgres::query: $7.92 (79,200 requests)
```

### Multi-Environment Support

Different policies for dev/staging/prod:

```yaml
# Use session metadata to distinguish environments
policies:
  # Production: Strict policies
  - scope: "tool:postgres::query"
    action: deny
    priority: 200
    conditions:
      - type: session_metadata
        key: env
        value: production
      - type: sql_operation
        value: ["DELETE", "DROP", "TRUNCATE"]

  # Development: Relaxed policies
  - scope: "tool:postgres::query"
    action: allow
    priority: 100
    conditions:
      - type: session_metadata
        key: env
        value: development
```

Create environment-specific sessions:

```bash
# Production session
forculus session create \
  --operator openclaw-prod \
  --metadata '{"env":"production","region":"us-east-1"}'

# Development session
forculus session create \
  --operator openclaw-dev \
  --metadata '{"env":"development","region":"local"}'
```

## Troubleshooting

### Session Invalid

If OpenClaw can't connect:

1. Verify session token: `forculus session list`
2. Check token in OpenClaw config
3. Create new session if expired
4. Check Forculus MCP gateway is running

### Tool Not Available

If OpenClaw reports tool not found:

1. Check MCP server configuration in `forculus.yaml`
2. Test MCP server directly: `npx @modelcontextprotocol/server-github`
3. Check server logs: Forculus logs MCP server stdout/stderr
4. Verify policy allows the tool

### Approval Flow Not Working

If approval requests aren't showing:

1. Check policy has `require_approval: true`
2. Verify approval UI is accessible
3. Check Forculus logs for approval request creation
4. Test approval flow: `forculus approval list`

### Content Inspection Too Aggressive

If too many false positives:

1. Review recent findings: `forculus audit query --event-type ContentInspectionTriggered`
2. Disable problematic rules: `enabled: false`
3. Lower severity: `severity: Info`
4. Change action: `action: Log` instead of `Block`

## Integration with OpenClaw Features

### OpenClaw Agent Chains

When using OpenClaw's agent chaining, each sub-agent can have its own session:

```yaml
# Main agent
main_agent:
  session_token: "bwk_sess_main..."
  policies: "main-agent-policies.yaml"

# Research sub-agent (read-only)
research_agent:
  session_token: "bwk_sess_research..."
  policies: "research-agent-policies.yaml"

# Action sub-agent (write access with approval)
action_agent:
  session_token: "bwk_sess_action..."
  policies: "action-agent-policies.yaml"
```

### OpenClaw Memory/Context

Forculus can inspect and redact sensitive data in OpenClaw's memory:

```yaml
content_inspection:
  scan_context: true  # Scan agent context/memory
  rules:
    - id: ssn
      action: Redact
    - id: credit-card
      action: Redact
```

### OpenClaw Workflows

Track workflow execution in audit logs:

```bash
# View workflow execution
forculus audit query \
  --operator openclaw-agent \
  --since 1h \
  --format json | \
  jq -r '.[] | select(.details.workflow_id != null) | "\(.timestamp) | \(.details.workflow_id) | \(.details.tool_name)"'
```

## Summary

OpenClaw integration with Forculus provides:

1. **Transparent governance**: Policies enforced without changing OpenClaw code
2. **Secure credential management**: No credentials in OpenClaw config
3. **Comprehensive audit**: Every tool call logged and traceable
4. **Content protection**: Automatic redaction of sensitive data
5. **Cost control**: Track and limit spending per agent

Start with conservative policies and gradually relax based on usage patterns and audit logs.
