# Claude Code Integration

Claude Code is Anthropic's official CLI for Claude, providing agentic capabilities for software development tasks. Forculus integrates with Claude Code via the MCP (Model Context Protocol) to add governance, policy enforcement, and audit logging.

## Overview

Forculus provides Claude Code with:

- **Policy enforcement**: Control which tools Claude Code can use
- **Credential management**: Securely inject API keys and tokens
- **Audit logging**: Track all tool calls and decisions
- **Content inspection**: Scan for secrets, PII, and security issues
- **Rate limiting**: Control request rates and costs
- **Governance metadata**: Show policy decisions in Claude's UI

## Architecture

```
Claude Code CLI
    |
    | (MCP stdio/JSON-RPC)
    |
Forculus MCP Gateway
    |
    | (Policy, Credentials, Audit, Content Inspection)
    |
MCP Servers (filesystem, github, slack, etc.)
```

Claude Code connects to Forculus's MCP gateway, which enforces policies and forwards approved requests to the actual MCP servers.

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
        - "/Users/alice/projects"
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
```

### 2. Configure Claude Code

Edit Claude Code's MCP settings file (`~/.claude/config.json` or similar):

```json
{
  "mcpServers": {
    "forculus": {
      "command": "forculus",
      "args": ["mcp", "gateway"],
      "env": {
        "FORCULUS_SESSION_TOKEN": "bwk_sess_your_session_token_here"
      }
    }
  }
}
```

Note: Instead of connecting directly to MCP servers, Claude Code connects to Forculus's gateway.

### 3. Create Session Token

```bash
# Create a session for your operator ID
forculus session create --operator alice

# Output:
# Session created: bwk_sess_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
# Store this token securely - it won't be shown again
```

Copy the token into your Claude Code MCP config (step 2 above).

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
    operators:
      - alice

  - credential_id: slack-token
    tools:
      - "slack::*"
    scopes:
      - chat:write
    operators:
      - alice
```

### 6. Configure Policies

Edit `~/.forculus/policies.yaml`:

```yaml
policies:
  # Allow filesystem operations
  - scope: "tool:filesystem::*"
    action: allow
    priority: 100

  # Allow GitHub read operations
  - scope: "tool:github::list-*"
    action: allow
    priority: 100

  - scope: "tool:github::get-*"
    action: allow
    priority: 100

  # Require approval for GitHub write operations
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

  # Allow Slack operations
  - scope: "tool:slack::*"
    action: allow
    priority: 100

  # Default deny
  - scope: "*"
    action: deny
    priority: 0
```

## Session Token Delivery

The session token is passed via the `FORCULUS_SESSION_TOKEN` environment variable when starting the MCP gateway. Forculus stores this token internally and uses it for all requests.

### Token Management

The MCP gateway stores the session token in a `Mutex<Option<String>>` for thread-safe access:

```rust
struct McpGateway {
    session_token: Arc<Mutex<Option<String>>>,
    // ...
}
```

When processing requests, Forculus uses this token to:
1. Validate the session
2. Look up the operator ID
3. Enforce operator-specific policies
4. Inject operator-specific credentials
5. Log events with operator context

## Governance and Permission Prompts

Forculus's governance decisions are surfaced in Claude Code's UI through governance metadata.

### Policy Allow (No Approval Required)

When a policy allows a tool without requiring approval:

```
Claude Code UI:
> I'll help you list the repositories.

[Tool: github::list-repos]
Status: Allowed by policy
Policy: allow-github-read (priority: 100)
Scope: tool:github::list-*

[Executing...]
```

### Policy Allow (Approval Required)

When a policy requires approval:

```
Claude Code UI:
> I'll create the GitHub issue, but this requires your approval.

[Tool: github::create-issue]
Status: Requires approval
Policy: github-write-approval (priority: 100)
Scope: tool:github::create-*
Parameters:
  repo: owner/repo
  title: "Bug: Login fails"
  body: "Steps to reproduce..."

[Approve] [Deny]
```

After user approves:

```
[Tool: github::create-issue]
Status: Approved by user
Executing...

Result: Issue #123 created successfully
```

### Policy Deny

When a policy denies a tool:

```
Claude Code UI:
> I cannot delete the repository because this operation is blocked by policy.

[Tool: github::delete-repo]
Status: Denied by policy
Policy: deny-github-destructive (priority: 200)
Scope: tool:github::delete-*
Reason: Destructive operations are not allowed

I can help you archive the repository instead, which is a safer alternative.
```

### Content Inspection Block

When content inspection blocks a request:

```
Claude Code UI:
> I attempted to send the message, but it was blocked by content inspection.

[Tool: slack::post-message]
Status: Blocked by content inspection
Rule: aws-key (severity: Critical)
Reason: AWS access key detected in message content

I've removed the sensitive data from the message. Would you like me to send it without the access key?
```

## Example Session

Complete example of using Claude Code with Forculus governance:

### Setup

```bash
# 1. Start with Forculus configured (see Configuration section above)

# 2. Create session
forculus session create --operator alice
# Token: bwk_sess_abc123...

# 3. Add to Claude Code config
# (See step 2 in Configuration)

# 4. Start Claude Code
claude-code
```

### Interaction

```
User: Can you list my GitHub repositories?

Claude: I'll list your GitHub repositories using the GitHub MCP server.

[Checking policy...]
[Tool: github::list-repos]
Status: Allowed by policy
Policy: allow-github-read

[Executing...]
[Success]

Here are your repositories:
1. owner/repo1 - A web application
2. owner/repo2 - CLI tool
3. owner/repo3 - Library

User: Create an issue in repo1 titled "Add login button"

Claude: I'll create the issue, but this requires your approval since it's a write operation.

[Tool: github::create-issue]
Status: Requires approval
Policy: github-write-approval
Parameters:
  repo: owner/repo1
  title: "Add login button"
  body: "We need to add a login button to the homepage."

[Approve] [Deny]

User: [Clicks Approve]

Claude: [Executing...]
[Success]

Issue #42 created successfully in owner/repo1.

User: Delete repo3, I don't need it anymore

Claude: I cannot delete the repository because this operation is blocked by policy. Destructive operations like deleting repositories require additional safeguards.

[Tool: github::delete-repo]
Status: Denied by policy
Policy: deny-github-destructive
Reason: Destructive operations are not allowed

Instead, I can:
1. Archive the repository (makes it read-only)
2. Make it private
3. Transfer it to another owner

Would you like me to do any of these?

User: Can you post "Our AWS key is AKIAIOSFODNN7EXAMPLE" to Slack?

Claude: I attempted to send the message, but it was blocked by content inspection.

[Tool: slack::post-message]
Status: Blocked by content inspection
Rule: aws-key (severity: Critical)
Reason: AWS access key detected in message content

I detected an AWS access key in the message. Posting credentials to Slack is a security risk. I've blocked this operation.

If you need to share AWS credentials with your team:
1. Use AWS IAM roles instead of access keys
2. Use a secure secret management system
3. Never post credentials in chat

Would you like me to help you set up secure credential sharing?
```

## Audit Trail

All interactions are logged to Forculus's audit system:

```bash
# View recent Claude Code activity
forculus audit query --operator alice --since 1h

# Output:
# 2026-02-15 10:30:00 | SessionCreated | alice | Created session bwk_sess_abc123...
# 2026-02-15 10:31:00 | RequestProcessed | alice | github::list-repos | 200 OK
# 2026-02-15 10:31:00 | PolicyDecision | alice | github::list-repos | allow
# 2026-02-15 10:32:00 | RequestProcessed | alice | github::create-issue | 200 OK
# 2026-02-15 10:32:00 | PolicyDecision | alice | github::create-issue | allow (approval required)
# 2026-02-15 10:32:00 | CredentialInjected | alice | github-token | github::create-issue
# 2026-02-15 10:33:00 | PolicyDecision | alice | github::delete-repo | deny
# 2026-02-15 10:34:00 | ContentInspectionTriggered | alice | aws-key | Block

# Export for analysis
forculus audit export --operator alice --since 24h --output claude-activity.jsonl
```

## Best Practices

### 1. Use Scoped Sessions

Create different sessions for different contexts:

```bash
# Development session
forculus session create --operator alice --metadata '{"env":"dev"}'

# Production session (with stricter policies)
forculus session create --operator alice --metadata '{"env":"prod"}'
```

### 2. Principle of Least Privilege

Start with minimal permissions and add as needed:

```yaml
# Week 1: Read-only access
policies:
  - scope: "tool:github::list-*"
    action: allow
  - scope: "tool:github::get-*"
    action: allow
  - scope: "*"
    action: deny

# Week 2: Add write with approval
policies:
  - scope: "tool:github::create-*"
    action: allow
    require_approval: true
```

### 3. Monitor for Anomalies

Set up alerts for unusual activity:

```bash
#!/bin/bash
# claude-anomaly-detection.sh

# Alert if more than 10 policy denials in 1 hour
DENIALS=$(forculus audit query \
  --operator alice \
  --event-type PolicyDecision \
  --since 1h | \
  grep "deny" | wc -l)

if [ "$DENIALS" -gt 10 ]; then
  echo "ALERT: Unusual number of policy denials for alice"
fi
```

### 4. Regular Audit Reviews

Review Claude Code activity weekly:

```bash
# Weekly review
forculus audit stats --operator alice --since 7d

# Look for:
# - Denied operations (why?)
# - Content inspection blocks (security issues?)
# - High request rates (runaway agent?)
# - Expensive tool usage (cost optimization?)
```

### 5. Rotate Session Tokens

Rotate session tokens monthly:

```bash
# Create new session
NEW_TOKEN=$(forculus session create --operator alice | grep "bwk_sess_" | awk '{print $3}')

# Update Claude Code config
# (Manual step or automation)

# Revoke old session
forculus session revoke bwk_sess_old_token_here
```

## Troubleshooting

### Session Invalid

If Claude Code can't connect:

1. Check session token: `forculus session list`
2. Verify token in Claude Code config
3. Check expiration: Sessions expire after 24 hours by default
4. Create new session if needed

### Tool Not Available

If Claude Code can't see expected tools:

1. Check MCP server configuration in `forculus.yaml`
2. Verify MCP server is starting: Check Forculus logs
3. Test MCP server directly: `npx @modelcontextprotocol/server-github`
4. Check policy: Tool may be denied by policy

### Credential Not Injected

If tool calls fail due to missing credentials:

1. Check credential exists: `forculus cred list`
2. Verify binding: `cat ~/.forculus/vault/bindings.yaml`
3. Check tool name matches binding pattern
4. Review audit logs: `forculus audit query --event-type CredentialInjected`

### Performance Issues

If Claude Code is slow:

1. Check rate limits: `forculus rate-limit status`
2. Disable content inspection for responses: `scan_responses: false`
3. Reduce max_body_size in content inspection
4. Check MCP server performance: May be the bottleneck

## Advanced Configuration

### Custom Metadata in Responses

Add custom governance metadata to tool responses:

```yaml
mcp:
  governance_metadata:
    include_policy_details: true
    include_credential_info: true
    include_cost_info: true
```

This adds metadata to every tool response:

```json
{
  "result": {...},
  "_governance": {
    "policy_decision": {
      "decision": "allow",
      "rule_id": "allow-github-read",
      "priority": 100
    },
    "credential_used": {
      "credential_id": "github-token",
      "scopes": ["repo", "read:user"]
    },
    "cost": {
      "usd": 0.001,
      "operator_total_usd": 45.67
    }
  }
}
```

### Multi-Operator Support

Share Forculus instance across multiple operators:

```bash
# Each operator creates their own session
forculus session create --operator alice
forculus session create --operator bob
forculus session create --operator charlie

# Each operator configures their Claude Code with their token
# Forculus enforces operator-specific policies and credentials
```

### Integration with CI/CD

Use Claude Code with Forculus in CI/CD:

```yaml
# .github/workflows/claude-code.yml
name: Claude Code Analysis
on: [pull_request]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Setup Forculus
        run: |
          # Install Forculus
          curl -L https://github.com/forculus/forculus/releases/download/latest/forculus -o /usr/local/bin/forculus
          chmod +x /usr/local/bin/forculus

          # Create session for CI
          export FORCULUS_SESSION=$(forculus session create --operator ci-bot --format json | jq -r '.token')
          echo "FORCULUS_SESSION_TOKEN=$FORCULUS_SESSION" >> $GITHUB_ENV

      - name: Run Claude Code Analysis
        run: |
          claude-code analyze --diff origin/main...HEAD
```
