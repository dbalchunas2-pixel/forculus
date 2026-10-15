# Codex Integration

Codex is an AI agent for software development that operates through HTTP APIs. Forculus integrates with Codex via the HTTP forward proxy to add governance, policy enforcement, and audit logging.

## Overview

Forculus provides Codex with:

- **Policy enforcement**: Control which APIs Codex can access
- **Credential management**: Securely inject API keys and tokens
- **Audit logging**: Track all HTTP requests and decisions
- **Content inspection**: Scan for secrets, PII, and security issues
- **Rate limiting**: Control request rates and costs
- **TLS MITM**: Inspect HTTPS traffic for governance

## Architecture

```
Codex Agent
    |
    | (HTTP/HTTPS proxy)
    |
Forculus HTTP Proxy
    |
    | (Policy, Credentials, Audit, Content Inspection)
    |
External APIs (GitHub, Slack, AWS, etc.)
```

Codex is configured to route all HTTP traffic through Forculus's forward proxy, which enforces policies and injects credentials before forwarding to external APIs.

## Configuration

### 1. Configure Forculus HTTP Proxy

Create or edit `~/.forculus/forculus.yaml`:

```yaml
http:
  enabled: true
  listen_addr: "127.0.0.1:8080"

  # TLS MITM for HTTPS inspection
  tls:
    enabled: true
    ca_cert: ~/.forculus/ca/forculus-ca.crt
    ca_key: ~/.forculus/ca/forculus-ca.key

  # URL-to-tool mappings for policy enforcement
  tool_mappings:
    - url_pattern: "https://api.github.com/*"
      tool_name: "github::api"

    - url_pattern: "https://api.github.com/repos/*/issues"
      tool_name: "github::create-issue"
      methods: ["POST"]

    - url_pattern: "https://api.github.com/repos/*/issues/*"
      tool_name: "github::update-issue"
      methods: ["PATCH"]

    - url_pattern: "https://api.github.com/repos/*"
      tool_name: "github::delete-repo"
      methods: ["DELETE"]

    - url_pattern: "https://slack.com/api/chat.postMessage"
      tool_name: "slack::post-message"
      methods: ["POST"]

    - url_pattern: "https://*.amazonaws.com/*"
      tool_name: "aws::api"

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

### 2. Generate TLS CA Certificate

Forculus needs a CA certificate to perform TLS MITM:

```bash
# Generate CA certificate and key
forculus ca generate

# Output:
# CA certificate: ~/.forculus/ca/forculus-ca.crt
# CA key: ~/.forculus/ca/forculus-ca.key
#
# Install the CA certificate in your system trust store:
# macOS: sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.forculus/ca/forculus-ca.crt
# Linux: sudo cp ~/.forculus/ca/forculus-ca.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates
# Windows: certutil -addstore -f "ROOT" %USERPROFILE%\.forculus\ca\forculus-ca.crt
```

Install the CA certificate in your system trust store using the command for your OS.

### 3. Start Forculus Proxy

```bash
# Start the HTTP proxy
forculus proxy start

# Output:
# Forculus HTTP Proxy listening on 127.0.0.1:8080
# TLS MITM enabled with CA: ~/.forculus/ca/forculus-ca.crt
```

### 4. Configure Codex to Use Proxy

Configure Codex to route all HTTP traffic through Forculus:

```bash
# Set proxy environment variables
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080

# Start Codex
codex start
```

Or in Codex configuration file:

```json
{
  "proxy": {
    "http": "http://localhost:8080",
    "https": "http://localhost:8080"
  }
}
```

### 5. Create Session Token

```bash
# Create a session for Codex
forculus session create --operator codex-agent

# Output:
# Session created: fcl_sess_c1d2e3f4g5h6i7j8k9l0m1n2o3p4q5r6
```

Configure Codex to send this token in requests:

```json
{
  "headers": {
    "X-Forculus-Session": "fcl_sess_c1d2e3f4g5h6i7j8k9l0m1n2o3p4q5r6"
  }
}
```

### 6. Add Credentials

```bash
# Add GitHub token
forculus cred add github-token
# Type: bearer_token
# Secret: ghp_your_github_token_here

# Add Slack token
forculus cred add slack-token
# Type: bearer_token
# Secret: xoxb-your-slack-token-here

# Add AWS credentials
forculus cred add aws-key
# Type: custom
# Secret: {"access_key_id": "AKIAIOSFODNN7EXAMPLE", "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
```

### 7. Configure Credential Bindings

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
      - codex-agent

  - credential_id: slack-token
    tools:
      - "slack::*"
    scopes:
      - chat:write
    operators:
      - codex-agent

  - credential_id: aws-key
    tools:
      - "aws::*"
    scopes:
      - s3:read
      - ec2:read
    operators:
      - codex-agent
```

### 8. Configure Policies

Edit `~/.forculus/policies.yaml`:

```yaml
policies:
  # Allow GitHub read operations
  - scope: "tool:github::api"
    action: allow
    priority: 100
    conditions:
      - type: http_method
        value: ["GET", "HEAD"]

  # Require approval for GitHub write operations
  - scope: "tool:github::create-issue"
    action: allow
    priority: 100
    require_approval: true

  - scope: "tool:github::update-issue"
    action: allow
    priority: 100
    require_approval: true

  # Block destructive GitHub operations
  - scope: "tool:github::delete-repo"
    action: deny
    priority: 200

  # Allow Slack operations
  - scope: "tool:slack::post-message"
    action: allow
    priority: 100

  # Allow AWS read operations
  - scope: "tool:aws::api"
    action: allow
    priority: 100
    conditions:
      - type: http_method
        value: ["GET", "HEAD"]

  # Default deny
  - scope: "*"
    action: deny
    priority: 0
```

## Tool Mappings

Tool mappings translate HTTP requests to tool names for policy enforcement.

### URL Pattern Matching

Patterns support wildcards:

- `*`: Matches any sequence of characters (excluding `/`)
- `**`: Matches any sequence of characters (including `/`)
- `?`: Matches a single character
- `{a,b}`: Matches either `a` or `b`
- `[abc]`: Matches a single character from the set

Examples:

```yaml
tool_mappings:
  # Match all GitHub API endpoints
  - url_pattern: "https://api.github.com/**"
    tool_name: "github::api"

  # Match specific endpoint with path parameters
  - url_pattern: "https://api.github.com/repos/{owner}/{repo}/issues"
    tool_name: "github::list-issues"
    methods: ["GET"]

  # Match with query parameters
  - url_pattern: "https://api.github.com/search/repositories?q=*"
    tool_name: "github::search-repos"

  # Match AWS S3 buckets
  - url_pattern: "https://*.s3.amazonaws.com/**"
    tool_name: "aws::s3::api"

  # Match AWS EC2 API
  - url_pattern: "https://ec2.*.amazonaws.com/*"
    tool_name: "aws::ec2::api"
```

### Method-Specific Mappings

Map different methods on the same URL to different tools:

```yaml
tool_mappings:
  # GET = list issues
  - url_pattern: "https://api.github.com/repos/*/issues"
    tool_name: "github::list-issues"
    methods: ["GET"]

  # POST = create issue
  - url_pattern: "https://api.github.com/repos/*/issues"
    tool_name: "github::create-issue"
    methods: ["POST"]

  # PATCH = update issue
  - url_pattern: "https://api.github.com/repos/*/issues/*"
    tool_name: "github::update-issue"
    methods: ["PATCH"]

  # DELETE = delete issue
  - url_pattern: "https://api.github.com/repos/*/issues/*"
    tool_name: "github::delete-issue"
    methods: ["DELETE"]
```

## Credential Injection

Forculus automatically injects credentials based on tool mappings and bindings.

### Bearer Token Injection

For `bearer_token` credentials:

```yaml
# Binding
bindings:
  - credential_id: github-token
    tools:
      - "github::*"
```

Original request:
```http
GET /user/repos HTTP/1.1
Host: api.github.com
```

Injected request:
```http
GET /user/repos HTTP/1.1
Host: api.github.com
Authorization: Bearer ghp_xxxxxxxxxxxxxxxxxxxx
```

### Custom Header Injection

For `api_key` credentials with custom headers:

```yaml
# Credential metadata
{
  "id": "openai-key",
  "type": "api_key",
  "injection": {
    "header": "X-OpenAI-API-Key"
  }
}
```

Original request:
```http
POST /v1/chat/completions HTTP/1.1
Host: api.openai.com
```

Injected request:
```http
POST /v1/chat/completions HTTP/1.1
Host: api.openai.com
X-OpenAI-API-Key: sk-xxxxxxxxxxxxxxxxxxxx
```

### AWS Signature Injection

For AWS credentials:

```yaml
# Credential
{
  "id": "aws-key",
  "type": "custom",
  "value": {
    "access_key_id": "AKIAIOSFODNN7EXAMPLE",
    "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  }
}
```

Forculus calculates AWS Signature Version 4 and adds headers:

```http
GET /bucket/object HTTP/1.1
Host: s3.amazonaws.com
Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20260215/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=...
X-Amz-Date: 20260215T103045Z
```

## Example Session

Complete example of using Codex with Forculus:

### Setup

```bash
# 1. Start Forculus proxy
forculus proxy start

# 2. Create session
forculus session create --operator codex-agent
# Token: fcl_sess_abc123...

# 3. Configure Codex to use proxy and session token
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080

# 4. Start Codex
codex start --header "X-Forculus-Session: fcl_sess_abc123..."
```

### Interaction

```
Codex: Listing GitHub repositories...

[HTTP Request]
GET https://api.github.com/user/repos
X-Forculus-Session: fcl_sess_abc123...

[Forculus Processing]
1. Extract session: codex-agent
2. Map URL to tool: github::api
3. Check policy: allow (GET method)
4. Inject credential: github-token
5. Forward request

[HTTP Response]
200 OK
[{"name": "repo1", ...}, {"name": "repo2", ...}]

Codex: Found 2 repositories: repo1, repo2

---

Codex: Creating issue in repo1...

[HTTP Request]
POST https://api.github.com/user/repos/repo1/issues
X-Forculus-Session: fcl_sess_abc123...
Content-Type: application/json

{"title": "Add login button", "body": "We need a login button"}

[Forculus Processing]
1. Extract session: codex-agent
2. Map URL to tool: github::create-issue
3. Check policy: allow (require_approval: true)
4. BLOCK - Approval required

[HTTP Response]
403 Forbidden
X-Forculus-Approval-Required: true

{
  "error": {
    "code": "approval_required",
    "message": "This operation requires approval",
    "approval_url": "https://forculus.local/approve?request_id=req_xyz"
  }
}

Codex: Operation requires approval. Visit: https://forculus.local/approve?request_id=req_xyz

---

[User approves via Forculus UI]

Codex: Retrying after approval...

[HTTP Request]
POST https://api.github.com/user/repos/repo1/issues
X-Forculus-Session: fcl_sess_abc123...
X-Forculus-Approval-Token: appr_xyz
Content-Type: application/json

{"title": "Add login button", "body": "We need a login button"}

[Forculus Processing]
1. Verify approval token
2. Inject credential: github-token
3. Forward request

[HTTP Response]
201 Created
{"number": 42, "title": "Add login button", ...}

Codex: Issue #42 created successfully

---

Codex: Deleting repository repo2...

[HTTP Request]
DELETE https://api.github.com/repos/owner/repo2
X-Forculus-Session: fcl_sess_abc123...

[Forculus Processing]
1. Map URL to tool: github::delete-repo
2. Check policy: deny
3. BLOCK

[HTTP Response]
403 Forbidden

{
  "error": {
    "code": "policy_denied",
    "message": "This operation is denied by policy",
    "policy_rule": "deny-github-destructive"
  }
}

Codex: Operation denied by policy. Cannot delete repository.

---

Codex: Posting to Slack...

[HTTP Request]
POST https://slack.com/api/chat.postMessage
X-Forculus-Session: fcl_sess_abc123...
Content-Type: application/json

{"channel": "#general", "text": "Our AWS key is AKIAIOSFODNN7EXAMPLE"}

[Forculus Processing]
1. Map URL to tool: slack::post-message
2. Check policy: allow
3. Content inspection: DETECT aws-key
4. BLOCK - Content inspection

[HTTP Response]
403 Forbidden

{
  "error": {
    "code": "content_inspection_failed",
    "message": "Request blocked: AWS access key detected",
    "rule_id": "aws-key",
    "severity": "Critical"
  }
}

Codex: Request blocked by content inspection. Cannot post sensitive data.
```

## Audit Trail

All HTTP requests are logged:

```bash
# View recent Codex activity
forculus audit query --operator codex-agent --since 1h

# Output:
# 2026-02-15 10:30:00 | RequestProcessed | codex-agent | github::api | GET /user/repos | 200
# 2026-02-15 10:31:00 | PolicyDecision | codex-agent | github::api | allow
# 2026-02-15 10:31:00 | CredentialInjected | codex-agent | github-token | github::api
# 2026-02-15 10:32:00 | RequestProcessed | codex-agent | github::create-issue | POST /repos/*/issues | 403
# 2026-02-15 10:32:00 | PolicyDecision | codex-agent | github::create-issue | allow (approval required)
# 2026-02-15 10:33:00 | RequestProcessed | codex-agent | github::delete-repo | DELETE /repos/* | 403
# 2026-02-15 10:33:00 | PolicyDecision | codex-agent | github::delete-repo | deny
# 2026-02-15 10:34:00 | ContentInspectionTriggered | codex-agent | aws-key | Block
```

## Best Practices

### 1. Map URLs to Granular Tools

Create specific tool names for fine-grained policies:

```yaml
tool_mappings:
  # Granular GitHub mappings
  - url_pattern: "https://api.github.com/repos/*/issues"
    tool_name: "github::list-issues"
    methods: ["GET"]

  - url_pattern: "https://api.github.com/repos/*/issues"
    tool_name: "github::create-issue"
    methods: ["POST"]

  # Generic fallback
  - url_pattern: "https://api.github.com/**"
    tool_name: "github::api"
```

### 2. Use Content Inspection for Sensitive APIs

Enable content inspection for APIs that handle sensitive data:

```yaml
content_inspection:
  enabled: true
  scan_requests: true
  scan_responses: true

  # Focus on sensitive endpoints
  url_patterns:
    - "https://api.github.com/**"
    - "https://slack.com/api/**"
    - "https://*.amazonaws.com/**"
```

### 3. Monitor Proxy Performance

The proxy adds latency. Monitor and optimize:

```bash
# Check average response times
forculus audit export --event-type RequestProcessed --since 24h --output requests.jsonl
cat requests.jsonl | jq -r '.details.response_time_ms' | awk '{sum+=$1; count++} END {print "Average: " sum/count "ms"}'

# Identify slow requests
cat requests.jsonl | jq 'select(.details.response_time_ms > 1000)'
```

### 4. Rotate CA Certificate Annually

Rotate the TLS CA certificate annually:

```bash
# Generate new CA
forculus ca generate --force

# Install new CA in system trust store
# Remove old CA from trust store
```

### 5. Use Session Metadata

Add metadata to sessions for better audit trails:

```bash
forculus session create \
  --operator codex-agent \
  --metadata '{"env":"production","version":"1.2.3","hostname":"codex-prod-1"}'
```

## Troubleshooting

### TLS Certificate Errors

If Codex reports TLS certificate errors:

1. Verify CA is installed in system trust store
2. Check CA certificate path in `forculus.yaml`
3. Regenerate CA if corrupted: `forculus ca generate --force`
4. Check Codex trusts system certificates

### Credential Not Injected

If API calls fail with 401 Unauthorized:

1. Check tool mapping: Does URL match pattern?
2. Verify credential binding: `cat ~/.forculus/vault/bindings.yaml`
3. Check session: `forculus session list`
4. Review audit logs: `forculus audit query --event-type CredentialInjected`

### Proxy Not Forwarding

If requests hang or timeout:

1. Check proxy is running: `ps aux | grep forculus`
2. Verify listen address: `forculus config show`
3. Test proxy directly: `curl -x http://localhost:8080 https://api.github.com`
4. Check logs: `forculus proxy logs`

### Performance Issues

If proxy is slow:

1. Disable content inspection for responses: `scan_responses: false`
2. Reduce max_body_size: `max_body_size: 262144` (256 KB)
3. Disable TLS MITM if not needed: `tls.enabled: false`
4. Check network latency to upstream APIs

## Advanced Configuration

### Conditional Credential Injection

Inject different credentials based on URL:

```yaml
bindings:
  # Production GitHub token
  - credential_id: github-token-prod
    tools:
      - "github::*"
    operators:
      - codex-agent
    conditions:
      - type: url_contains
        value: "/repos/prod-org/"

  # Development GitHub token
  - credential_id: github-token-dev
    tools:
      - "github::*"
    operators:
      - codex-agent
    conditions:
      - type: url_contains
        value: "/repos/dev-org/"
```

### Multi-Agent Support

Run multiple Codex agents with different policies:

```bash
# Production agent
forculus session create --operator codex-prod --metadata '{"env":"prod"}'

# Development agent
forculus session create --operator codex-dev --metadata '{"env":"dev"}'

# Different policies per operator
policies:
  - scope: "tool:github::delete-repo"
    action: deny
    conditions:
      - type: operator
        value: "codex-prod"  # Deny for production

  - scope: "tool:github::delete-repo"
    action: allow
    conditions:
      - type: operator
        value: "codex-dev"  # Allow for development
```
