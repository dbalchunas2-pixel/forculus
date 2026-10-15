# Credential Management

Forculus provides a secure credential vault for managing API keys, tokens, and other secrets used by AI agents. Credentials are encrypted at rest using the age encryption standard and can be bound to specific tools and scopes.

## Overview

The credential vault system consists of:

- **Encrypted storage**: Credentials are encrypted with age and stored as `.age` files
- **Metadata sidecars**: Each credential has a `.meta.json` file with non-sensitive metadata
- **Credential bindings**: YAML configuration mapping tools to credentials with scope constraints
- **Session tokens**: `fcl_sess_` prefixed tokens for authenticating sessions
- **Automatic injection**: Credentials are injected into requests based on bindings

## Adding Credentials

Use the `forculus cred add` command to add a new credential:

```bash
# Add a GitHub token
forculus cred add github-token

# You'll be prompted for:
# - Credential ID: github-token (suggested from argument)
# - Credential type: api_key, bearer_token, basic_auth, oauth2, custom
# - The secret value (hidden input)
# - Optional metadata (description, tags)
```

### Credential Types

- **api_key**: API keys injected as custom headers or query parameters
- **bearer_token**: OAuth 2.0 bearer tokens (Authorization: Bearer header)
- **basic_auth**: HTTP Basic authentication (username:password)
- **oauth2**: Full OAuth 2.0 flow credentials (client_id, client_secret, refresh_token)
- **custom**: Custom credential formats with user-defined injection

### Storage Format

Credentials are stored in `~/.forculus/vault/`:

```
~/.forculus/vault/
├── github-token.age           # Encrypted credential
├── github-token.meta.json     # Metadata (created_at, type, etc.)
├── aws-key.age
├── aws-key.meta.json
└── bindings.yaml              # Credential bindings
```

The `.age` file contains the encrypted secret value. The `.meta.json` file contains:

```json
{
  "id": "github-token",
  "type": "bearer_token",
  "created_at": "2026-02-15T10:30:00Z",
  "last_used": null,
  "description": "GitHub API access for code operations",
  "tags": ["github", "production"]
}
```

## Credential Bindings

Bindings define which credentials are available to which tools. Edit `~/.forculus/vault/bindings.yaml`:

```yaml
bindings:
  - credential_id: github-token
    tools:
      - "github::*"                    # All GitHub MCP tools
      - "code-assistant::git-push"     # Specific tool
    scopes:
      - read:user
      - repo
    operators: []                      # Empty = all operators allowed

  - credential_id: aws-key
    tools:
      - "aws::s3::*"
      - "aws::ec2::describe-instances"
    scopes:
      - s3:read
      - ec2:read
    operators:
      - "operator-alice"               # Restrict to specific operators

  - credential_id: slack-webhook
    tools:
      - "slack::post-message"
    scopes: []
    max_uses_per_day: 100              # Rate limiting per credential
```

### Binding Fields

- **credential_id**: ID of the credential (must match a .age file)
- **tools**: Glob patterns matching tool names (supports `*`, `?`, `{a,b}`, `[abc]`)
- **scopes**: Required OAuth scopes or permission levels
- **operators**: Restrict to specific operator IDs (empty = all allowed)
- **max_uses_per_day**: Optional rate limit per credential

## Credential Injection

### HTTP Proxy

For HTTP proxy mode, credentials are injected based on the request URL and tool mapping:

```yaml
# In forculus.yaml
vault:
  enabled: true
  vault_dir: ~/.forculus/vault

# Bindings map URLs to tools
http:
  tool_mappings:
    - url_pattern: "https://api.github.com/*"
      tool_name: "github::api"
```

When a request matches, Forculus:

1. Looks up the tool name from the URL pattern
2. Finds matching credential bindings
3. Injects the credential into the request

Example injection for bearer token:

```http
GET /user/repos HTTP/1.1
Host: api.github.com
Authorization: Bearer ghp_xxxxxxxxxxxxxxxxxxxx
```

### MCP Gateway

For MCP mode, credentials are injected into tool parameters or headers:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "github::create-issue",
    "arguments": {
      "repo": "owner/repo",
      "title": "Bug report"
    }
  }
}
```

Forculus injects the credential before forwarding to the MCP server:

```json
{
  "name": "github::create-issue",
  "arguments": {
    "repo": "owner/repo",
    "title": "Bug report",
    "_forculus_credential": "Bearer ghp_xxxxxxxxxxxxxxxxxxxx"
  }
}
```

## Session Tokens

Sessions authenticate agents and track usage across requests.

### Creating Sessions

```bash
# Create a new session
forculus session create --operator alice

# Output:
# Session created: fcl_sess_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
# Store this token securely - it won't be shown again
```

Session tokens have the format: `fcl_sess_` + 32 hexadecimal characters.

### Using Sessions

Sessions are passed via the `X-Forculus-Session` header:

```http
GET /api/resource HTTP/1.1
Host: api.example.com
X-Forculus-Session: fcl_sess_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
```

For MCP, configure the session token in the MCP client configuration.

### Session Storage

Sessions are stored in SQLite: `~/.forculus/vault/sessions.db`

```sql
CREATE TABLE sessions (
    token TEXT PRIMARY KEY,
    operator_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER,
    expires_at INTEGER,
    metadata TEXT
);
```

## Credential Rotation

Rotate credentials regularly to maintain security:

```bash
# Update a credential's secret value
forculus cred rotate github-token

# You'll be prompted for the new secret value
# The .age file is updated, metadata tracks rotation_count
```

### Rotation Best Practices

1. **Regular rotation**: Rotate credentials every 90 days
2. **Incident response**: Rotate immediately if credentials are compromised
3. **Zero downtime**: Update bindings before deleting old credentials
4. **Audit trail**: Check audit logs for credential usage before rotation

```bash
# Check recent usage before rotating
forculus audit query --event-type CredentialInjected --credential github-token --since 7d

# Rotate the credential
forculus cred rotate github-token

# Verify injection is working
forculus audit query --event-type CredentialInjected --credential github-token --since 5m
```

## Listing and Inspecting Credentials

```bash
# List all credentials (shows metadata only, never secrets)
forculus cred list

# Output:
# ID              Type          Created              Last Used            Tags
# github-token    bearer_token  2026-01-15 10:30    2026-02-15 09:45    github, production
# aws-key         api_key       2026-01-20 14:00    2026-02-14 16:20    aws, s3
# slack-webhook   custom        2026-02-01 08:15    Never               slack

# Show details for a specific credential
forculus cred show github-token

# Output includes bindings, usage stats, and metadata
```

## Deleting Credentials

```bash
# Delete a credential and its metadata
forculus cred delete github-token

# Confirmation required
# This removes the .age file and .meta.json file
# Bindings referencing this credential will fail
```

## Security Considerations

1. **Encryption at rest**: All credentials are encrypted with age
2. **No plaintext logs**: Secrets are never logged in plaintext
3. **Session expiry**: Sessions expire after configurable timeout
4. **Least privilege**: Use bindings to restrict credential scope
5. **Audit everything**: All credential operations are audited

## Example Workflow

Complete example of setting up credentials for a GitHub integration:

```bash
# 1. Create a session for the operator
forculus session create --operator alice
# Save token: fcl_sess_abc123...

# 2. Add GitHub credential
forculus cred add github-token
# Type: bearer_token
# Secret: ghp_your_github_token_here

# 3. Edit bindings
cat >> ~/.forculus/vault/bindings.yaml <<EOF
bindings:
  - credential_id: github-token
    tools:
      - "github::*"
    scopes:
      - repo
      - read:user
    operators:
      - alice
EOF

# 4. Test the integration
curl -x http://localhost:8080 \
  -H "X-Forculus-Session: fcl_sess_abc123..." \
  https://api.github.com/user/repos

# 5. Check audit logs
forculus audit query --event-type CredentialInjected --since 1h
```

## Troubleshooting

### Credential Not Found

If credential injection fails, check:

1. Credential file exists: `ls ~/.forculus/vault/github-token.age`
2. Binding is configured: `cat ~/.forculus/vault/bindings.yaml`
3. Tool pattern matches: Use `*` for debugging, then tighten
4. Operator is allowed: Check `operators` field in binding

### Permission Denied

If credential is found but not injected:

1. Check scopes in binding match required scopes
2. Verify operator ID matches session operator
3. Check rate limits: `forculus cred show <id>` for usage stats
4. Review audit logs: `forculus audit query --event-type PolicyDecision`

### Session Invalid

If session is rejected:

1. Verify token format: `fcl_sess_` + 32 hex chars
2. Check expiration: `forculus session list`
3. Verify session exists: Query sessions.db directly if needed
4. Create new session if expired
