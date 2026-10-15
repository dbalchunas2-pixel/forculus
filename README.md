# Forculus

**Local-first governance layer for AI agents.** God of the door: he decides when it opens.

Forculus sits between AI agents and external tools, enforcing policies, managing credentials, inspecting content, and maintaining a complete audit trail. One policy governs all your agents - Claude Code, Codex, or any MCP/HTTP client.

> **Provenance:** Forculus is a hard fork of [Bulwark](https://github.com/claudius-ars/bulwark) (Apache-2.0), renamed and extended with tool-definition hash pinning and Forculus-specific hardening. Attribution and change record per Apache-2.0 4(b): [NOTICE](./NOTICE) and [CHANGES.md](./CHANGES.md).

## Why Forculus?

AI agents are powerful but ungoverned. They can access any tool, leak any credential, and leave no audit trail. Forculus fixes this:

- **Policy enforcement** - YAML-based rules control which tools agents can use, with glob patterns, scope-based precedence, and hot-reload
- **Credential management** - Agents never see real secrets. Forculus injects credentials at the last mile, encrypted at rest with age
- **Content inspection** - Scan requests and responses for secrets, PII, and prompt injection. Block or redact automatically
- **Audit logging** - Every action recorded in a tamper-evident SQLite database with blake3 hash chains
- **Rate limiting** - Token-bucket rate limits per session, operator, tool, or globally. Cost tracking with budget enforcement
- **MCP-native** - Works as an MCP gateway or HTTP forward proxy. Governance metadata on every tool call response

## Install

```bash
# From source (macOS / Linux, Rust toolchain required)
git clone https://github.com/dbalchunas2-pixel/forculus.git
cd forculus && cargo build --release

# Prebuilt binaries, Homebrew tap, and Docker images: coming soon
```

## Quick Start: Govern Claude Code with GitHub

This walkthrough connects Claude Code to GitHub through Forculus. Every tool call is policy-evaluated, audited, and credential-injected - in about 5 minutes.

**Prerequisites:** [Claude Code](https://code.claude.com/) installed, a [GitHub personal access token](https://github.com/settings/tokens), and Node.js/npm (for the GitHub MCP server).

### 1. Initialize and verify

```bash
forculus init my-project && cd my-project
forculus doctor
```

`doctor` runs 9 diagnostic checks. All should pass.

### 2. Store your GitHub token

```bash
forculus cred add github-token --type bearer_token
# Prompts for the token - hidden input, encrypted with age at rest
```

Configure the credential-to-tool binding in your bindings file so Forculus knows to inject this token for GitHub tool calls.

### 3. Configure the upstream GitHub server

Edit `forculus.yaml`:

```yaml
mcp_gateway:
  upstream_servers:
    - name: github
      command: "npx"
      args: ["-y", "@modelcontextprotocol/server-github"]
      env:
        GITHUB_PERSONAL_ACCESS_TOKEN: "${GITHUB_TOKEN}"

policy:
  policies_dir: "./policies"
  hot_reload: true

audit:
  enabled: true

inspect:
  enabled: true
  inspect_requests: true
  inspect_responses: true
```

Make sure `GITHUB_TOKEN` is set in your shell (`export GITHUB_TOKEN=ghp_...`).

### 4. Write a policy

```bash
cat > policies/base.yaml << 'EOF'
metadata:
  name: quickstart-policy
  scope: global

rules:
  - name: allow-reads
    description: "Allow all read operations"
    match:
      actions: ["read_*", "get_*", "list_*", "search_*"]
    verdict: allow
    priority: 10

  - name: allow-github-writes
    description: "Allow creating issues, comments, PRs"
    match:
      tools: ["github__*"]
      actions: ["create_*", "update_*"]
    verdict: allow
    priority: 10

  - name: block-destructive
    description: "Block all delete and force-push operations"
    match:
      actions: ["delete_*", "force_push_*"]
    verdict: deny
    priority: 20
    message: "Destructive operations are blocked by policy"

  - name: default-deny
    match: {}
    verdict: deny
    priority: -100
    message: "No policy explicitly allows this action"
EOF

forculus policy validate
```

### 5. Create a session and connect Claude Code

```bash
# Create a session (--ttl is in seconds: 28800 = 8 hours)
forculus session create --operator $(whoami) --agent-type claude-code --ttl 28800
# -> Token: fcl_sess_7f3a...

export FORCULUS_SESSION="fcl_sess_7f3a..."   # paste your actual token

# Register Forculus as an MCP server in Claude Code
claude mcp add --transport stdio forculus \
  --env FORCULUS_SESSION=$FORCULUS_SESSION \
  -- forculus mcp start
```

### 6. Use Claude Code - now governed

Start Claude Code. GitHub tools appear namespaced as `github__list_issues`, `github__create_issue`, etc.

Try it:

> "List the open issues in my repo"

Open a second terminal:

```bash
forculus audit tail
```

```
22:01:03  github__list_issues   ✓ allow   3ms  (allow-reads)
```

Every call is logged with the verdict, matched rule, and timing. Now try something destructive:

> "Delete issue #1"

```
22:02:01  github__delete_issue  ✗ deny    <1ms (block-destructive)
```

Blocked. Sub-millisecond - policy evaluation happens in memory. The agent gets a structured error explaining which rule denied it.

### What just happened

Claude Code connected to Forculus (not directly to GitHub). For every tool call, Forculus validated the session, scanned for secrets/PII, evaluated the policy, injected the real GitHub token, scanned the response, and recorded a tamper-evident audit event. Same agent experience - full governance underneath.

## Going Deeper

**Content inspection** - Built-in patterns scan for AWS keys, GitHub tokens, private keys, PII, and prompt injection. Redaction happens before content reaches the agent.

```bash
forculus inspect rules
forculus inspect scan --text "my key is AKIAIOSFODNN7EXAMPLE"
```

**Policy replay** - Preview the impact of policy changes against real audit history before deploying:

```bash
forculus policy test --dir ./new-policies/ --since 1h
```

**Audit forensics** - Reconstruct a session timeline and verify the hash chain:

```bash
forculus session inspect <session-id>
forculus audit verify
forculus audit export --since 24h --format json
```

**HTTP proxy mode** - For non-MCP agents, Forculus runs as a forward proxy with TLS interception:

```bash
forculus proxy start
forculus ca export   # trust the CA in your HTTP client
```

## Architecture

```
+-------------+     +------------------------------------------------+     +--------------+
|             |     |                   Forculus                     |     |              |
|  AI Agent   |---->|  Session > Inspect > Policy > Inject > Proxy   |---->|  Upstream    |
|  (Claude,   |<----|  <---- Audit <---- Inspect <---- Response <----|<----|  Tool/API    |
|   Codex,    |     |                                                |     |              |
|   custom)   |     +------------------------------------------------+     +--------------+
+-------------+
```

## Integration Modes

| Mode | Transport | Best For |
|------|-----------|----------|
| MCP Gateway (stdio) | stdio/JSON-RPC | Claude Code, any MCP client |
| MCP Gateway (HTTP) | Streamable HTTP | Remote agents, MCP registry, multi-agent |
| HTTP Proxy | HTTP/HTTPS | Codex, curl, any HTTP client |

## Example Policy

```yaml
# policies/base.yaml
metadata:
  name: my-policy
  scope: global

rules:
  - name: allow-reads
    verdict: allow
    priority: 10
    match:
      actions: ["read*", "get*", "list*"]

  - name: block-destructive-in-prod
    verdict: deny
    priority: 100
    match:
      actions: ["delete*", "drop*"]
    conditions:
      environments: ["production"]

  - name: default-deny
    verdict: deny
    match: {}
```

See [examples/policies/](./examples/policies/) for complete policy sets (startup, enterprise, development, multi-agent).

## CLI

```
forculus init <path>              # Scaffold a new project
forculus proxy start              # Start HTTP/HTTPS proxy
forculus mcp start                # Start MCP gateway (stdio)
forculus mcp serve                # Start MCP gateway (HTTP)
forculus doctor                   # Diagnose setup issues (9 checks)
forculus status                   # Health dashboard
forculus policy validate          # Validate policy files
forculus policy test --dir <path> # Test policies against audit log
forculus session create|list|revoke|inspect
forculus cred add|list|remove|test
forculus audit search|tail|stats|export|verify
forculus inspect scan|rules       # Content inspection
forculus ca export|path           # CA certificate management
forculus completions <shell>      # Shell completions (bash/zsh/fish)
```

## Documentation

- [Getting Started](./docs/getting-started.md)
- [Architecture Overview](./docs/architecture.md)
- [Policy Reference](./docs/policy-reference.md)
- [Configuration Reference](./docs/configuration.md)
- [Credential Management](./docs/credentials.md)
- [Audit System](./docs/audit.md)
- [Content Inspector](./docs/content-inspector.md)
- [Rate Limiting](./docs/rate-limiting.md)
- [Threat Model](./docs/threat-model.md)
- Agent Guides: [Claude Code](./docs/agents/claude-code.md) | [Codex](./docs/agents/codex.md)

## Development

```bash
git clone https://github.com/dbalchunas2-pixel/forculus.git
cd forculus
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

### Project Structure

```
crates/
  cli/        # CLI binary and commands
  proxy/      # HTTP/HTTPS forward proxy with TLS MITM
  mcp/        # MCP governance gateway
  config/     # Configuration loading and types
  policy/     # YAML policy engine with hot-reload
  vault/      # Credential storage and session management
  audit/      # Tamper-evident audit logging
  inspect/    # Content inspection (secrets, PII, injection)
  ratelimit/  # Token-bucket rate limiter and cost tracker
  common/     # Shared types and error definitions
```

## License

Apache 2.0. See [LICENSE](./LICENSE). Fork of [Bulwark](https://github.com/claudius-ars/bulwark) - see [NOTICE](./NOTICE) and [CHANGES.md](./CHANGES.md).
