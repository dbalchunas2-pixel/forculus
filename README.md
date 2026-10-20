# Forculus

**Local-first governance layer for AI agents.** God of the door: he decides when it opens.

Forculus sits between AI agents and external tools, enforcing policies, managing credentials, inspecting content, and maintaining a complete audit trail. One policy governs all your agents - Claude Code, Codex, or any MCP/HTTP client.

> **Provenance:** Forculus is a hard fork of [Bulwark](https://github.com/claudius-ars/bulwark) (Apache-2.0), renamed and extended with tool-definition hash pinning and Forculus-specific hardening. Attribution and change record per Apache-2.0 4(b): [NOTICE](./NOTICE) and [CHANGES.md](./CHANGES.md).

## Status

Forculus is in active development and private dogfood burn-in on a live multi-server MCP fleet.

**There is no release yet.** Do not route production agent traffic through it - the external security review that would justify that trust is still ahead of the code.

Source is published in the meantime because the build process should be as inspectable as the product:

- **Shipped:** tool-definition hash pinning, poisoning pattern detection (validated against a 13-case adversarial torture corpus), hash-chained audit log, policy engine with hot-reload, MCP gateway (stdio + Streamable HTTP)
- **Landing in the next commit:** progressive schema disclosure (a running 429-tool fleet collapsed into a 1.3 KB meta-interface; code in final testing)
- **In the build:** LLM-as-sensor intent classification, capability sandboxes, scoped credential vault, provenance trust cards, air-gapped threat-feed imports
- **First public release:** after external security review. Watch this repo.

Retrospective dev reports - accounts of completed work, each naming the commits it shipped in - live in `docs/dev-reports/`.

## Why Forculus?

AI agents are powerful but ungoverned. They can access any tool, leak any credential, and leave no audit trail. Forculus fixes this:

- **Policy enforcement** - YAML-based rules control which tools agents can use, with glob patterns, scope-based precedence, and hot-reload
- **Credential management** - Agents never see real secrets. Forculus injects credentials at the last mile, encrypted at rest with age
- **Content inspection** - Scan requests and responses for secrets, PII, and prompt injection. Block or redact automatically
- **Audit logging** - Every action recorded in a tamper-evident SQLite database with blake3 hash chains
- **Rate limiting** - Token-bucket rate limits per session, operator, tool, or globally. Cost tracking with budget enforcement
- **MCP-native** - Works as an MCP gateway or HTTP forward proxy. Governance metadata on every tool call response

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
