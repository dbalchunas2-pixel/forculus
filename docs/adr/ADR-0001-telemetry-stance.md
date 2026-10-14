# ADR-0001: Telemetry Stance

**Status:** Accepted (2026-10-14)
**Deciders:** David Balchunas

## Context

Forculus is a security layer that sits between AI agents and MCP servers. By design, it sees everything an agent sends and receives: tool arguments, API keys, model outputs, file paths. This makes telemetry simultaneously (a) the most valuable data a security product can collect, (b) the biggest trust liability, and (c) the single greatest hypocrisy risk - a firewall that phones home is a contradiction.

Cloud competitors (enterprise MCP gateways) monetize telemetry. Forculus's differentiation is local-first integrity. The threat feed (DBA-8) needs some data flow, which creates pressure to ship telemetry early.

## Decision

1. **Zero telemetry by default.** No metrics, no crash reporting, no analytics, no update pings beyond the Tauri update check itself. The default install sends nothing anywhere.
2. **Structural, not policy.** User arguments, credentials, and tool payloads never leave the machine - not as a configuration promise but as architecture. There is no code path that can export them. A --telemetry flag that turns it off implies it can be on; instead, opt-in features ship their own explicit, purpose-built, content-sanitized data collection or they do not ship.
3. **Opt-in only, feature-scoped.** Any future data sharing (threat feed contributions, crash reports) is a separate explicit opt-in per feature, with a human-readable description of exactly what leaves the machine. Silence means no.
4. **The threat feed inherits this.** Contributions to the threat feed (DBA-8) must be hash/signature-based indicators, sanitized server definitions, or metadata the user can inspect before sending. Never raw payloads.
5. **No analytics in the GUI, ever.** No usage dashboards that secretly aggregate. If we want product insight, we read public GitHub issues and talk to users.

## Consequences

- We will know less about how Forculus is used than competitors know about their users. Accepted - trust is the product.
- Crash debugging relies on user-submitted local logs (the doctor command exports a sanitized bundle). The audit log (vault/audit crate) stays local.
- The F2 security audit should verify claim (2): no code path exports payloads. This becomes an audit acceptance criterion.
- Every future ADR touching data egress cites this one.
