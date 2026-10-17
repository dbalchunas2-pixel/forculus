# Dev Report - 2026-10-17: F3 pin verification wired into the proxy runtime

**Type:** Dev report (written same day)
**Session date:** 2026-10-17
**Status:** Completed

## Summary

The tool-definition hash pinning engine (`pins.rs`, committed earlier as `0f3c1f4`) was an isolated, unit-tested component. This session wired it into both proxy traffic paths so that a server whose tool definitions drift after first sighting is now blocked at the protocol level, with a denied audit event emitted. This completes the last runtime gap in F3 ahead of Checkpoint A dogfooding.

## Work completed

1. **`ToolPinViolation` audit event** (`crates/audit/src/event.rs`, commit `c84ecb8`): new event type for tool-definition hash mismatches, emitted with `EventOutcome::Denied` and category `tool_pin_violation`.

2. **`pin_store` on the request context** (`crates/proxy/src/context.rs`, commit `c84ecb8`): `ProxyRequestContext` now carries an optional shared `PinStore`, following the same Arc/Mutex handle pattern as the vault and rate limiter. `ProxyServer::with_pin_store()` builder added (`server.rs`, commit `0bc5875`).

3. **Shared verification hook** (`crates/proxy/src/pincheck.rs`, commits `4862582`, `0bc5875`): detects `tools/list` JSON-RPC requests before request bodies are consumed, parses successful `tools/list` responses (accepting both `inputSchema` and `input_schema`), verifies against the pin store, emits the audit event on mismatch, and produces the JSON-RPC error body (`code -32001`) that replaces the blocked response. Unit tests cover request detection, id extraction, response parsing, and error body shape.

4. **Wired into both traffic paths**:
   - Plain HTTP forward proxy (`forward.rs`, commit `4862582`) - blocked responses return HTTP 403 with the JSON-RPC error.
   - HTTPS CONNECT MITM tunnel (`tunnel.rs`, commit `0bc5875`) - same verification on the decrypted response path, channel-tagged `HttpsProxy`.

5. **End-to-end test** (`crates/proxy/tests/pin_verification_integration.rs`, commit `0bc5875`): raw upstream serves a benign `tools/list` (passes through, pins created), then serves a poisoned description from the same address (blocked with 403/-32001, error names the offending tool).

## Decisions

- **Changed pins are never silently refreshed.** A third benign-looking response would still be blocked until an operator explicitly re-pins; the test asserts the 403 path does not update the store.
- **Verification is keyed by upstream host** on both paths. Per-session or per-agent keying remains open for Checkpoint B (identity pillar).
- **New servers pass through once, pinning at first sighting** - the `NewServer` verdict creates pins and forwards, matching the spec's first-connection semantics.

## Metrics

- `cargo test -p forculus-proxy`: 84 passed (32 lib incl. 4 new pincheck tests; 51 proxy integration; 1 mock-hostile; 1 new end-to-end pin test), 0 failed. One pre-existing flake (`adversarial_oversized_request_body`, parallel-test contention documented on 2026-10-14) failed under full parallel run and passed in isolation, unchanged by this work.
- Commits: `c84ecb8`, `4862582`, `0bc5875` on `main`.

## What changed since the last report

The 2026-10-16 report established the case-study proof-of-need. Since then: the mock hostile MCP server and protocol-level corpus test landed (`d400f2b`/`3f841d7`), the F2.5 binary self-audit ran (`35ad801`), and this session closed the F3 runtime gap. Remaining before Checkpoint A: run the keygen script, then dogfood burn-in on the 25-server stack with the REA MCP server (207 tools) as the first pin target.
