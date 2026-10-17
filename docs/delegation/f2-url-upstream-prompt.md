# F2-URL: HTTP/SSE URL-upstream support for the MCP gateway

## Mission
Add remote-URL upstream support to the Forculus MCP gateway so servers already running over Streamable HTTP can be governed (fingerprinted + pinned) without the gateway spawning them as stdio children.

## Context (read first, in this order, SLICES ONLY - never read whole files)
1. crates/config/src/lib.rs - struct UpstreamServerConfig (around line 186): fields name, command, args, env.
2. crates/mcp/src/upstream.rs - struct UpstreamServer (line ~27): transport is Option<StdioTransport<ChildStdout, ChildStdin>>, pin_store field (F3), status/tools/next_request_id. Note how stdio initialize + tools/list + tools/call flow works, and how pin_store verifies tool definitions.
3. crates/mcp/src/gateway.rs - boot loop iterates UpstreamServerConfig list, calls UpstreamServer::new, fail-soft skip on error. Tool routing splits namespaced name 'server__tool' (line ~371).
4. crates/toolguard/src/pins.rs - PinStore API used at handshake.
5. crates/proxy/tests/fixtures/mock-hostile-server/ - existing HTTP fixture you can pattern-match for the new test fixture.

## Design (keep it minimal, follow existing patterns)
1. Config: add `#[serde(default)] pub url: Option<String>` to UpstreamServerConfig. If url is Some, command/args/env are ignored.
2. UpstreamServer: introduce an internal transport enum, e.g. enum UpstreamTransport { Stdio(StdioTransport<...>), Http(HttpUpstream) }, where HttpUpstream holds a reqwest::Client (or the HTTP client crate already used elsewhere in the workspace - check crates/proxy/Cargo.toml first and reuse the same dep/version) plus the base URL.
3. HTTP mode behavior: POST JSON-RPC to the URL with headers Content-Type: application/json and Accept: application/json, text/event-stream. Method mapping: initialize -> initialize, tools/list -> tools/list, tools/call -> tools/call forwarding params verbatim. Handle BOTH response styles: application/json body, and text/event-stream (parse data: lines until a JSON-RPC response with matching id). Follow any Mcp-Session-Id response header and echo it on subsequent requests.
4. Pin verification: the tool list fetched over HTTP MUST pass through the SAME pin_store verification as stdio (same ToolPinViolation audit event, same changed-tools error). No exceptions.
5. Gateway: the fail-soft skip path applies identically to URL upstreams. Tool namespacing/routing code should need NO changes (tools arrive in the same Tool struct).
6. Add reqwest (or the workspace's existing HTTP client) to crates/mcp/Cargo.toml only if not already a dependency.

## Tests
- New integration test in crates/mcp/tests/ (or alongside existing gateway tests): spin a mock Streamable-HTTP MCP server on a random port serving 3 benign tools; assert the gateway pins it on boot (pins_db_path temp file) and merged_tools contains namespaced names.
- Tamper case: restart mock with one changed tool description -> assert ToolPinViolation + server skipped (fail-soft), pin file NOT refreshed.

## Build discipline (HARD RULES)
- NEVER read a whole file; use sed -n slices or grep -n to locate, then edit surgically.
- Do NOT run cargo in the foreground more than once for check: run `PATH=$HOME/.cargo/bin:$PATH nohup cargo check > /tmp/f2url-check.log 2>&1 &` then poll the log.
- Same pattern for tests: nohup cargo test -p forculus-mcp -p forculus-config > /tmp/f2url-test.log 2>&1 &
- If check fails, fix and re-run; iterate until green.
- Do NOT touch dogfood.yaml, do NOT restart any running services, do NOT commit to anything but the feature branch.

## Finish
- git checkout -b f2-url-upstream && git add the touched crates + new tests && commit with message 'f2: URL upstream support for MCP gateway (Streamable HTTP, pinned)' && git push origin f2-url-upstream. Do NOT merge.
- Write a 15-line summary to docs/dev-reports/2026-10-17-f2-url-upstream.md: files touched, design choices, test results, known limitations.
