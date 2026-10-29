# 2026-10-29: schema_diet wired into gateway tool disclosure

- Commit: 3e2c617 feat(mcp): wire schema_diet into gateway tool disclosure
- schema_diet.rs (previously untracked) registered in crates/mcp/src/lib.rs
- Added pub const MAX_DESCRIPTION_CHARS (256) to schema_diet.rs
- McpGateway::merged_tools now applies minify_tool to every disclosed tool (namespaced upstreams + builtins) before it reaches the agent
- cargo build -p forculus-mcp green; cargo test -p forculus-mcp green (url_upstream suite 2/2)
- Context: first step of the Warden -> Forculus Sentinel bridge for the Meta Global AI Developer Hackathon (submission due Nov 4, 9:00 PM ET)
