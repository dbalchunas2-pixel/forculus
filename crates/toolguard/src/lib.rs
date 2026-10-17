//! Forculus toolguard - F3 tool-definition hash pinning.
//!
//! Pins a SHA-256 hash over each MCP server's tool definitions at first
//! connection so that later changes are detected and blocked.

pub mod pins;
