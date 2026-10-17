//! Forculus MCP — governance gateway for the Model Context Protocol.
//!
//! Forculus acts as an MCP server (agent-facing) and as an MCP client
//! (connecting to upstream tool servers).  Every tool call passes through
//! the gateway — logged now, enforced by policy later.
#![forbid(unsafe_code)]

pub mod client;
pub mod gateway;
pub mod http;
pub mod governance;
pub mod logging;
pub mod server;
pub mod tools;
pub mod transport;
pub mod types;
pub mod upstream;
