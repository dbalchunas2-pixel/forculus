//! Upstream MCP server lifecycle — spawn, handshake, health, restart.

use std::process::Stdio;
use std::sync::Arc;

use forculus_common::ForculusError;
use forculus_config::{UpstreamServerConfig, resolve_env_vars};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

use crate::client;
use crate::transport::stdio::StdioTransport;
use crate::types::{Tool, ToolCallResult};

const MAX_RETRIES: u32 = 3;

/// Status of an upstream MCP server.
#[derive(Debug, Clone)]
pub enum ServerStatus {
    Stopped,
    Starting,
    Ready,
    Failed { error: String, retries: u32 },
}

/// A managed upstream MCP tool server.
pub struct UpstreamServer {
    pub name: String,
    pub config: UpstreamServerConfig,
    status: ServerStatus,
    process: Option<Child>,
    transport: Option<StdioTransport<ChildStdout, ChildStdin>>,
    tools: Vec<Tool>,
    next_request_id: i64,
    /// F3: optional tool-definition pin store; `None` disables verification.
    pin_store: Option<Arc<parking_lot::Mutex<forculus_toolguard::pins::PinStore>>>,
}

impl UpstreamServer {
    /// Create and start an upstream server from config.
    pub async fn new(
        config: UpstreamServerConfig,
        pin_store: Option<Arc<parking_lot::Mutex<forculus_toolguard::pins::PinStore>>>,
    ) -> forculus_common::Result<Self> {
        let name = config.name.clone();
        let mut server = Self {
            name,
            config,
            status: ServerStatus::Stopped,
            process: None,
            transport: None,
            tools: Vec::new(),
            next_request_id: 1,
            pin_store,
        };
        server.start().await?;
        Ok(server)
    }

    /// Create an upstream server with a pre-built transport (for testing).
    pub fn new_with_transport(
        name: String,
        transport: StdioTransport<ChildStdout, ChildStdin>,
    ) -> Self {
        Self {
            name,
            config: UpstreamServerConfig {
                name: String::new(),
                command: String::new(),
                args: Vec::new(),
                env: Default::default(),
            },
            status: ServerStatus::Starting,
            process: None,
            transport: Some(transport),
            tools: Vec::new(),
            next_request_id: 1,
            pin_store: None,
        }
    }

    /// Start (or restart) the upstream server process.
    pub async fn start(&mut self) -> forculus_common::Result<()> {
        self.status = ServerStatus::Starting;
        tracing::info!(server = %self.name, command = %self.config.command, "starting upstream server");

        // Resolve env vars.
        let resolved_env: std::collections::HashMap<String, String> = self
            .config
            .env
            .iter()
            .map(|(k, v)| (k.clone(), resolve_env_vars(v)))
            .collect();

        let mut child = Command::new(&self.config.command)
            .args(&self.config.args)
            .envs(&resolved_env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                ForculusError::Mcp(format!("failed to spawn '{}': {e}", self.config.command))
            })?;

        let child_stdin = child.stdin.take().unwrap();
        let child_stdout = child.stdout.take().unwrap();
        let child_stderr = child.stderr.take().unwrap();

        // Drain stderr in background so the child doesn't block.
        let server_name = self.name.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::new(child_stderr);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line).await {
                    Ok(0) => break, // EOF
                    Ok(_) => {
                        tracing::debug!(server = %server_name, stderr = %line.trim_end(), "upstream stderr");
                    }
                    Err(_) => break,
                }
            }
        });

        self.process = Some(child);
        let mut transport = StdioTransport::new(child_stdout, child_stdin);

        // MCP handshake.
        let _init_result = client::initialize(&mut transport, &mut self.next_request_id).await?;

        // Discover tools.
        self.tools = client::list_tools(&mut transport, &mut self.next_request_id).await?;

        // F3: verify tool-definition pins before this server's tools may be
        // served. A mismatched catalog fails the server; it is never served.
        if let Some(store) = &self.pin_store {
            let defs: Vec<forculus_toolguard::pins::ToolDef> = self
                .tools
                .iter()
                .map(|t| forculus_toolguard::pins::ToolDef {
                    name: t.name.clone(),
                    description: t.description.clone().unwrap_or_default(),
                    input_schema: t.input_schema.clone(),
                })
                .collect();
            let mut pinned = store.lock();
            match pinned.verify(&self.name, &defs) {
                forculus_toolguard::pins::PinVerdict::Pinned
                | forculus_toolguard::pins::PinVerdict::NewServer => {}
                forculus_toolguard::pins::PinVerdict::Changed(names) => {
                    tracing::error!(
                        server = %self.name,
                        changed = ?names,
                        "TOOL PIN VIOLATION: server tool definitions changed; blocking server"
                    );
                    return Err(ForculusError::Mcp(format!(
                        "tool pin violation on server {}: changed tools: {}",
                        self.name,
                        names.join(", ")
                    )));
                }
            }
        }

        tracing::info!(
            server = %self.name,
            tool_count = self.tools.len(),
            "upstream server ready"
        );

        self.transport = Some(transport);
        self.status = ServerStatus::Ready;
        Ok(())
    }

    /// Stop the upstream server.
    pub async fn stop(&mut self) {
        tracing::info!(server = %self.name, "stopping upstream server");
        self.transport = None;
        if let Some(ref mut child) = self.process {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        self.process = None;
        self.status = ServerStatus::Stopped;
    }

    /// Call a tool on this upstream server.
    pub async fn call_tool(
        &mut self,
        name: &str,
        arguments: Option<serde_json::Value>,
    ) -> forculus_common::Result<ToolCallResult> {
        let transport = self
            .transport
            .as_mut()
            .ok_or_else(|| ForculusError::Mcp(format!("server '{}' is not running", self.name)))?;
        client::call_tool(transport, &mut self.next_request_id, name, arguments).await
    }

    /// Attempt to restart the server after a failure, with exponential backoff.
    pub async fn restart_with_backoff(&mut self) -> forculus_common::Result<()> {
        let current_retries = match &self.status {
            ServerStatus::Failed { retries, .. } => *retries,
            _ => 0,
        };

        if current_retries >= MAX_RETRIES {
            return Err(ForculusError::Mcp(format!(
                "server '{}' exceeded max retries ({MAX_RETRIES})",
                self.name
            )));
        }

        let delay = std::time::Duration::from_secs(1 << current_retries); // 1s, 2s, 4s
        tracing::info!(
            server = %self.name,
            retry = current_retries + 1,
            delay_secs = delay.as_secs(),
            "restarting upstream server"
        );
        tokio::time::sleep(delay).await;

        self.stop().await;
        match self.start().await {
            Ok(()) => Ok(()),
            Err(e) => {
                self.status = ServerStatus::Failed {
                    error: e.to_string(),
                    retries: current_retries + 1,
                };
                Err(e)
            }
        }
    }

    /// Get the tools discovered from this server.
    pub fn tools(&self) -> &[Tool] {
        &self.tools
    }

    /// Get the current server status.
    pub fn status(&self) -> &ServerStatus {
        &self.status
    }
}
