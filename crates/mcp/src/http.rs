//! HTTP upstream transport - Streamable HTTP (JSON + SSE) client for remote MCP servers.

use serde_json::{Value, json};

use forculus_common::ForculusError;

use crate::types::{Tool, ToolCallResult};

const PROTOCOL_VERSION: &str = "2024-11-05";

/// Client for a remote MCP server exposed over Streamable HTTP.
pub struct HttpUpstream {
    url: String,
    client: reqwest::Client,
    session_id: Option<String>,
}

impl HttpUpstream {
    pub fn new(url: String) -> Result<Self, ForculusError> {
        let client = reqwest::Client::builder()
            .build()
            .map_err(|e| ForculusError::Mcp(format!("http client build failed: {e}")))?;
        Ok(Self { url, client, session_id: None })
    }

    async fn post(&self, body: Value) -> Result<reqwest::Response, ForculusError> {
        let mut req = self
            .client
            .post(&self.url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .json(&body);
        if let Some(sid) = &self.session_id {
            req = req.header("Mcp-Session-Id", sid);
        }
        req.send()
            .await
            .map_err(|e| ForculusError::Mcp(format!("http request failed: {e}")))
    }

    /// Send a JSON-RPC request; handles JSON and SSE responses plus session header.
    async fn request(&mut self, id: i64, method: &str, params: Value) -> Result<Value, ForculusError> {
        let body = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        let resp = self.post(body).await?;
        if let Some(sid) = resp.headers().get("mcp-session-id") {
            if let Ok(v) = sid.to_str() {
                self.session_id = Some(v.to_string());
            }
        }
        let status = resp.status();
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        if !status.is_success() {
            return Err(ForculusError::Mcp(format!("http upstream returned {status}")));
        }
        let extract = |v: Value| -> Result<Value, ForculusError> {
            if let Some(err) = v.get("error") {
                return Err(ForculusError::Mcp(format!("upstream error: {err}")));
            }
            Ok(v.get("result").cloned().unwrap_or(Value::Null))
        };
        if content_type.contains("text/event-stream") {
            let text = resp
                .text()
                .await
                .map_err(|e| ForculusError::Mcp(format!("sse read failed: {e}")))?;
            for line in text.lines() {
                if let Some(data) = line.strip_prefix("data:") {
                    let data = data.trim();
                    if data.is_empty() {
                        continue;
                    }
                    if let Ok(v) = serde_json::from_str::<Value>(data) {
                        if v.get("id").and_then(|i| i.as_i64()) == Some(id) {
                            return extract(v);
                        }
                    }
                }
            }
            Ok(Value::Null)
        } else {
            let v: Value = resp
                .json()
                .await
                .map_err(|e| ForculusError::Mcp(format!("json decode failed: {e}")))?;
            extract(v)
        }
    }

    async fn notify(&self, method: &str) {
        let body = json!({ "jsonrpc": "2.0", "method": method });
        let _ = self.post(body).await;
    }

    pub async fn initialize(&mut self, id: &mut i64) -> Result<(), ForculusError> {
        *id += 1;
        let params = json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": { "name": "forculus-gateway", "version": env!("CARGO_PKG_VERSION") },
        });
        self.request(*id, "initialize", params).await?;
        self.notify("notifications/initialized").await;
        Ok(())
    }

    pub async fn list_tools(&mut self, id: &mut i64) -> Result<Vec<Tool>, ForculusError> {
        *id += 1;
        let result = self.request(*id, "tools/list", json!({})).await?;
        let tools = result.get("tools").cloned().unwrap_or(Value::Array(vec![]));
        let tools: Vec<Tool> = serde_json::from_value(tools)
            .map_err(|e| ForculusError::Mcp(format!("bad tools/list payload: {e}")))?;
        Ok(tools)
    }

    pub async fn call_tool(
        &mut self,
        id: &mut i64,
        name: &str,
        args: Value,
    ) -> Result<ToolCallResult, ForculusError> {
        *id += 1;
        let params = json!({ "name": name, "arguments": args });
        let result = self.request(*id, "tools/call", params).await?;
        let r: ToolCallResult = serde_json::from_value(result)
            .map_err(|e| ForculusError::Mcp(format!("bad tools/call payload: {e}")))?;
        Ok(r)
    }
}
