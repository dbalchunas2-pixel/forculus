//! MCP client — protocol interactions with an upstream tool server.

use forculus_common::ForculusError;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::transport::stdio::StdioTransport;
use crate::types::{
    InitializeResult, JsonRpcMessage, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse,
    RequestId, Tool, ToolCallParams, ToolCallResult,
};

/// Send a request and wait for the matching response.
async fn request<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    transport: &mut StdioTransport<R, W>,
    request_id: &mut i64,
    method: &str,
    params: Option<serde_json::Value>,
) -> forculus_common::Result<JsonRpcResponse> {
    let id = *request_id;
    *request_id += 1;

    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: RequestId::Number(id),
        method: method.to_string(),
        params,
    };
    transport.write_message(&req).await?;

    // Read messages until we get a response matching our request ID.
    // Skip any notifications that arrive in between.
    loop {
        let msg = transport.read_message().await?.ok_or_else(|| {
            ForculusError::Mcp(format!(
                "upstream closed while awaiting response to {method}"
            ))
        })?;
        match msg {
            JsonRpcMessage::Response(resp) if resp.id == RequestId::Number(id) => {
                return Ok(resp);
            }
            JsonRpcMessage::Notification(n) => {
                tracing::debug!(method = %n.method, "notification from upstream (ignored)");
            }
            _ => {
                tracing::debug!(
                    "unexpected message from upstream while awaiting {method} response"
                );
            }
        }
    }
}

/// Perform the MCP initialize handshake over a transport.
pub async fn initialize<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    transport: &mut StdioTransport<R, W>,
    request_id: &mut i64,
) -> forculus_common::Result<InitializeResult> {
    let resp = request(
        transport,
        request_id,
        "initialize",
        Some(serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "forculus",
                "version": forculus_common::VERSION
            }
        })),
    )
    .await?;

    if let Some(err) = resp.error {
        return Err(ForculusError::Mcp(format!(
            "initialize failed: {}",
            err.message
        )));
    }

    let result: InitializeResult = serde_json::from_value(
        resp.result
            .ok_or_else(|| ForculusError::Mcp("initialize response missing result".into()))?,
    )
    .map_err(|e| ForculusError::Mcp(format!("invalid initialize result: {e}")))?;

    // Send initialized notification.
    let notif = JsonRpcNotification {
        jsonrpc: "2.0".to_string(),
        method: "notifications/initialized".to_string(),
        params: None,
    };
    transport.write_message(&notif).await?;

    Ok(result)
}

/// Discover tools from an upstream server.
pub async fn list_tools<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    transport: &mut StdioTransport<R, W>,
    request_id: &mut i64,
) -> forculus_common::Result<Vec<Tool>> {
    let resp = request(transport, request_id, "tools/list", None).await?;

    if let Some(err) = resp.error {
        return Err(ForculusError::Mcp(format!(
            "tools/list failed: {}",
            err.message
        )));
    }

    let result = resp
        .result
        .ok_or_else(|| ForculusError::Mcp("tools/list response missing result".into()))?;

    let tools: Vec<Tool> = serde_json::from_value(
        result
            .get("tools")
            .cloned()
            .unwrap_or(serde_json::Value::Array(vec![])),
    )
    .map_err(|e| ForculusError::Mcp(format!("invalid tools/list result: {e}")))?;

    Ok(tools)
}

/// Call a tool on an upstream server.
pub async fn call_tool<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    transport: &mut StdioTransport<R, W>,
    request_id: &mut i64,
    name: &str,
    arguments: Option<serde_json::Value>,
) -> forculus_common::Result<ToolCallResult> {
    let params = ToolCallParams {
        name: name.to_string(),
        arguments,
    };

    let resp = request(
        transport,
        request_id,
        "tools/call",
        Some(serde_json::to_value(&params).unwrap()),
    )
    .await?;

    if let Some(err) = resp.error {
        return Err(ForculusError::Mcp(format!(
            "tools/call failed: {}",
            err.message
        )));
    }

    let result: ToolCallResult = serde_json::from_value(
        resp.result
            .ok_or_else(|| ForculusError::Mcp("tools/call response missing result".into()))?,
    )
    .map_err(|e| ForculusError::Mcp(format!("invalid tools/call result: {e}")))?;

    Ok(result)
}
