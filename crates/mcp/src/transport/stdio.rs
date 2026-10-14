//! Stdio transport — newline-delimited JSON over `AsyncRead`/`AsyncWrite`.

use forculus_common::ForculusError;
use serde::Serialize;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::types::JsonRpcMessage;

/// A bidirectional JSON-RPC transport over generic async byte streams.
///
/// Works with `tokio::io::stdin()`/`stdout()` (agent-facing) or with
/// child-process `ChildStdout`/`ChildStdin` (upstream-facing).
pub struct StdioTransport<R, W> {
    reader: BufReader<R>,
    writer: W,
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> StdioTransport<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader: BufReader::new(reader),
            writer,
        }
    }

    /// Read the next JSON-RPC message.  Returns `None` on EOF.
    pub async fn read_message(&mut self) -> forculus_common::Result<Option<JsonRpcMessage>> {
        let mut line = String::new();
        loop {
            line.clear();
            let n = self
                .reader
                .read_line(&mut line)
                .await
                .map_err(|e| ForculusError::Mcp(format!("read error: {e}")))?;
            if n == 0 {
                return Ok(None); // EOF
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue; // skip blank lines
            }
            match serde_json::from_str::<JsonRpcMessage>(trimmed) {
                Ok(msg) => return Ok(Some(msg)),
                Err(e) => {
                    tracing::warn!(line = %trimmed, error = %e, "skipping malformed JSON-RPC message");
                    continue;
                }
            }
        }
    }

    /// Write a JSON-RPC message (serialised as JSON + newline).
    pub async fn write_message(&mut self, msg: &impl Serialize) -> forculus_common::Result<()> {
        let json = serde_json::to_string(msg)
            .map_err(|e| ForculusError::Mcp(format!("serialization error: {e}")))?;
        self.writer
            .write_all(json.as_bytes())
            .await
            .map_err(|e| ForculusError::Mcp(format!("write error: {e}")))?;
        self.writer
            .write_all(b"\n")
            .await
            .map_err(|e| ForculusError::Mcp(format!("write error: {e}")))?;
        self.writer
            .flush()
            .await
            .map_err(|e| ForculusError::Mcp(format!("flush error: {e}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn write_then_read_roundtrip() {
        // Two separate duplex channels to simulate bidirectional pipes:
        //   a_to_b: a writes → b reads
        //   b_to_a: b writes → a reads
        let (a_to_b_read, a_to_b_write) = duplex(8192);
        let (b_to_a_read, b_to_a_write) = duplex(8192);

        let mut transport_a = StdioTransport::new(b_to_a_read, a_to_b_write);
        let mut transport_b = StdioTransport::new(a_to_b_read, b_to_a_write);

        let req = crate::types::JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: crate::types::RequestId::Number(1),
            method: "ping".into(),
            params: None,
        };
        transport_a.write_message(&req).await.unwrap();
        let msg = transport_b.read_message().await.unwrap().unwrap();
        assert!(matches!(msg, crate::types::JsonRpcMessage::Request(r) if r.method == "ping"));
    }

    #[tokio::test]
    async fn read_multiple_messages() {
        let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"a\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"b\"}\n";
        let reader = &input[..];
        let writer = tokio::io::sink();
        let mut transport = StdioTransport::new(reader, writer);

        let m1 = transport.read_message().await.unwrap().unwrap();
        assert!(matches!(m1, crate::types::JsonRpcMessage::Request(r) if r.method == "a"));
        let m2 = transport.read_message().await.unwrap().unwrap();
        assert!(matches!(m2, crate::types::JsonRpcMessage::Request(r) if r.method == "b"));
        let m3 = transport.read_message().await.unwrap();
        assert!(m3.is_none()); // EOF
    }

    #[tokio::test]
    async fn skip_empty_lines() {
        let input = b"\n\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"x\"}\n\n";
        let mut transport = StdioTransport::new(&input[..], tokio::io::sink());
        let msg = transport.read_message().await.unwrap().unwrap();
        assert!(matches!(msg, crate::types::JsonRpcMessage::Request(r) if r.method == "x"));
    }

    #[tokio::test]
    async fn malformed_json_skipped() {
        let input = b"not json\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ok\"}\n";
        let mut transport = StdioTransport::new(&input[..], tokio::io::sink());
        // malformed line is skipped, next valid message is returned
        let msg = transport.read_message().await.unwrap().unwrap();
        assert!(matches!(msg, crate::types::JsonRpcMessage::Request(r) if r.method == "ok"));
    }
}
