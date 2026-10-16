#!/usr/bin/env node
'use strict';

const http = require('http');
const url = require('url');
const fs = require('fs');
const path = require('path');

// Load all fixture definitions
const fixturesDir = path.join(__dirname, '..', 'torture-corpus');
const fixtures = {};

function loadFixture(filepath) {
  const content = fs.readFileSync(filepath, 'utf8');
  return JSON.parse(content);
}

// Load all benign fixtures
const benignDir = path.join(fixturesDir, 'benign');
fs.readdirSync(benignDir).forEach(file => {
  if (file.endsWith('.json')) {
    const fixture = loadFixture(path.join(benignDir, file));
    fixtures[fixture.serverInfo.name] = fixture;
  }
});

// Load all malicious fixtures
const maliciousDir = path.join(fixturesDir, 'malicious');
fs.readdirSync(maliciousDir).forEach(file => {
  if (file.endsWith('.json')) {
    const fixture = loadFixture(path.join(maliciousDir, file));
    fixtures[fixture.serverInfo.name] = fixture;
  }
});

// MCP Server implementation
class MockMCPServer {
  constructor() {
    this.fixtures = fixtures;
  }

  // Handle MCP JSON-RPC requests
  handleRequest(request, response) {
    let body = '';

    request.on('data', chunk => {
      body += chunk.toString();
    });

    request.on('end', async () => {
      try {
        const parsed = JSON.parse(body);
        let result;

        switch (parsed.method) {
          case 'initialize':
            result = {
              protocolVersion: '2024-11-05',
              capabilities: {
                tools: {}
              },
              serverInfo: {
                name: 'mock-hostile-server',
                version: '1.0.0'
              }
            };
            break;

          case 'tools/list':
            // Return all tools from all fixtures
            const allTools = [];
            Object.values(this.fixtures).forEach(fixture => {
              if (fixture.tools) {
                allTools.push(...fixture.tools);
              }
            });
            result = { tools: allTools };
            break;

          case 'tools/call':
            // For simplicity, just acknowledge the call
            result = {
              content: [{
                type: 'text',
                text: `Tool ${parsed.params.name} called successfully`
              }]
            };
            break;

          default:
            result = { error: { code: -32601, message: 'Method not found' } };
        }

        response.writeHead(200, { 'Content-Type': 'application/json' });
        response.end(JSON.stringify({
          jsonrpc: '2.0',
          id: parsed.id,
          result: result
        }));
      } catch (err) {
        response.writeHead(400, { 'Content-Type': 'application/json' });
        response.end(JSON.stringify({
          jsonrpc: '2.0',
          id: null,
          error: { code: -32700, message: 'Invalid request' }
        }));
      }
    });
  }

  // Start HTTP server for StreamableHTTP transport
  startHTTP(port) {
    const server = http.createServer((req, res) => {
      // Handle MCP endpoint
      if (req.method === 'POST' && req.url === '/mcp') {
        this.handleRequest(req, res);
      } else {
        res.writeHead(404);
        res.end('Not Found');
      }
    });

    server.listen(port, () => {
      console.log(`Mock MCP Server listening on http://localhost:${port}`);
    });

    return server;
  }

  // Start stdio transport
  startStdio() {
    const stdin = process.stdin;
    const stdout = process.stdout;

    let data = '';

    stdin.on('data', chunk => {
      data += chunk.toString();

      // Try to parse complete JSON messages
      try {
        const lines = data.split('\n');
        data = lines.pop(); // Keep incomplete line

        for (const line of lines) {
          if (line.trim()) {
            const request = JSON.parse(line);
            this.handleStdioRequest(request, stdout);
          }
        }
      } catch (err) {
        // Incomplete JSON, wait for more data
      }
    });

    stdin.on('end', () => {
      if (data.trim()) {
        try {
          const request = JSON.parse(data);
          this.handleStdioRequest(request, stdout);
        } catch (err) {
          // Ignore parse errors on end
        }
      }
    });
  }

  handleStdioRequest(request, stdout) {
    let result;

    switch (request.method) {
      case 'initialize':
        result = {
          protocolVersion: '2024-11-05',
          capabilities: {
            tools: {}
          },
          serverInfo: {
            name: 'mock-hostile-server',
            version: '1.0.0'
          }
        };
        break;

      case 'tools/list':
        const allTools = [];
        Object.values(this.fixtures).forEach(fixture => {
          if (fixture.tools) {
            allTools.push(...fixture.tools);
          }
        });
        result = { tools: allTools };
        break;

      case 'tools/call':
        result = {
          content: [{
            type: 'text',
            text: `Tool ${request.params.name} called successfully`
          }]
        };
        break;

      default:
        result = { error: { code: -32601, message: 'Method not found' } };
    }

    const response = {
      jsonrpc: '2.0',
      id: request.id,
      result: result
    };

    stdout.write(JSON.stringify(response) + '\n');
  }
}

// Main execution
const server = new MockMCPServer();

// Check if we should start stdio or HTTP based on arguments
const args = process.argv.slice(2);
if (args.includes('--http')) {
  const port = parseInt(args[args.indexOf('--http') + 1]) || 3000;
  server.startHTTP(port);
} else {
  // Default to stdio transport
  server.startStdio();
}

module.exports = MockMCPServer;