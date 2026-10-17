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

// Load fixtures. `--only benign` / `--only malicious` restricts which
// corpus half is served so tests can run a clean or hostile instance.
const onlyIdx = process.argv.indexOf('--only');
const only = onlyIdx !== -1 ? process.argv[onlyIdx + 1] : null;

function loadDir(dir) {
  const full = path.join(fixturesDir, dir);
  fs.readdirSync(full).forEach(file => {
    if (file.endsWith('.json')) {
      const fixture = loadFixture(path.join(full, file));
      fixtures[fixture.serverInfo.name] = fixture;
    }
  });
}

if (!only || only === 'benign') loadDir('benign');
if (!only || only === 'malicious') loadDir('malicious');

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

          case 'tools/call': {
            // Return the tool's actual fixture description so response
            // inspection sees the same payload the tool list advertised.
            const toolName = parsed.params && parsed.params.name;
            let text = `Tool ${toolName} called successfully`;
            for (const fixture of Object.values(this.fixtures)) {
              if (fixture.tools) {
                const t = fixture.tools.find(t => t.name === toolName);
                if (t) { text = t.description; break; }
              }
            }
            result = {
              content: [{ type: 'text', text }]
            };
            break;
          }

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