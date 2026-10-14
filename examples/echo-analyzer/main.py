#!/usr/bin/env python3
"""
Example HTTP callout analyzer for Forculus.

This analyzer echoes back any findings it detects in the request body.
It demonstrates the Forculus analyzer protocol:
- Receives POST /analyze with JSON body
- Returns findings in the standard format

Usage:
    pip install flask
    python main.py

Configure in forculus.yaml:
    inspect:
      http_analyzers:
        - name: echo-analyzer
          endpoint: http://localhost:5050/analyze
          timeout_ms: 2000
          on_error: fail_open
"""

import base64
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
import json

PATTERNS = [
    {
        "id": "email-detector",
        "pattern": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "description": "Email address detected",
        "severity": "medium",
        "category": "pii",
        "action": "flag",
    },
    {
        "id": "phone-detector",
        "pattern": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
        "description": "Phone number detected",
        "severity": "medium",
        "category": "pii",
        "action": "flag",
    },
]


class AnalyzerHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        request = json.loads(body)

        # Decode the base64-encoded content
        content = base64.b64decode(request.get("body_base64", "")).decode(
            "utf-8", errors="replace"
        )

        findings = []
        for pattern_def in PATTERNS:
            matches = re.finditer(pattern_def["pattern"], content)
            for match in matches:
                findings.append(
                    {
                        "type": pattern_def["id"],
                        "severity": pattern_def["severity"],
                        "detail": f"{pattern_def['description']}: {match.group()[:20]}...",
                        "action": pattern_def["action"],
                    }
                )

        verdict = "transform" if findings else "allow"

        response = {"findings": findings, "verdict": verdict}

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

    def log_message(self, format, *args):
        print(f"[echo-analyzer] {args[0]}")


if __name__ == "__main__":
    port = 5050
    server = HTTPServer(("0.0.0.0", port), AnalyzerHandler)
    print(f"Echo analyzer listening on port {port}")
    server.serve_forever()
