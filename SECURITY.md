# Security Policy

## Reporting a Vulnerability

**Contact:** dbalchunas2@icloud.com 

If you have found a vulnerability in Forculus, please report it privately. Do not open a public GitHub issue for security reports.

Please include:
- Affected version (commit hash or release tag)
- A description of the vulnerability and its impact
- Steps to reproduce or a proof of concept
- Any suggested mitigation

## Response Commitment

- **Acknowledgment:** within 72 hours of report.
- **Triage and severity assessment:** within 7 days.
- **Fix or mitigation target:** within 30 days for critical/high issues; 90 days for medium/low.
- We will keep you informed throughout and credit reporters in release notes unless you prefer anonymity.

## Coordinated Disclosure

We practice coordinated disclosure. We ask that you give us a reasonable window (90 days default) to ship a fix before public disclosure. We will never take legal action against good-faith research conducted within this policy.

## Scope

In scope: all crates in this repository, the Tauri GUI, distributed binaries, and the update mechanism.

Out of scope (do not report via this process):
- Vulnerabilities in upstream MCP servers (report to the server's maintainer; if Forculus should detect/contain it, tell us too)
- Social engineering of individual users
- Reports from automated scanners without a demonstrated impact path

## Security Philosophy

Forculus is local-first (ADR-0001): arguments, credentials, and tool payloads never leave the user's machine by design. Reports showing an unintended egress path are automatically critical severity.
