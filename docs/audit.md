# Audit System

Forculus maintains a comprehensive audit log of all governance decisions, credential usage, and agent operations. The audit system uses SQLite for storage and includes hash chain verification to prevent tampering.

## Overview

The audit system provides:

- **Immutable logs**: Events are recorded with cryptographic hash chains
- **Rich event types**: Track requests, policy decisions, credentials, sessions, and more
- **Powerful querying**: Filter by event type, operator, tool, time range, etc.
- **Export capabilities**: Export to JSON Lines format for analysis
- **Tamper detection**: Verify hash chain integrity to detect modifications
- **Retention policies**: Automatic cleanup of old events

## Event Types

Forculus tracks the following event types:

### RequestProcessed

Logged for every HTTP request or MCP tool call processed by Forculus.

```json
{
  "event_id": "evt_a1b2c3d4",
  "event_type": "RequestProcessed",
  "timestamp": "2026-02-15T10:30:45Z",
  "operator_id": "alice",
  "session_token": "fcl_sess_abc123...",
  "details": {
    "method": "GET",
    "url": "https://api.github.com/user/repos",
    "tool_name": "github::list-repos",
    "status_code": 200,
    "response_time_ms": 245
  }
}
```

### PolicyDecision

Logged when the policy engine evaluates a request.

```json
{
  "event_id": "evt_b2c3d4e5",
  "event_type": "PolicyDecision",
  "timestamp": "2026-02-15T10:30:45Z",
  "operator_id": "alice",
  "details": {
    "tool_name": "github::create-issue",
    "scope": "operator:alice",
    "decision": "allow",
    "matched_rules": [
      {
        "rule_id": "allow-github-read",
        "action": "allow",
        "priority": 100
      }
    ],
    "required_approval": false
  }
}
```

### CredentialInjected

Logged when a credential is injected into a request.

```json
{
  "event_id": "evt_c3d4e5f6",
  "event_type": "CredentialInjected",
  "timestamp": "2026-02-15T10:30:45Z",
  "operator_id": "alice",
  "details": {
    "credential_id": "github-token",
    "tool_name": "github::list-repos",
    "injection_type": "bearer_token",
    "scopes": ["repo", "read:user"]
  }
}
```

### SessionCreated

Logged when a new session is created.

```json
{
  "event_id": "evt_d4e5f6g7",
  "event_type": "SessionCreated",
  "timestamp": "2026-02-15T09:00:00Z",
  "operator_id": "alice",
  "details": {
    "session_token": "fcl_sess_abc123...",
    "expires_at": "2026-02-16T09:00:00Z",
    "created_by": "cli"
  }
}
```

### SessionExpired

Logged when a session expires or is invalidated.

```json
{
  "event_id": "evt_e5f6g7h8",
  "event_type": "SessionExpired",
  "timestamp": "2026-02-16T09:00:00Z",
  "operator_id": "alice",
  "details": {
    "session_token": "fcl_sess_abc123...",
    "reason": "timeout",
    "lifetime_seconds": 86400
  }
}
```

### ContentInspectionTriggered

Logged when content inspection detects sensitive data or policy violations.

```json
{
  "event_id": "evt_f6g7h8i9",
  "event_type": "ContentInspectionTriggered",
  "timestamp": "2026-02-15T10:30:45Z",
  "operator_id": "alice",
  "details": {
    "rule_id": "aws-key",
    "severity": "Critical",
    "action": "Block",
    "pattern_matched": "AKIA...",
    "location": "request.body.parameters.config"
  }
}
```

### RateLimitExceeded

Logged when a rate limit is exceeded.

```json
{
  "event_id": "evt_g7h8i9j0",
  "event_type": "RateLimitExceeded",
  "timestamp": "2026-02-15T10:30:45Z",
  "operator_id": "alice",
  "details": {
    "dimension": "Session",
    "limit": 100,
    "window": "1m",
    "current_count": 101,
    "retry_after_seconds": 30
  }
}
```

### CostBudgetExceeded

Logged when a cost budget is exceeded.

```json
{
  "event_id": "evt_h8i9j0k1",
  "event_type": "CostBudgetExceeded",
  "timestamp": "2026-02-15T10:30:45Z",
  "operator_id": "alice",
  "details": {
    "operator_id": "alice",
    "monthly_budget_usd": 100.00,
    "current_spend_usd": 100.50,
    "period": "2026-02"
  }
}
```

## Querying Audit Logs

Use the `forculus audit query` command to search audit logs:

```bash
# Query all events in the last hour
forculus audit query --since 1h

# Query specific event types
forculus audit query --event-type PolicyDecision --since 24h

# Query by operator
forculus audit query --operator alice --since 7d

# Query by tool
forculus audit query --tool "github::*" --since 24h

# Combine filters
forculus audit query \
  --event-type CredentialInjected \
  --operator alice \
  --credential github-token \
  --since 1d

# Query with time range
forculus audit query \
  --after "2026-02-14T00:00:00Z" \
  --before "2026-02-15T00:00:00Z"
```

### Query Filters

- `--event-type <type>`: Filter by event type
- `--operator <id>`: Filter by operator ID
- `--session <token>`: Filter by session token
- `--tool <pattern>`: Filter by tool name (supports globs)
- `--credential <id>`: Filter by credential ID
- `--since <duration>`: Events since duration ago (1h, 24h, 7d, etc.)
- `--after <timestamp>`: Events after timestamp (RFC3339 format)
- `--before <timestamp>`: Events before timestamp (RFC3339 format)
- `--limit <n>`: Limit number of results (default: 100)

## Exporting Audit Logs

Export audit logs to JSON Lines format for analysis:

```bash
# Export all events
forculus audit export --output audit.jsonl

# Export with filters
forculus audit export \
  --event-type RequestProcessed \
  --since 7d \
  --output requests.jsonl

# Export for specific operator
forculus audit export \
  --operator alice \
  --since 30d \
  --output alice-audit.jsonl
```

The output is in JSON Lines format (one JSON object per line):

```jsonl
{"event_id":"evt_a1b2c3d4","event_type":"RequestProcessed","timestamp":"2026-02-15T10:30:45Z",...}
{"event_id":"evt_b2c3d4e5","event_type":"PolicyDecision","timestamp":"2026-02-15T10:30:45Z",...}
{"event_id":"evt_c3d4e5f6","event_type":"CredentialInjected","timestamp":"2026-02-15T10:30:45Z",...}
```

### Processing Exports

Use standard Unix tools or jq to process exports:

```bash
# Count events by type
cat audit.jsonl | jq -r '.event_type' | sort | uniq -c

# Find all blocked requests
cat audit.jsonl | jq 'select(.event_type == "PolicyDecision" and .details.decision == "deny")'

# Calculate average response times
cat audit.jsonl | jq -r 'select(.event_type == "RequestProcessed") | .details.response_time_ms' | awk '{sum+=$1; count++} END {print sum/count}'

# Export to CSV for Excel analysis
cat audit.jsonl | jq -r '[.timestamp, .event_type, .operator_id, .details.tool_name] | @csv' > audit.csv
```

## Hash Chain Verification

Forculus uses blake3 hash chains to ensure audit log integrity. Each event includes the hash of the previous event, creating an immutable chain.

### Verify Hash Chain

```bash
# Verify the entire hash chain
forculus audit verify

# Output:
# Verifying hash chain for 1,234 events...
# Hash chain is valid. No tampering detected.

# Or if tampering detected:
# Hash chain verification FAILED at event evt_x9y8z7
# Expected hash: blake3_abc123...
# Actual hash: blake3_def456...
# Possible tampering detected!
```

### Hash Chain Structure

Each event stores:

```json
{
  "event_id": "evt_c3d4e5f6",
  "previous_hash": "blake3_b2c3d4e5f6g7h8i9...",
  "event_hash": "blake3_c3d4e5f6g7h8i9j0...",
  "event_type": "CredentialInjected",
  ...
}
```

The hash is computed over:
- Previous event hash
- Current event ID
- Timestamp
- Event type
- All event details

This ensures that any modification to any event will break the chain.

## Retention Policies

Configure audit log retention in `forculus.yaml`:

```yaml
audit:
  enabled: true
  database_path: ~/.forculus/audit/audit.db
  retention:
    default_days: 90        # Keep events for 90 days by default
    critical_days: 365      # Keep critical events for 1 year
    max_events: 1000000     # Maximum events before rotation
```

### Retention by Event Type

Configure different retention periods for different event types:

```yaml
audit:
  retention:
    default_days: 90
    by_event_type:
      SessionCreated: 30
      SessionExpired: 30
      RequestProcessed: 60
      PolicyDecision: 180
      CredentialInjected: 365
      ContentInspectionTriggered: 365
      RateLimitExceeded: 90
      CostBudgetExceeded: 365
```

### Manual Cleanup

```bash
# Delete events older than 90 days
forculus audit cleanup --older-than 90d

# Delete specific event types
forculus audit cleanup --event-type SessionExpired --older-than 30d

# Dry run to see what would be deleted
forculus audit cleanup --older-than 90d --dry-run
```

## Audit Commands

Complete reference of audit commands:

```bash
# Query audit logs
forculus audit query [OPTIONS]

# Export audit logs
forculus audit export --output <file> [OPTIONS]

# Verify hash chain integrity
forculus audit verify

# Show audit statistics
forculus audit stats [--since <duration>]

# Clean up old events
forculus audit cleanup --older-than <duration> [OPTIONS]

# Show audit configuration
forculus audit config
```

## Audit Statistics

View audit statistics to understand system usage:

```bash
# Show overall statistics
forculus audit stats

# Output:
# Audit Statistics (All Time)
# ===========================
# Total Events: 45,678
#
# Events by Type:
#   RequestProcessed:              38,450 (84.2%)
#   PolicyDecision:                 3,820 (8.4%)
#   CredentialInjected:             2,145 (4.7%)
#   SessionCreated:                   890 (1.9%)
#   ContentInspectionTriggered:       245 (0.5%)
#   RateLimitExceeded:                 98 (0.2%)
#   CostBudgetExceeded:                30 (0.1%)
#
# Top Operators:
#   alice:     25,340 events (55.5%)
#   bob:       15,678 events (34.3%)
#   charlie:    4,660 events (10.2%)
#
# Top Tools:
#   github::list-repos:        8,450 events
#   slack::post-message:       6,230 events
#   aws::s3::list-objects:     4,890 events

# Show statistics for last 24 hours
forculus audit stats --since 24h
```

## Security Best Practices

1. **Regular verification**: Run `forculus audit verify` regularly (daily or weekly)
2. **Export backups**: Export audit logs to external systems for long-term storage
3. **Monitor critical events**: Set up alerts for ContentInspectionTriggered, RateLimitExceeded, etc.
4. **Restrict access**: Audit database should only be readable by Forculus process
5. **Tamper detection**: Investigate immediately if hash chain verification fails

## Integration Examples

### Send Critical Events to SIEM

```bash
# Export critical events and send to SIEM
forculus audit export \
  --event-type ContentInspectionTriggered \
  --event-type CostBudgetExceeded \
  --since 1h \
  --output /tmp/critical-events.jsonl

# Send to SIEM (example with Splunk)
curl -X POST "https://siem.example.com/services/collector" \
  -H "Authorization: Splunk YOUR_TOKEN" \
  --data-binary @/tmp/critical-events.jsonl
```

### Daily Audit Report

```bash
#!/bin/bash
# daily-audit-report.sh

DATE=$(date +%Y-%m-%d)
REPORT="/var/log/forculus/audit-report-${DATE}.txt"

echo "Forculus Audit Report - ${DATE}" > "${REPORT}"
echo "======================================" >> "${REPORT}"
echo "" >> "${REPORT}"

# Get statistics
forculus audit stats --since 24h >> "${REPORT}"

echo "" >> "${REPORT}"
echo "Critical Events:" >> "${REPORT}"
forculus audit query \
  --event-type ContentInspectionTriggered \
  --since 24h \
  --limit 100 >> "${REPORT}"

# Email report
mail -s "Forculus Audit Report ${DATE}" admin@example.com < "${REPORT}"
```

## Troubleshooting

### Database Locked

If you see "database is locked" errors:

1. Check for other Forculus processes: `ps aux | grep forculus`
2. Kill stale processes if needed
3. Wait a few seconds and retry
4. Check file permissions: `ls -l ~/.forculus/audit/audit.db`

### Hash Chain Verification Failed

If hash chain verification fails:

1. **DO NOT** delete or modify the database
2. Export the full audit log immediately: `forculus audit export --output audit-backup.jsonl`
3. Review recent events around the failure point
4. Check file system integrity: `fsck` or disk diagnostics
5. Report to security team - this may indicate tampering or corruption
6. Consider restoring from backup if corruption is confirmed

### Slow Queries

If queries are slow:

1. Add indexes: Forculus creates indexes automatically, but verify with `sqlite3 ~/.forculus/audit/audit.db ".schema"`
2. Reduce query scope: Use `--since` and `--limit` to narrow results
3. Archive old events: Run `forculus audit cleanup --older-than 180d`
4. Consider read replica: Copy database to another location for analysis
