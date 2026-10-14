# Rate Limiting

Forculus provides flexible rate limiting to control agent request rates and costs. The system uses token bucket algorithms across multiple dimensions: session, operator, tool, and global.

## Overview

Rate limiting in Forculus:

- **Token bucket algorithm**: Smooth traffic bursts while enforcing limits
- **Multi-dimensional**: Limit by session, operator, tool, or globally
- **Configurable**: Set requests per minute (RPM) and burst sizes
- **Cost tracking**: Track and limit monthly costs per operator
- **Graceful degradation**: Return retry-after headers instead of hard failures

## Token Bucket Algorithm

The token bucket algorithm allows traffic bursts while maintaining average rate limits.

### How It Works

Imagine a bucket that holds tokens:

1. **Bucket capacity**: Maximum tokens (burst size)
2. **Refill rate**: Tokens added per minute (RPM)
3. **Token cost**: Each request consumes 1 token
4. **Request allowed**: If bucket has tokens, remove 1 and allow request
5. **Request rejected**: If bucket is empty, reject with retry-after

### Example

Configuration:
- Capacity: 10 tokens (burst)
- Refill rate: 60 tokens/minute (1 token/second)

Timeline:
```
Time    Tokens  Action              Result
0:00    10      Request arrives     Allowed (9 tokens remain)
0:00    9       Request arrives     Allowed (8 tokens remain)
0:00    8       10 requests arrive  Allowed until 0 tokens
0:01    1       Request arrives     Allowed (refilled 1 token)
0:01    0       Request arrives     REJECTED (retry after 1s)
0:10    10      Request arrives     Allowed (bucket refilled to max)
```

This allows:
- **Bursts**: Handle 10 requests instantly
- **Sustained rate**: 60 requests/minute average
- **Smooth recovery**: Bucket refills gradually

## Configuration

Configure rate limits in `forculus.yaml`:

```yaml
rate_limiting:
  enabled: true

  # Global limits (all traffic)
  global:
    requests_per_minute: 1000
    burst: 100

  # Per-operator limits
  operator:
    requests_per_minute: 300
    burst: 30

  # Per-session limits
  session:
    requests_per_minute: 100
    burst: 10

  # Per-tool limits
  tool:
    requests_per_minute: 60
    burst: 5

  # Tool-specific overrides
  tool_overrides:
    "github::create-issue":
      requests_per_minute: 10
      burst: 2
    "slack::post-message":
      requests_per_minute: 20
      burst: 5
    "aws::ec2::terminate-instances":
      requests_per_minute: 1
      burst: 1
```

## Multi-Dimensional Limiting

Rate limits are checked in order:

1. **Global**: Total traffic across all operators/sessions
2. **Operator**: Traffic for a specific operator
3. **Session**: Traffic for a specific session
4. **Tool**: Traffic for a specific tool

A request must pass ALL applicable limits.

### Example Scenario

Configuration:
```yaml
rate_limiting:
  global:
    requests_per_minute: 1000
    burst: 100
  operator:
    requests_per_minute: 300
    burst: 30
  session:
    requests_per_minute: 100
    burst: 10
  tool:
    requests_per_minute: 60
    burst: 5
```

Request from operator "alice", session "bwk_sess_abc123", tool "github::list-repos":

1. Check global limit: 1000 RPM - PASS (50 requests this minute)
2. Check operator limit: 300 RPM - PASS (80 requests this minute)
3. Check session limit: 100 RPM - PASS (80 requests this minute)
4. Check tool limit: 60 RPM - FAIL (60 requests this minute)

Result: **Request rejected** (tool limit exceeded)

Response:
```http
HTTP/1.1 429 Too Many Requests
Retry-After: 15
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1676455815

{
  "error": {
    "code": "rate_limit_exceeded",
    "message": "Rate limit exceeded for tool github::list-repos",
    "dimension": "Tool",
    "limit": 60,
    "window": "1m",
    "retry_after_seconds": 15
  }
}
```

## Dimension Configurations

### Global Limits

Protects Forculus infrastructure and downstream services:

```yaml
rate_limiting:
  global:
    requests_per_minute: 1000
    burst: 100
```

Use cases:
- Prevent overload on Forculus proxy
- Protect downstream APIs from aggregate traffic
- Ensure fair sharing among all operators

### Operator Limits

Limits per operator ID:

```yaml
rate_limiting:
  operator:
    requests_per_minute: 300
    burst: 30
```

Use cases:
- Fair sharing among team members
- Prevent one operator from monopolizing resources
- Enforce per-user quotas

### Session Limits

Limits per session token:

```yaml
rate_limiting:
  session:
    requests_per_minute: 100
    burst: 10
```

Use cases:
- Limit individual agent instances
- Detect runaway agents
- Separate limits for different agent types (prod vs. dev)

### Tool Limits

Limits per tool name:

```yaml
rate_limiting:
  tool:
    requests_per_minute: 60
    burst: 5

  tool_overrides:
    "slack::post-message":
      requests_per_minute: 20
      burst: 5
    "aws::ec2::terminate-instances":
      requests_per_minute: 1
      burst: 1
```

Use cases:
- Protect specific APIs (e.g., Slack rate limits)
- Prevent dangerous operations (e.g., terminate instances)
- Match downstream API rate limits

## Cost Tracking

Track and limit monthly costs per operator:

```yaml
cost_tracking:
  enabled: true

  # Default monthly budget per operator (USD)
  default_monthly_budget: 100.00

  # Operator-specific budgets
  operator_budgets:
    alice: 500.00
    bob: 200.00
    charlie: 50.00

  # Cost models for different tools
  tool_costs:
    # OpenAI API costs
    "openai::chat-completion":
      cost_per_request: 0.002  # $0.002 per request
      cost_per_token: 0.00001  # $0.00001 per token

    # AWS API costs (estimate)
    "aws::s3::put-object":
      cost_per_request: 0.000005  # $0.000005 per PUT

    # Default cost for unknown tools
    default:
      cost_per_request: 0.001
```

### Cost Calculation

For each request:
1. Look up tool cost model
2. Calculate cost based on request and/or tokens
3. Add to operator's monthly total
4. Check against monthly budget
5. Reject if budget exceeded

### Example

Operator "alice" with $100 monthly budget:

```
Date       Tool                      Cost      Total
Feb 1      openai::chat-completion   $0.45     $0.45
Feb 1      github::create-issue      $0.001    $0.451
Feb 2      openai::chat-completion   $1.20     $1.651
...
Feb 15     openai::chat-completion   $2.10     $99.85
Feb 15     openai::chat-completion   $0.30     $100.15  <- REJECTED (budget exceeded)
```

When budget is exceeded:

```json
{
  "error": {
    "code": "cost_budget_exceeded",
    "message": "Monthly cost budget exceeded for operator alice",
    "operator_id": "alice",
    "monthly_budget_usd": 100.00,
    "current_spend_usd": 100.15,
    "period": "2026-02"
  }
}
```

### Cost Monitoring

```bash
# Show current month costs per operator
forculus cost show

# Output:
# Operator Cost Report - February 2026
# =====================================
# Operator    Budget      Spent       Remaining   Requests
# alice       $100.00     $99.85      $0.15       45,234
# bob         $200.00     $45.20      $154.80     18,901
# charlie     $50.00      $12.30      $37.70      5,678

# Show detailed cost breakdown
forculus cost show --operator alice --detailed

# Output:
# Cost Breakdown for alice - February 2026
# =========================================
# Tool                        Requests    Total Cost
# openai::chat-completion     12,345      $89.50
# github::create-issue        8,901       $8.90
# slack::post-message         2,456       $1.23
# Other                       21,532      $0.22
# -------------------------------------------------
# TOTAL                       45,234      $99.85
```

## Monitoring Rate Limits

### Check Current Usage

```bash
# Show current rate limit usage
forculus rate-limit status

# Output:
# Rate Limit Status
# =================
# Dimension   Limit (RPM)   Current   Remaining   Reset In
# Global      1000          234       766         45s
# Operator    300           89        211         12s
# Session     100           45        55          8s
# Tool        60            12        48          3s

# Show for specific operator
forculus rate-limit status --operator alice

# Show for specific tool
forculus rate-limit status --tool "github::list-repos"
```

### Audit Rate Limit Violations

```bash
# Show recent rate limit violations
forculus audit query --event-type RateLimitExceeded --since 24h

# Export for analysis
forculus audit export \
  --event-type RateLimitExceeded \
  --since 7d \
  --output rate-limit-violations.jsonl

# Top offenders
cat rate-limit-violations.jsonl | \
  jq -r '.operator_id' | \
  sort | uniq -c | sort -rn
```

## Advanced Patterns

### Tiered Rate Limits

Different limits for different operator tiers:

```yaml
# In forculus.yaml, reference operator tier from metadata
rate_limiting:
  enabled: true
  tier_based: true

  tiers:
    free:
      requests_per_minute: 60
      burst: 5
      monthly_budget: 10.00

    pro:
      requests_per_minute: 300
      burst: 30
      monthly_budget: 100.00

    enterprise:
      requests_per_minute: 1000
      burst: 100
      monthly_budget: 1000.00

# Map operators to tiers
operator_tiers:
  alice: enterprise
  bob: pro
  charlie: free
```

### Time-Based Limits

Different limits at different times:

```yaml
rate_limiting:
  enabled: true

  # Default limits
  operator:
    requests_per_minute: 300
    burst: 30

  # Time-based overrides
  schedules:
    # Higher limits during business hours
    - name: business-hours
      schedule: "0 9-17 * * 1-5"  # 9am-5pm Mon-Fri
      operator:
        requests_per_minute: 500
        burst: 50

    # Lower limits during maintenance window
    - name: maintenance
      schedule: "0 2-4 * * *"  # 2am-4am daily
      operator:
        requests_per_minute: 100
        burst: 10
```

### Adaptive Rate Limiting

Adjust limits based on system load:

```yaml
rate_limiting:
  enabled: true
  adaptive: true

  # Base limits
  global:
    requests_per_minute: 1000
    burst: 100

  # Adaptive scaling
  adaptive_config:
    # Reduce limits when CPU > 80%
    cpu_threshold: 0.8
    cpu_scale_factor: 0.5  # Reduce to 50%

    # Reduce limits when error rate > 5%
    error_rate_threshold: 0.05
    error_scale_factor: 0.7  # Reduce to 70%
```

## Best Practices

### 1. Start Conservative, Then Relax

Begin with tight limits and relax based on usage:

```yaml
# Week 1: Very conservative
rate_limiting:
  operator:
    requests_per_minute: 60
    burst: 5

# Week 2: After monitoring, increase
rate_limiting:
  operator:
    requests_per_minute: 120
    burst: 10

# Month 2: Stabilize based on patterns
rate_limiting:
  operator:
    requests_per_minute: 300
    burst: 30
```

### 2. Match Downstream Limits

Align tool limits with downstream API limits:

```yaml
# Slack API: 1 message per second
tool_overrides:
  "slack::post-message":
    requests_per_minute: 60
    burst: 5

# GitHub API: 5000 requests per hour = 83/min
tool_overrides:
  "github::*":
    requests_per_minute: 80
    burst: 10
```

### 3. Separate Prod and Dev

Different limits for production and development:

```yaml
# Use session metadata to distinguish
rate_limiting:
  session_based: true

  session_configs:
    # Production sessions
    - pattern: "bwk_sess_prod_*"
      requests_per_minute: 300
      burst: 30

    # Development sessions
    - pattern: "bwk_sess_dev_*"
      requests_per_minute: 60
      burst: 5
```

### 4. Alert on Violations

Set up alerts for repeated rate limit violations:

```bash
#!/bin/bash
# rate-limit-alerts.sh

# Count violations in last 5 minutes
VIOLATIONS=$(forculus audit query \
  --event-type RateLimitExceeded \
  --since 5m \
  --format json | jq 'length')

if [ "$VIOLATIONS" -gt 10 ]; then
  echo "ALERT: $VIOLATIONS rate limit violations in last 5 minutes"
  # Send to Slack, PagerDuty, etc.
fi
```

### 5. Review Cost Reports Monthly

Set up monthly cost reports:

```bash
#!/bin/bash
# monthly-cost-report.sh

MONTH=$(date +%Y-%m)
REPORT="/var/log/forculus/cost-report-${MONTH}.txt"

forculus cost show --detailed > "${REPORT}"

# Email to finance team
mail -s "Forculus Cost Report ${MONTH}" finance@example.com < "${REPORT}"
```

## Troubleshooting

### Rate Limit Exceeded

If agents are hitting rate limits frequently:

1. **Check current usage**: `forculus rate-limit status`
2. **Review audit logs**: `forculus audit query --event-type RateLimitExceeded`
3. **Identify hot tools**: Which tools are hitting limits?
4. **Adjust limits**: Increase RPM or burst size
5. **Optimize agent**: Reduce unnecessary requests

### Cost Budget Exceeded

If operators exceed monthly budgets:

1. **Review spend**: `forculus cost show --operator alice --detailed`
2. **Identify expensive tools**: Which tools cost the most?
3. **Increase budget**: If usage is legitimate
4. **Optimize usage**: Cache responses, batch requests, reduce token usage
5. **Set alerts**: Warn at 80% budget utilization

### Uneven Load

If some operators use much more than others:

1. **Review usage**: `forculus cost show`
2. **Investigate high users**: `forculus audit query --operator alice --since 7d`
3. **Check for runaway agents**: Repeating patterns, errors
4. **Adjust individual limits**: Increase or decrease per operator
5. **Implement quotas**: Hard limits on per-operator usage

## Example Configurations

### Small Team (5 operators)

```yaml
rate_limiting:
  enabled: true
  global:
    requests_per_minute: 500
    burst: 50
  operator:
    requests_per_minute: 100
    burst: 10
  session:
    requests_per_minute: 100
    burst: 10

cost_tracking:
  enabled: true
  default_monthly_budget: 50.00
```

### Large Organization (100+ operators)

```yaml
rate_limiting:
  enabled: true
  global:
    requests_per_minute: 10000
    burst: 1000
  operator:
    requests_per_minute: 300
    burst: 30
  session:
    requests_per_minute: 100
    burst: 10

  tool_overrides:
    "slack::post-message":
      requests_per_minute: 20
      burst: 5
    "aws::ec2::terminate-instances":
      requests_per_minute: 1
      burst: 1

cost_tracking:
  enabled: true
  default_monthly_budget: 100.00
  operator_budgets:
    team-leads: 500.00
    engineers: 200.00
    interns: 50.00
```

### High-Throughput Production

```yaml
rate_limiting:
  enabled: true
  global:
    requests_per_minute: 100000
    burst: 10000
  operator:
    requests_per_minute: 1000
    burst: 100

  # Adaptive scaling based on system load
  adaptive: true
  adaptive_config:
    cpu_threshold: 0.8
    cpu_scale_factor: 0.5

cost_tracking:
  enabled: true
  default_monthly_budget: 1000.00
```
