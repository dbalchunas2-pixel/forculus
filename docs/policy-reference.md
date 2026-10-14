# Policy Reference

Forculus's policy engine uses YAML files to define governance rules for AI agents. Policies control which tools, actions, and resources agents can access based on conditions like team membership, environment, and agent type.

## Table of Contents

- [Policy File Format](#policy-file-format)
- [Scope Hierarchy](#scope-hierarchy)
- [Rules](#rules)
- [Match Patterns](#match-patterns)
- [Conditions](#conditions)
- [Verdicts](#verdicts)
- [Precedence Rules](#precedence-rules)
- [Hot Reload](#hot-reload)
- [Examples](#examples)

## Policy File Format

Each policy file is a YAML document with two top-level sections:

```yaml
metadata:
  name: policy-name
  description: Human-readable description
  scope: global  # global, agent, team, project, or override

rules:
  - name: rule-name
    description: What this rule does
    verdict: allow
    reason: Why this decision is made
    # ... additional fields
```

### Metadata Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | String | Yes | Unique identifier for the policy |
| `description` | String | Yes | Human-readable explanation of the policy's purpose |
| `scope` | String | Yes | One of: `global`, `agent`, `team`, `project`, `override` |

## Scope Hierarchy

Policies are organized in a hierarchy from broadest to narrowest:

1. **global** - Organization-wide defaults
2. **team** - Team-specific policies
3. **project** - Project-specific policies
4. **agent** - Individual agent policies
5. **override** - Emergency overrides (highest precedence)

Higher scopes override lower scopes. For example, a `team` policy overrides a `global` policy for the same tool.

## Rules

Each rule defines a governance decision for specific tools, actions, and resources.

### Rule Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | String | Yes | - | Unique identifier within the policy |
| `description` | String | Yes | - | What this rule does |
| `verdict` | String | Yes | - | One of: `allow`, `deny`, `escalate`, `transform` |
| `reason` | String | Yes | - | Explanation shown when rule triggers |
| `priority` | Integer | No | 0 | Higher numbers = higher priority |
| `enabled` | Boolean | No | true | Whether this rule is active |
| `match` | Object | Yes | - | Criteria for matching requests |
| `conditions` | Object | No | - | Additional context-based conditions |

### Match Criteria

The `match` section uses glob patterns to match against tool names, actions, and resources:

```yaml
match:
  tools:
    - "github:*"
    - "slack:*"
  actions:
    - "read"
    - "list"
  resources:
    - "repo:acme/*"
```

| Field | Type | Description |
|-------|------|-------------|
| `tools` | Array of Strings | Glob patterns matching tool names |
| `actions` | Array of Strings | Glob patterns matching action names |
| `resources` | Array of Strings | Glob patterns matching resource identifiers |

All arrays are optional. If omitted, that dimension matches everything.

## Match Patterns

Forculus uses glob-style patterns with the following syntax (case-insensitive):

| Pattern | Matches | Example |
|---------|---------|---------|
| `*` | Any characters (including none) | `github:*` matches `github:api`, `github:rest` |
| `?` | Single character | `file:read?` matches `file:read1`, `file:readX` |
| `{a,b}` | Alternation | `{prod,staging}` matches `prod` or `staging` |
| `[abc]` | Character class | `file[123]` matches `file1`, `file2`, `file3` |

### Pattern Examples

```yaml
# Match all GitHub tools
tools: ["github:*"]

# Match specific database actions
actions: ["{read,write,delete}"]

# Match staging and development repos
resources: ["repo:{staging,dev}/*"]

# Match any production resource
resources: ["*:prod:*"]
```

## Conditions

Conditions add context-based filtering beyond tool/action/resource matching:

```yaml
conditions:
  operators:
    - "alice@example.com"
    - "bob@example.com"
  teams:
    - "platform"
    - "infrastructure"
  environments:
    - "production"
  agent_types:
    - "deployment-bot"
    - "monitoring-agent"
  labels:
    compliance: "required"
    cost_center: "engineering"
```

| Field | Type | Description |
|-------|------|-------------|
| `operators` | Array of Strings | Email addresses or user IDs |
| `teams` | Array of Strings | Team names |
| `environments` | Array of Strings | Environment names (prod, staging, dev, etc.) |
| `agent_types` | Array of Strings | Agent type identifiers |
| `labels` | Map of String to String | Arbitrary key-value pairs |

All condition fields are optional and use AND logic within a rule. A request must satisfy ALL specified conditions to match.

## Verdicts

When a rule matches, its verdict determines what happens:

### `allow`

Permits the requested operation to proceed.

```yaml
verdict: allow
reason: Read access approved for monitoring team
```

### `deny`

Blocks the requested operation.

```yaml
verdict: deny
reason: Write access to production requires approval
```

### `escalate`

Requires human approval before proceeding.

```yaml
verdict: escalate
reason: Database modifications require DBA review
```

### `transform`

Modifies the request before allowing it (future feature - currently treated as allow).

```yaml
verdict: transform
reason: Redact sensitive fields from response
```

## Precedence Rules

When multiple rules match a request, Forculus applies them in this order:

1. **Scope** - Higher scopes win (`override` > `agent` > `project` > `team` > `global`)
2. **Priority** - Higher priority numbers win (default: 0)
3. **Deny beats allow** - If same scope and priority, `deny` and `escalate` override `allow`
4. **Load order** - First loaded rule wins if all else is equal

### Precedence Examples

```yaml
# Rule A: global scope, priority 0, deny
# Rule B: team scope, priority 0, allow
# Winner: Rule B (team scope beats global scope)

# Rule A: team scope, priority 10, allow
# Rule B: team scope, priority 5, deny
# Winner: Rule A (higher priority)

# Rule A: team scope, priority 0, allow
# Rule B: team scope, priority 0, deny
# Winner: Rule B (deny beats allow)
```

### Default Behavior

If no rules match a request, Forculus defaults to **deny**. This fail-secure approach ensures unexpected requests are blocked until explicitly allowed.

## Hot Reload

Forculus supports hot-reloading policies without restarting the service:

```yaml
# In forculus.yaml
policy:
  policies_dir: /etc/forculus/policies
  hot_reload: true  # Enable automatic reload on file changes
```

When hot reload is enabled:
- Forculus watches the policies directory for changes
- New or modified YAML files are loaded automatically
- Invalid YAML files are logged but don't crash the service
- Changes take effect immediately for new requests
- No restart or downtime required

### Manual Reload

You can also trigger a reload by sending SIGHUP:

```bash
kill -HUP $(pgrep forculus)
```

## Examples

### Example 1: Read-Only Access for Monitoring

```yaml
metadata:
  name: monitoring-readonly
  description: Allow monitoring agents read-only access
  scope: team

rules:
  - name: allow-read-operations
    description: Permit all read operations for monitoring team
    verdict: allow
    reason: Monitoring requires read access to observe system state
    match:
      actions:
        - "read"
        - "list"
        - "describe"
        - "get"
    conditions:
      teams:
        - "monitoring"
        - "sre"
```

### Example 2: Restrict Production Database Access

```yaml
metadata:
  name: prod-db-protection
  description: Require approval for production database writes
  scope: global

rules:
  - name: block-prod-db-writes
    description: Prevent unapproved database modifications
    verdict: escalate
    reason: Production database changes require DBA approval
    priority: 10
    match:
      tools:
        - "postgres:*"
        - "mysql:*"
        - "mongodb:*"
      actions:
        - "write"
        - "update"
        - "delete"
        - "drop"
      resources:
        - "*:production:*"

  - name: allow-prod-db-reads
    description: Allow read-only queries
    verdict: allow
    reason: Read queries are safe for production
    priority: 5
    match:
      tools:
        - "postgres:*"
        - "mysql:*"
        - "mongodb:*"
      actions:
        - "read"
        - "select"
        - "query"
      resources:
        - "*:production:*"
```

### Example 3: Environment-Based Access

```yaml
metadata:
  name: environment-controls
  description: Different access levels per environment
  scope: project

rules:
  - name: dev-full-access
    description: Developers have full access in dev environment
    verdict: allow
    reason: Development environment allows experimentation
    match:
      tools: ["*"]
      actions: ["*"]
      resources: ["*:dev:*", "*:development:*"]
    conditions:
      teams:
        - "engineering"

  - name: staging-limited-writes
    description: Staging requires approval for destructive operations
    verdict: escalate
    reason: Staging mirrors production and needs protection
    priority: 10
    match:
      actions:
        - "delete"
        - "drop"
        - "destroy"
      resources:
        - "*:staging:*"

  - name: prod-strict-controls
    description: Production changes require explicit approval
    verdict: deny
    reason: Production is protected by default
    priority: 20
    match:
      resources:
        - "*:prod:*"
        - "*:production:*"
```

### Example 4: Emergency Override

```yaml
metadata:
  name: incident-response
  description: Emergency access during incidents
  scope: override

rules:
  - name: incident-commander-access
    description: Grant full access during declared incidents
    verdict: allow
    reason: Incident response requires unrestricted access
    priority: 100
    match:
      tools: ["*"]
      actions: ["*"]
      resources: ["*"]
    conditions:
      operators:
        - "oncall@example.com"
      labels:
        incident: "declared"
```

### Example 5: Cost Control

```yaml
metadata:
  name: expensive-operations
  description: Protect against costly operations
  scope: global

rules:
  - name: limit-batch-operations
    description: Batch operations require approval
    verdict: escalate
    reason: Large batch jobs can incur significant costs
    priority: 15
    match:
      actions:
        - "batch:*"
        - "*:bulk"
      tools:
        - "aws:*"
        - "gcp:*"
        - "azure:*"

  - name: block-expensive-resources
    description: Block access to expensive resource types
    verdict: deny
    reason: These resources exceed budget limits
    priority: 20
    match:
      resources:
        - "instance:*:x-large"
        - "instance:*:gpu"
    conditions:
      environments:
        - "dev"
        - "test"
```

### Example 6: GitHub Repository Access

```yaml
metadata:
  name: github-access-control
  description: Control GitHub repository operations
  scope: team

rules:
  - name: allow-public-repo-reads
    description: Anyone can read public repositories
    verdict: allow
    reason: Public repositories are openly accessible
    match:
      tools:
        - "github:api"
        - "github:rest"
      actions:
        - "read"
        - "clone"
        - "pull"
      resources:
        - "repo:*/public-*"

  - name: restrict-repo-admin
    description: Repository admin actions need approval
    verdict: escalate
    reason: Administrative changes affect team workflow
    priority: 10
    match:
      tools:
        - "github:*"
      actions:
        - "admin:*"
        - "settings:*"
        - "delete"
    conditions:
      teams:
        - "platform"

  - name: protect-main-branch
    description: Prevent direct commits to main
    verdict: deny
    reason: Main branch requires pull request workflow
    priority: 15
    match:
      tools:
        - "github:*"
      actions:
        - "push"
        - "force-push"
      resources:
        - "repo:*/branch:main"
        - "repo:*/branch:master"
```

### Example 7: Time-Based Access

```yaml
metadata:
  name: business-hours
  description: Restrict operations to business hours
  scope: global

rules:
  - name: after-hours-escalation
    description: Non-urgent changes outside business hours require approval
    verdict: escalate
    reason: After-hours changes should be reviewed for necessity
    match:
      actions:
        - "deploy"
        - "update"
        - "modify"
    conditions:
      labels:
        urgency: "low"
        # Note: Time-based conditions would require additional implementation
```

## Best Practices

1. **Start with deny-by-default** - Use `global` scope to set restrictive defaults, then add more permissive rules at higher scopes
2. **Use descriptive names and reasons** - Future operators will thank you for clear explanations
3. **Leverage priority** - Use priority to override lower-level rules without changing scope
4. **Test in development** - Validate policies in dev/staging before applying to production
5. **Document exceptions** - Use comments and descriptions to explain why overrides exist
6. **Regular audits** - Review policies periodically to remove obsolete rules
7. **Version control** - Keep policy files in git to track changes and enable rollback
8. **Monitor escalations** - Track which operations require approval to tune policies

## Troubleshooting

### Rule Not Matching

If a rule doesn't match as expected:

1. Check glob pattern syntax (patterns are case-insensitive)
2. Verify all conditions are met (conditions use AND logic)
3. Confirm the rule is enabled (`enabled: true`)
4. Check if a higher-precedence rule matches first

### Default Deny Behavior

If all requests are being denied:

1. Verify policy files are loaded from the correct directory
2. Check that at least one `allow` rule matches your request
3. Review logs for policy evaluation details

### Hot Reload Not Working

If policy changes aren't taking effect:

1. Verify `hot_reload: true` in forculus.yaml
2. Check file permissions on the policies directory
3. Review logs for YAML parsing errors
4. Ensure file system notifications are working (inotify on Linux, FSEvents on macOS)
