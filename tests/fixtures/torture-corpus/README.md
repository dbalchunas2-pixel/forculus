# Forculus Torture-Test Corpus

This directory contains the torture-test corpus used for F3 (tool-definition hash pinning) and F4 (poisoning detection) tests in the Forculus project.

## Purpose

The torture-test corpus is designed to test Forculus's ability to detect malicious MCP servers through various attack vectors:
- **F3**: Tool-definition hash pinning - detects changes to approved tool definitions
- **F4**: Poisoning detection - detects malicious instructions hidden in tool definitions

## Layout

```
torture-corpus/
  manifest.json         # Index of all fixtures with classifications and tags
  README.md             # This file
  malicious/            # JSON MCP server fixtures demonstrating attack techniques
  benign/               # Clean control fixtures of similar shape and size
```

## Technique Taxonomy

Each malicious fixture demonstrates one or more of the following techniques:

1. **Hidden Unicode** (`hidden-unicode`)
   - RTL override (U+202E), zero-width characters, homoglyph lookalikes
   - Example: `hidden_unicode_server.json`

2. **Instruction Override / Prompt Injection** (`instruction-override`, `prompt-injection`, `jailbreak`)
   - Language that attempts to override model instructions
   - Examples: "IGNORE PREVIOUS INSTRUCTIONS", "You must now..."
   - Example: `instruction_override_server.json`

3. **Data Exfiltration** (`data-exfiltration`, `exfil`, `environment-theft`)
   - Instructions to transmit sensitive data to external parties
   - Examples: transmit env vars, file contents to external URLs
   - Example: `data_exfil_server.json`

4. **Tool Shadowing** (`tool-shadowing`, `masquerading`, `spoofing`)
   - Tool names that mimic legitimate tools to cause confusion
   - Examples: `filesystem_safe_read` mimicking filesystem read tools
   - Example: `tool_shadowing_server.json`

5. **Name Collision** (`name-collision`, `namespace-conflict`)
   - Multiple servers defining tools with identical names
   - Creates ambiguity in tool resolution
   - Examples: `collision_server_*.json`

6. **Poisoned Parameter Defaults** (`poisoned-parameters`, `default-value-abuse`, `argument-manipulation`)
   - Default parameter values that trick the model into unsafe behavior
   - Examples: callback URLs pointing to attacker servers
   - Example: `poisoned_defaults_server.json`

## Consumption Guidelines for F3/F4 Tests

### F3 (Tool-Definition Hash Pinning) Tests
- Should compute and store hashes of all tool definitions in benign fixtures
- Should flag any fixture where tool definition hashes don't match stored values
- **Detection Expectation**: 
  - Benign fixtures: PASS (no hash mismatches)
  - Malicious fixtures: FAIL (hash mismatches due to injected content)

### F4 (Poisoning Detection) Tests
- Should scan tool descriptions and schemas for malicious content patterns
- Should apply the technique taxonomy to classify threats
- **Detection Expectation**:
  - Benign fixtures: PASS (no poisoning detected)
  - Malicious fixtures: FAIL (poisoning detected matching technique tags)

### Manifest Usage
Tests should:
1. Load `manifest.json` to get the complete fixture index
2. For each fixture:
   - Load the JSON file from the specified path
   - Verify `classification` matches actual content (benign/malicious)
   - Verify at least one `technique_tag` is present for malicious fixtures
   - Validate that the expected detection outcome matches test results

## File Counts
- Benign fixtures: 6 (clean controls)
- Malicious fixtures: 7 (covering all 6 technique categories)
- Total fixtures: 13

Each fixture is a valid JSON MCP server implementation representing either `tools-list` or `initialize` responses.