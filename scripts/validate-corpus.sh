#!/bin/bash

# Validate Forculus torture-test corpus
# Exits nonzero on any failure

set -euo pipefail

CORPUS_DIR="tests/fixtures/torture-corpus"
MANIFEST="$CORPUS_DIR/manifest.json"

echo "Validating torture-test corpus..."

# Check if manifest exists
if [[ ! -f "$MANIFEST" ]]; then
    echo "Error: Manifest not found at $MANIFEST"
    exit 1
fi

# Parse manifest and get all fixture paths using while loop instead of mapfile
FIXTURES=()
while IFS= read -r line; do
    FIXTURES+=("$line")
done < <(jq -r '.fixtures[].filename' "$MANIFEST" 2>/dev/null || true)

if [[ ${#FIXTURES[@]} -eq 0 ]]; then
    echo "Error: No fixtures found in manifest"
    exit 1
fi

echo "Found ${#FIXTURES[@]} fixtures in manifest"

FAILED=0

# Validate each fixture
for fixture in "${FIXTURES[@]}"; do
    FIXTURE_PATH="$CORPUS_DIR/$fixture"

    echo "Checking $fixture..."

    # Check if file exists
    if [[ ! -f "$FIXTURE_PATH" ]]; then
        echo "  ERROR: Fixture file not found: $FIXTURE_PATH"
        ((FAILED++))
        continue
    fi

    # Check if valid JSON
    if ! jq -e '.' "$FIXTURE_PATH" >/dev/null 2>&1; then
        echo "  ERROR: Invalid JSON in $FIXTURE_PATH"
        ((FAILED++))
        continue
    fi

    # Get manifest entry for this fixture
    MANIFEST_ENTRY=$(jq -r --arg f "$fixture" '.fixtures[] | select(.filename == $f)' "$MANIFEST")

    if [[ -z "$MANIFEST_ENTRY" ]]; then
        echo "  ERROR: No manifest entry found for $fixture"
        ((FAILED++))
        continue
    fi

    # Check classification
    CLASSIFICATION=$(echo "$MANIFEST_ENTRY" | jq -r '.classification')
    if [[ "$CLASSIFICATION" != "benign" && "$CLASSIFICATION" != "malicious" ]]; then
        echo "  ERROR: Invalid classification for $fixture: $CLASSIFICATION"
        ((FAILED++))
        continue
    fi

    # For malicious fixtures, check technique tags
    if [[ "$CLASSIFICATION" == "malicious" ]]; then
        TECHNIQUE_TAGS=$(echo "$MANIFEST_ENTRY" | jq -r '.technique_tags | length')
        if [[ "$TECHNIQUE_TAGS" -eq 0 ]]; then
            echo "  ERROR: Malicious fixture $fixture has no technique tags"
            ((FAILED++))
            continue
        fi
    fi

    echo "  OK: $fixture"
done

# Summary
if [[ $FAILED -eq 0 ]]; then
    echo "✅ All validations passed! ${#FIXTURES[@]} fixtures validated."
else
    echo "❌ Validation failed! $FAILED errors found."
    exit 1
fi