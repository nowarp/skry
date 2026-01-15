#!/bin/bash
# Check that all Move files in test/fixtures/e2e compile
# Uses temp directory - NEVER modifies original files
# Usage: ./check_e2e_syntax.sh [rule_name]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
E2E_DIR="$ROOT_DIR/test/fixtures/e2e"
SUI_FRAMEWORK="$ROOT_DIR/third-party/sui/crates/sui-framework/packages/sui-framework"

FILTER_RULE="${1:-}"

FAILED=()
PASSED=()

for dir in "$E2E_DIR"/*/; do
    rule=$(basename "$dir")
    dir=$(realpath "$dir")

    # Skip infrastructure
    [[ "$rule" == "_infrastructure" ]] && continue

    # Filter by rule name if specified
    [[ -n "$FILTER_RULE" && "$rule" != "$FILTER_RULE" ]] && continue

    # Check if there are any .move files
    if ! ls "$dir"/*.move >/dev/null 2>&1; then
        echo "[$rule] SKIP - no .move files"
        continue
    fi

    # Create temp build directory
    tmpdir=$(mktemp -d)
    trap "rm -rf $tmpdir" EXIT

    # Create Move.toml
    cat > "$tmpdir/Move.toml" <<EOF
[package]
name = "test"
version = "0.0.1"
edition = "2024.beta"

[dependencies]
Sui = { local = "$SUI_FRAMEWORK" }

[addresses]
test = "0x0"
EOF

    # Symlink sources
    mkdir -p "$tmpdir/sources"
    for f in "$dir"/*.move; do
        ln -s "$f" "$tmpdir/sources/"
    done

    # Build
    echo -n "[$rule] "
    output=$(cd "$tmpdir" && sui move build --silence-warnings --no-lint 2>&1) || true

    # Cleanup temp
    rm -rf "$tmpdir"

    # Check for errors
    if echo "$output" | grep -qE "error\[E|Failed to build"; then
        echo "FAILED"
        # Show error details - try structured errors first, fallback to raw output
        error_lines=$(echo "$output" | grep -A3 "error\[E" | head -20)
        if [[ -n "$error_lines" ]]; then
            echo "$error_lines"
        else
            echo "$output" | tail -20
        fi
        FAILED+=("$rule")
    else
        echo "OK"
        PASSED+=("$rule")
    fi
done

echo ""
echo "=== SUMMARY ==="
echo "Passed: ${#PASSED[@]}"
echo "Failed: ${#FAILED[@]}"

if [[ ${#FAILED[@]} -gt 0 ]]; then
    echo ""
    echo "Failed rules:"
    for rule in "${FAILED[@]}"; do
        echo "  - $rule"
    done
    exit 1
fi
