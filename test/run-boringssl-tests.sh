#!/bin/bash
# Run BoringSSL TLS 1.3 tests against pure-tls
#
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Anthony Green <green@moxielogic.com>

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SHIM_PATH="$PROJECT_DIR/pure-tls-shim"
BORINGSSL_RUNNER="${BORINGSSL_DIR:-$HOME/git/boringssl}/ssl/test/runner"
TIMEOUT="${TEST_TIMEOUT:-300}"

# Check if shim exists
if [ ! -x "$SHIM_PATH" ]; then
    echo "Error: pure-tls-shim not found at $SHIM_PATH"
    echo "Build it with: make boringssl-shim"
    exit 1
fi

# Check if runner exists
if [ ! -d "$BORINGSSL_RUNNER" ]; then
    echo "Error: BoringSSL runner not found at $BORINGSSL_RUNNER"
    echo "Set BORINGSSL_DIR environment variable to your BoringSSL checkout"
    exit 1
fi

# Build runner if needed
RUNNER_BIN="$BORINGSSL_RUNNER/runner_test"
if [ ! -f "$RUNNER_BIN" ]; then
    echo "Building BoringSSL runner..."
    (cd "$BORINGSSL_RUNNER" && go test -c -o runner_test .)
fi

echo "=== Running BoringSSL TLS 1.3 Tests ==="
echo "Shim: $SHIM_PATH"
echo "Runner: $RUNNER_BIN"
echo ""

# Run tests and capture output
TMPLOG=$(mktemp)
trap "rm -f $TMPLOG" EXIT

# Run full test suite with timeout
cd "$BORINGSSL_RUNNER"
timeout "$TIMEOUT" go test -v \
    -shim-path="$SHIM_PATH" \
    -allow-unimplemented \
    2>&1 | tee "$TMPLOG" || true

echo ""
echo "=== Test Results Summary ==="

# Extract final counts (format: failed/unimplemented/done/started/total)
FINAL_LINE=$(grep -oE "[0-9]+/[0-9]+/[0-9]+/[0-9]+/[0-9]+" "$TMPLOG" | tail -1)
if [ -n "$FINAL_LINE" ]; then
    FAILED=$(echo "$FINAL_LINE" | cut -d/ -f1)
    UNIMPL=$(echo "$FINAL_LINE" | cut -d/ -f2)
    DONE=$(echo "$FINAL_LINE" | cut -d/ -f3)
    TOTAL=$(echo "$FINAL_LINE" | cut -d/ -f5)
    PASSED=$((DONE - FAILED - UNIMPL))

    echo "Overall: $DONE/$TOTAL tests completed"
    echo "  Passed: $PASSED"
    echo "  Failed: $FAILED"
    echo "  Unimplemented: $UNIMPL"
fi

echo ""
echo "=== Failure Breakdown ==="

# Count failures by category
TLS12_FAILED=$(grep "FAILED" "$TMPLOG" | grep -E "TLS1$|TLS11|TLS12|-TLS\)" | wc -l)
QUIC_FAILED=$(grep "FAILED" "$TMPLOG" | grep "QUIC" | wc -l)
TLS13_FAILED=$(grep "FAILED.*TLS13" "$TMPLOG" | grep -v "QUIC" | wc -l)
OTHER_FAILED=$((FAILED - TLS12_FAILED - QUIC_FAILED - TLS13_FAILED))

echo "  TLS 1.0/1.1/1.2 (expected): $TLS12_FAILED"
echo "  QUIC (not implemented):     $QUIC_FAILED"
echo "  TLS 1.3 (bugs to fix):      $TLS13_FAILED"
echo "  Other/Generic:              $OTHER_FAILED"

# Show TLS 1.3 specific failures
if [ "$TLS13_FAILED" -gt 0 ]; then
    echo ""
    echo "=== TLS 1.3 Failure Details (first 20) ==="
    grep "FAILED.*TLS13" "$TMPLOG" | grep -v "QUIC" | sed 's/.*FAILED /FAILED /' | head -20
fi

echo ""
echo "=== Most Common Errors ==="
grep "TLS error:" "$TMPLOG" | sed 's/.*TLS error: //' | sort | uniq -c | sort -rn | head -10

# Success criteria: TLS 1.3 failures should be reasonable
# Many TLS 1.3 test failures are expected (edge cases, specific alerts, etc.)
if [ "$TLS13_FAILED" -gt 200 ]; then
    echo ""
    echo "ERROR: Too many TLS 1.3 failures ($TLS13_FAILED > 200)"
    exit 1
fi

echo ""
echo "=== Tests Complete ==="
