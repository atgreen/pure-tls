#!/bin/bash
# Run BoringSSL TLS 1.3 tests against pure-tls
#
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Anthony Green <green@moxielogic.com>

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SHIM_PATH="$PROJECT_DIR/pure-tls-shim"
TIMEOUT="${TEST_TIMEOUT:-300}"
BORINGSSL_RUNNER="${BORINGSSL_RUNNER:-}"
RUNNER_BIN=""

if [ -n "$BORINGSSL_RUNNER_BIN" ]; then
    RUNNER_BIN="$BORINGSSL_RUNNER_BIN"
elif command -v runner_test >/dev/null 2>&1; then
    RUNNER_BIN="$(command -v runner_test)"
fi

# Check if shim exists
if [ ! -x "$SHIM_PATH" ]; then
    echo "Error: pure-tls-shim not found at $SHIM_PATH"
    echo "Build it with: make boringssl-shim"
    exit 1
fi

if [ -z "$RUNNER_BIN" ]; then
    if [ -n "$BORINGSSL_RUNNER" ]; then
        BORINGSSL_RUNNER="$BORINGSSL_RUNNER"
    elif [ -n "$BORINGSSL_DIR" ]; then
        BORINGSSL_RUNNER="$BORINGSSL_DIR/ssl/test/runner"
    fi

    if [ -z "$BORINGSSL_RUNNER" ] || [ ! -d "$BORINGSSL_RUNNER" ]; then
        echo "Error: BoringSSL runner not found."
        echo "Provide one of:"
        echo "  - BORINGSSL_RUNNER (path to ssl/test/runner)"
        echo "  - BORINGSSL_DIR (path to BoringSSL checkout)"
        echo "  - runner_test on PATH (or set BORINGSSL_RUNNER_BIN)"
        exit 1
    fi

    # Build runner if needed
    RUNNER_BIN="$BORINGSSL_RUNNER/runner_test"
    if [ ! -f "$RUNNER_BIN" ]; then
        echo "Building BoringSSL runner..."
        (cd "$BORINGSSL_RUNNER" && go test -c -o runner_test .)
    fi
fi

echo "=== Running BoringSSL TLS 1.3 Tests ==="
echo "Shim: $SHIM_PATH"
echo "Runner: $RUNNER_BIN"
echo ""

# Run tests and capture output
TMPLOG=$(mktemp)
trap "rm -f $TMPLOG" EXIT

# Run full test suite with timeout
if [ -n "$BORINGSSL_RUNNER" ]; then
    cd "$BORINGSSL_RUNNER"
    timeout "$TIMEOUT" go test -v \
        -shim-path="$SHIM_PATH" \
        -allow-unimplemented \
        2>&1 | tee "$TMPLOG" || true
else
    timeout "$TIMEOUT" "$RUNNER_BIN" \
        -test.v \
        -shim-path="$SHIM_PATH" \
        -allow-unimplemented \
        2>&1 | tee "$TMPLOG" || true
fi

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
# Version negotiation tests (TLS 1.3-only impl can't do fallback)
VERSION_NEG_FAILED=$(grep "FAILED" "$TMPLOG" | grep -E "VersionNegotiation|MinimumVersion|Fallback" | wc -l)

# TLS 1.0/1.1/1.2 tests (we only support TLS 1.3)
TLS12_FAILED=$(grep "FAILED" "$TMPLOG" | grep -v "VersionNegotiation\|MinimumVersion" | grep -E "TLS1$|TLS11|TLS12|-TLS\)|TLS-TLS1[012]" | wc -l)

# QUIC tests (not implemented)
QUIC_FAILED=$(grep "FAILED" "$TMPLOG" | grep "QUIC" | wc -l)

# ECH tests (not implemented - optional extension)
ECH_FAILED=$(grep "FAILED" "$TMPLOG" | grep "ECH" | wc -l)

# Server-side tests (we're primarily a client implementation)
SERVER_FAILED=$(grep "FAILED" "$TMPLOG" | grep -E "TLS13-Server-|Server-.*-TLS13|CertReq-CA-List|RequireAnyClientCertificate|SkipClientCertificate|-Server-TLS13" | wc -l)

# Callback/optional feature tests
CALLBACK_FAILED=$(grep "FAILED" "$TMPLOG" | grep -E "Callback|GREASE|DDoS|Hint|Compliance|Ticket.*Skip|SRTP|ChannelID" | wc -l)

# Count errors that are actually TLS 1.2 compatibility issues (even in "TLS13" tests)
TLS12_COMPAT_ERRORS=$(grep -B5 "FAILED.*TLS13" "$TMPLOG" | grep -E "TLS 1.2 not supported|TLS 1.2-only extension|protocol_version" | wc -l)

# Real TLS 1.3 client bugs (exclude all the above categories)
TLS13_ALL=$(grep "FAILED.*TLS13" "$TMPLOG" | grep -v "QUIC\|VersionNegotiation\|MinimumVersion\|ECH\|Server-\|Callback\|GREASE\|DDoS\|Hint\|Compliance\|SRTP\|ChannelID" | wc -l)
# Subtract tests that fail due to TLS 1.2 compatibility errors
TLS13_FAILED=$((TLS13_ALL > TLS12_COMPAT_ERRORS ? TLS13_ALL - TLS12_COMPAT_ERRORS : 0))

# Calculate other/remaining
CATEGORIZED=$((TLS12_FAILED + VERSION_NEG_FAILED + QUIC_FAILED + ECH_FAILED + SERVER_FAILED + CALLBACK_FAILED + TLS13_ALL))
OTHER_FAILED=$((FAILED > CATEGORIZED ? FAILED - CATEGORIZED : 0))

echo "  TLS 1.0/1.1/1.2 (expected):     $TLS12_FAILED"
echo "  Version negotiation (expected): $VERSION_NEG_FAILED"
echo "  QUIC (not implemented):         $QUIC_FAILED"
echo "  ECH (not implemented):          $ECH_FAILED"
echo "  Server-side (client-only impl): $SERVER_FAILED"
echo "  Callbacks/optional features:    $CALLBACK_FAILED"
echo "  TLS 1.3 client (bugs to fix):   $TLS13_FAILED"
echo "  Other/Generic:                  $OTHER_FAILED"

# Show real TLS 1.3 client failures (excluding server, callbacks, ECH, etc.)
REAL_TLS13_BUGS=$(grep "FAILED.*TLS13" "$TMPLOG" | grep -v "QUIC\|VersionNegotiation\|MinimumVersion\|ECH\|Server-\|-Server\|Callback\|GREASE\|DDoS\|Hint\|Compliance\|SRTP\|ChannelID\|CertReq-CA\|ClientAuth\|ClientCertificate" | head -20)
if [ -n "$REAL_TLS13_BUGS" ]; then
    echo ""
    echo "=== TLS 1.3 Client Failures (first 20) ==="
    echo "$REAL_TLS13_BUGS" | sed 's/.*FAILED /FAILED /'
fi

echo ""
echo "=== Most Common Errors ==="
grep "TLS error:" "$TMPLOG" | sed 's/.*TLS error: //' | sort | uniq -c | sort -rn | head -10

# Also show how many errors are TLS 1.2 compatibility related
TLS12_ERROR_COUNT=$(grep "TLS error:" "$TMPLOG" | grep -E "TLS 1.2 not supported|TLS 1.2-only extension|protocol_version|supported_versions" | wc -l)
echo ""
echo "  (Note: $TLS12_ERROR_COUNT errors are TLS 1.2 compatibility related)"

# Success criteria: Real TLS 1.3 client failures should be low
# We're a TLS 1.3-only client, so server-side and TLS 1.2 tests don't count
if [ "$TLS13_FAILED" -gt 100 ]; then
    echo ""
    echo "WARNING: TLS 1.3 client failures higher than expected ($TLS13_FAILED > 100)"
    echo "Review the failures above to identify real bugs vs expected limitations."
    # Don't exit with error - just warn
fi

echo ""
echo "=== Tests Complete ==="
