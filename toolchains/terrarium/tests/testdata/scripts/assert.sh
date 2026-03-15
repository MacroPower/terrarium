#!/bin/sh
# Assertion runner framework for terrarium E2E tests.
# Source this file, define assertions, then call run_assertions.
set -e

PASS=0
FAIL=0

assert_allowed() {
    url="$1"
    desc="${2:-$url reachable}"
    if curl -sf -k --max-time 10 "$url" >/dev/null 2>&1; then
        echo "PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "FAIL: $desc (expected ALLOWED, got DENIED)"
        FAIL=$((FAIL + 1))
    fi
}

assert_denied() {
    url="$1"
    desc="${2:-$url denied}"
    if curl -sf -k --max-time 10 "$url" >/dev/null 2>&1; then
        echo "FAIL: $desc (expected DENIED, got ALLOWED -- SECURITY VIOLATION)"
        FAIL=$((FAIL + 1))
    else
        echo "PASS: $desc"
        PASS=$((PASS + 1))
    fi
}

assert_l7_allowed() {
    url="$1"
    method="${2:-GET}"
    expected_body="$3"
    desc="${4:-$method $url allowed}"
    body=$(curl -sf -k --max-time 10 -X "$method" "$url" 2>/dev/null) || {
        echo "FAIL: $desc (expected L7 ALLOWED, connection failed)"
        FAIL=$((FAIL + 1))
        return
    }
    if [ -n "$expected_body" ]; then
        if echo "$body" | grep -q "$expected_body"; then
            echo "PASS: $desc"
            PASS=$((PASS + 1))
        else
            echo "FAIL: $desc (expected body containing '$expected_body', got '$body')"
            FAIL=$((FAIL + 1))
        fi
    else
        echo "PASS: $desc"
        PASS=$((PASS + 1))
    fi
}

assert_l7_denied() {
    url="$1"
    method="${2:-GET}"
    desc="${3:-$method $url denied}"
    status=$(curl -s -k --max-time 10 -o /dev/null -w "%{http_code}" -X "$method" "$url" 2>/dev/null) || true
    if [ "$status" = "403" ]; then
        echo "PASS: $desc (HTTP 403)"
        PASS=$((PASS + 1))
    elif [ "$status" = "000" ]; then
        # Connection failed entirely -- also counts as denied for L7
        echo "PASS: $desc (connection refused)"
        PASS=$((PASS + 1))
    else
        echo "FAIL: $desc (expected HTTP 403, got HTTP $status -- SECURITY VIOLATION)"
        FAIL=$((FAIL + 1))
    fi
}

report_results() {
    echo ""
    echo "Results: $PASS passed, $FAIL failed"
    if [ "$FAIL" -ne 0 ]; then
        exit 1
    fi
}
