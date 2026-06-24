#!/bin/bash
# ============================================================================
# security-headers-check.sh — verify Dimension emits the hardened header set
# ============================================================================
# Run against a live Dimension instance (default http://localhost:8184) and
# check that the security headers from the v2 hardening pass are present.
#
# Exits 0 if all required headers are present, 1 if any are missing or weak.
#
# Usage:
#   tools/security-headers-check.sh                    # localhost:8184
#   tools/security-headers-check.sh https://dim.example.com
#
# Add to CI: run after `npm run build && npm start` in a smoke job.
# ============================================================================
set -uo pipefail

URL="${1:-http://localhost:8184/api/v1/dimension/version}"
# Use a HEAD-equivalent GET; some endpoints need auth, but the response
# headers are emitted by middleware before any auth check runs.
CURL_OUT=$(mktemp)
trap "rm -f $CURL_OUT" EXIT

http_code=$(curl -s -o /dev/null -D "$CURL_OUT" -w "%{http_code}" "$URL" 2>&1 || echo "000")
echo "==> $URL  →  HTTP $http_code"

PASS=0
FAIL=0
WARN=0

check_header() {
    local pattern="$1"
    local label="$2"
    local required="${3:-yes}"   # yes | warn
    if grep -i -q "^${pattern}:" "$CURL_OUT"; then
        local value=$(grep -i "^${pattern}:" "$CURL_OUT" | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
        echo "  PASS  $label: $value"
        PASS=$((PASS+1))
    else
        if [ "$required" = "yes" ]; then
            echo "  FAIL  $label: MISSING"
            FAIL=$((FAIL+1))
        else
            echo "  WARN  $label: MISSING (recommended)"
            WARN=$((WARN+1))
        fi
    fi
}

echo ""
echo "=== Required security headers ==="

# --- Strict-Transport-Security (HSTS) ---
hsts=$(grep -i "^strict-transport-security:" "$CURL_OUT" | head -1 | tr -d '\r' || true)
if [ -n "$hsts" ]; then
    if echo "$hsts" | grep -qi "max-age=31536000"; then
        echo "  PASS  Strict-Transport-Security: 1y (good)"
        PASS=$((PASS+1))
    elif echo "$hsts" | grep -qi "max-age="; then
        echo "  WARN  Strict-Transport-Security present but max-age < 1y"
        WARN=$((WARN+1))
    fi
else
    # HSTS only meaningful over HTTPS; allow warn over HTTP
    if echo "$URL" | grep -qi "^https"; then
        echo "  FAIL  Strict-Transport-Security MISSING on HTTPS endpoint"
        FAIL=$((FAIL+1))
    else
        echo "  WARN  Strict-Transport-Security skipped (HTTP)"
        WARN=$((WARN+1))
    fi
fi

# --- X-Frame-Options ---
check_header "x-frame-options" "X-Frame-Options (clickjacking)" yes

# --- X-Content-Type-Options ---
check_header "x-content-type-options" "X-Content-Type-Options (MIME-sniffing)" yes

# --- Referrer-Policy ---
check_header "referrer-policy" "Referrer-Policy (info-leak)" warn

# --- Cross-Origin-Resource-Policy ---
check_header "cross-origin-resource-policy" "Cross-Origin-Resource-Policy" warn

# --- X-DNS-Prefetch-Control (helmet default) ---
check_header "x-dns-prefetch-control" "X-DNS-Prefetch-Control" warn

# --- X-Download-Options (helmet default) ---
check_header "x-download-options" "X-Download-Options" warn

# --- X-Permitted-Cross-Domain-Policies (helmet default) ---
check_header "x-permitted-cross-domain-policies" "X-Permitted-Cross-Domain-Policies" warn

# --- Content-Security-Policy ---
check_header "content-security-policy" "Content-Security-Policy" warn

# --- X-Request-Id (our addition) ---
check_header "x-request-id" "X-Request-Id (traceability)" warn

# --- X-Powered-By (should be ABSENT) ---
if grep -i -q "^x-powered-by:" "$CURL_OUT"; then
    echo "  FAIL  X-Powered-By PRESENT (should be disabled)"
    FAIL=$((FAIL+1))
else
    echo "  PASS  X-Powered-By absent"
    PASS=$((PASS+1))
fi

echo ""
echo "=== Verdict ==="
echo "  PASS=$PASS  WARN=$WARN  FAIL=$FAIL"

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "FAILED: $FAIL required header(s) missing or wrong."
    echo "See SECURITY.md § 'Express hardening (v2)' for the policy."
    exit 1
fi
echo "OK (with $WARN optional warning(s))"
exit 0
