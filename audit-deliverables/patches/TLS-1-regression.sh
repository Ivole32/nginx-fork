#!/bin/bash
# TLS-1 regression driver. Usage: TLS-1-regression.sh <nginx-binary>
# Starts nginx with the GH-TLS-1 config, runs the no-SNI client-cert bypass
# matrix via openssl s_client, prints PASS/FAIL, stops nginx, returns non-zero
# if any assertion fails. Ports 19000-19003, loopback only.
set -u
BIN="${1:?usage: $0 <nginx-binary>}"
BASE=/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-tls1/run
C=/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/val-tls1/certs
mkdir -p "$BASE/logs" "$BASE/tmp"; : > "$BASE/logs/error.log"

req() { # port sni cert host  -> echoes first HTTP status line (or TLS alert)
  local port=$1 sni=$2 cert=$3 host=$4
  local a="-connect 127.0.0.1:$port -quiet"
  [ "$sni" = none ] && a="$a -noservername" || a="$a -servername $sni"
  [ "$cert" != none ] && a="$a -cert $C/$cert.crt -key $C/$cert.key"
  local out
  out=$( ( printf 'GET / HTTP/1.0\r\nHost: %s\r\n\r\n' "$host"; sleep 0.6 ) \
         | timeout 6 openssl s_client $a 2>"$BASE/tmp/sc.err" )
  local line
  line=$(printf '%s' "$out" | grep -a -E '^HTTP/' | head -1 | tr -d '\r')
  if [ -z "$line" ]; then
    line="TLS-$(grep -a -oE 'alert number [0-9]+|unrecognized name' "$BASE/tmp/sc.err" | head -1)"
  fi
  printf '%s' "$line"
}

check() { # desc expected-regex  port sni cert host
  local desc=$1 exp=$2; shift 2
  local got; got=$(req "$@")
  if printf '%s' "$got" | grep -qE "$exp"; then
    echo "PASS | $desc | got: $got"
  else
    echo "FAIL | $desc | expected /$exp/ got: $got"
    FAILED=1
  fi
}

"$BIN" -c "$BASE/nginx.conf" -p "$BASE" >"$BASE/tmp/stdout.log" 2>&1 &
NGX=$!
sleep 1.5
if ! kill -0 "$NGX" 2>/dev/null; then echo "nginx failed to start"; cat "$BASE/tmp/stdout.log"; exit 2; fi

FAILED=0
echo "=== binary: $BIN ==="
# --- THE FIX ASSERTION: no-SNI bypass must become 421 ---
check "S1 noSNI clientA Host=b (BYPASS->must be 421)" '^HTTP/1.1 421'           19000 none    clientA b.example
check "S1 unmatchedSNI clientA Host=b (BYPASS->must be 421)" '^HTTP/1.1 421'    19000 c.example clientA b.example
check "S2 noSNI clientA Host=b (BYPASS->must be 421)" '^HTTP/1.1 421'           19001 none    clientA b.example
# --- CONTROLS: must keep their result ---
check "S1 noSNI clientA Host=a (default server, legit)" '^HTTP/1.1 200'         19000 none    clientA a.example
check "S1 SNI=a clientA Host=b (existing SNI-guard 421)" '^HTTP/1.1 421'        19000 a.example clientA b.example
check "S1 SNI=b clientB Host=b (legit B client)" '^HTTP/1.1 200'                19000 b.example clientB b.example
# denial cases: no-SNI routed to a different verify-enabled vhost is denied
# (unpatched 400 "no required cert"; patched 421 at routing). Either way: NOT 200.
check "S1 noSNI noCert Host=b (must be denied, not 200)" '^HTTP/1.1 (400|421)'  19000 none    none    b.example
check "S4 noSNI clientB Host=b (must be denied, not 200)" '^HTTP/1.1 (400|421)' 19003 none    clientB b.example
check "S4 SNI=b clientB Host=b (legit via SNI)" '^HTTP/1.1 200'                 19003 b.example clientB b.example

kill "$NGX" 2>/dev/null; wait "$NGX" 2>/dev/null
ASAN=$(grep -c -a "AddressSanitizer\|runtime error" "$BASE/logs/error.log" "$BASE/tmp/stdout.log" 2>/dev/null | awk -F: '{s+=$2} END{print s+0}')
echo "sanitizer-hits: $ASAN"
echo "RESULT: $([ $FAILED -eq 0 ] && echo ALL-PASS || echo HAS-FAIL)"
exit $FAILED
