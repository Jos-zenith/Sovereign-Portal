#!/usr/bin/env bash
# Run on an LSP application instance after applying the egress_lockdown module.
# Every check must print PASS; any FAIL means application code can bypass the proxy.
#
#   ./verify_lockdown.sh 10.0.2.15:3128

set -u
PROXY="${1:?usage: verify_lockdown.sh <proxy-host:port>}"
failures=0

pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; failures=$((failures + 1)); }

if curl -s -o /dev/null --noproxy '*' --max-time 5 https://example.com; then
  fail "direct HTTPS to the internet succeeded"
else
  pass "direct HTTPS to the internet is blocked"
fi

if curl -s -o /dev/null --noproxy '*' --max-time 5 https://1.1.1.1; then
  fail "direct HTTPS to a raw IP succeeded"
else
  pass "direct HTTPS to a raw IP is blocked"
fi

if curl -s -o /dev/null --noproxy '*' --max-time 5 http://example.com; then
  fail "direct plain HTTP succeeded"
else
  pass "direct plain HTTP is blocked"
fi

code=$(curl -s -o /dev/null --max-time 5 -w '%{http_connect}' -x "http://${PROXY}" https://example.com)
if [ "$code" = "407" ]; then
  pass "proxy refuses a call without a consent token (407)"
else
  fail "proxy answered '${code}' to a call without a consent token, expected 407"
fi

echo
echo "Not checked: DNS. Queries to the Amazon-provided resolver bypass security groups and NACLs."
echo "See README.md in this module."
exit "$failures"
