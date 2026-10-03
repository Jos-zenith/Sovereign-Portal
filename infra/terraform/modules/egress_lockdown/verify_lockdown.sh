#!/usr/bin/env bash
# Adversarial egress probe. Run on an LSP application instance after applying egress_lockdown.
#
# It does not read configuration. It tries to get data out by every route it knows and
# records what actually happened, so the report is evidence of behaviour, not a claim.
#
#   ./verify_lockdown.sh 10.0.2.15:3128
#
# Optional probes, enabled by setting the variable:
#   OWN_BUCKET=lsp-bucket              control: S3 in this account must work
#   FOREIGN_BUCKET=other-bucket        a bucket in ANOTHER account whose policy lets anyone write;
#                                      reading or writing it must fail
#   FOREIGN_SQS_URL=https://sqs...     a queue in another account; sending to it must fail
#   RELAY_CANDIDATES="10.0.5.10:3128"  internal hosts that might forward traffic; none may
#   REPORT=report.json                 where to write the JSON report (default lockdown-report-<time>.json)
#   STRICT=1                           count known gaps (DNS) as failures
#
# Run it from an app instance in each app subnet, with the app's own security groups and IAM
# role. A run from anywhere else, such as a bastion, proves nothing about the app's path.
#
# Each result is PASS, FAIL, GAP (open, known and documented) or SKIP (could not be tested).
# Exit code: number of FAIL results, plus GAP results when STRICT=1.

set -u
PROXY="${1:?usage: verify_lockdown.sh <proxy-host:port>}"
STAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
REPORT="${REPORT:-lockdown-report-$(date -u +%Y%m%dT%H%M%SZ).json}"
WAIT=6
fails=0
gaps=0
results=()

command -v curl >/dev/null || { echo "curl is required" >&2; exit 2; }

json_escape() {
  local s=${1//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/ }
  s=${s//$'\r'/ }
  printf '%s' "$s"
}

record() { # record STATUS PROBE DETAIL
  printf '%-5s %-26s %s\n' "$1" "$2" "$3"
  [ "$1" = FAIL ] && fails=$((fails + 1))
  [ "$1" = GAP ] && gaps=$((gaps + 1))
  results+=("{\"probe\":\"$(json_escape "$2")\",\"status\":\"$1\",\"detail\":\"$(json_escape "$3")\"}")
}

last_line() { printf '%s' "$1" | tr -s '\r\n' '\n' | grep -v '^$' | tail -n 1 | cut -c1-140; }

# blocked PROBE WHAT CMD...: the attempt must fail. A refusal or reset still means the
# packet reached the other side, so it counts as a path out.
blocked() {
  local probe=$1 what=$2 out
  shift 2
  if out=$("$@" 2>&1); then
    record FAIL "$probe" "$what succeeded"
  elif printf '%s' "$out" | grep -qiE 'refused|reset by peer'; then
    record FAIL "$probe" "$what reached the other side: $(last_line "$out")"
  else
    record PASS "$probe" "$what blocked: $(last_line "$out")"
  fi
}

no_proxy_env() { env -u HTTPS_PROXY -u https_proxy -u HTTP_PROXY -u http_proxy -u ALL_PROXY -u all_proxy "$@"; }

# aws_blocked PROBE WHAT CMD...: success is a path out; a policy denial or no route is a pass;
# missing credentials means the probe proved nothing.
aws_blocked() {
  local probe=$1 what=$2 out
  shift 2
  if out=$(no_proxy_env "$@" 2>&1); then
    record FAIL "$probe" "$what succeeded"
  elif printf '%s' "$out" | grep -qiE 'Unable to locate credentials|NoCredentials|ExpiredToken|InvalidClientTokenId'; then
    record SKIP "$probe" "no usable AWS credentials: $(last_line "$out")"
  elif printf '%s' "$out" | grep -qiE 'AccessDenied|Forbidden|not authorized|403'; then
    record PASS "$probe" "$what denied by policy: $(last_line "$out")"
  else
    record PASS "$probe" "$what found no path: $(last_line "$out")"
  fi
}

echo "VICT egress probe · proxy ${PROXY} · ${STAMP}"
echo

# 1. Straight out, ignoring the proxy. Targets accept connections on these ports, so only a
#    drop (timeout) counts as blocked.
blocked direct-https-hostname "direct HTTPS to example.com" curl -sS -o /dev/null --noproxy '*' --max-time "$WAIT" https://example.com
blocked direct-https-ipv4 "direct HTTPS to 1.1.1.1" curl -sS -o /dev/null --noproxy '*' --max-time "$WAIT" https://1.1.1.1
blocked direct-http "direct plain HTTP to 1.1.1.1" curl -sS -o /dev/null --noproxy '*' --max-time "$WAIT" http://1.1.1.1
blocked direct-tcp-53 "raw TCP to 1.1.1.1:53" timeout "$WAIT" bash -c 'exec 3<>/dev/tcp/1.1.1.1/53'

if ! command -v ip >/dev/null; then
  record SKIP direct-ipv6 "ip command not available to check for IPv6 addresses"
elif ip -6 addr show scope global 2>/dev/null | grep -q inet6; then
  blocked direct-ipv6 "direct HTTPS over IPv6" curl -6 -sS -o /dev/null --noproxy '*' --max-time "$WAIT" 'https://[2606:4700:4700::1111]'
else
  record PASS direct-ipv6 "instance has no global IPv6 address"
fi

if command -v python3 >/dev/null; then
  UDP_DNS='import socket, sys
q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
s.sendto(q, ("1.1.1.1", 53))
try:
    s.recvfrom(512)
except OSError as exc:
    print(exc)
    sys.exit(1)'
  blocked direct-udp-dns "DNS query straight to 1.1.1.1" python3 -c "$UDP_DNS"
else
  record SKIP direct-udp-dns "python3 not available"
fi

# 2. DNS through the VPC resolver. If it answers for outside names, lookups can carry data out.
if ! command -v getent >/dev/null; then
  record SKIP vpc-resolver-external "getent not available"
elif getent hosts example.com >/dev/null 2>&1; then
  record GAP vpc-resolver-external "VPC resolver answers for external names; DNS can carry data out until Route 53 Resolver DNS Firewall is on"
else
  record PASS vpc-resolver-external "VPC resolver does not answer for external names"
fi

# 3. The proxy itself.
code=$(curl -s -o /dev/null --max-time "$WAIT" -w '%{http_connect}' -x "http://${PROXY}" https://example.com)
[ "$code" = 407 ] && record PASS proxy-no-token "proxy asks for a consent token (407)" \
  || record FAIL proxy-no-token "proxy answered '${code}' without a token, expected 407"

code=$(curl -s -o /dev/null --max-time "$WAIT" -w '%{http_connect}' -x "http://${PROXY}" --proxy-user 'vict:not-a-token' https://example.com)
[ "$code" = 403 ] && record PASS proxy-forged-token "proxy rejects a token it did not sign (403)" \
  || record FAIL proxy-forged-token "proxy answered '${code}' to a forged token, expected 403"

code=$(curl -s -o /dev/null --max-time "$WAIT" -w '%{http_code}' -x "http://${PROXY}" http://example.com)
[ "$code" = 405 ] && record PASS proxy-plain-http "proxy refuses plain HTTP (405)" \
  || record FAIL proxy-plain-http "proxy answered '${code}' to plain HTTP, expected 405"

# 4. AWS services. Data can leave through another account's bucket or queue as easily as
#    through the internet, so these must be denied, not just unrouted.
if command -v aws >/dev/null; then
  if [ -n "${OWN_BUCKET:-}" ]; then
    if out=$(no_proxy_env aws s3api head-bucket --bucket "$OWN_BUCKET" 2>&1); then
      record PASS s3-own-account "own bucket reachable, so the foreign-bucket probes test the endpoint policy"
    else
      record FAIL s3-own-account "own bucket not reachable, so foreign-bucket results only show there is no S3 path: $(last_line "$out")"
    fi
  fi
  if [ -n "${FOREIGN_BUCKET:-}" ]; then
    probe_file=$(mktemp)
    echo "vict egress probe ${STAMP}" >"$probe_file"
    aws_blocked s3-foreign-write "writing to another account's bucket" \
      aws s3api put-object --bucket "$FOREIGN_BUCKET" --key "vict-egress-probe" --body "$probe_file"
    aws_blocked s3-foreign-read "listing another account's bucket" \
      aws s3api list-objects-v2 --bucket "$FOREIGN_BUCKET" --max-items 1
    rm -f "$probe_file"
  else
    record SKIP s3-foreign-write "set FOREIGN_BUCKET to a bucket in another account"
  fi
  if [ -n "${FOREIGN_SQS_URL:-}" ]; then
    aws_blocked sqs-foreign-send "sending to another account's queue" \
      aws sqs send-message --queue-url "$FOREIGN_SQS_URL" --message-body "vict egress probe"
  else
    record SKIP sqs-foreign-send "set FOREIGN_SQS_URL to a queue in another account"
  fi
else
  record SKIP aws-services "aws CLI not installed"
fi

# 5. Internal relays: anything reachable that forwards to the internet defeats the lockdown.
for candidate in ${RELAY_CANDIDATES:-}; do
  blocked "relay-${candidate}" "HTTPS to example.com through ${candidate}" \
    curl -sS -o /dev/null --max-time "$WAIT" -x "http://${candidate}" https://example.com
done
[ -z "${RELAY_CANDIDATES:-}" ] && record SKIP relays "set RELAY_CANDIDATES to internal hosts that might forward traffic"

# Report. Where it ran matters as much as what it found: a probe from a bastion says nothing
# about the app's path, so record the instance, subnet, security groups and role.
imds() {
  curl -s --noproxy '*' --max-time 2 -H "X-aws-ec2-metadata-token: ${imds_token}" "http://169.254.169.254/latest/meta-data/$1" 2>/dev/null || true
}
imds_token=$(curl -s --noproxy '*' --max-time 2 -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' http://169.254.169.254/latest/api/token 2>/dev/null || true)
instance_id=$(imds instance-id)
mac=$(imds mac)
subnet_id=""
vpc_id=""
security_groups=""
if [ -n "$mac" ]; then
  subnet_id=$(imds "network/interfaces/macs/${mac}/subnet-id")
  vpc_id=$(imds "network/interfaces/macs/${mac}/vpc-id")
  security_groups=$(imds "network/interfaces/macs/${mac}/security-group-ids" | tr '\n' ' ')
fi
iam_role=$(imds iam/info | grep -o '"InstanceProfileArn"[^,]*' | cut -d'"' -f4)

script_path="${BASH_SOURCE[0]}"
script_sha256=$(sha256sum "$script_path" 2>/dev/null | cut -d' ' -f1)
git_commit=$(git -C "$(dirname "$script_path")" rev-parse HEAD 2>/dev/null || echo unknown)

attestation="Self-reported: the operator ran this script on its own instance. A signature shows who published the report and that it is unchanged since; it does not prove the probes ran as described or from the stated position. Not a third-party attestation."

joined=$(IFS=,; printf '%s' "${results[*]}")
printf '{"tool":"verify_lockdown.sh","version":3,"generated_at":"%s","script_sha256":"%s","git_commit":"%s","position":{"instance_id":"%s","subnet_id":"%s","vpc_id":"%s","security_groups":"%s","iam_role":"%s","host":"%s"},"proxy":"%s","attestation":"%s","summary":{"total":%d,"fail":%d,"gap":%d},"results":[%s]}\n' \
  "$STAMP" "$script_sha256" "$(json_escape "$git_commit")" \
  "$(json_escape "$instance_id")" "$(json_escape "$subnet_id")" "$(json_escape "$vpc_id")" \
  "$(json_escape "${security_groups% }")" "$(json_escape "$iam_role")" "$(json_escape "$(hostname)")" \
  "$(json_escape "$PROXY")" "$attestation" \
  "${#results[@]}" "$fails" "$gaps" "$joined" >"$REPORT"

echo
echo "${#results[@]} probes: ${fails} failed, ${gaps} known gaps. Report: ${REPORT}"
[ -z "$subnet_id" ] && echo "Warning: not on EC2 or metadata unreachable; the report records no network position."
echo "Sign it for the NBFC: python -m src.egress.attest sign ${REPORT} --key lsp-checkpoint.pem"

if [ "${STRICT:-0}" = 1 ]; then
  exit $((fails + gaps))
fi
exit "$fails"
