#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Smoke test a deployed mcp-server-imap-smtp gateway from anywhere. No credentials are used or needed.
#
#   deploy/smoke.sh https://mcp.example.com
#
# Options (environment):
#   MAIL_PATH=/mail            path of the mail MCP service
#   SMOKE_RESOLVE=host:443:IP  pin the hostname to an address (test a VPS before DNS points at it);
#                              passed to curl --resolve and used for the certificate check
#   SMOKE_INSECURE=1           skip certificate verification (self-signed test setups only; the TLS
#                              check then reports FAIL)
# An http:// base URL (local development) skips the TLS, redirect, HSTS and Server-header checks.
# Exits 1 if any check fails. Needs curl and python3; openssl for the certificate expiry check.
set -euo pipefail

[[ $# -eq 1 ]] || { echo "usage: $0 BASE_URL   (for example https://mcp.example.com)" >&2; exit 2; }
base="${1%/}"
mail_path="${MAIL_PATH:-/mail}"
[[ $base =~ ^(https?)://([^/:]+)(:([0-9]+))?$ ]] || { echo "BASE_URL must be scheme://host[:port] with no path" >&2; exit 2; }
scheme="${BASH_REMATCH[1]}"
host="${BASH_REMATCH[2]}"
port="${BASH_REMATCH[4]:-$([[ $scheme == https ]] && echo 443 || echo 80)}"

curl_opts=(-sS --max-time 20)
if [[ -n ${SMOKE_RESOLVE:-} ]]; then
    curl_opts+=(--resolve "$SMOKE_RESOLVE")
    http_resolve="${SMOKE_RESOLVE/:443:/:80:}"
fi
[[ ${SMOKE_INSECURE:-0} == 1 ]] && curl_opts+=(-k)

failed=0
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; failed=1; }
skip() { printf 'SKIP  %s\n' "$*"; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# fetch NAME METHOD URL [curl args...]: headers to $tmp/NAME.h, body to $tmp/NAME.b, prints the status.
fetch() {
    local name=$1 method=$2 url=$3
    shift 3
    curl "${curl_opts[@]}" -X "$method" -D "$tmp/$name.h" -o "$tmp/$name.b" -w '%{http_code}' "$@" "$url" 2>"$tmp/$name.err" || echo "000"
}
# header NAME Header-Name: last value of that header, CR stripped.
header() { grep -i "^$2:" "$tmp/$1.h" 2>/dev/null | tail -n1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//' || true; }

# 1. TLS certificate: valid chain and name (curl verifies), and expiry.
if [[ $scheme == https ]]; then
    if [[ ${SMOKE_INSECURE:-0} == 1 ]]; then
        fail "TLS: certificate not verified (SMOKE_INSECURE=1)"
    elif curl "${curl_opts[@]}" -o /dev/null "$base/.well-known/oauth-authorization-server" 2>"$tmp/tls.err"; then
        pass "TLS: certificate chain and hostname valid for $host"
    else
        fail "TLS: $(tr -d '\n' < "$tmp/tls.err")"
    fi
    if command -v openssl >/dev/null; then
        connect="$host:$port"
        if [[ -n ${SMOKE_RESOLVE:-} ]]; then
            addr="${SMOKE_RESOLVE#*:*:}"
            [[ $addr == *:* && $addr != \[* ]] && addr="[$addr]"
            connect="$addr:$port"
        fi
        end="$(openssl s_client -connect "$connect" -servername "$host" </dev/null 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2 || true)"
        if [[ -n $end ]]; then
            days=$(( ($(date -d "$end" +%s) - $(date +%s)) / 86400 ))
            if (( days >= 14 )); then pass "TLS: certificate valid for $days more days"; else fail "TLS: certificate expires in $days days ($end)"; fi
        else
            fail "TLS: could not read the certificate from $connect"
        fi
    else
        skip "TLS expiry: openssl not installed"
    fi
else
    skip "TLS: base URL is http"
fi

# 2. Plain HTTP redirects to HTTPS (ACME path aside).
if [[ $scheme == https ]]; then
    redir_opts=(-sS --max-time 20 -o /dev/null -w '%{http_code} %{redirect_url}')
    [[ -n ${http_resolve:-} ]] && redir_opts+=(--resolve "$http_resolve")
    got="$(curl "${redir_opts[@]}" "http://$host/smoke-check?x=1" 2>/dev/null || echo "000")"
    if [[ $got == "301 https://$host/smoke-check?x=1" ]]; then pass "HTTP: redirects to HTTPS"; else fail "HTTP: expected 301 to https://$host/smoke-check?x=1, got '$got'"; fi
else
    skip "HTTP redirect: base URL is http"
fi

# 3. Protected-resource metadata (RFC 9728) for the mail service.
status="$(fetch prm GET "$base/.well-known/oauth-protected-resource$mail_path")"
if [[ $status == 200 ]]; then
    if msg="$(python3 - "$tmp/prm.b" "$base" "$mail_path" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
base, path = sys.argv[2], sys.argv[3]
problems = []
if doc.get("resource") != base + path:
    problems.append(f"resource is {doc.get('resource')!r}, expected {base + path!r}")
if not any(str(s).rstrip("/") == base for s in doc.get("authorization_servers", [])):
    problems.append(f"authorization_servers {doc.get('authorization_servers')!r} does not list {base}")
if "offline_access" not in doc.get("scopes_supported", []):
    problems.append("offline_access missing from scopes_supported")
print("; ".join(problems))
sys.exit(1 if problems else 0)
PY
)"; then pass "protected-resource metadata: 200, resource = $base$mail_path, offline_access"; else fail "protected-resource metadata: $msg"; fi
else
    fail "protected-resource metadata: HTTP $status $(cat "$tmp/prm.err" 2>/dev/null)"
fi

# 4. Authorization-server metadata (RFC 8414).
status="$(fetch asm GET "$base/.well-known/oauth-authorization-server")"
if [[ $status == 200 ]]; then
    if msg="$(python3 - "$tmp/asm.b" "$base" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
base = sys.argv[2]
problems = []
if str(doc.get("issuer", "")).rstrip("/") != base:
    problems.append(f"issuer is {doc.get('issuer')!r}")
if "S256" not in doc.get("code_challenge_methods_supported", []):
    problems.append("S256 missing from code_challenge_methods_supported")
for key in ("registration_endpoint", "authorization_endpoint", "token_endpoint"):
    if not str(doc.get(key, "")).startswith(base + "/"):
        problems.append(f"{key} is {doc.get(key)!r}")
if doc.get("client_id_metadata_document_supported") is not True:
    problems.append("client_id_metadata_document_supported is not true")
if "offline_access" not in doc.get("scopes_supported", []):
    problems.append("offline_access missing from scopes_supported (ChatGPT needs it to refresh)")
print("; ".join(problems))
sys.exit(1 if problems else 0)
PY
)"; then pass "authorization-server metadata: 200, S256, registration endpoint, CIMD supported, offline_access"; else fail "authorization-server metadata: $msg"; fi
else
    fail "authorization-server metadata: HTTP $status $(cat "$tmp/asm.err" 2>/dev/null)"
fi

# 5. Unauthenticated MCP request: 401 pointing at the protected-resource metadata.
status="$(fetch mcp POST "$base$mail_path" -H 'content-type: application/json' \
    -H 'accept: application/json, text/event-stream' \
    --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}')"
www="$(header mcp WWW-Authenticate)"
want="resource_metadata=\"$base/.well-known/oauth-protected-resource$mail_path\""
if [[ $status == 401 && $www == *"$want"* ]]; then
    pass "POST $mail_path without a token: 401, WWW-Authenticate has $want"
else
    fail "POST $mail_path without a token: HTTP $status, WWW-Authenticate '$www' (want 401 with $want)"
fi

# 6. Sign-in page without a request id: 400 with the security headers.
status="$(fetch login GET "$base${mail_path%/}/login")"
problems=()
[[ $status == 400 ]] || problems+=("HTTP $status, expected 400")
[[ "$(header login X-Frame-Options)" == DENY ]] || problems+=("X-Frame-Options not DENY")
[[ "$(header login Content-Security-Policy)" == *"default-src 'none'"* ]] || problems+=("Content-Security-Policy missing or weak")
[[ "$(header login Cache-Control)" == *no-store* ]] || problems+=("Cache-Control lacks no-store")
[[ "$(header login Referrer-Policy)" == no-referrer ]] || problems+=("Referrer-Policy not no-referrer")
if [[ $scheme == https ]]; then
    [[ "$(header login Strict-Transport-Security)" == *max-age=* ]] || problems+=("Strict-Transport-Security missing")
fi
if (( ${#problems[@]} == 0 )); then pass "GET ${mail_path%/}/login without req: 400 with security headers"; else fail "GET ${mail_path%/}/login: ${problems[*]}"; fi

# 7. nginx does not advertise its version.
if [[ $scheme == https ]]; then
    server="$(header login Server)"
    if [[ $server =~ [0-9] ]]; then fail "Server header reveals a version: '$server'"; else pass "Server header has no version ('$server')"; fi
else
    skip "Server header: base URL is http"
fi

if (( failed )); then
    echo "smoke: FAILED"
    exit 1
fi
echo "smoke: all checks passed for $base"
