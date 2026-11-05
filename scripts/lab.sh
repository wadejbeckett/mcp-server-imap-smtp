#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Container test lab for `pytest -m lab`: Dovecot 2.4 + Pigeonhole and Postfix, three profiles.
#   scripts/lab.sh up      build the image, make the lab CA (once) and start every profile
#   scripts/lab.sh down    stop and remove the lab containers (mailboxes start empty next time)
#   scripts/lab.sh status  show the containers and the ports each profile listens on
#   scripts/lab.sh clean   down, then delete the lab CA and certificates in lab/.state
# Every port is bound to 127.0.0.1 only. Needs docker and openssl.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE="$ROOT/lab/.state"
TLS="$STATE/tls"     # mounted into the containers: ca.pem, server.pem, server.key
CAKEY="$STATE/ca"    # the CA key, never mounted
IMAGE="mcp-imap-smtp-lab:latest"
# profile:port-prefix. Host ports are <prefix><container port's last three digits>, e.g. flat IMAP 10993.
PROFILES=(flat:10 prefixed:11 stripped:12)

ports() {   # profile prefix -> docker -p arguments
  local p="$1"
  echo "-p 127.0.0.1:${p}993:993 -p 127.0.0.1:${p}465:465 -p 127.0.0.1:${p}587:587 -p 127.0.0.1:${p}190:4190"
}

make_tls() {
  [ -s "$TLS/ca.pem" ] && [ -s "$TLS/server.pem" ] && [ -s "$TLS/server.key" ] && return 0
  mkdir -p "$TLS" "$CAKEY"; chmod 700 "$STATE" "$TLS" "$CAKEY"
  local tmp; tmp="$(mktemp -d)"
  openssl req -x509 -new -nodes -newkey rsa:2048 -sha256 -days 3650 \
    -subj "/CN=mcp-server-imap-smtp test lab CA" \
    -addext "basicConstraints=critical,CA:true" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "$CAKEY/ca.key" -out "$TLS/ca.pem" 2>/dev/null
  openssl req -new -nodes -newkey rsa:2048 -sha256 -subj "/CN=localhost" \
    -keyout "$TLS/server.key" -out "$tmp/server.csr" 2>/dev/null
  printf '%s\n' "basicConstraints=CA:false" "keyUsage=critical,digitalSignature,keyEncipherment" \
    "extendedKeyUsage=serverAuth" "subjectAltName=DNS:localhost,IP:127.0.0.1" > "$tmp/ext"
  openssl x509 -req -in "$tmp/server.csr" -CA "$TLS/ca.pem" -CAkey "$CAKEY/ca.key" \
    -CAserial "$tmp/ca.srl" -CAcreateserial -days 825 -sha256 -extfile "$tmp/ext" -out "$TLS/server.pem" 2>/dev/null
  rm -rf "$tmp"
  # The containers read the server key as root; nobody else on the host needs either key.
  chmod 600 "$TLS/server.key" "$CAKEY/ca.key"
  echo "lab CA written to $TLS/ca.pem (scripts/lab.sh clean renews it)"
}

wait_ready() {   # container: until Dovecot (993, 4190) and Postfix (465, 587) listen inside it
  local name="$1" i
  for i in $(seq 1 60); do
    if docker exec "$name" bash -c 'for p in 993 4190 465 587; do (exec 3<>/dev/tcp/127.0.0.1/$p) 2>/dev/null || exit 1; done' \
        >/dev/null 2>&1; then return 0; fi
    if [ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null)" != "true" ]; then
      echo "$name stopped:" >&2; docker logs --tail 30 "$name" >&2; return 1
    fi
    sleep 1
  done
  echo "$name did not become ready in 60 s" >&2; docker logs --tail 30 "$name" >&2; return 1
}

up() {
  make_tls
  docker build -q -t "$IMAGE" "$ROOT/lab" >/dev/null
  local entry name prefix
  for entry in "${PROFILES[@]}"; do
    name="mcp-lab-${entry%%:*}"; prefix="${entry##*:}"
    docker rm -f "$name" >/dev/null 2>&1 || true
    # shellcheck disable=SC2046
    docker run -d --name "$name" --label mcp-imap-smtp-lab=1 -e "LAB_PROFILE=${entry%%:*}" \
      -v "$TLS:/lab/tls:ro" $(ports "$prefix") "$IMAGE" >/dev/null
  done
  for entry in "${PROFILES[@]}"; do wait_ready "mcp-lab-${entry%%:*}"; done
  status
}

down() {
  local ids; ids="$(docker ps -aq --filter label=mcp-imap-smtp-lab=1)"
  [ -n "$ids" ] && docker rm -f $ids >/dev/null
  echo "lab stopped"
}

status() {
  local entry p
  docker ps -a --filter label=mcp-imap-smtp-lab=1 --format 'table {{.Names}}\t{{.Status}}'
  for entry in "${PROFILES[@]}"; do
    p="${entry##*:}"
    printf '%-9s IMAPS %s993  SMTPS %s465  submission %s587  ManageSieve %s190\n' "${entry%%:*}" "$p" "$p" "$p" "$p"
  done
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  status) status ;;
  clean) down; rm -rf "$STATE"; echo "lab CA removed" ;;
  *) echo "usage: $0 up|down|status|clean" >&2; exit 2 ;;
esac
