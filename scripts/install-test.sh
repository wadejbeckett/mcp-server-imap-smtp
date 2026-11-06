#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Clean-machine install test: install the gateway on a fresh Debian 13 VM the way docs/DEPLOY.md says, in
# front of a mail server it has never seen, and check it from outside with deploy/smoke.sh and deploy/e2e.py.
#
#   scripts/install-test.sh                 fresh install of HEAD
#   scripts/install-test.sh --upgrade REV   install REV first, keep a signed-in connection, install HEAD
#                                           over it and show that connection still works
#   KEEP=1 scripts/install-test.sh ...      leave the VM and the mail container running at the end
#   scripts/install-test.sh up              only start the mail server and the VM, for working by hand
#                                           (ssh -F <work dir>/ssh_config vm); implies KEEP=1
#   scripts/install-test.sh down            remove a VM and container left by KEEP=1
#
# What it does, unattended, as an unprivileged user (nothing is installed on this machine):
#   1. Downloads the official Debian 13 generic cloud image over HTTPS into its own directory and checks
#      it against the published SHA512SUMS (cached; re-checked every run). Boots it with QEMU and KVM
#      (2 CPUs, 2 GB, a copy-on-write overlay, user-mode networking with SSH, 80 and 443 forwarded to
#      127.0.0.1 on this machine), with a cloud-init seed that lets root in with a key made for this run.
#   2. Starts one container of the test lab's mail server (lab/, flat profile) under its own name, with a
#      certificate for mail.example.test from a test CA made for this run. The VM reaches it as
#      mail.example.test through QEMU's gateway address (an /etc/hosts line stands in for DNS).
#   3. Clones this checkout, builds the bundle with deploy/build.sh, ships it with scp and runs install.sh
#      with the command docs/DEPLOY.md gives, as an operator with a private CA would: the CA is added to
#      the VM's trust store and the gateway gets a certificate from that CA through TLS_CERT and TLS_KEY.
#      Then it binds the gateway to the mail server in /etc/<name>/config.toml, re-runs install.sh (which
#      opens the firewall to it), and runs deploy/smoke.sh and deploy/e2e.py --write --send from here as
#      the lab user alice@example.test.
#
# What it cannot test: a public name, real DNS and Let's Encrypt issuance (certbot never runs here), and
# Debian 12. The VM's port 443 is reached through an unprivileged port on this machine, so smoke.sh and
# e2e.py run with their connections pointed there (curl --connect-to, and a getaddrinfo shim for e2e.py);
# the names, certificates and Host headers they check are the real ones.
#
# Needs: qemu-system-x86_64 and qemu-img with /dev/kvm, genisoimage, docker, openssl, ssh, curl, git,
# python3 >= 3.11 and uv. Takes about 4 minutes (6 with --upgrade) once the image is cached, plus the first
# download of the image (about 430 MB).
# Environment: INSTALL_TEST_DIR (default ~/.cache/mcp-server-imap-smtp-install-test) holds the image
# cache, each run's work directory and, after a failed run, that run's logs in last-failure/;
# INSTALL_TEST_PORT_BASE (default 22000) picks the host ports BASE+22 (SSH), +80, +443, +993 (IMAPS) and
# +465 (SMTPS), all on 127.0.0.1.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_DIR="${INSTALL_TEST_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/mcp-server-imap-smtp-install-test}"
IMAGE_URL="https://cloud.debian.org/images/cloud/trixie/latest"
IMAGE_FILE="debian-13-generic-amd64.qcow2"
PORT_BASE="${INSTALL_TEST_PORT_BASE:-22000}"
P_SSH=$((PORT_BASE + 22)) P_HTTP=$((PORT_BASE + 80)) P_HTTPS=$((PORT_BASE + 443))
P_IMAPS=$((PORT_BASE + 993)) P_SMTPS=$((PORT_BASE + 465))
PREFIX=mcp-vmtest
CONTAINER=$PREFIX-mail
MAIL_IMAGE=$PREFIX-mail:latest
GATEWAY=mcp.example.test
MAIL_HOST=mail.example.test
NAME=mcp-server-imap-smtp
W="$BASE_DIR/run"          # this run's work directory: VM overlay, keys, certificates, clone, logs
INSTALLS=0 INSTALL_LOG=""

log() { printf '\n[install-test %s] %s\n' "$(date +%H:%M:%S)" "$*"; }
die() { printf '\n[install-test] FAILED: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null || die "$1 not found (see the requirements at the top of $0)"; }

# --- 0. Clean-up -------------------------------------------------------------------------------------
down() {
    local pid
    pid="$(cat "$W/qemu.pid" 2>/dev/null || true)"
    # Only the QEMU this script started: its pid file, and this run's disk on its command line.
    if [[ $pid =~ ^[0-9]+$ ]] && tr '\0' '\n' < "/proc/$pid/cmdline" 2>/dev/null | grep -qF "file=$W/disk.qcow2"; then
        kill "$pid" 2>/dev/null || true
        for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
    fi
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    rm -rf "$W"
}

# keep_logs: copies a failed run's logs out of the work directory, which down() removes.
keep_logs() {
    local keep="$BASE_DIR/last-failure" f
    rm -rf "$keep"
    mkdir -p "$keep"
    for f in "$W"/console.log "$W"/*.build.log "$W"/install.*.log; do
        if [[ -f $f ]]; then cp "$f" "$keep/"; fi
    done
    printf '\n[install-test] The logs of this run (console.log, *.build.log, install.N.log) are in %s\n' "$keep" >&2
}

on_exit() {
    local rc=$?
    if [[ ${KEEP:-0} == 1 ]]; then
        printf '\nKEEP=1: VM and %s left running. ssh -F %s/ssh_config vm; %s down to remove.\n' "$CONTAINER" "$W" "$0"
        # keep_logs does not run here, so last-failure/ is absent or an older run's: name this run's own logs.
        (( rc == 0 )) || printf '\n[install-test] The logs of this run (console.log, *.build.log, install.N.log) are in %s\n' "$W" >&2
    else
        (( rc == 0 )) || keep_logs
        down
    fi
    exit $rc
}

# --- 1. The image, checked against SHA512SUMS ----------------------------------------------------------
fetch_image() {
    local dir="$BASE_DIR/image" sums
    mkdir -p "$dir"
    sums="$(curl -fsSL --proto =https --proto-redir =https --tlsv1.2 "$IMAGE_URL/SHA512SUMS")" || die "could not fetch SHA512SUMS"
    local want; want="$(awk -v f="$IMAGE_FILE" '$2 == f {print $1}' <<<"$sums")"
    [[ $want =~ ^[0-9a-f]{128}$ ]] || die "no SHA512 for $IMAGE_FILE in SHA512SUMS"
    if [[ -f $dir/$IMAGE_FILE ]] && [[ "$(sha512sum < "$dir/$IMAGE_FILE" | cut -d' ' -f1)" == "$want" ]]; then
        log "Image cached and matches SHA512SUMS"
        return
    fi
    log "Downloading $IMAGE_FILE"
    local start=$SECONDS
    rm -f "$dir/$IMAGE_FILE.part"
    curl -fsSL --proto =https --proto-redir =https --tlsv1.2 -o "$dir/$IMAGE_FILE.part" "$IMAGE_URL/$IMAGE_FILE" || die "image download failed"
    [[ "$(sha512sum < "$dir/$IMAGE_FILE.part" | cut -d' ' -f1)" == "$want" ]] || die "image does not match SHA512SUMS"
    mv -f "$dir/$IMAGE_FILE.part" "$dir/$IMAGE_FILE"
    log "Image downloaded and verified in $((SECONDS - start)) s"
}

# --- 2. Test PKI: one CA, a certificate for the mail server and one for the gateway --------------------
make_pki() {
    local d="$W/pki" n
    mkdir -p "$d"; chmod 700 "$d"
    openssl req -x509 -new -nodes -newkey rsa:2048 -sha256 -days 120 -subj "/CN=mcp-server-imap-smtp install test CA" \
        -addext "basicConstraints=critical,CA:true" -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -keyout "$d/ca.key" -out "$d/ca.pem" 2>/dev/null
    for n in "$MAIL_HOST" "$GATEWAY"; do
        openssl req -new -nodes -newkey rsa:2048 -sha256 -subj "/CN=$n" -keyout "$d/$n.key" -out "$d/$n.csr" 2>/dev/null
        printf '%s\n' "basicConstraints=CA:false" "keyUsage=critical,digitalSignature,keyEncipherment" \
            "extendedKeyUsage=serverAuth" "subjectAltName=DNS:$n" > "$d/$n.ext"
        openssl x509 -req -in "$d/$n.csr" -CA "$d/ca.pem" -CAkey "$d/ca.key" -CAcreateserial -days 90 -sha256 \
            -extfile "$d/$n.ext" -out "$d/$n.pem" 2>/dev/null
        cat "$d/$n.pem" "$d/ca.pem" > "$d/$n.fullchain.pem"
    done
    # The lab image reads /lab/tls/{ca.pem,server.pem,server.key}.
    mkdir -p "$W/mail-tls"
    cp "$d/ca.pem" "$W/mail-tls/ca.pem"; cp "$d/$MAIL_HOST.fullchain.pem" "$W/mail-tls/server.pem"
    cp "$d/$MAIL_HOST.key" "$W/mail-tls/server.key"; chmod 600 "$W/mail-tls/server.key"
}

# --- 3. The mail server: one lab container, flat profile, its own name and ports ----------------------
start_mail() {
    log "Mail server container $CONTAINER"
    docker build -q -t "$MAIL_IMAGE" "$ROOT/lab" >/dev/null
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    docker run -d --name "$CONTAINER" -e LAB_PROFILE=flat -v "$W/mail-tls:/lab/tls:ro" \
        -p "127.0.0.1:$P_IMAPS:993" -p "127.0.0.1:$P_SMTPS:465" "$MAIL_IMAGE" >/dev/null
    for _ in $(seq 1 60); do
        if docker exec "$CONTAINER" bash -c 'for p in 993 465; do (exec 3<>/dev/tcp/127.0.0.1/$p) 2>/dev/null || exit 1; done' 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    docker logs --tail 30 "$CONTAINER" >&2
    die "mail server container did not start"
}

# --- 4. The VM -----------------------------------------------------------------------------------------
start_vm() {
    log "Booting a fresh Debian 13 VM"
    ssh-keygen -q -t ed25519 -N '' -C "install-test" -f "$W/id_vm"
    qemu-img create -q -f qcow2 -F qcow2 -b "$BASE_DIR/image/$IMAGE_FILE" "$W/disk.qcow2" 20G
    mkdir -p "$W/seed"
    printf 'instance-id: install-test-%s\nlocal-hostname: gateway\n' "$(date +%s)" > "$W/seed/meta-data"
    # Root logs in with this run's key only. The /etc/hosts line stands in for the mail server's DNS
    # record: 10.0.2.2 is QEMU's user-mode gateway, which reaches this machine's 127.0.0.1.
    cat > "$W/seed/user-data" <<EOF
#cloud-config
disable_root: false
ssh_pwauth: false
users:
  - name: root
    lock_passwd: true
    ssh_authorized_keys:
      - $(cat "$W/id_vm.pub")
manage_etc_hosts: false
runcmd:
  - [sh, -c, "echo '10.0.2.2 $MAIL_HOST' >> /etc/hosts"]
EOF
    genisoimage -quiet -output "$W/seed.iso" -volid cidata -joliet -rock "$W/seed/user-data" "$W/seed/meta-data"
    qemu-system-x86_64 -name "$PREFIX-vm" -machine accel=kvm -cpu host -smp 2 -m 2048 \
        -drive "file=$W/disk.qcow2,if=virtio,format=qcow2" -drive "file=$W/seed.iso,if=virtio,format=raw,readonly=on" \
        -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$P_SSH-:22,hostfwd=tcp:127.0.0.1:$P_HTTP-:80,hostfwd=tcp:127.0.0.1:$P_HTTPS-:443" \
        -device virtio-net-pci,netdev=n0 -display none -serial "file:$W/console.log" \
        -daemonize -pidfile "$W/qemu.pid"
    cat > "$W/ssh_config" <<EOF
Host vm
  HostName 127.0.0.1
  Port $P_SSH
  User root
  IdentityFile "$W/id_vm"
  IdentitiesOnly yes
  UserKnownHostsFile "$W/known_hosts"
  StrictHostKeyChecking accept-new
  ConnectTimeout 5
  ServerAliveInterval 15
  LogLevel ERROR
EOF
    local start=$SECONDS
    until vm true 2>/dev/null; do
        (( SECONDS - start < 300 )) || die "VM did not accept SSH within 300 s (see console.log)"
        sleep 3
    done
    vm cloud-init status --wait >/dev/null || die "cloud-init failed in the VM (see console.log)"
    log "VM up in $((SECONDS - start)) s"
}

# shellcheck disable=SC2032,SC2033   # the second "vm" is the host alias in ssh_config, not this function
vm() { ssh -F "$W/ssh_config" vm "$@"; }
vm_copy() { scp -q -F "$W/ssh_config" "$@"; }

# --- 5. The operator's steps, as docs/DEPLOY.md gives them ----------------------------------------------
clone_and_build() {   # clone_and_build REV DIR: a fresh clone at REV, set up as README says, then build.sh
    local rev=$1 dir=$2
    git clone -q "$ROOT" "$dir"
    git -C "$dir" -c advice.detachedHead=false checkout -q "$rev"
    (cd "$dir" && uv venv -q && uv pip install -q -e ".[dev]" && deploy/build.sh) > "$dir.build.log" 2>&1 \
        || { tail -n 30 "$dir.build.log" >&2; die "deploy/build.sh failed at $rev"; }
    BUNDLE="$(sed -n 's/^Built \(.*\.tar\.gz\)$/\1/p' "$dir.build.log" | tail -n1)"
    [[ -f $BUNDLE ]] || die "build.sh printed no bundle"
    log "Built $(basename "$BUNDLE")"
}

trust_test_ca() {   # what an operator with a private CA does: docs/RUNNING.md, "Mail servers with a private CA"
    vm_copy "$W/pki/ca.pem" vm:/usr/local/share/ca-certificates/install-test-ca.crt
    vm update-ca-certificates >/dev/null
}

provide_certificate() {   # an operator-supplied certificate (docs/DEPLOY.md, "Without Let's Encrypt")
    vm install -d -m 0755 /etc/ssl/install-test
    vm_copy "$W/pki/$GATEWAY.fullchain.pem" vm:/etc/ssl/install-test/fullchain.pem
    vm_copy "$W/pki/$GATEWAY.key" vm:/etc/ssl/install-test/privkey.pem
    vm chmod 0600 /etc/ssl/install-test/privkey.pem
}

# The old-style route for a release before TLS_CERT existed: the certificate where certbot would put it.
provide_certificate_in_letsencrypt_path() {
    vm install -d -m 0755 "/etc/letsencrypt/live/$GATEWAY"
    vm_copy "$W/pki/$GATEWAY.fullchain.pem" "vm:/etc/letsencrypt/live/$GATEWAY/fullchain.pem"
    vm_copy "$W/pki/$GATEWAY.key" "vm:/etc/letsencrypt/live/$GATEWAY/privkey.pem"
    vm chmod 0600 "/etc/letsencrypt/live/$GATEWAY/privkey.pem"
}

install_bundle() {   # install_bundle BUNDLE [extra --setenv arguments]: DEPLOY.md section 4, word for word
    local bundle=$1 base; shift
    base="$(basename "$bundle" .tar.gz)"
    vm_copy "$bundle" vm:/root/
    local start=$SECONDS
    INSTALL_LOG="$W/install.$((++INSTALLS)).log"
    # shellcheck disable=SC2029  # the command line is expanded here on purpose, as DEPLOY.md's is
    vm "tar -xzf /root/$base.tar.gz -C /root && \
        systemd-run --quiet --unit $NAME-install --collect --wait \
          -p StandardOutput=truncate:/root/$NAME-install.log -p StandardError=inherit \
          --setenv MCP_HOSTNAME=$GATEWAY --setenv NAME=$NAME $* \
          --setenv \"SSH_CONNECTION=\$SSH_CONNECTION\" /root/$base/install.sh; \
        rc=\$?; cat /root/$NAME-install.log; exit \$rc" > "$INSTALL_LOG" 2>&1 \
        || { tail -n 40 "$INSTALL_LOG" >&2; die "install.sh failed ($bundle)"; }
    log "install.sh finished in $((SECONDS - start)) s"
    grep -E '^(WARNING|==> (Certificate|Active release))' "$INSTALL_LOG" || true
    sed -n '/^=* .* install summary =*$/,/^=*$/p' "$INSTALL_LOG"
}

summary_says() {   # summary_says TEXT: the last install summary has this line (a fixed string)
    grep -qF -- "$1" "$INSTALL_LOG" || die "install summary lacks: $1"
}

bind_mail_server() {   # DEPLOY.md: set the names and replace the example [[mail_servers]], then re-run install.sh
    vm python3 - "/etc/$NAME/config.toml" "$MAIL_HOST" "$P_IMAPS" "$P_SMTPS" <<'PY'
import sys
path, host, imap_port, smtp_port = sys.argv[1:]
text = open(path).read()
head = text.split("\n[[mail_servers]]", 1)[0]
for key, value in (("operator_name", "Install Test"), ("product_name", "Install Test Mail"),
                   ("support_url", "https://www.example.test/support"), ("support_email", "support@example.test")):
    head = "\n".join(f'{key} = "{value}"' if line.startswith(f"{key} =") else line for line in head.split("\n"))
head += f'\n[[mail_servers]]\nhost = "{host}"\ndomains = ["example.test", "example.org"]\nimap_port = {imap_port}\nsmtp_port = {smtp_port}\nmax_sessions = 8\n'
open(path, "w").write(head)
PY
}

# --- 6. Checks from outside -------------------------------------------------------------------------------
make_shims() {   # curl and openssl that reach mcp.example.test:443 and :80 at the forwarded ports
    mkdir -p "$W/bin"
    cat > "$W/bin/curl" <<EOF
#!/bin/sh
exec "$(command -v curl)" --connect-to "$GATEWAY:443:127.0.0.1:$P_HTTPS" --connect-to "$GATEWAY:80:127.0.0.1:$P_HTTP" "\$@"
EOF
    cat > "$W/bin/openssl" <<EOF
#!/bin/sh
real="$(command -v openssl)"
if [ "\$1" = s_client ]; then
    shift; set -- s_client "\$@"
    for a do shift; [ "\$a" = "$GATEWAY:443" ] && a="127.0.0.1:$P_HTTPS"; set -- "\$@" "\$a"; done
fi
exec "\$real" "\$@"
EOF
    chmod 0755 "$W/bin/curl" "$W/bin/openssl"
    install -m 600 /dev/null "$W/e2e.env"
    printf 'MCP_E2E_ADDRESS=alice@example.test\nMCP_E2E_PASSWORD=alice-lab-password\n' > "$W/e2e.env"
}

client() {   # client MODE ...: deploy/e2e.py from this checkout, connecting to the forwarded HTTPS port
    python3 -I "$ROOT/scripts/install-test-client.py" "$GATEWAY:443:127.0.0.1:$P_HTTPS" "$@"
}

smoke() {
    log "deploy/smoke.sh https://$GATEWAY"
    # The private CA as DEPLOY.md section 4a gives it to smoke.sh.
    CURL_CA_BUNDLE="$W/pki/ca.pem" PATH="$W/bin:$PATH" "$ROOT/deploy/smoke.sh" "https://$GATEWAY" || die "smoke.sh failed"
}

e2e() {
    log "deploy/e2e.py https://$GATEWAY --write --send"
    client e2e "https://$GATEWAY" --env-file "$W/e2e.env" --cafile "$W/pki/ca.pem" --write --send || die "e2e.py failed"
}

# --- Main ------------------------------------------------------------------------------------------------
main() {
    local upgrade_from=""
    case "${1:-}" in
        down) down; echo "removed"; exit 0 ;;
        up) KEEP=1 ;;
        --upgrade) upgrade_from="${2:?--upgrade needs a git revision}" ;;
        "") ;;
        *) echo "usage: $0 [--upgrade REV] | up | down" >&2; exit 2 ;;
    esac
    for c in qemu-system-x86_64 qemu-img genisoimage docker openssl ssh scp ssh-keygen curl git python3 uv; do need "$c"; done
    [[ -r /dev/kvm && -w /dev/kvm ]] || die "/dev/kvm is not usable by $(id -un)"
    python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))' || die "python3 >= 3.11 needed for e2e.py"
    local head; head="$(git -C "$ROOT" rev-parse HEAD)"
    [[ -z $upgrade_from ]] || git -C "$ROOT" rev-parse --verify -q "$upgrade_from^{commit}" >/dev/null || die "unknown revision $upgrade_from"

    [[ ! -e $W ]] || die "$W exists: a run is in progress or was kept (KEEP=1); '$0 down' removes it"
    mkdir -p "$W"
    trap on_exit EXIT
    local start=$SECONDS

    fetch_image
    make_pki
    start_mail
    start_vm
    make_shims
    trust_test_ca
    [[ ${1:-} != up ]] || exit 0

    if [[ -n $upgrade_from ]]; then
        clone_and_build "$upgrade_from" "$W/old"; local old=$BUNDLE
        provide_certificate_in_letsencrypt_path
        install_bundle "$old"
        bind_mail_server
        install_bundle "$old"
        smoke
        log "Signing a test user in with $upgrade_from and keeping the connection"
        client keep "$W/connection.json" "https://$GATEWAY" --env-file "$W/e2e.env" --cafile "$W/pki/ca.pem" \
            || die "sign-in on $upgrade_from failed"
        clone_and_build "$head" "$W/new"
        install_bundle "$BUNDLE"
        summary_says "Renewal            none: certbot did not issue"
        log "The connection made before the upgrade"
        client resume "$W/connection.json" "https://$GATEWAY" --env-file "$W/e2e.env" --cafile "$W/pki/ca.pem" \
            || die "the connection made before the upgrade no longer works"
        log "DEPLOY.md 4a: the hand-placed certificate moved to TLS_CERT"
        install_bundle "$BUNDLE" --setenv "TLS_CERT=/etc/letsencrypt/live/$GATEWAY/fullchain.pem" \
            --setenv "TLS_KEY=/etc/letsencrypt/live/$GATEWAY/privkey.pem"
    else
        clone_and_build "$head" "$W/new"
        provide_certificate
        install_bundle "$BUNDLE" --setenv TLS_CERT=/etc/ssl/install-test/fullchain.pem \
            --setenv TLS_KEY=/etc/ssl/install-test/privkey.pem
        summary_says "Renewal            yours:"
        bind_mail_server
        install_bundle "$BUNDLE"      # as DEPLOY.md's update command: no TLS_CERT, the record has it
    fi
    summary_says "Renewal            yours:"
    summary_says "$MAIL_HOST  IMAP $P_IMAPS tls ok, SMTP $P_SMTPS tls ok"
    smoke
    e2e
    log "PASSED in $((SECONDS - start)) s"
}

main "$@"
