#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Install or update mcp-server-imap-smtp on a dedicated Debian 12 (bookworm) or 13 (trixie) VPS. Run as root
# from an unpacked bundle made by deploy/build.sh. Safe to re-run: every step converges.
#
#   MCP_HOSTNAME=mcp.example.com ADMIN_EMAIL=you@example.com LE_AGREE_TOS=yes ./install.sh [BUNDLE_DIR]
#
# Environment:
#   MCP_HOSTNAME   public hostname (required). Not HOSTNAME: bash sets that to the machine name.
#   NAME           install name for the service, user, directories and commands (default mcp-server-imap-smtp).
#                  Keep the same NAME on every update of one server.
#   ADMIN_EMAIL    Let's Encrypt account e-mail (expiry notices). Required only while no certificate exists.
#   LE_AGREE_TOS   must be "yes" while no certificate exists: you accept the Let's Encrypt Subscriber
#                  Agreement (https://letsencrypt.org/repository/) for this account.
#   LE_STAGING=1   issue from the Let's Encrypt staging CA (testing; browsers will not trust it).
#   EGRESS         "restricted" (default): outbound IMAP/SMTP only to the configured mail servers, plus DNS,
#                  NTP, DHCP, HTTP and HTTPS; "open": all outbound traffic allowed.
#   SSH_HARDEN=0   do not write the sshd drop-in (keys only, no forwarding).
#   SSH_PORT       extra SSH port to allow in ufw. The ports sshd listens on and the port of the current
#                  SSH session are always allowed, so the firewall cannot lock you out.
#   KEEP_RELEASES  installed releases to keep under /opt/$NAME/releases (default 3, minimum 2).
#
# Layout:
#   /opt/$NAME/releases/<release>/venv   code and dependencies, root-owned, read-only to the service
#   /opt/$NAME/venv -> releases/<release>/venv   the active release (switched atomically)
#   /etc/$NAME/config.toml               root:$NAME 0640, created from the template only if absent
#   /var/lib/$NAME                       $NAME 0700, the SQLite database
#   /var/backups/$NAME                   root 0700, nightly backups ($NAME-backup.timer)
#   /usr/local/sbin/$NAME-admin          admin CLI wrapper (runs as $NAME)
#   /usr/local/sbin/$NAME-backup         backup script
#
# Order matters: the new release is built and the config validated with it, then the firewall,
# upgrades, nginx and the certificate are done, and only then is the active symlink switched and the
# service restarted. A failure before that point leaves the running release and the symlink untouched.
# If the new release does not answer its health check, the symlink goes back to the previous release.
#
# Run it detached from the SSH session (systemd-run, as docs/DEPLOY.md shows) so a dropped connection
# cannot kill it half-way.
set -euo pipefail
umask 022

die()  { printf '\nERROR: %s\n' "$*" >&2; exit 1; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
log()  { printf '==> %s\n' "$*"; }

[[ $EUID -eq 0 ]] || die "run as root"

BUNDLE="$(cd "${1:-$(dirname "${BASH_SOURCE[0]}")}" && pwd)"
MCP_HOSTNAME="${MCP_HOSTNAME:-}"
NAME="${NAME:-mcp-server-imap-smtp}"
ADMIN_EMAIL="${ADMIN_EMAIL:-}"
LE_AGREE_TOS="${LE_AGREE_TOS:-no}"
LE_STAGING="${LE_STAGING:-0}"
SSH_PORT="${SSH_PORT:-}"
KEEP_RELEASES="${KEEP_RELEASES:-3}"

[[ -n $MCP_HOSTNAME ]] || die "set MCP_HOSTNAME to the public hostname"
[[ $NAME =~ ^[a-z][a-z0-9-]{0,31}$ ]] || die "NAME '$NAME' must be lowercase letters, digits and hyphens (at most 32)"
SERVICE_USER=$NAME
APP=/opt/$NAME
ETC=/etc/$NAME
CONFIG=$ETC/config.toml
STATE=/var/lib/$NAME
BACKUPS=/var/backups/$NAME
ACME_ROOT=/var/www/acme
SITE=/etc/nginx/sites-available/$NAME.conf
CERT=/etc/letsencrypt/live/$MCP_HOSTNAME/fullchain.pem

[[ $MCP_HOSTNAME =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]] || die "MCP_HOSTNAME '$MCP_HOSTNAME' is not a lowercase DNS name"
if [[ ! $KEEP_RELEASES =~ ^[0-9]+$ ]] || (( KEEP_RELEASES < 2 )); then die "KEEP_RELEASES must be a number >= 2"; fi
[[ -z $SSH_PORT || $SSH_PORT =~ ^[0-9]+$ ]] || die "SSH_PORT must be a port number"

# --- 1. Preflight -------------------------------------------------------------------------------
# Read in a subshell: os-release sets NAME (and other variables) that would overwrite ours.
os_field() { (. /etc/os-release && eval "printf '%s' \"\${$1:-}\""); }
OS_ID="$(os_field ID)"; OS_VERSION_ID="$(os_field VERSION_ID)"; OS_PRETTY="$(os_field PRETTY_NAME)"
if [[ $OS_ID != debian || ! $OS_VERSION_ID =~ ^(12|13)$ ]]; then
    [[ ${ALLOW_UNSUPPORTED_OS:-0} == 1 ]] || die "supported: Debian 12 or 13 (found ${OS_PRETTY:-unknown}); ALLOW_UNSUPPORTED_OS=1 to try anyway"
    warn "unsupported OS ${OS_PRETTY:-unknown}; continuing because ALLOW_UNSUPPORTED_OS=1"
fi

for f in BUILD_INFO SHA256SUMS requirements.lock service.unit backup.service.unit \
         backup.timer.unit nginx-site.conf config.prod.toml.template backup.sh; do
    [[ -f $BUNDLE/$f ]] || die "bundle incomplete: $BUNDLE/$f missing (build it with deploy/build.sh)"
done
log "Verifying bundle checksums"
(cd "$BUNDLE" && sha256sum --check --quiet --strict SHA256SUMS) || die "bundle checksum mismatch"

RELEASE="$(sed -n 's/^release=//p' "$BUNDLE/BUILD_INFO")"
WHEEL="$(sed -n 's/^wheel=//p' "$BUNDLE/BUILD_INFO")"
[[ $RELEASE =~ ^[A-Za-z0-9._+-]+$ ]] || die "bad release id in BUILD_INFO: '$RELEASE'"
[[ $WHEEL =~ ^mcp_server_imap_smtp-[A-Za-z0-9._+-]+\.whl$ && -f $BUNDLE/$WHEEL ]] || die "wheel '$WHEEL' from BUILD_INFO not found in bundle"
log "Release $RELEASE for https://$MCP_HOSTNAME"

# Certificate inputs are checked now, before anything on the host changes.
if [[ ! -s $CERT ]]; then
    [[ -n $ADMIN_EMAIL ]] || die "no certificate for $MCP_HOSTNAME yet: set ADMIN_EMAIL for the Let's Encrypt account"
    [[ $LE_AGREE_TOS == yes ]] || die "no certificate for $MCP_HOSTNAME yet: set LE_AGREE_TOS=yes to accept the Let's Encrypt Subscriber Agreement"
fi
cd /

# --- 2. Packages (Debian archive only) ----------------------------------------------------------
log "Installing Debian packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q --no-install-recommends \
    python3 python3-venv nginx certbot ufw unattended-upgrades poppler-utils sqlite3 rsync \
    ca-certificates curl openssl iproute2
python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))' || die "python3 >= 3.11 required ($(python3 -V))"

# --- 3. Service account and directories ---------------------------------------------------------
log "Service user and directories"
getent group "$SERVICE_USER" >/dev/null || groupadd --system "$SERVICE_USER"
id -u "$SERVICE_USER" >/dev/null 2>&1 || useradd --system --gid "$SERVICE_USER" --no-create-home \
    --home-dir /nonexistent --shell /usr/sbin/nologin --comment "$NAME gateway" "$SERVICE_USER"
install -d -o root -g root -m 0755 "$APP" "$APP/releases" "$ACME_ROOT"
install -d -o root -g "$SERVICE_USER" -m 0750 "$ETC"
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0700 "$STATE"
install -d -o root -g root -m 0700 "$BACKUPS"
[[ ! -e $APP/venv || -L $APP/venv ]] || die "$APP/venv exists and is not a symlink; move it aside first"

# --- 4. Release: virtualenv with pinned, hash-checked wheels, then the app wheel -----------------
REL="$APP/releases/$RELEASE"
PARTIAL=""
cleanup() { if [[ -n $PARTIAL ]]; then rm -rf -- "$PARTIAL"; fi; }
trap cleanup EXIT
release_ok() { [[ -f $REL/.complete ]] && "$REL/venv/bin/python" -c 'import mcp_server_imap_smtp.app, mcp_server_imap_smtp.cli' >/dev/null 2>&1; }
if release_ok; then
    log "Release $RELEASE already installed"
else
    if [[ -f $REL/.complete ]]; then
        warn "release $RELEASE is installed but its virtualenv no longer imports (Python changed, e.g. a Debian upgrade?); rebuilding it"
    fi
    log "Building virtualenv for $RELEASE"
    rm -rf -- "$REL"
    PARTIAL="$REL"
    install -d -m 0755 "$REL"
    python3 -m venv "$REL/venv"
    export PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1 PIP_NO_INPUT=1
    "$REL/venv/bin/pip" install --quiet --require-hashes --only-binary=:all: -r "$BUNDLE/requirements.lock"
    "$REL/venv/bin/pip" install --quiet --no-deps --no-index "$BUNDLE/$WHEEL"
    "$REL/venv/bin/pip" check
    "$REL/venv/bin/python" -c 'import mcp_server_imap_smtp.app, mcp_server_imap_smtp.cli'
    install -m 0644 "$BUNDLE/BUILD_INFO" "$BUNDLE/requirements.lock" "$REL/"
    touch "$REL/.complete"
    PARTIAL=""
fi
chown -R root:root "$REL"
chmod -R go-w "$REL"

# --- 5. Configuration ---------------------------------------------------------------------------
if [[ -e $CONFIG ]]; then
    log "Keeping existing $CONFIG"
else
    log "Writing $CONFIG from template"
    sed -e "s/@MCP_HOSTNAME@/$MCP_HOSTNAME/g" -e "s/@NAME@/$NAME/g" "$BUNDLE/config.prod.toml.template" > "$CONFIG.new"
    mv -f "$CONFIG.new" "$CONFIG"
fi
chown root:"$SERVICE_USER" "$CONFIG"
chmod 0640 "$CONFIG"

# Validated with the NEW release's code, before it becomes active.
mapfile -t CFG < <(runuser -u "$SERVICE_USER" -- "$REL/venv/bin/python" - "$CONFIG" <<'PY'
import sys
from pathlib import Path
from urllib.parse import urlparse
from mcp_server_imap_smtp.config import load_settings
s = load_settings(Path(sys.argv[1]))
for v in (s.listen_host, s.listen_port, s.public_host, s.mail_path, s.db_path, int(s.trusted_proxy),
          s.forwarded_allow_ips, s.issuer_url, int(s.allow_loopback_redirects), s.mail_resource_url,
          urlparse(s.mail_resource_url).netloc,
          " ".join(f"{m.host}:{m.imap_port}:{m.smtp_port}" for m in s.mail_servers)):
    print(v)
PY
)
(( ${#CFG[@]} == 12 )) || die "$CONFIG does not load (see the Python error above)"
LISTEN_HOST="${CFG[0]}" LISTEN_PORT="${CFG[1]}" PUBLIC_HOST="${CFG[2]}" MAIL_PATH="${CFG[3]}" DB_PATH="${CFG[4]}"
TRUSTED_PROXY="${CFG[5]}" FORWARDED_ALLOW="${CFG[6]}" ISSUER="${CFG[7]}" LOOPBACK="${CFG[8]}"
MAIL_RESOURCE="${CFG[9]}" MAIL_RESOURCE_HOST="${CFG[10]}" MAIL_SERVERS="${CFG[11]}"   # host:imap:smtp, space-separated
[[ $PUBLIC_HOST == "$MCP_HOSTNAME" ]] || die "issuer_url host in $CONFIG is '$PUBLIC_HOST' but MCP_HOSTNAME is '$MCP_HOSTNAME'"
[[ $ISSUER == https://* ]] || die "issuer_url in $CONFIG must be https://"
[[ $MAIL_RESOURCE == https://* ]] || die "mail_resource_url in $CONFIG must be https://"
[[ $MAIL_RESOURCE_HOST == "$PUBLIC_HOST" ]] || die "mail_resource_url host in $CONFIG is '$MAIL_RESOURCE_HOST' but the issuer_url host is '$PUBLIC_HOST' (token audience and resource metadata would disagree)"
[[ $LISTEN_HOST == 127.0.0.1 ]] || die "listen_host in $CONFIG must be 127.0.0.1 (nginx proxies to it)"
[[ $(dirname "$DB_PATH") == "$STATE" ]] || die "db_path in $CONFIG must be inside $STATE (the only path the service may write)"
[[ $TRUSTED_PROXY == 1 && ,$FORWARDED_ALLOW, == *,127.0.0.1,* ]] || warn "trusted_proxy/forwarded_allow_ips are not 'true'/'127.0.0.1': rate limits will see nginx's address, not the client's"

# --- 6. Firewall --------------------------------------------------------------------------------
log "Firewall (ufw)"
ssh_ports=()
[[ -n $SSH_PORT ]] && ssh_ports+=("$SSH_PORT")
if command -v sshd >/dev/null; then
    while read -r p; do ssh_ports+=("$p"); done < <(sshd -T 2>/dev/null | awk '$1 == "port" {print $2}')
fi
if [[ -n ${SSH_CONNECTION:-} ]]; then
    ssh_ports+=("$(awk '{print $4}' <<<"$SSH_CONNECTION")")
fi
(( ${#ssh_ports[@]} )) || ssh_ports=(22)
mapfile -t ssh_ports < <(printf '%s\n' "${ssh_ports[@]}" | sort -un)
ufw default deny incoming >/dev/null
for p in "${ssh_ports[@]}"; do ufw allow "$p/tcp" comment 'ssh' >/dev/null; done
ufw allow 80/tcp comment 'http (ACME, redirect)' >/dev/null
ufw allow 443/tcp comment 'https' >/dev/null
# Outbound. EGRESS=restricted (the default): IMAP and SMTP only to the configured mail servers' current
# addresses, so a compromised gateway cannot guess passwords on, or relay through, any other mail server;
# plus DNS to this host's resolvers, NTP, DHCP, and HTTP/HTTPS anywhere (apt, PyPI, Let's Encrypt, client
# metadata documents behind CDNs). Re-run install.sh when a mail server's address changes; rules for an
# old address stay until removed with `ufw status numbered` and `ufw delete <n>`. EGRESS=open allows all.
if [[ ${EGRESS:-restricted} == open ]]; then
    ufw default allow outgoing >/dev/null
    log "ufw: outbound open (EGRESS=open)"
else
    ufw allow out 53 comment 'dns' >/dev/null
    ufw allow out 123/udp comment 'ntp' >/dev/null
    ufw allow out 67/udp comment 'dhcp' >/dev/null
    ufw allow out 547/udp comment 'dhcpv6' >/dev/null
    ufw allow out 80/tcp comment 'http out (apt, acme)' >/dev/null
    ufw allow out 443/tcp comment 'https out (pypi, acme, client metadata)' >/dev/null
    mail_rules=0
    for entry in $MAIL_SERVERS; do
        IFS=: read -r mh mi ms <<<"$entry"
        mapfile -t maddrs < <(getent ahosts "$mh" | awk '{print $1}' | sort -u)
        (( ${#maddrs[@]} )) || warn "mail server $mh does not resolve; no outbound rule added for it"
        for a in "${maddrs[@]}"; do
            ufw allow out proto tcp to "$a" port "$mi,$ms" comment "mail $mh" >/dev/null
            mail_rules=$((mail_rules + 1))
        done
    done
    ufw default deny outgoing >/dev/null
    log "ufw: outbound restricted (mail to $mail_rules configured server address(es); dns, ntp, dhcp, 80, 443)"
fi
ufw --force enable >/dev/null
log "ufw: allowing tcp ${ssh_ports[*]} (ssh), 80, 443 in"

# SSH: keys only, no forwarding (security review 2026-10-20, finding 5). Skipped with SSH_HARDEN=0.
# The drop-in is read before sshd_config, so its values win; it is removed again if sshd rejects it.
SSHD_DROPIN=/etc/ssh/sshd_config.d/10-$NAME.conf
if [[ ${SSH_HARDEN:-1} == 1 && -d /etc/ssh/sshd_config.d ]] && command -v sshd >/dev/null; then
    if [[ -z $(find /root/.ssh/authorized_keys -size +0 2>/dev/null) ]]; then
        warn "root has no authorized_keys: SSH hardening skipped so password logins are not cut off"
    else
        sed "s/@NAME@/$NAME/g" > "$SSHD_DROPIN.new" <<'EOF'
# Written by @NAME@ install.sh (SSH_HARDEN=0 to skip). Remove this file and `systemctl reload ssh` to reverse.
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
MaxAuthTries 3
EOF
        mv -f "$SSHD_DROPIN.new" "$SSHD_DROPIN"
        if sshd -t; then
            systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || warn "could not reload sshd"
            log "sshd: keys only, no forwarding ($SSHD_DROPIN)"
        else
            rm -f "$SSHD_DROPIN"
            warn "sshd rejected $SSHD_DROPIN; removed it, SSH settings unchanged"
        fi
    fi
fi

# --- 7. Unattended security upgrades -------------------------------------------------------------
log "Unattended security upgrades"
AUTO_UPGRADES=/etc/apt/apt.conf.d/20auto-upgrades
# Back up a file this script did not write, once (apt ignores *.bak in apt.conf.d).
if [[ -f $AUTO_UPGRADES && ! -e $AUTO_UPGRADES.$NAME.bak ]] && ! grep -q "Written by $NAME install.sh" "$AUTO_UPGRADES"; then
    cp -p "$AUTO_UPGRADES" "$AUTO_UPGRADES.$NAME.bak"
    log "Backed up $AUTO_UPGRADES to $AUTO_UPGRADES.$NAME.bak"
fi
sed "s/@NAME@/$NAME/g" > "$AUTO_UPGRADES.new" <<'EOF'
// Written by @NAME@ install.sh (the original, if there was one: 20auto-upgrades.@NAME@.bak)
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
mv -f "$AUTO_UPGRADES.new" "$AUTO_UPGRADES"
systemctl enable --quiet apt-daily.timer apt-daily-upgrade.timer || warn "could not enable apt timers"

# --- 8. nginx and the certificate ---------------------------------------------------------------
HAVE_IPV6=0
[[ -f /proc/net/if_inet6 ]] && HAVE_IPV6=1

render_site() {   # render_site full|bootstrap
    local out
    out="$(sed -e "s/@MCP_HOSTNAME@/$MCP_HOSTNAME/g" -e "s/@LISTEN_PORT@/$LISTEN_PORT/g" -e "s/@NAME@/$NAME/g" "$BUNDLE/nginx-site.conf")"
    (( HAVE_IPV6 )) || out="$(grep -v '# ipv6$' <<<"$out")"
    [[ $1 == full ]] || out="$(sed '/^# BEGIN TLS$/,/^# END TLS$/d' <<<"$out")"
    printf '%s\n' "$out"
}

# Debian's default site claims default_server on port 80, so it must leave sites-enabled for ours to
# pass nginx -t. It is set aside outside sites-enabled and put back if ours is rejected.
DEFAULT_SITE=/etc/nginx/sites-enabled/default
DEFAULT_SAVED=/etc/nginx/sites-enabled-default.$NAME-saved
install_site() {  # install_site full|bootstrap: write, test, reload; restore the previous state if nginx -t fails
    local had_prev=0 had_default=0
    if [[ -f $SITE ]]; then cp -p "$SITE" "$SITE.prev"; had_prev=1; fi
    if [[ -e $DEFAULT_SITE || -L $DEFAULT_SITE ]]; then mv -f "$DEFAULT_SITE" "$DEFAULT_SAVED"; had_default=1; fi
    render_site "$1" > "$SITE.new"
    mv -f "$SITE.new" "$SITE"
    ln -sfn "$SITE" /etc/nginx/sites-enabled/$NAME.conf
    if ! nginx -t -q; then
        if (( had_prev )); then mv -f "$SITE.prev" "$SITE"; else rm -f "$SITE" /etc/nginx/sites-enabled/$NAME.conf; fi
        if (( had_default )); then mv -f "$DEFAULT_SAVED" "$DEFAULT_SITE"; fi
        die "nginx rejected the $1 site configuration; previous configuration restored"
    fi
    rm -f "$SITE.prev"
    if (( had_default )); then
        if [[ -L $DEFAULT_SAVED ]]; then
            rm -f "$DEFAULT_SAVED"
            log "Debian's default nginx site unlinked (it stays in sites-available)"
        else
            log "Debian's default nginx site was a file, not a link; kept as $DEFAULT_SAVED"
        fi
    fi
    systemctl enable --quiet nginx
    systemctl reload-or-restart nginx
}

log "nginx site for $MCP_HOSTNAME"
if [[ ! -s $CERT ]]; then
    install_site bootstrap
    if ! getent ahosts "$MCP_HOSTNAME" >/dev/null; then
        warn "$MCP_HOSTNAME does not resolve yet; certificate issuance will fail until DNS points here"
    fi
    log "Requesting Let's Encrypt certificate for $MCP_HOSTNAME"
    staging=()
    [[ $LE_STAGING == 1 ]] && staging=(--test-cert)
    certbot certonly --webroot --webroot-path "$ACME_ROOT" --domain "$MCP_HOSTNAME" --cert-name "$MCP_HOSTNAME" \
        --non-interactive --agree-tos --email "$ADMIN_EMAIL" --no-eff-email \
        --deploy-hook 'systemctl reload nginx' "${staging[@]}" \
        || die "certbot failed. Check that $MCP_HOSTNAME resolves to this server (Cloudflare DNS-only) and port 80 is reachable, then re-run"
fi
install_site full
systemctl enable --quiet certbot.timer 2>/dev/null || warn "certbot.timer not enabled; certificates will not renew automatically"

# --- 9. Activate: units, helpers, symlink switch, restart, health check --------------------------
log "Installing systemd units and helpers"
render() { sed -e "s/@NAME@/$NAME/g" "$1"; }   # render TEMPLATE: the bundle's unit and site templates for this NAME
render "$BUNDLE/service.unit" > "/etc/systemd/system/$NAME.service"
render "$BUNDLE/backup.service.unit" > "/etc/systemd/system/$NAME-backup.service"
render "$BUNDLE/backup.timer.unit" > "/etc/systemd/system/$NAME-backup.timer"
chmod 0644 "/etc/systemd/system/$NAME.service" "/etc/systemd/system/$NAME-backup.service" "/etc/systemd/system/$NAME-backup.timer"
# The install name becomes the backup script's default, so running it by hand needs no NAME.
sed "s/^NAME=\"\${NAME:-mcp-server-imap-smtp}\"/NAME=\"\${NAME:-$NAME}\"/" "$BUNDLE/backup.sh" > "/usr/local/sbin/$NAME-backup.new"
chmod 0755 "/usr/local/sbin/$NAME-backup.new" && mv -f "/usr/local/sbin/$NAME-backup.new" "/usr/local/sbin/$NAME-backup"
[[ -f $BUNDLE/smoke.sh ]] && install -m 0755 "$BUNDLE/smoke.sh" /usr/local/sbin/$NAME-smoke
cat > "/usr/local/sbin/$NAME-admin.new" <<EOF
#!/bin/sh
# $NAME admin CLI (installed by deploy/install.sh). Runs as the service user so database
# files never become root-owned. Usage: $NAME-admin grants list | grants revoke --grant ID | --mailbox ADDRESS
cd / && exec runuser -u $NAME -- /opt/$NAME/venv/bin/mcp-server-imap-smtp-admin --config /etc/$NAME/config.toml "\$@"
EOF
chmod 0755 /usr/local/sbin/$NAME-admin.new
mv -f /usr/local/sbin/$NAME-admin.new /usr/local/sbin/$NAME-admin

switch_to() {   # switch_to RELEASE: atomically repoint /opt/$NAME/venv at releases/RELEASE/venv
    ln -sfn "releases/$1/venv" "$APP/venv.new"
    mv -Tf "$APP/venv.new" "$APP/venv"
}
PREVIOUS="$(readlink "$APP/venv" 2>/dev/null || true)"   # releases/<release>/venv, or empty
PREVIOUS_REL=""
if [[ $PREVIOUS =~ ^releases/([A-Za-z0-9._+-]+)/venv$ ]]; then PREVIOUS_REL="${BASH_REMATCH[1]}"; fi
switch_to "$RELEASE"
[[ $PREVIOUS_REL == "$RELEASE" ]] || log "Active release: $RELEASE (previous: ${PREVIOUS_REL:-none})"

if command -v systemd-analyze >/dev/null; then
    systemd-analyze verify /etc/systemd/system/$NAME.service /etc/systemd/system/$NAME-backup.service \
        /etc/systemd/system/$NAME-backup.timer || warn "systemd-analyze verify reported problems (above)"
fi
systemctl daemon-reload

log "Starting $NAME"
systemctl enable --quiet $NAME.service $NAME-backup.timer
systemctl start $NAME-backup.timer

PRM="/.well-known/oauth-protected-resource$MAIL_PATH"
healthy() {   # the gateway answers on its loopback listener within 30 s
    local _
    for _ in $(seq 1 30); do
        if curl -fsS -o /dev/null --max-time 3 "http://127.0.0.1:$LISTEN_PORT$PRM" 2>/dev/null; then return 0; fi
        sleep 1
    done
    return 1
}
systemctl restart $NAME.service || true
if ! healthy; then
    journalctl -u $NAME -n 40 --no-pager >&2 || true
    if [[ -n $PREVIOUS_REL && $PREVIOUS_REL != "$RELEASE" && -x $APP/releases/$PREVIOUS_REL/venv/bin/mcp-server-imap-smtp ]]; then
        warn "release $RELEASE did not answer; switching back to $PREVIOUS_REL"
        switch_to "$PREVIOUS_REL"
        systemctl reset-failed $NAME.service 2>/dev/null || true   # clear any start-rate limit hit by the failed release
        systemctl restart $NAME.service || true
        healthy || die "$NAME $RELEASE did not answer (log above); rolled back to $PREVIOUS_REL, which does not answer either: journalctl -u $NAME"
        die "$NAME $RELEASE did not answer on 127.0.0.1:$LISTEN_PORT within 30 s (log above); rolled back to $PREVIOUS_REL, which is running"
    fi
    die "$NAME did not answer on 127.0.0.1:$LISTEN_PORT within 30 s (log above)"
fi

# Prune only now that the new release is healthy. Kept: the new release, the one it replaced, and the
# newest others up to KEEP_RELEASES in total (for rollback).
kept=1
while IFS= read -r dir; do
    [[ $dir == "$REL" ]] && continue
    if [[ -n $PREVIOUS_REL && $dir == "$APP/releases/$PREVIOUS_REL" ]]; then kept=$((kept + 1)); continue; fi
    if (( kept < KEEP_RELEASES )); then kept=$((kept + 1)); else log "Removing old release ${dir##*/}"; rm -rf -- "$dir"; fi
done < <(find "$APP/releases" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -rn | cut -d' ' -f2-)

# --- 10. Verification summary -------------------------------------------------------------------
check() { if "$@" >/dev/null 2>&1; then echo ok; else echo FAILED; fi; }
via_nginx="$(check curl -fsS --max-time 5 --resolve "$MCP_HOSTNAME:443:127.0.0.1" -k "https://$MCP_HOSTNAME$PRM")"
unauth="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 --resolve "$MCP_HOSTNAME:443:127.0.0.1" -k \
    -X POST -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' \
    --data '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' "https://$MCP_HOSTNAME$MAIL_PATH" || true)"
cert_end="$(openssl x509 -noout -enddate -in "$CERT" 2>/dev/null | cut -d= -f2 || true)"
cert_issuer="$(openssl x509 -noout -issuer -in "$CERT" 2>/dev/null | sed 's/^issuer=//' || true)"
db_state="not created yet (first sign-in creates it)"
[[ -f $DB_PATH ]] && db_state="$(stat -c '%U:%G %a %s bytes' "$DB_PATH")"
mapfile -t addrs < <(ip -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
# TLS handshake only (no sign-in) to each configured mail server from this server's own address. FAILED
# usually means the mail server's firewall or ban list drops this address: docs/DEPLOY.md sections 6 and 6a.
mail_tls() { timeout 15 openssl s_client -connect "$1:$2" -servername "$1" -verify_hostname "$1" \
                 -verify_return_error -brief </dev/null; }
mail_lines=""
for entry in $MAIL_SERVERS; do
    IFS=: read -r mh mi ms <<<"$entry"
    mail_lines+="$(printf '\n  %s  IMAPS %s %s, SMTPS %s %s' "$mh" "$mi" "$(check mail_tls "$mh" "$mi")" "$ms" "$(check mail_tls "$mh" "$ms")")"
done

cat <<EOF

================ $NAME install summary ================
Release            $RELEASE (Python $(sed -n 's/^version *= *//p' "$APP/venv/pyvenv.cfg" 2>/dev/null))
Public URL         https://$MCP_HOSTNAME$MAIL_PATH
Config             $CONFIG ($(stat -c '%U:%G %a' "$CONFIG")); loopback redirects $( (( LOOPBACK )) && echo allowed || echo refused )
Database           $DB_PATH: $db_state
$NAME         $(systemctl is-active $NAME) / $(systemctl is-enabled $NAME)
nginx              $(systemctl is-active nginx) / $(systemctl is-enabled nginx)
Gateway (direct)   ok: http://127.0.0.1:$LISTEN_PORT$PRM
Gateway via nginx  $via_nginx (TLS on 127.0.0.1, certificate not checked here)
Unauthenticated    POST $MAIL_PATH -> HTTP $unauth (expect 401)
Certificate        ${cert_issuer:-?}; expires ${cert_end:-?}
Renewal timer      $(systemctl is-enabled certbot.timer 2>/dev/null || echo missing)
Backup timer       $(systemctl is-enabled $NAME-backup.timer) (next: $(systemctl show -P NextElapseUSecRealtime $NAME-backup.timer 2>/dev/null || echo ?))
Firewall           $(ufw status | head -n1)
Global addresses   ${addrs[*]:-none found}
Mail servers TLS   (handshake only, no sign-in)$mail_lines
=============================================================

Next:
  1. From the workstation: deploy/smoke.sh https://$MCP_HOSTNAME
  2. On each mail server, exempt this server's public addresses (above) from login-failure blocking
     (fail2ban, a control panel's IP banning, a host firewall), since every user's sign-ins come from
     here; then re-check "Mail servers TLS" (docs/DEPLOY.md). Behind a floating or NAT address, use that.
  3. Admin: $NAME-admin grants list   Logs: journalctl -u $NAME -f
EOF
[[ $via_nginx == ok && $unauth == 401 ]] || die "post-install checks failed (summary above)"
