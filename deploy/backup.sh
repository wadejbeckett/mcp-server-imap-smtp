#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Online backup of the $NAME SQLite database. Installed as /usr/local/sbin/$NAME-backup and
# run nightly as root by $NAME-backup.timer; safe to run by hand at any time.
#
# The copy is taken with SQLite's online backup API while the service runs, as the service user so
# the live database's -wal/-shm files never become root-owned. The finished file is moved to
# BACKUP_DIR (root 0700), owned by root, mode 0600, converted to a single self-contained file and
# integrity-checked. Files older than RETAIN_DAYS are removed.
#
# Off-box copies are not done here yet: see docs/DEPLOY.md, "Backups".
set -euo pipefail
umask 077

NAME="${NAME:-mcp-server-imap-smtp}"   # the install name (install.sh NAME); the backup unit sets it
CONFIG="${CONFIG:-/etc/$NAME/config.toml}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/$NAME}"
RETAIN_DAYS="${RETAIN_DAYS:-14}"
[[ $NAME =~ ^[a-z][a-z0-9-]{0,31}$ ]] || { echo "NAME must be lowercase letters, digits and hyphens" >&2; exit 2; }
SERVICE_USER=$NAME
PY=/opt/$NAME/venv/bin/python

die() { printf '%s-backup: %s\n' "$NAME" "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root"
[[ $RETAIN_DAYS =~ ^[0-9]+$ ]] || die "RETAIN_DAYS must be a whole number of days"
cd /

db="$(runuser -u "$SERVICE_USER" -- "$PY" -c \
    'import sys; from pathlib import Path; from mcp_server_imap_smtp.config import load_settings; print(load_settings(Path(sys.argv[1])).db_path)' \
    "$CONFIG")" || die "cannot read db_path from $CONFIG"
if [[ ! -f $db ]]; then
    echo "$NAME-backup: no database at $db yet; nothing to back up"
    exit 0
fi

stage=""
cleanup() { if [[ -n $stage ]]; then rm -f -- "$stage" "$stage-journal" "$stage-wal" "$stage-shm"; fi; }
trap cleanup EXIT

stage="$(runuser -u "$SERVICE_USER" -- mktemp -p "$(dirname "$db")" .backup-XXXXXXXX.sqlite)"
runuser -u "$SERVICE_USER" -- sqlite3 -cmd ".timeout 30000" "$db" ".backup '$stage'"

install -d -o root -g root -m 0700 "$BACKUP_DIR"
final="$BACKUP_DIR/$NAME-$(date -u +%Y%m%dT%H%M%SZ).sqlite"
mv -- "$stage" "$final"
stage=""
chown root:root "$final"
chmod 0600 "$final"

# Local copies and failed-check files older than RETAIN_DAYS go, whether or not this run's check passes.
prune() { find "$BACKUP_DIR" -maxdepth 1 -type f \( -name "$NAME-*.sqlite" -o -name "$NAME-*.sqlite.failed-check" \) \
              -mtime +"$RETAIN_DAYS" -delete; }

sqlite3 "$final" "PRAGMA journal_mode=DELETE;" >/dev/null || true   # an unreadable file fails the check below
check="$(sqlite3 "$final" "PRAGMA integrity_check;" 2>&1 || true)"
if [[ $check != ok ]]; then
    mv -- "$final" "$final.failed-check"
    prune
    # Non-zero exit marks $NAME-backup.service failed: visible in `systemctl --failed`.
    die "integrity check failed; kept as $final.failed-check"
fi
prune

echo "$NAME-backup: ok $final ($(stat -c %s "$final") bytes)"
