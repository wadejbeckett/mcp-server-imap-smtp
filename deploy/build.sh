#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Build an mcp-server-imap-smtp deployment bundle on the workstation.
#
#   cd <repository> && deploy/build.sh
#
# Produces deploy/dist/mcp-server-imap-smtp-<release>.tar.gz containing:
#   - the mcp_server_imap_smtp wheel (pure Python, built from src/ in a clean copy),
#   - requirements.lock: every runtime dependency pinned to the versions resolved in the
#     project's .venv (the versions the unit tests ran against), with sha256 hashes for every
#     platform wheel, resolved for Python >= 3.11 (Debian 12 has 3.11, Debian 13 has 3.13),
#   - install.sh, the systemd units, the nginx site, the config template, backup.sh, smoke.sh,
#   - BUILD_INFO and SHA256SUMS.
# Then it installs the bundle into a throwaway virtualenv (pip, hashes required, wheels only)
# and imports the app, so a broken lock fails here rather than on the server.
# VERIFY_PYTHON picks that interpreter (default python3; for example VERIFY_PYTHON=3.11).
# Needs: uv, python3, git, network access to PyPI.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project="$(dirname "$here")"
dist="$here/dist"

die() { printf 'build.sh: %s\n' "$*" >&2; exit 1; }

command -v uv >/dev/null || die "uv not found"
command -v python3 >/dev/null || die "python3 not found"
[[ -x "$project/.venv/bin/python" ]] || die "project venv missing: $project/.venv (see docs/RUNNING.md)"

version="$(python3 -c 'import sys, tomllib; print(tomllib.load(open(sys.argv[1], "rb"))["project"]["version"])' "$project/pyproject.toml")"
sha="$(git -C "$project" rev-parse --short=12 HEAD 2>/dev/null || echo nogit)"
# deploy/ ships in the bundle too, so it counts (deploy/dist/ is git-ignored and does not).
if [[ -n "$(git -C "$project" status --porcelain -- src pyproject.toml deploy 2>/dev/null)" ]]; then
    sha="$sha-dirty"
    printf 'build.sh: WARNING: src/, pyproject.toml or deploy/ has uncommitted changes; release is marked -dirty.\n' >&2
    printf 'build.sh: commit them before a production build so the bundle can be rebuilt from its git id.\n' >&2
fi
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
release="$version-$stamp-$sha"
name="mcp-server-imap-smtp-$release"
out="$dist/$name"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

mkdir -p "$out"

# 1. Wheel, built from a clean copy so setuptools leaves no build/ or egg-info in the tree.
mkdir -p "$work/src"
cp "$project/pyproject.toml" "$project/README.md" "$project/LICENSE" "$work/src/"   # metadata names both
cp -r "$project/src" "$work/src/src"
find "$work/src" \( -name '__pycache__' -o -name '*.egg-info' \) -prune -exec rm -rf {} +
uv build --quiet --wheel --out-dir "$out" "$work/src"
rm -f "$out/.gitignore"   # uv build drops one into the out dir
wheel="$(cd "$out" && ls mcp_server_imap_smtp-*.whl)"
[[ "$(wc -w <<<"$wheel")" -eq 1 ]] || die "expected exactly one wheel, got: $wheel"
python3 -c 'import sys, zipfile; names = zipfile.ZipFile(sys.argv[1]).namelist()
sys.exit(not any(n.endswith(".dist-info/licenses/LICENSE") for n in names))' "$out/$wheel" \
    || die "the wheel carries no licenses/LICENSE"

# 2. requirements.lock: runtime dependencies from pyproject.toml, constrained to the exact
#    versions in .venv.
uv pip freeze --python "$project/.venv/bin/python" --exclude-editable > "$work/constraints.txt"
uv pip compile --quiet "$project/pyproject.toml" \
    --constraint "$work/constraints.txt" \
    --universal --python-version 3.11 --generate-hashes \
    --no-header --output-file "$out/requirements.lock"

# 3. Deployment files.
for f in install.sh backup.sh smoke.sh service.unit backup.service.unit \
         backup.timer.unit nginx-site.conf config.prod.toml.template; do
    install -m "$([[ $f == *.sh ]] && echo 0755 || echo 0644)" "$here/$f" "$out/$f"
done

cat > "$out/BUILD_INFO" <<EOF
release=$release
version=$version
git=$sha
built=$stamp
wheel=$wheel
EOF

(cd "$out" && sha256sum -- * > SHA256SUMS)

# 4. Prove the bundle installs the way install.sh installs it, then imports.
uv venv --quiet --seed --python "${VERIFY_PYTHON:-python3}" "$work/venv"
PIP_DISABLE_PIP_VERSION_CHECK=1 "$work/venv/bin/pip" install --quiet --no-cache-dir \
    --require-hashes --only-binary=:all: -r "$out/requirements.lock"
PIP_DISABLE_PIP_VERSION_CHECK=1 "$work/venv/bin/pip" install --quiet --no-cache-dir --no-deps --no-index "$out/$wheel"
PIP_DISABLE_PIP_VERSION_CHECK=1 "$work/venv/bin/pip" check >/dev/null
"$work/venv/bin/python" -c 'import mcp_server_imap_smtp.app, mcp_server_imap_smtp.cli' || die "bundle installed but mcp_server_imap_smtp.app does not import"
"$work/venv/bin/mcp-server-imap-smtp" --help >/dev/null
"$work/venv/bin/mcp-server-imap-smtp-admin" --help >/dev/null

tar -C "$dist" -czf "$dist/$name.tar.gz" "$name"
bundle_q="$(printf %q "$dist/$name.tar.gz")"   # pasted as printed, so quoted for a path with spaces

cat <<EOF

Built $dist/$name.tar.gz
  release  $release
  wheel    $wheel
  verified in a throwaway venv ($("$work/venv/bin/python" -V 2>&1)): hashes, wheels only, pip check, import

Ship and install (replace VPS, MCP_HOSTNAME and, on a server installed under another name, NAME). install.sh runs as a transient systemd
unit, so a dropped SSH connection cannot kill it half-way; its output is in /root/mcp-server-imap-smtp-install.log.

  VPS=root@<vps address>
  scp $bundle_q \$VPS:/root/
  ssh \$VPS 'tar -xzf /root/$name.tar.gz -C /root && \\
      systemd-run --quiet --unit mcp-server-imap-smtp-install --collect --wait \\
        -p StandardOutput=truncate:/root/mcp-server-imap-smtp-install.log -p StandardError=inherit \\
        --setenv MCP_HOSTNAME=mcp.example.com --setenv NAME=mcp-server-imap-smtp --setenv ADMIN_EMAIL=REPLACE_ME@example.com --setenv LE_AGREE_TOS=yes \\
        --setenv "SSH_CONNECTION=\$SSH_CONNECTION" /root/$name/install.sh; \\
      rc=\$?; cat /root/mcp-server-imap-smtp-install.log; exit \$rc'

  ADMIN_EMAIL and LE_AGREE_TOS are needed only on the first install (certificate issue).
  If the connection drops: ssh \$VPS 'systemctl status mcp-server-imap-smtp-install; tail -n 40 /root/mcp-server-imap-smtp-install.log'
  Then from the workstation: deploy/smoke.sh https://mcp.example.com
EOF
