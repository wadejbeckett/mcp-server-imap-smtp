# SPDX-License-Identifier: AGPL-3.0-or-later
"""Security review 2026-10-20, findings 16 and 17: the service unit's sandbox and automatic restarts after
security updates."""
import subprocess
from pathlib import Path

DEPLOY = Path(__file__).resolve().parent.parent / "deploy"


def test_unit_is_tightened():
    unit = (DEPLOY / "service.unit").read_text()
    for line in ("SystemCallFilter=~@privileged @resources", "SocketBindAllow=tcp:@LISTEN_PORT@", "SocketBindDeny=any",
                 "ProcSubset=pid", "MemoryMax=1G", "TasksMax=256"):
        assert line in unit, line


def test_install_renders_the_listen_port_into_units():
    assert 's/@LISTEN_PORT@/$LISTEN_PORT/g' in (DEPLOY / "install.sh").read_text().split("render() {")[1].split("\n")[0]
    subprocess.run(["bash", "-n", str(DEPLOY / "install.sh")], check=True)


def test_security_updates_restart_services():
    install = (DEPLOY / "install.sh").read_text()
    assert " needrestart " in install and "$nrconf{restart}" in install
    assert "Unattended-Upgrade::Automatic-Reboot" in install


def test_systemd_stop_timeout_is_only_a_backstop_above_the_services_own_bound():
    """The service exits within app.STOP_SECONDS of SIGTERM by itself; systemd kills only well after that."""
    import re
    from mcp_server_imap_smtp.app import STOP_SECONDS
    unit = (DEPLOY / "service.unit").read_text()
    timeout = int(re.search(r"^TimeoutStopSec=(\d+)s$", unit, re.MULTILINE)[1])
    assert timeout >= 2 * STOP_SECONDS
    assert "KillMode=" not in unit and "SendSIGKILL=no" not in unit     # the defaults: SIGTERM, then SIGKILL


# Ticket 09: the firewall and the TLS check follow each mail server's ports and security mode.

def _install_python() -> str:
    """The Python install.sh runs to read the configuration (the heredoc after `mapfile -t CFG`)."""
    text = (DEPLOY / "install.sh").read_text()
    return text.split("mapfile -t CFG", 1)[1].split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]


def _install_function(name: str) -> str:
    text = (DEPLOY / "install.sh").read_text()
    start = text.index(f"\n{name}() {{") + 1
    return text[start:text.index("\n}\n", start) + 3]


def test_install_reads_each_servers_ports_and_security(tmp_path):
    import sys
    cfg = tmp_path / "c.toml"
    cfg.write_text(f'issuer_url = "https://mcp.example.test"\nmail_resource_url = "https://mcp.example.test/mail"\n'
                   f'db_path = "{tmp_path / "x.sqlite"}"\n'
                   '[[mail_servers]]\nhost = "mail.example.test"\n'
                   '[[mail_servers]]\nhost = "mail.example.org"\nsmtp_security = "starttls"\nimap_security = "starttls"\n'
                   'imap_port = 1143\n')
    out = subprocess.run([sys.executable, "-", str(cfg)], input=_install_python(), capture_output=True, text=True,
                         check=True).stdout.splitlines()
    assert out[-1] == "mail.example.test:993:465:tls:tls mail.example.org:1143:587:starttls:starttls"


def _bash(script: str) -> list[str]:
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True).stdout.splitlines()


def test_tls_check_uses_starttls_for_a_starttls_service():
    fn = _install_function("mail_tls_args")
    assert _bash(fn + "mail_tls_args mail.example.test 993 tls imap") == [
        "-connect", "mail.example.test:993", "-servername", "mail.example.test", "-verify_hostname",
        "mail.example.test", "-verify_return_error", "-brief"]
    args = _bash(fn + "mail_tls_args mail.example.test 587 starttls smtp")
    assert args[:2] == ["-connect", "mail.example.test:587"] and args[-2:] == ["-starttls", "smtp"]
    assert _bash(fn + "mail_tls_args mail.example.test 143 starttls imap")[-2:] == ["-starttls", "imap"]


def test_egress_rules_and_summary_use_every_field_of_a_server_entry():
    install = (DEPLOY / "install.sh").read_text()
    assert install.count("IFS=: read -r mh mi ms msi mss") == 2      # the firewall loop and the TLS check loop
    assert 'port "$mi,$ms"' in install
    assert 'mail_tls "$mh" "$mi" "$msi" imap' in install and 'mail_tls "$mh" "$ms" "$mss" smtp' in install
    subprocess.run(["bash", "-n", str(DEPLOY / "install.sh")], check=True)


# Ticket 76: an operator-supplied certificate (TLS_CERT, TLS_KEY) instead of Let's Encrypt, for a gateway
# with no public name (a private network, a corporate CA) or a certificate obtained elsewhere.

def _make_cert(d: Path, host: str = "mcp.example.test", *, self_signed: bool = False, expired: bool = False
               ) -> tuple[Path, Path]:
    """A CA and a leaf for host signed by it (or a self-signed leaf): returns (fullchain, key), key mode 0600."""
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    def name(cn: str) -> x509.Name:
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    now = datetime.datetime.now(datetime.timezone.utc)
    start, end = (now - datetime.timedelta(days=60), now - datetime.timedelta(days=1)) if expired else \
        (now - datetime.timedelta(minutes=5), now + datetime.timedelta(days=30))
    ca_key, leaf_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca = (x509.CertificateBuilder().subject_name(name("Test CA")).issuer_name(name("Test CA"))
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(days=90)).not_valid_after(now + datetime.timedelta(days=90))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .sign(ca_key, hashes.SHA256()))
    issuer, signer = (name(host), leaf_key) if self_signed else (ca.subject, ca_key)
    leaf = (x509.CertificateBuilder().subject_name(name(host)).issuer_name(issuer)
            .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(start).not_valid_after(end)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .sign(signer, hashes.SHA256()))
    d.mkdir(parents=True, exist_ok=True)
    chain, key = d / "fullchain.pem", d / "privkey.pem"
    pem = serialization.Encoding.PEM
    chain.write_bytes(leaf.public_bytes(pem) + (b"" if self_signed else ca.public_bytes(pem)))
    key.write_bytes(leaf_key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    key.chmod(0o600)
    return chain, key


def _check_cert(cert: Path | str, key: Path | str, host: str = "mcp.example.test") -> subprocess.CompletedProcess:
    script = _install_function("safe_path") + _install_function("check_operator_cert")
    return subprocess.run(["bash", "-c", script + 'check_operator_cert "$1" "$2" "$3"', "-", str(cert), str(key), host],
                          capture_output=True, text=True)


def test_operator_certificate_from_a_ca_is_accepted(tmp_path):
    cert, key = _make_cert(tmp_path)
    r = _check_cert(cert, key)
    assert r.returncode == 0, r.stdout + r.stderr


def test_operator_key_may_be_group_readable_but_not_world_readable(tmp_path):
    cert, key = _make_cert(tmp_path)
    key.chmod(0o640)
    assert _check_cert(cert, key).returncode == 0
    key.chmod(0o644)
    r = _check_cert(cert, key)
    assert r.returncode != 0 and "TLS_KEY" in r.stdout and "644" in r.stdout
    key.chmod(0o660)
    assert _check_cert(cert, key).returncode != 0


def test_operator_certificate_for_another_name_is_refused(tmp_path):
    cert, key = _make_cert(tmp_path, host="other.example.test")
    r = _check_cert(cert, key)
    assert r.returncode != 0 and "not valid for mcp.example.test" in r.stdout


def test_operator_certificate_with_another_key_is_refused(tmp_path):
    cert, _ = _make_cert(tmp_path / "a")
    _, other_key = _make_cert(tmp_path / "b")
    r = _check_cert(cert, other_key)
    assert r.returncode != 0 and "does not belong" in r.stdout


def test_passphrase_protected_operator_key_is_refused_for_what_it_is(tmp_path):
    """nginx cannot use an encrypted key without ssl_password_file. Corporate CAs often issue one, and the check
    used to call it a key that does not belong to the certificate, which sent the operator the wrong way."""
    from cryptography.hazmat.primitives import serialization
    cert, key = _make_cert(tmp_path)
    plain = serialization.load_pem_private_key(key.read_bytes(), password=None)
    key.write_bytes(plain.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                        serialization.BestAvailableEncryption(b"test-passphrase")))
    r = _check_cert(cert, key)
    assert r.returncode != 0 and "encrypted" in r.stdout and "does not belong" not in r.stdout


def test_expired_operator_certificate_is_refused(tmp_path):
    cert, key = _make_cert(tmp_path, expired=True)
    r = _check_cert(cert, key)
    assert r.returncode != 0 and "expired" in r.stdout


def test_self_signed_operator_certificate_is_refused(tmp_path):
    """Browsers and AI apps refuse a self-signed certificate, so the kit never serves one."""
    cert, key = _make_cert(tmp_path, self_signed=True)
    r = _check_cert(cert, key)
    assert r.returncode != 0 and "self-signed" in r.stdout


def test_operator_certificate_paths_must_be_plain_absolute_paths(tmp_path):
    cert, key = _make_cert(tmp_path)
    for bad in ("fullchain.pem", "/etc/ssl/a b.pem", "/etc/ssl/x;.pem", "/etc/ssl/../x.pem", "/etc/ssl/x|y.pem"):
        r = _check_cert(bad, key)
        assert r.returncode != 0 and "TLS_CERT" in r.stdout, bad
    assert _check_cert(tmp_path / "missing.pem", key).returncode != 0
    assert _check_cert(cert, tmp_path / "missing.key").returncode != 0


def _certificate_source(tmp_path, env: dict, record: str | None) -> subprocess.CompletedProcess:
    path = tmp_path / "tls-certificate"
    path.unlink(missing_ok=True)
    if record is not None:
        path.write_text(record)
    script = _install_function("certificate_source") + f'certificate_source "{path}"'
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                          env={"PATH": "/usr/bin:/bin", **env})


def test_certificate_source_prefers_the_environment_then_the_record(tmp_path):
    given = {"TLS_CERT": "/etc/ssl/a/fullchain.pem", "TLS_KEY": "/etc/ssl/a/privkey.pem"}
    record = "TLS_CERT=/etc/ssl/b/fullchain.pem\nTLS_KEY=/etc/ssl/b/privkey.pem\n"
    assert _certificate_source(tmp_path, given, record).stdout.split() == list(given.values())
    assert _certificate_source(tmp_path, {}, record).stdout.split() == ["/etc/ssl/b/fullchain.pem",
                                                                        "/etc/ssl/b/privkey.pem"]
    none = _certificate_source(tmp_path, {}, None)
    assert none.returncode == 0 and none.stdout.strip() == ""          # Let's Encrypt
    r = _certificate_source(tmp_path, {"TLS_CERT": "/etc/ssl/a/fullchain.pem"}, None)
    assert r.returncode != 0 and "both" in r.stdout


def test_nginx_site_serves_the_chosen_certificate():
    text = (DEPLOY / "nginx-site.conf").read_text()
    assert "ssl_certificate     @TLS_CERT@;" in text and "ssl_certificate_key @TLS_KEY@;" in text
    assert "/etc/letsencrypt" not in text.split("# BEGIN TLS")[1]
    script = _install_function("render_site") + (
        f'BUNDLE="{DEPLOY}" MCP_HOSTNAME=mcp.example.test LISTEN_PORT=8765 NAME=mcp-server-imap-smtp HAVE_IPV6=0 '
        'CERT=/etc/ssl/a/fullchain.pem KEY=/etc/ssl/a/privkey.pem; render_site full')
    site = "\n".join(_bash(script))
    assert "ssl_certificate     /etc/ssl/a/fullchain.pem;" in site
    assert "ssl_certificate_key /etc/ssl/a/privkey.pem;" in site
    assert "@" not in site.replace("$remote_addr", "")


def test_operator_certificate_skips_certbot_and_says_whose_job_renewal_is():
    install = (DEPLOY / "install.sh").read_text()
    certbot = install.index("certbot certonly")
    assert install.rfind('if [[ -z $TLS_CERT && ! -s $CERT ]]', 0, certbot) != -1
    preflight = install.split("# --- 2. Packages")[0]
    assert '[[ -z $TLS_CERT && ! -s $CERT ]]' in preflight            # no ADMIN_EMAIL or LE_AGREE_TOS needed
    assert "check_operator_cert" in preflight                         # checked before anything changes
    assert "renewal is yours" in install


def test_build_prints_ship_commands_that_survive_spaces_in_the_checkout_path():
    """The printed scp line is pasted as it is; a checkout under a directory with a space broke it."""
    build = (DEPLOY / "build.sh").read_text()
    commands = build.split("Ship and install", 1)[1]
    assert "scp $dist/$name.tar.gz" not in commands
    assert 'bundle_q="$(printf %q "$dist/$name.tar.gz")"' in build and "scp $bundle_q " in commands


def test_certbot_failure_names_the_way_without_a_public_name():
    install = (DEPLOY / "install.sh").read_text()
    failure = install.split("certbot certonly", 1)[1].split("\nfi\n", 1)[0]
    assert "TLS_CERT" in failure and "Cloudflare" not in failure


def test_bundle_wheel_is_built_with_the_licence_and_readme():
    """build.sh builds the wheel from a clean copy; without LICENSE and README.md in it the shipped wheel had
    no licence file and no description (found by the ticket 76 package check)."""
    build = (DEPLOY / "build.sh").read_text()
    wheel_step = build.split("# 1. Wheel", 1)[1].split("# 2.", 1)[0]
    assert 'cp "$project/pyproject.toml" "$project/README.md" "$project/LICENSE" "$work/src/"' in wheel_step
    assert "licenses/LICENSE" in wheel_step          # and checks the wheel really carries it


def test_build_marks_a_release_dirty_when_the_readme_or_licence_changed():
    """README.md and LICENSE go into the bundled wheel, so an uncommitted change to either must mark the release
    -dirty; otherwise rebuilding from the git id in BUILD_INFO would not give back the shipped bundle."""
    build = (DEPLOY / "build.sh").read_text()
    assert "status --porcelain -- src pyproject.toml README.md LICENSE deploy" in build


# Ticket 76: scripts/install-test.sh removes its work directory at the end, but not the logs of a failed run.

SCRIPTS = DEPLOY.parent / "scripts"


def _install_test_function(name: str) -> str:
    text = (SCRIPTS / "install-test.sh").read_text()
    start = text.index(f"\n{name}() {{") + 1
    return text[start:text.index("\n}\n", start) + 3]


def _run_install_test_exit(tmp_path, rc: int) -> subprocess.CompletedProcess:
    """Runs the script's EXIT handling on a work directory holding a run's logs, with docker stubbed out."""
    base, w = tmp_path / "base", tmp_path / "base" / "run"
    w.mkdir(parents=True)
    for log in ("console.log", "old.build.log", "new.build.log", "install.1.log"):
        (w / log).write_text(log)
    (w / "disk.qcow2").write_text("disk")
    script = ("docker() { :; }\n" + "".join(_install_test_function(f) for f in ("down", "keep_logs", "on_exit"))
              + f"trap on_exit EXIT\nexit {rc}\n")
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                          env={"PATH": "/usr/bin:/bin", "W": str(w), "BASE_DIR": str(base), "CONTAINER": "none"})


def test_install_test_keeps_the_logs_of_a_failed_run(tmp_path):
    r = _run_install_test_exit(tmp_path, 1)
    kept = tmp_path / "base" / "last-failure"
    assert r.returncode == 1
    assert not (tmp_path / "base" / "run").exists()
    assert sorted(p.name for p in kept.iterdir()) == ["console.log", "install.1.log", "new.build.log", "old.build.log"]
    assert str(kept) in r.stderr


def test_install_test_keeps_nothing_after_a_passing_run(tmp_path):
    r = _run_install_test_exit(tmp_path, 0)
    assert r.returncode == 0
    assert not (tmp_path / "base" / "run").exists() and not (tmp_path / "base" / "last-failure").exists()
