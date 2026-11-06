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
