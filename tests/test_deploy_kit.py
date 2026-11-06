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
