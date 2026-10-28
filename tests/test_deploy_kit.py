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
