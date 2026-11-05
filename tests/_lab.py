# SPDX-License-Identifier: AGPL-3.0-or-later
"""The container test lab (scripts/lab.sh, lab/): where each profile listens, its fixture users, and the lab
CA. Lab tests are marked `lab` and deselected by default; run `scripts/lab.sh up`, then `pytest -m lab`."""
import os
import socket
import ssl
from dataclasses import dataclass
from pathlib import Path

import pytest

from mcp_server_imap_smtp.mail.hosts import MailServer

ROOT = Path(__file__).resolve().parent.parent
CA_FILE = Path(os.environ.get("MCP_LAB_CA", ROOT / "lab" / ".state" / "tls" / "ca.pem"))
HOST = "localhost"   # the name on the lab server certificate


@dataclass(frozen=True)
class Profile:
    """One lab container. Host ports are <prefix><last three digits of the service port> (scripts/lab.sh)."""
    name: str
    prefix: int

    def port(self, service: int) -> int:
        return int(f"{self.prefix}{service % 1000:03d}")

    @property
    def imaps(self): return self.port(993)
    @property
    def smtps(self): return self.port(465)
    @property
    def submission(self): return self.port(587)
    @property
    def sieve(self): return self.port(190)

    def server(self) -> MailServer:
        return MailServer(HOST, imap_port=self.imaps, smtp_port=self.smtps, domains=("*",), match_mx=False)


FLAT = Profile("flat", 10)          # flat namespace, every extension
PREFIXED = Profile("prefixed", 11)  # INBOX.-prefixed namespace
STRIPPED = Profile("stripped", 12)  # flat, without MOVE, UIDPLUS or ESEARCH
PROFILES = (FLAT, PREFIXED, STRIPPED)


def users() -> dict[str, str]:
    """Fixture mailboxes and their lab-only passwords, read from the Dovecot passwd-file the lab uses."""
    out = {}
    for line in (ROOT / "lab" / "dovecot" / "users").read_text().splitlines():
        if line.strip() and not line.startswith("#"):
            address, secret = line.split(":", 2)[:2]
            out[address] = secret.removeprefix("{PLAIN}")
    return out


def context() -> ssl.SSLContext:
    """A verifying client context that trusts only the lab CA."""
    return ssl.create_default_context(cafile=str(CA_FILE))


def require_lab() -> None:
    """Fail (not skip) with the fix when the lab is not up: `-m lab` was asked for explicitly."""
    if not CA_FILE.exists():
        pytest.fail(f"no lab CA at {CA_FILE}: run scripts/lab.sh up")
    for p in PROFILES:
        try:
            socket.create_connection((HOST, p.imaps), timeout=3).close()
        except OSError:
            pytest.fail(f"lab profile {p.name} is not listening on {p.imaps}: run scripts/lab.sh up")
