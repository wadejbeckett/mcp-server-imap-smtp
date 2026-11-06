# SPDX-License-Identifier: AGPL-3.0-or-later
"""The container test lab (scripts/lab.sh, lab/): where each profile listens, its fixture users, and the lab
CA. Lab tests are marked `lab` and deselected by default; run `scripts/lab.sh up`, then `pytest -m lab`."""
import contextlib
import imaplib
import os
import socket
import ssl
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

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


@contextlib.contextmanager
def record_commands(conn: imaplib.IMAP4):
    """Record the IMAP commands sent on conn (an ImapClient's `.c`): yields a list of (name, args) tuples,
    names upper-case and `UID x` as `UID X`. The stripped profile only hides MOVE, UIDPLUS and ESEARCH
    from CAPABILITY, so fallback tests assert on this list that the connector never sent them."""
    sent: list[tuple[str, tuple]] = []
    original = conn._command

    def spy(name, *args):
        name = name.upper()
        if name == "UID" and args:
            name = f"UID {str(args[0]).upper()}"
        sent.append((name, args))
        return original(name if " " not in name else "UID", *args)

    conn._command = spy
    try:
        yield sent
    finally:
        conn._command = original


def free_port() -> int:
    """A loopback TCP port nothing listens on right now."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _toml(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_toml(v) for v in value) + "]"
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


@contextlib.contextmanager
def running_connector(profile: Profile, workdir: Path, **settings) -> Iterator[str]:
    """Start the real connector (its `main`, in a subprocess) on a free loopback port, signing in to
    `profile`'s mail server and trusting only the lab CA; yield its base URL (http://127.0.0.1:PORT, the MCP
    endpoint at /mail) and stop it afterwards. Extra keyword arguments become top-level config keys. The
    server's output goes to workdir/connector.log, shown when it does not start."""
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    config = {"issuer_url": base, "mail_resource_url": f"{base}/mail", "db_path": str(workdir / "connector.sqlite"),
              "listen_port": port, "operator_name": "Lab", "product_name": "Lab Mail", **settings}
    lines = [f"{k} = {_toml(v)}" for k, v in config.items()]
    lines += ["[[mail_servers]]", f"host = {_toml(HOST)}", f"imap_port = {profile.imaps}",
              f"smtp_port = {profile.smtps}", 'domains = ["*"]', "match_mx = false"]
    (workdir / "connector.toml").write_text("\n".join(lines) + "\n")
    env = {k: v for k, v in os.environ.items() if k != "SSL_CERT_DIR"}
    env["SSL_CERT_FILE"] = str(CA_FILE)
    log = open(workdir / "connector.log", "wb")
    proc = subprocess.Popen([sys.executable, "-c", "from mcp_server_imap_smtp.app import main; main()",
                             "--config", str(workdir / "connector.toml")], stdout=log, stderr=subprocess.STDOUT,
                            env=env, cwd=workdir)
    try:
        deadline = time.monotonic() + 30
        while True:
            if proc.poll() is not None:
                pytest.fail(f"the connector exited ({proc.returncode}):\n{(workdir / 'connector.log').read_text()[-3000:]}")
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1).close()
                break
            except OSError:
                if time.monotonic() > deadline:
                    pytest.fail(f"the connector did not listen within 30 s:\n"
                                f"{(workdir / 'connector.log').read_text()[-3000:]}")
                time.sleep(0.2)
        yield base
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        log.close()
