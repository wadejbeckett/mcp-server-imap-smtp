# SPDX-License-Identifier: AGPL-3.0-or-later
"""The gateway served the way the service runs it (app.serve), with a fake sign-in check and a fake mail
server, for tests/test_shutdown.py: python tests/_stop_server.py DIR PORT.

The fake IMAP session's commands answer at once, unless a file in DIR says otherwise: "block", a socket read
on a listener that never answers (a silent mail server) that the session can interrupt as ImapClient does;
"stuck", the same read on a socket the session does not hold (work nothing can interrupt, such as an SMTP
exchange); "slow", a one-second wait. Events ("started", "blocked", "logout") are written as lines to DIR/events, so a
test can follow the session after the process has gone."""
import socket
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mcp_server_imap_smtp import app as app_mod  # noqa: E402
from mcp_server_imap_smtp.config import Settings  # noqa: E402
from mcp_server_imap_smtp.mail.hosts import MailServer  # noqa: E402
from mcp_server_imap_smtp.mail.imap import TIMEOUT  # noqa: E402

ADDRESS, PASSWORD = "me@x.example", "pw"


class SilentServer:
    """A listener that accepts connections and never sends a byte."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)

    def connect(self) -> socket.socket:
        conn = socket.create_connection(self.sock.getsockname())
        conn.settimeout(TIMEOUT)          # as ImapClient sets on its socket
        return conn


class FakeSession:
    def __init__(self, folder: Path, silent: SilentServer):
        self.folder, self.silent = folder, silent
        self.sock: socket.socket | None = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        with open(self.folder / "events", "a") as f:
            f.write("logout\n")
        self.drop()

    def interrupt(self):
        if self.sock is not None:
            try:
                socket.socket.shutdown(self.sock, socket.SHUT_RDWR)
            except OSError:
                pass

    def drop(self):
        if self.sock is not None:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.sock.close()

    def reset(self):
        pass

    def folders(self):
        if (self.folder / "slow").exists():
            with open(self.folder / "events", "a") as f:
                f.write("started\n")
            time.sleep(1)
        for mode in ("block", "stuck"):
            if (self.folder / mode).exists():
                sock = self.silent.connect()
                if mode == "block":
                    self.sock = sock
                with open(self.folder / "events", "a") as f:
                    f.write("blocked\n")
                if not sock.recv(1):         # a read the mail server never answers
                    raise OSError("connection closed")
        return []

    def namespaces(self):
        return {"personal": [["", "/"]], "other": [], "shared": []}


def main() -> None:
    folder, port = Path(sys.argv[1]), int(sys.argv[2])
    base = f"http://127.0.0.1:{port}"
    settings = Settings(issuer_url=base, mail_resource_url=f"{base}/mail", listen_port=port,
                        mail_servers=(MailServer("mail.example.test", domains=("x.example",), match_mx=False),),
                        db_path=folder / "gateway.sqlite", allow_loopback_redirects=True)
    silent = SilentServer()
    gateway = app_mod.build_app(settings, verifier=lambda a, p, server: (a, p) == (ADDRESS, PASSWORD),
                                opener=lambda server, address, password: FakeSession(folder, silent),
                                sender=lambda *a, **k: [])
    app_mod.serve(gateway, settings)


if __name__ == "__main__":
    main()
