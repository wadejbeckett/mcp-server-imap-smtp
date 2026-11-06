# SPDX-License-Identifier: AGPL-3.0-or-later
"""Lab tests for stopping the service (ticket 34) on a real Dovecot over TLS: a command waiting on the mail
server is interrupted at once, and Sessions.close logs out kept sessions."""
import threading
import time

import anyio
import pytest

from mcp_server_imap_smtp.mail.imap import ImapClient
from mcp_server_imap_smtp.mail.sessions import Sessions
from tests._lab import CA_FILE, FLAT, record_commands, require_lab, users

pytestmark = pytest.mark.lab

ALICE = "alice@example.test"


@pytest.fixture(scope="module", autouse=True)
def _lab_up():
    require_lab()


@pytest.fixture
def lab_ca(monkeypatch):
    monkeypatch.setenv("SSL_CERT_FILE", str(CA_FILE))
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)


@pytest.fixture
def anyio_backend():
    return "asyncio"


def test_interrupt_ends_a_read_the_server_is_not_answering(lab_ca):
    """In IDLE the server sends nothing until mail arrives: the read waits as a call does on a slow server.
    interrupt() from another thread ends it at once, through TLS, and the session then closes promptly."""
    c = ImapClient.open(FLAT.server(), ALICE, users()[ALICE])
    try:
        c.c.send(c.c._new_tag() + b" IDLE\r\n")
        assert c.c.readline().startswith(b"+")
        ended = []

        def wait_for_server():
            try:
                ended.append(c.c.readline())
            except Exception as exc:          # imaplib.abort or ssl.SSLError, depending on Python
                ended.append(exc)
        reader = threading.Thread(target=wait_for_server, daemon=True)
        reader.start()
        time.sleep(0.3)
        assert reader.is_alive()               # really waiting on the server
        started = time.monotonic()
        c.interrupt()
        reader.join(5)
        assert not reader.is_alive() and time.monotonic() - started < 2
        assert ended[0] == b"" or isinstance(ended[0], Exception)
    finally:
        started = time.monotonic()
        c.close()
        assert time.monotonic() - started < 6


@pytest.mark.anyio
async def test_close_logs_out_a_kept_session(lab_ca):
    server = FLAT.server()
    s = Sessions([server])
    sent = {}

    def work(lease):
        def opened():
            client = ImapClient.open(server, ALICE, users()[ALICE])
            sent["client"] = client
            sent["recorder"] = record_commands(client.c)
            sent["commands"] = sent["recorder"].__enter__()
            return client
        with lease.session(ALICE, opened) as c:
            c.c.noop()
    async with s.lease(server, "g", ALICE, pool_key=("g", ALICE)) as lease:
        await anyio.to_thread.run_sync(work, lease)
    assert s.counts(server.host)["idle"] == 1
    with anyio.fail_after(5):
        await s.close()
    assert [name for name, _ in sent["commands"]][-1] == "LOGOUT"
    assert sent["client"].c.sock.fileno() == -1
    assert s.counts(server.host) == {"used": 0, "idle": 0, "boxes": {}, "waiting": 0}
