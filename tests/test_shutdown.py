# SPDX-License-Identifier: AGPL-3.0-or-later
"""The service stops within a few seconds of SIGTERM, whatever it is doing: with an AI app's long-lived
stream open, with a tool call waiting on a silent mail server, and with kept IMAP sessions (which get
their LOGOUT). Each test runs the gateway in its own process, served by app.serve as the service is, and
signs in over real HTTP (tests/_stop_server.py has the fake mail server)."""
import base64
import hashlib
import html
import os
import re
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from mcp_server_imap_smtp.app import STOP_SECONDS
from tests._stop_server import ADDRESS, PASSWORD

SERVER = Path(__file__).with_name("_stop_server.py")
STOP_WITHIN = 10.0          # seconds from SIGTERM to exit, with room to spare on a slow machine
CB = "http://127.0.0.1:53280/callback"
ACCEPT = {"accept": "application/json, text/event-stream", "mcp-protocol-version": "2025-06-18"}
_LINK = re.compile(r'<a class="b" href="([^"]+)"')

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="SIGTERM")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Gateway:
    def __init__(self, folder: Path):
        self.folder, self.port = folder, free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        self.log = open(folder / "server.log", "wb")
        self.proc = subprocess.Popen([sys.executable, str(SERVER), str(folder), str(self.port)],
                                     stdout=self.log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 30
        while True:
            try:
                httpx.get(f"{self.base}/.well-known/oauth-authorization-server", timeout=1)
                return
            except httpx.TransportError:
                if self.proc.poll() is not None or time.monotonic() > deadline:
                    raise AssertionError(self.output())
                time.sleep(0.05)

    def output(self) -> str:
        self.log.flush()
        return (self.folder / "server.log").read_text(errors="replace")

    def events(self) -> list[str]:
        path = self.folder / "events"
        return path.read_text().split() if path.exists() else []

    def wait_for(self, event: str, timeout: float = 10.0) -> None:
        deadline = time.monotonic() + timeout
        while event not in self.events():
            assert time.monotonic() < deadline, f"no {event!r} event"
            time.sleep(0.02)

    def token(self) -> str:
        """Register, authorize, sign in and exchange the code, as an AI app does."""
        with httpx.Client(base_url=self.base, follow_redirects=False, timeout=10) as c:
            reg = c.post("/register", json={"redirect_uris": [CB], "token_endpoint_auth_method": "none",
                                            "grant_types": ["authorization_code", "refresh_token"],
                                            "client_name": "Test"}).json()
            verifier = secrets.token_urlsafe(48)
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
            r = c.get("/authorize", params={"response_type": "code", "client_id": reg["client_id"], "redirect_uri": CB,
                                            "code_challenge": challenge, "code_challenge_method": "S256",
                                            "state": "s", "resource": f"{self.base}/mail"})
            req = parse_qs(urlparse(r.headers["location"]).query)["req"][0]
            r = c.post("/mail/login", data={"req": req, "email": ADDRESS, "password": PASSWORD})
            code = parse_qs(urlparse(html.unescape(_LINK.search(r.text)[1])).query)["code"][0]
            r = c.post("/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": CB,
                                       "client_id": reg["client_id"], "code_verifier": verifier,
                                       "resource": f"{self.base}/mail"})
            return r.json()["access_token"]

    def call(self, token: str, tool: str, **arguments) -> httpx.Response:
        return httpx.post(f"{self.base}/mail", headers={**ACCEPT, "authorization": f"Bearer {token}"},
                          json={"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                "params": {"name": tool, "arguments": arguments}}, timeout=60)

    def stop(self, sig: int = signal.SIGTERM) -> tuple[int, float]:
        """SIGTERM (or `sig`); (exit status, seconds until the process had gone)."""
        started = time.monotonic()
        self.proc.send_signal(sig)
        try:
            status = self.proc.wait(timeout=60)
        finally:
            if self.proc.poll() is None:
                self.proc.kill()
                self.proc.wait()
        return status, time.monotonic() - started

    def close(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()
        self.log.close()


@pytest.fixture
def gateway(tmp_path):
    g = Gateway(tmp_path)
    yield g
    g.close()


def clean(status: int) -> bool:
    """uvicorn ends a SIGTERM shutdown by raising the signal again once it has finished, which systemd
    counts as a clean stop, like exit status 0."""
    return status in (0, -signal.SIGTERM)


def assert_stopped_cleanly(gateway, status, took):
    assert clean(status), (status, gateway.output())
    assert took < STOP_WITHIN, (took, gateway.output())


def assert_stopped_without_the_backstop(gateway, status, took):
    """Stopped by the stop path itself, not by the last-resort exit at STOP_SECONDS (which also exits 0)."""
    assert_stopped_cleanly(gateway, status, took)
    assert "stopping took longer than" not in gateway.output(), gateway.output()
    assert took < STOP_SECONDS - 1, (took, gateway.output())


def test_stops_at_once_when_idle(gateway):
    status, took = gateway.stop()
    assert_stopped_without_the_backstop(gateway, status, took)


def test_ctrl_c_in_a_foreground_run_stops_quietly(gateway):
    """Ctrl+C (SIGINT) ends a foreground run with status 0 and no traceback, as uvicorn.run does."""
    status, took = gateway.stop(signal.SIGINT)
    assert status == 0, (status, gateway.output())
    assert took < STOP_WITHIN and "Traceback" not in gateway.output(), gateway.output()


def test_stops_with_an_open_stream(gateway):
    """An AI app keeps the GET stream open for server messages; it must not hold the shutdown."""
    token = gateway.token()
    opened = threading.Event()

    def listen():
        try:
            with httpx.stream("GET", f"{gateway.base}/mail", timeout=60,
                              headers={"accept": "text/event-stream", "mcp-protocol-version": "2025-06-18",
                                       "authorization": f"Bearer {token}"}) as r:
                assert r.status_code == 200, r.status_code
                opened.set()
                for _ in r.iter_bytes():
                    pass
        except httpx.HTTPError:
            pass
    reader = threading.Thread(target=listen, daemon=True)
    reader.start()
    assert opened.wait(10)
    status, took = gateway.stop()
    assert_stopped_without_the_backstop(gateway, status, took)


def test_stops_with_a_tool_call_waiting_on_a_silent_mail_server(gateway):
    token = gateway.token()
    (gateway.folder / "block").touch()
    answers = []
    caller = threading.Thread(target=lambda: answers.append(_answer(gateway, token)), daemon=True)
    caller.start()
    gateway.wait_for("blocked")
    status, took = gateway.stop()
    assert_stopped_without_the_backstop(gateway, status, took)
    caller.join(10)


def _answer(gateway, token):
    try:
        return gateway.call(token, "mail_folders")
    except httpx.HTTPError as exc:
        return exc


def test_kept_sessions_are_logged_out_on_stop(gateway):
    token = gateway.token()
    r = gateway.call(token, "mail_folders")
    assert r.status_code == 200 and '"isError":false' in r.text.replace(" ", ""), r.text
    assert gateway.events() == []          # the session is kept for the next call, not logged out
    status, took = gateway.stop()
    assert_stopped_without_the_backstop(gateway, status, took)
    assert gateway.events() == ["logout"]


def test_a_call_in_flight_gets_a_short_grace_to_finish(gateway):
    token = gateway.token()
    (gateway.folder / "slow").touch()
    answers = []
    caller = threading.Thread(target=lambda: answers.append(_answer(gateway, token)), daemon=True)
    caller.start()
    gateway.wait_for("started")          # the call is under way (it takes a second)
    status, took = gateway.stop()
    assert_stopped_without_the_backstop(gateway, status, took)
    caller.join(10)
    assert isinstance(answers[0], httpx.Response) and '"isError":false' in answers[0].text.replace(" ", "")


def test_stops_even_when_work_in_flight_cannot_be_interrupted(gateway):
    """The last resort: work blocked where nothing can reach it (an SMTP exchange, a converter) is
    abandoned after the stop bound rather than holding the process until its own timeout."""
    token = gateway.token()
    (gateway.folder / "stuck").touch()
    caller = threading.Thread(target=lambda: _answer(gateway, token), daemon=True)
    caller.start()
    gateway.wait_for("blocked")
    status, took = gateway.stop()
    assert_stopped_cleanly(gateway, status, took)
    assert "stopping took longer than" in gateway.output()
