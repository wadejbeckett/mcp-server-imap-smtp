# SPDX-License-Identifier: AGPL-3.0-or-later
"""Security review fixes of 20 October 2026 (docs/security-review-2026-10-20.md, findings 1-3, 7, 8, 12)."""
from __future__ import annotations

import imaplib
import logging

import pytest
from mcp.server.auth.provider import AuthorizationParams
from mcp.server.mcpserver import MCPServer
from mcp.shared.auth import OAuthClientInformationFull
from pydantic import AnyUrl
from starlette.applications import Starlette
from starlette.testclient import TestClient

from mcp_server_imap_smtp.app import build_app
from mcp_server_imap_smtp.auth.login import LoginLimits, login_routes
from mcp_server_imap_smtp.auth.provider import GatewayProvider, registration_problem
from mcp_server_imap_smtp.config import Settings
from mcp_server_imap_smtp.mail import imap as imap_mod
from mcp_server_imap_smtp.mail import tools as tools_mod
from mcp_server_imap_smtp.mail.hosts import MailServer
from mcp_server_imap_smtp.mail.resolve import Resolver
from mcp_server_imap_smtp.ratelimit import RateLimiter, client_key, client_network
from mcp_server_imap_smtp.store import Store
from tests._signin import connected

MAIL1 = MailServer("mail.example.net", domains=("x.example",), match_mx=False)
CB = "https://claude.ai/api/mcp/auth_callback"


def settings(tmp_path, **kw):
    return Settings(issuer_url="http://127.0.0.1:8765", mail_resource_url="http://127.0.0.1:8765/mail",
                    mail_servers=(MAIL1,), db_path=tmp_path / "s.sqlite", **kw)


# --- finding 1: IPv6 clients are one /64; per-host, daily and per-page caps --------------------------

@pytest.mark.parametrize("host,key", [
    ("2001:db8:1:2:aaaa::1", "2001:db8:1:2::/64"),
    ("2001:db8:1:2:ffff:ffff:ffff:ffff", "2001:db8:1:2::/64"),
    ("::ffff:192.0.2.7", "192.0.2.7"),
    ("192.0.2.7", "192.0.2.7"),
    ("testclient", "testclient"),
    (None, "?"),
])
def test_client_key(host, key):
    assert client_key(host) == key


def login_env(tmp_path, verify, **kw):
    s = settings(tmp_path, **kw)
    store = Store(s.db_path)
    prov = GatewayProvider(s, store)

    def pending():
        return store.create_pending("c1", AuthorizationParams(state="st", scopes=None, code_challenge="cc",
                                    redirect_uri=AnyUrl(CB), redirect_uri_provided_explicitly=True,
                                    resource=s.mail_resource_url), ttl=600)
    limits = LoginLimits.from_settings(s)
    app = Starlette(routes=login_routes(prov, Resolver((MAIL1,)), verify, limits, s))
    return app, pending, limits


def post_from(app, ip, data):
    with TestClient(app, follow_redirects=False, client=(ip, 50000)) as c:
        return c.post("/mail/login", data=data)


def test_ipv6_rotation_within_a_64_shares_one_budget(tmp_path):
    app, pending, limits = login_env(tmp_path, lambda a, p, s: False, login_failures=3)
    req = pending()
    codes = [post_from(app, f"2001:db8:1:2::{i:x}", {"req": req, "email": f"u{i}@x.example", "password": "bad"}).status_code
             for i in range(1, 5)]
    assert codes == [200, 200, 200, 429]


def test_host_cap_stops_spraying_across_mailboxes_and_addresses(tmp_path, caplog):
    caplog.set_level(logging.WARNING)
    tried = []

    def verify(a, p, s):
        tried.append(a)
        return False
    app, pending, limits = login_env(tmp_path, verify, host_login_failures=4, request_login_failures=100)
    for i in range(6):
        post_from(app, f"192.0.2.{i}", {"req": pending(), "email": f"u{i}@x.example", "password": "bad"})
    assert len(tried) == 4                                  # the fifth and sixth never reached the server
    assert "sign-in limit reached for mail server mail.example.net" in caplog.text
    r = post_from(app, "192.0.2.99", {"req": pending(), "email": "ok@x.example", "password": "x"})
    assert r.status_code == 429 and "this mail server" in r.text


def test_daily_cap_per_mailbox(tmp_path):
    app, pending, limits = login_env(tmp_path, lambda a, p, s: False, login_daily_failures=2)
    limits.window = RateLimiter(100, 900)     # take the 15-minute budget out of the way
    app = Starlette(routes=login_routes(GatewayProvider(settings(tmp_path), Store(tmp_path / "s.sqlite")),
                                        Resolver((MAIL1,)), lambda a, p, s: False, limits, settings(tmp_path)))
    codes = [post_from(app, f"192.0.2.{i}", {"req": pending(), "email": "boss@x.example", "password": "bad"}).status_code
             for i in range(3)]
    assert codes == [200, 200, 429]


def test_one_sign_in_page_allows_only_a_few_wrong_passwords(tmp_path):
    app, pending, _ = login_env(tmp_path, lambda a, p, s: False, request_login_failures=2, login_failures=50)
    req = pending()
    codes = [post_from(app, f"192.0.2.{i}", {"req": req, "email": f"u{i}@x.example", "password": "bad"}).status_code
             for i in range(3)]
    assert codes == [200, 200, 429]


# --- finding 7: a wrong first password does not lock the other mailboxes on the form ------------------

def test_untried_mailboxes_keep_their_budget(tmp_path):
    app, pending, limits = login_env(tmp_path, lambda a, p, s: a == "b@x.example", login_failures=2,
                                     request_login_failures=100)
    for i in range(5):
        post_from(app, f"192.0.2.{i}", {"req": pending(), "email": "a@x.example", "password": "bad",
                                         "more": "b@x.example good"})
    assert limits.window.count("addr:b@x.example") == 0
    assert limits.window.blocked("addr:a@x.example")


# --- finding 3: registration size and type limits ----------------------------------------------------

def client_info(**kw):
    return OAuthClientInformationFull(**{"client_id": "c", "redirect_uris": [AnyUrl(CB)],
                                         "token_endpoint_auth_method": "none", **kw})


def test_registration_problem_limits():
    assert registration_problem(client_info(client_name="Claude")) is None
    assert "client_name" in registration_problem(client_info(client_name="x" * 101))
    assert "redirect_uris" in registration_problem(client_info(redirect_uris=[AnyUrl(f"http://127.0.0.1:{p}/cb")
                                                                              for p in range(1000, 1011)]))
    assert "logo_uri" in registration_problem(client_info(logo_uri=AnyUrl("https://e.example/" + "a" * 600)))


@pytest.fixture
def app_client(tmp_path):
    app = build_app(settings(tmp_path), opener=None, sender=None)
    with TestClient(app, base_url="http://127.0.0.1:8765") as c:
        yield c


def test_register_refuses_non_json_and_oversized_bodies(app_client):
    ok = {"redirect_uris": [CB], "token_endpoint_auth_method": "none", "client_name": "Claude"}
    assert app_client.post("/register", json=ok).status_code == 201
    assert app_client.post("/register", content=b'{"redirect_uris":["' + CB.encode() + b'"]}',
                           headers={"content-type": "text/plain"}).status_code == 415
    big = {**ok, "client_name": "x" * 9000}
    assert app_client.post("/register", json=big).status_code == 413
    assert app_client.post("/register", json={**ok, "client_name": "x" * 200}).status_code == 400


def test_register_overall_cap(tmp_path):
    app = build_app(settings(tmp_path, register_overall_limit=2, register_limit=100), opener=None, sender=None)
    ok = {"redirect_uris": [CB], "token_endpoint_auth_method": "none"}
    codes = []
    for i in range(3):
        c = TestClient(app, base_url="http://127.0.0.1:8765", client=(f"192.0.2.{i}", 1))   # no lifespan needed
        codes.append(c.post("/register", json=ok).status_code)
    assert codes == [201, 201, 429]


# --- finding 8: refresh-token and code replay end the grant ------------------------------------------

def test_refresh_replay_after_grace_revokes_the_grant(tmp_path, monkeypatch):
    s = Store(tmp_path / "s.sqlite")
    gid, key = s.create_grant("c1", "r", [("me@x.example", "pw", MAIL1)])
    _, rt = s.issue_tokens(gid, key, "c1", [], "r", 3600, 86400)
    _, at2, rt2 = s.rotate_and_issue(rt, "c1", None, 3600, 86400)
    assert s.replayed_grant(rt, "refresh", grace=30) is None        # a quick retry: refused only
    assert s.load_token(at2, "access") is not None
    assert s.replayed_grant(rt, "refresh", grace=0) == gid          # a late replay: the grant ends
    assert s.load_token(at2, "access") is None and s.load_token(rt2, "refresh") is None


def test_wrong_secret_is_not_a_replay(tmp_path):
    s = Store(tmp_path / "s.sqlite")
    gid, key = s.create_grant("c1", "r", [("me@x.example", "pw", MAIL1)])
    _, rt = s.issue_tokens(gid, key, "c1", [], "r", 3600, 86400)
    _, at2, _ = s.rotate_and_issue(rt, "c1", None, 3600, 86400)
    forged = rt.rsplit(".", 1)[0] + ".forged"
    assert s.replayed_grant(forged, "refresh", grace=0) is None
    assert s.load_token(at2, "access") is not None


# --- finding 12: a temporary IMAP failure is not a wrong password ------------------------------------

class _NoConn:
    def __init__(self, text):
        self.text = text

    def login(self, *a):
        raise imaplib.IMAP4.error(self.text)

    def logout(self):
        pass

    def shutdown(self):
        pass


@pytest.mark.parametrize("text,exc", [
    ("b'[UNAVAILABLE] Temporary authentication failure.'", imap_mod.MailError),
    ("b'[SERVERBUG] Internal error'", imap_mod.MailError),
    ("b'[AUTHENTICATIONFAILED] Authentication failed.'", imap_mod.MailAuthError),
    ("b'Authentication failed.'", imap_mod.MailAuthError),
])
def test_login_failure_classification(monkeypatch, text, exc):
    class Sock:
        def settimeout(self, t):
            pass

        def close(self):
            pass
    monkeypatch.setattr(imap_mod.Connector, "tls_connect", lambda self, port: Sock())
    monkeypatch.setattr(imap_mod, "_Conn", lambda sock: _NoConn(text))
    monkeypatch.setattr(imap_mod, "_drop", lambda conn: None)
    with pytest.raises(exc):
        imap_mod.ImapClient.open(MAIL1, "me@x.example", "pw")


# --- finding 2: send mode, budgets, recipients and Bcc -----------------------------------------------

def send_env(tmp_path, monkeypatch, **kw):
    s = settings(tmp_path, **kw)
    store = Store(s.db_path)
    gid, key = store.create_grant("c1", s.mail_resource_url, [("me@x.example", "pw", MAIL1)])
    at, _ = store.issue_tokens(gid, key, "c1", [], s.mail_resource_url, 3600, 86400)

    class Tok:
        token = at
    monkeypatch.setattr(tools_mod, "get_access_token", lambda: Tok)
    sent = []

    class Imap:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def special(self, role):
            return None
    srv = MCPServer("t")
    tools_mod.register_mail_tools(srv, store, s, opener=lambda *a: Imap(),
                                  sender=lambda server, a, pw, m, bcc=(): sent.append(m) or [str(m["To"])])
    return srv, sent


def tool_names(srv):
    import asyncio
    return {t.name for t in asyncio.run(srv.list_tools())}


def test_send_modes(tmp_path, monkeypatch):
    # Default: sending is offered; draft_only and off stay operator options.
    assert Settings.__dataclass_fields__["send_mode"].default == "send"
    srv, _ = send_env(tmp_path, monkeypatch)
    assert {"mail_send", "mail_draft"} <= tool_names(srv)
    srv, _ = send_env(tmp_path / "draft", monkeypatch, send_mode="draft_only")
    assert "mail_send" not in tool_names(srv) and "mail_draft" in tool_names(srv)
    srv, _ = send_env(tmp_path / "off", monkeypatch, send_mode="off")
    assert not {"mail_send", "mail_draft"} & tool_names(srv)
    with pytest.raises(ValueError):
        settings(tmp_path, send_mode="yes")


def test_send_caps_are_off_by_default_and_must_not_be_negative(tmp_path):
    s = settings(tmp_path)
    assert (s.send_hourly_limit, s.send_daily_limit, s.send_max_recipients, s.send_allow_bcc) == (0, 0, 0, True)
    for name in ("send_hourly_limit", "send_daily_limit", "send_max_recipients", "max_mailboxes",
                 "search_max_mailboxes"):
        with pytest.raises(ValueError, match=name):
            settings(tmp_path, **{name: -1})


@pytest.mark.anyio
async def test_default_sending_has_no_cap_on_messages_recipients_or_bcc(tmp_path, monkeypatch):
    srv, sent = send_env(tmp_path, monkeypatch)
    many = [f"r{i}@y.example" for i in range(30)]
    for _ in range(120):          # past the old 20-an-hour and 100-a-day caps
        await srv.call_tool("mail_send", {"to": many[:15], "cc": many[15:], "bcc": ["hidden@y.example"],
                                          "subject": "s", "text": "t"})
    assert len(sent) == 120


@pytest.mark.anyio
async def test_send_budget_recipients_and_bcc_when_the_operator_sets_them(tmp_path, monkeypatch):
    srv, sent = send_env(tmp_path, monkeypatch, send_hourly_limit=2, send_max_recipients=3, send_allow_bcc=False)
    msg = {"to": ["a@y.example"], "subject": "s", "text": "t"}
    from mcp.server.mcpserver.exceptions import ToolError
    with pytest.raises(ToolError, match="Bcc is not allowed"):
        await srv.call_tool("mail_send", {**msg, "bcc": ["hidden@y.example"]})
    with pytest.raises(ToolError, match="Too many recipients"):
        await srv.call_tool("mail_send", {**msg, "to": ["a@y.example", "b@y.example"],
                                          "cc": ["c@y.example", "d@y.example"]})
    await srv.call_tool("mail_send", msg)
    await srv.call_tool("mail_send", msg)
    with pytest.raises(ToolError, match=r"sending limit for this connection is reached \(2 an hour\)"):
        await srv.call_tool("mail_send", msg)
    assert len(sent) == 2


@pytest.mark.anyio
async def test_daily_send_cap_alone_and_with_an_hourly_cap(tmp_path, monkeypatch):
    srv, sent = send_env(tmp_path / "a", monkeypatch, send_hourly_limit=5, send_daily_limit=1)
    msg = {"to": ["a@y.example"], "subject": "s", "text": "t"}
    from mcp.server.mcpserver.exceptions import ToolError
    await srv.call_tool("mail_send", msg)
    for _ in range(6):
        with pytest.raises(ToolError, match=r"\(5 an hour, 1 a day\)"):
            await srv.call_tool("mail_send", msg)
    assert len(sent) == 1
    srv, sent = send_env(tmp_path / "b", monkeypatch, send_daily_limit=2)   # a daily cap alone
    await srv.call_tool("mail_send", msg)
    await srv.call_tool("mail_send", msg)
    with pytest.raises(ToolError, match=r"\(2 a day\)"):
        await srv.call_tool("mail_send", msg)


@pytest.fixture
def anyio_backend():
    return "asyncio"


# --- review follow-ups ---------------------------------------------------------------------------------

def test_client_network():
    assert client_network("192.0.2.77") == "192.0.2.0/24"
    assert client_network("2001:db8:1:2::9") == "2001:db8:1::/48"


def test_known_mailbox_gets_through_while_the_server_cap_is_reached(tmp_path):
    app, pending, limits = login_env(tmp_path, lambda a, p, s: p == "good", host_login_failures=2,
                                     request_login_failures=100)
    store = Store(tmp_path / "s.sqlite")
    store.create_grant("c1", "r", [("known@x.example", "old", MAIL1)])
    for i in range(2):
        post_from(app, f"192.0.2.{i}", {"req": pending(), "email": f"u{i}@x.example", "password": "bad"})
    stranger = post_from(app, "198.51.100.1", {"req": pending(), "email": "new@x.example", "password": "good"})
    known = post_from(app, "198.51.100.2", {"req": pending(), "email": "known@x.example", "password": "good"})
    assert stranger.status_code == 429 and connected(known)


def test_daily_cap_is_per_network_with_an_overall_ceiling(tmp_path):
    s = settings(tmp_path, login_daily_failures=2)
    limits = LoginLimits.from_settings(s)
    limits.window = RateLimiter(100, 900)
    store = Store(s.db_path)
    prov = GatewayProvider(s, store)
    app = Starlette(routes=login_routes(prov, Resolver((MAIL1,)), lambda a, p, sv: False, limits, s))

    def pending():
        return store.create_pending("c1", AuthorizationParams(state="st", scopes=None, code_challenge="cc",
                                    redirect_uri=AnyUrl(CB), redirect_uri_provided_explicitly=True,
                                    resource=s.mail_resource_url), ttl=600)
    codes = [post_from(app, ip, {"req": pending(), "email": "boss@x.example", "password": "bad"}).status_code
             for ip in ("192.0.2.1", "192.0.2.2", "192.0.2.3", "198.51.100.1")]
    assert codes == [200, 200, 429, 200]        # one network locked out, another still allowed


def test_busy_mailbox_keeps_its_attempt(tmp_path):
    from mcp_server_imap_smtp.auth.login import MailboxBusy

    def busy(a, p, s):
        raise MailboxBusy("busy")
    app, pending, limits = login_env(tmp_path, busy)
    r = post_from(app, "192.0.2.1", {"req": pending(), "email": "me@x.example", "password": "x"})
    assert r.status_code == 503
    assert limits.window.count("addr:me@x.example") == 1 and limits.window.count("ip:192.0.2.1") == 0
