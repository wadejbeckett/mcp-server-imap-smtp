# SPDX-License-Identifier: AGPL-3.0-or-later
import html
import logging
import ssl
import threading
import time
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
from pydantic import AnyUrl
from starlette.applications import Starlette
from starlette.testclient import TestClient
from mcp.server.auth.provider import AuthorizationParams
from mcp.shared.auth import OAuthClientInformationFull
from mcp_server_imap_smtp.auth import login as login_mod
from mcp_server_imap_smtp.auth.login import MailUnavailable, imap_verifier, login_routes
from mcp_server_imap_smtp.auth.provider import GatewayProvider
from mcp_server_imap_smtp.config import Settings
from mcp_server_imap_smtp.mail.hosts import Connector, MailServer
from mcp_server_imap_smtp.mail.imap import MailAuthError, MailError
from mcp_server_imap_smtp.mail.resolve import ResolveUnavailable, Resolver
from mcp_server_imap_smtp.ratelimit import RateLimiter
from mcp_server_imap_smtp.store import Store
from tests._signin import connected, location

MAIL1 = MailServer("mail1.hosting.example", domains=("x.co.za",), match_mx=False)
RES = Resolver((MAIL1,))                     # x.co.za is hosted, every other domain is not; no DNS
GOOD = {"me@x.co.za": "pw", "accounts@x.co.za": "pw2"}
GENERIC = "Address or password incorrect"
DOWN = "The mail server could not be reached. Please try again in a minute."


def verifier(addr, pw, server):
    assert server is MAIL1
    return GOOD.get(addr) == pw


def make_env(tmp_path, verify=verifier, redirect="https://claude.ai/api/mcp/auth_callback", client_name=None, limit=3,
             resolver=RES, **settings_kw):
    s = Settings(issuer_url="http://127.0.0.1:8765", mail_resource_url="http://127.0.0.1:8765/mail",
                 mail_servers=resolver.servers, db_path=tmp_path / "s.sqlite", login_failures=limit,
                 operator_name="Acme Hosting", **settings_kw)
    store = Store(s.db_path); prov = GatewayProvider(s, store)
    req = store.create_pending("c1", AuthorizationParams(state="st", scopes=None, code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        redirect_uri=AnyUrl(redirect), redirect_uri_provided_explicitly=True,
        resource=s.mail_resource_url), ttl=600)
    if client_name:
        store.save_client(OAuthClientInformationFull(client_id="c1", client_name=client_name,
            redirect_uris=[AnyUrl(redirect)], token_endpoint_auth_method="none"))
    limiter = RateLimiter(limit, 900)
    app = Starlette(routes=login_routes(prov, resolver, verify, limiter, s))
    return TestClient(app, follow_redirects=False), req, store, limiter


@pytest.fixture
def env(tmp_path):
    c, req, store, _ = make_env(tmp_path)
    return c, req, store


def test_form_renders(env):
    c, req, _ = env
    r = c.get(f"/mail/login?req={req}")
    assert r.status_code == 200 and 'name="password"' in r.text and r.headers["x-frame-options"] == "DENY"


def test_unknown_request(env):
    c, _, _ = env
    assert c.get("/mail/login?req=nope").status_code == 400


def test_success_with_shared_mailbox(env):
    c, req, store = env
    r = c.post("/mail/login", data={"req": req, "email": "Me@X.co.za", "password": "pw", "more": "accounts@x.co.za pw2"})
    assert connected(r) and location(r).startswith("https://claude.ai/api/mcp/auth_callback?code=")
    assert store.list_grants()[0]["mailboxes"] == "me@x.co.za accounts@x.co.za"


def test_login_generic_error(env):
    c, req, _ = env
    for data, text in (({"email": "me@x.co.za", "password": "bad"}, "Address or password incorrect."),
                       ({"email": "not-an-address", "password": "x"}, "Address or password incorrect."),
                       ({"email": "me@x.co.za", "password": "pw", "more": "accounts@x.co.za bad"},
                        "Line 1 (accounts@x.co.za): address or password incorrect.")):
        r = c.post("/mail/login", data={"req": req, **data})
        assert r.status_code == 200 and text in r.text


def test_lockout(env):
    c, req, _ = env
    for _ in range(3):
        c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "bad"})
    r = c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "pw"})
    assert r.status_code == 429


def test_lockout_is_per_address_and_per_ip(tmp_path):
    c, req, _, lim = make_env(tmp_path)
    for _ in range(3):
        c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "bad"})
    assert lim.blocked("addr:me@x.co.za") and lim.blocked("ip:testclient")
    assert not lim.blocked("addr:accounts@x.co.za")


def test_success_resets_address_keys_only(tmp_path):
    c, req, _, lim = make_env(tmp_path)
    lim.fail("addr:me@x.co.za"); lim.fail("ip:testclient")
    r = c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "pw"})
    assert connected(r)
    assert lim.count("addr:me@x.co.za") == 0 and lim.count("ip:testclient") == 1


NO_PASSWORD = "Line 1: put the address, a space, then the password."
TOO_LONG = "Line 1: the address or password is too long."


@pytest.mark.parametrize("data,text", [
    ({"email": "", "password": "pw"}, GENERIC),
    ({"email": "me@x.co.za", "password": ""}, GENERIC),
    ({"email": "me@x.co.za", "password": "pw", "more": "accounts@x.co.za"}, NO_PASSWORD),   # address alone
    ({"email": "me@x.co.za", "password": "pw", "more": "  SeCrEt-pw2  "}, NO_PASSWORD),     # password alone
    ({"email": "m" * 250 + "@x.co.za", "password": "pw"}, GENERIC),                              # over 254
    ({"email": "me@x.co.za", "password": "p" * 1025}, GENERIC),
    ({"email": "me@x.co.za", "password": "pw", "more": "a" * 250 + "@x.co.za pw2"}, TOO_LONG),
    ({"email": "me@x.co.za", "password": "pw", "more": "accounts@x.co.za " + "p" * 1025}, TOO_LONG),
])
def test_input_validation_is_an_error_and_counts(tmp_path, data, text):
    calls = []
    def spy(addr, pw, server):
        calls.append(addr); return verifier(addr, pw, server)
    c, req, store, lim = make_env(tmp_path, spy)
    r = c.post("/mail/login", data={"req": req, **data})
    assert r.status_code == 200 and text in r.text and "SeCrEt" not in r.text
    assert calls == [] and store.list_grants() == []          # never reached the mail server, no grant made
    assert lim.count("ip:testclient") == 1                    # counted as a failure


def test_password_boundaries_are_accepted(tmp_path):
    ok = "p" * 1024
    c, req, _, _ = make_env(tmp_path, lambda a, p, server: p == ok)
    r = c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": ok})
    assert connected(r)


def test_rerendered_form_never_echoes_passwords(env):
    c, req, _ = env
    r = c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "SeCrEt-One-123",
                               "more": "accounts@x.co.za SeCrEt-Two-456\nsales@x.co.za SeCrEt-Three"})
    assert GENERIC in r.text and "SeCrEt" not in r.text
    assert 'value="me@x.co.za"' in r.text                   # the main address is kept for convenience
    assert "accounts@x.co.za" not in r.text and "></textarea>" in r.text    # the list, with its passwords, is not
    assert "paste the corrected list again" in r.text


def test_passwords_are_not_logged(env, caplog):
    c, req, _ = env
    with caplog.at_level(logging.DEBUG):
        c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "SeCrEt-One-123"})
    assert "SeCrEt" not in caplog.text


def test_mail_server_outage_is_503_and_never_counts(tmp_path):
    def down(addr, pw, server):
        raise MailUnavailable("down")
    live = {"verify": down}
    c, req, store, lim = make_env(tmp_path, lambda a, p, server: live["verify"](a, p, server))
    for _ in range(5):
        r = c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "SeCrEt-One-123"})
        assert r.status_code == 503 and DOWN in r.text and "SeCrEt" not in r.text
        assert r.headers["x-frame-options"] == "DENY"
    assert len(lim) == 0 and store.list_grants() == []           # nothing counted, nothing granted
    live["verify"] = verifier                                    # server is back: no lockout
    assert connected(c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "pw"}))


def test_outage_on_shared_mailbox_is_503_not_failure(tmp_path):
    def flaky(addr, pw, server):
        if addr == "accounts@x.co.za":
            raise MailUnavailable("down")
        return verifier(addr, pw, server)
    c, req, store, lim = make_env(tmp_path, flaky)
    r = c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "pw", "more": "accounts@x.co.za pw2"})
    assert r.status_code == 503 and len(lim) == 0 and store.list_grants() == []


def test_expired_request_on_post(env):
    c, _, _ = env
    assert c.post("/mail/login", data={"req": "nope", "email": "me@x.co.za", "password": "pw"}).status_code == 400


# imap_verifier mapping

class _Ctx:
    def __enter__(self): return self
    def __exit__(self, *a): return False


@pytest.mark.parametrize("effect,expected", [
    (None, True),
    (MailAuthError("no"), False),
])
def test_imap_verifier_results(monkeypatch, effect, expected):
    def fake_open(server, address, password):
        assert server is MAIL1
        if effect:
            raise effect
        return _Ctx()
    monkeypatch.setattr(login_mod.ImapClient, "open", staticmethod(fake_open))
    assert imap_verifier("a@x.co.za", "pw", MAIL1) is expected


@pytest.mark.parametrize("effect", [MailError("down"), ConnectionRefusedError(), TimeoutError(), ssl.SSLError("bad cert"),
                                    ssl.SSLCertVerificationError("bad cert")])
def test_imap_verifier_outage_raises_unavailable(monkeypatch, effect):
    def fake_open(server, address, password):
        raise effect
    monkeypatch.setattr(login_mod.ImapClient, "open", staticmethod(fake_open))
    with pytest.raises(MailUnavailable):
        imap_verifier("a@x.co.za", "pw", MAIL1)


# fix round 1

def csp(resp):
    return resp.headers["content-security-policy"]


def test_csp_allows_the_pending_redirect_origin(tmp_path):
    for redirect, origin in (("https://claude.ai/api/mcp/auth_callback", "https://claude.ai"),
                             ("http://127.0.0.1:53682/callback", "http://127.0.0.1:53682"),
                             ("https://chatgpt.com/connector/oauth/abc", "https://chatgpt.com")):
        c, req, _, _ = make_env(tmp_path / origin.split("//")[1].replace(":", "_"), redirect=redirect)
        g = c.get(f"/mail/login?req={req}")
        assert f"form-action 'self' {origin};" in csp(g) + ";" and "frame-ancestors 'none'" in csp(g)
        bad = c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "bad"})
        assert f"form-action 'self' {origin}" in csp(bad)
        ok = c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "pw"})
        assert connected(ok) and f"form-action 'self' {origin}" in csp(ok)
        assert ok.headers["cache-control"] == "no-store"


def test_csp_without_a_pending_request_is_self_only(env):
    c, _, _ = env
    r = c.get("/mail/login?req=nope")
    assert "form-action 'self';" in csp(r) + ";" and "claude.ai" not in csp(r)


def test_forged_x_forwarded_for_is_ignored(tmp_path):
    c, req, _, lim = make_env(tmp_path)
    c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "bad"},
           headers={"X-Forwarded-For": "6.6.6.6, 7.7.7.7", "Forwarded": "for=8.8.8.8"})
    assert lim.count("ip:testclient") == 1
    assert lim.count("ip:6.6.6.6") == 0 and lim.count("ip:7.7.7.7") == 0 and lim.count("ip:8.8.8.8") == 0


def test_parallel_wrong_passwords_cannot_outrun_the_lockout(tmp_path):
    release, entered, lock = threading.Event(), [], threading.Lock()
    def slow(addr, pw, server):
        with lock:
            entered.append(addr)
        release.wait(5)
        return False
    c, req, _, lim = make_env(tmp_path, slow, limit=5)
    results = []
    def go():
        results.append(c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "bad"}).status_code)
    ts = [threading.Thread(target=go) for _ in range(10)]
    [t.start() for t in ts]
    deadline = time.time() + 5
    while time.time() < deadline and (len(entered) < 5 or results.count(429) < 5):
        time.sleep(0.01)
    release.set()
    [t.join() for t in ts]
    assert len(entered) == 5 and results.count(429) == 5 and results.count(200) == 5


def test_success_refunds_the_ip_hit(tmp_path):
    c, req, _, lim = make_env(tmp_path)
    assert connected(c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "pw"}))
    assert lim.count("ip:testclient") == 0 and lim.count("addr:me@x.co.za") == 0


def test_wrong_credentials_keep_the_hits_and_outage_refunds_them(tmp_path):
    live = {"v": lambda a, p, server: False}
    def outage(a, p, server): raise MailUnavailable("x")
    c, req, _, lim = make_env(tmp_path, lambda a, p, server: live["v"](a, p, server))
    c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "bad"})
    assert lim.count("ip:testclient") == 1 and lim.count("addr:me@x.co.za") == 1
    live["v"] = outage
    assert c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "bad"}).status_code == 503
    assert lim.count("ip:testclient") == 1 and lim.count("addr:me@x.co.za") == 1   # the outage hit was given back


HOSTILE = '"><script>alert(1)</script>'


def test_hostile_values_are_escaped(tmp_path):
    c, req, _, _ = make_env(tmp_path, client_name=f"Evil {HOSTILE}")
    pages = [c.get(f"/mail/login?req={req}"),
             c.post("/mail/login", data={"req": req, "email": f"a{HOSTILE}@x.co.za", "password": "bad",
                                    "more": f"b{HOSTILE}@x.co.za x"})]
    for r in pages:
        assert "<script>" not in r.text and "&lt;script&gt;" in r.text
    assert 'value="a&quot;&gt;' in pages[1].text and "b&quot;" not in pages[1].text    # the list is never echoed


def test_an_address_named_in_an_error_is_escaped(tmp_path):
    odd = "o'b&c@x.co.za"                     # valid: ' and & are allowed in the local part
    c, req, _, _ = make_env(tmp_path, lambda a, p, server: a != odd)
    r = c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "pw", "more": f"{odd} bad"})
    assert "Line 1 (o&#x27;b&amp;c@x.co.za): address or password incorrect." in r.text


def test_security_headers_on_every_response(tmp_path):
    def down(a, p, server): raise MailUnavailable("x")
    c, req, _, _ = make_env(tmp_path, down, limit=2)
    c2, req2, _, _ = make_env(tmp_path / "b", limit=2)
    responses = [c.get(f"/mail/login?req={req}"), c.get("/mail/login?req=nope"),
                 c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "pw"})]          # 200, 400, 503
    for _ in range(2):
        c2.post("/mail/login", data={"req": req2, "email": "me@x.co.za", "password": "bad"})
    blocked = c2.post("/mail/login", data={"req": req2, "email": "me@x.co.za", "password": "bad"})               # 429
    responses.append(blocked)
    assert [r.status_code for r in responses] == [200, 400, 503, 429]
    for r in responses:
        assert r.headers["x-frame-options"] == "DENY" and r.headers["cache-control"] == "no-store"
        assert r.headers["referrer-policy"] == "same-origin"
        assert "default-src 'none'" in csp(r) and "frame-ancestors 'none'" in csp(r) and "form-action 'self'" in csp(r)
    assert blocked.headers["retry-after"] == "900"


def test_mail_server_bye_greeting_is_503_and_refunds_the_reservation(tmp_path, monkeypatch):
    """The real imap_verifier and ImapClient.open over a socketpair whose server greets with * BYE."""
    from tests.test_imap_parsing import ScriptedServer, logout_ok
    servers = []

    def connect(self, port, timeout=10.0):
        servers.append(ScriptedServer(logout_ok, greeting=b"* BYE Too many connections\r\n"))
        return servers[-1].client
    monkeypatch.setattr(Connector, "tls_connect", connect)
    c, req, store, lim = make_env(tmp_path, imap_verifier)
    try:
        r = c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "pw"})
    finally:
        for s in servers:
            s.close()
    assert r.status_code == 503 and DOWN in r.text
    assert len(lim) == 0 and store.list_grants() == [] and len(servers) == 1


def test_login_page_names_a_cimd_client_from_its_metadata_document(tmp_path):
    import httpx
    cimd_id, cb = "https://chatgpt.com/oauth/client.json", "https://chatgpt.com/connector_platform_oauth_redirect"
    s = Settings(issuer_url="http://127.0.0.1:8765", mail_resource_url="http://127.0.0.1:8765/mail",
                 mail_servers=(MAIL1,), db_path=tmp_path / "s.sqlite")
    doc = {"client_id": cimd_id, "client_name": "ChatGPT", "redirect_uris": [cb], "token_endpoint_auth_method": "none"}
    http = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=doc)))
    store = Store(s.db_path)
    prov = GatewayProvider(s, store, cimd_http=http)
    req = store.create_pending(cimd_id, AuthorizationParams(state="st", scopes=None, code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        redirect_uri=AnyUrl(cb), redirect_uri_provided_explicitly=True, resource=s.mail_resource_url), ttl=600)
    c = TestClient(Starlette(routes=login_routes(prov, RES, verifier, RateLimiter(3, 900), s)), follow_redirects=False)
    page = c.get(f"/mail/login?req={req}")
    assert page.status_code == 200 and "ChatGPT (name supplied by the app) is asking" in page.text
    again = c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "wrong"})
    assert "ChatGPT (name supplied by the app) is asking" in again.text


def test_login_page_names_a_registered_client(tmp_path):
    c, req, _, _ = make_env(tmp_path, client_name="Claude Code")
    assert "Claude Code (name supplied by the app) is asking" in c.get(f"/mail/login?req={req}").text


# several mailboxes and address resolution (generic phase 1, T3; the pasted list, 20 October)

ISP = MailServer("mail.client.example", domains=("client.example",), match_mx=False)
TWO = Resolver((MAIL1, ISP))


def boxes(n, domain="x.co.za"):
    """Form fields for mailboxes 1..n: box1 as the main pair, box2..n in the list one per line, pw{i} each."""
    return {"email": f"box1@{domain}", "password": "pw1",
            "more": "\n".join(f"box{i}@{domain} pw{i}" for i in range(2, n + 1))}


def accept_all(seen):
    def verify(addr, pw, server):
        seen.append((addr, pw, server.host)); return True
    return verify


def test_eighty_eight_mailboxes_on_two_servers_make_one_grant(tmp_path):
    """The first real case: 84 mailboxes on client.example and 4 on shop.example in one sign-in."""
    shop = MailServer("mail1.hosting.example", domains=("shop.example",), match_mx=False)
    lookups = []

    class Spy(Resolver):
        def resolve(self, address):
            lookups.append(address)
            return super().resolve(address)
    seen = []
    c, req, store, lim = make_env(tmp_path, accept_all(seen), resolver=Spy((shop, ISP)))
    staff = [f"staff{i}@client.example" for i in range(2, 85)] + [f"p{i}@shop.example" for i in range(1, 5)]
    more = "\n".join(f"{a}\tpw-{a}" for a in staff)          # pasted from a spreadsheet: tab separated
    r = c.post("/mail/login", data={"req": req, "email": "owner@client.example", "password": "pw-owner", "more": more})
    assert connected(r)
    (grant,) = store.list_grants()
    assert grant["mailboxes"].split() == ["owner@client.example", *staff]          # the form's order
    assert len(seen) == 88 and seen[0] == ("owner@client.example", "pw-owner", "mail.client.example")
    assert {(a, p) for a, p, _ in seen[1:]} == {(a, f"pw-{a}") for a in staff}
    assert {h for a, _, h in seen if a.endswith("@shop.example")} == {"mail1.hosting.example"}
    assert len(lookups) == 2                                # one resolution per domain, not per mailbox
    assert len(lim) == 0                                    # every reservation given back or reset
    code = parse_qs(urlsplit(location(r)).query)["code"][0]
    sealed = store.open_mailboxes(grant["id"], store.consume_code(code))
    assert len(sealed) == 88 and sealed["p4@shop.example"].password == "pw-p4@shop.example"


def test_no_mailbox_limit_by_default(tmp_path):
    assert Settings(issuer_url="http://i", mail_resource_url="http://i/mail", mail_servers=(MAIL1,),
                    db_path=tmp_path).max_mailboxes == 0
    seen = []
    c, req, store, _ = make_env(tmp_path, accept_all(seen))
    assert "Up to" not in c.get(f"/mail/login?req={req}").text
    assert connected(c.post("/mail/login", data={"req": req, **boxes(250)}))
    assert len(store.list_grants()[0]["mailboxes"].split()) == 250 and len(seen) == 250


def test_max_mailboxes_when_the_operator_sets_one(tmp_path):
    calls = []
    c, req, store, lim = make_env(tmp_path, accept_all(calls), max_mailboxes=3)
    assert "Up to 2 more." in c.get(f"/mail/login?req={req}").text
    r = c.post("/mail/login", data={"req": req, **boxes(4)})
    assert r.status_code == 200 and "At most 3 mailboxes can be connected at once; this form has 4." in r.text
    assert calls == [] and store.list_grants() == [] and lim.count("ip:testclient") == 1
    assert connected(c.post("/mail/login", data={"req": req, **boxes(3)}))


def test_form_offers_a_list_for_more_mailboxes(env):
    c, req, _ = env
    text = c.get(f"/mail/login?req={req}").text
    assert "<h2>Several mailboxes</h2>" in text and "<details" not in text     # always shown, never folded away
    assert '<textarea id="more" name="more"' in text and "the address, a space, then that mailbox's password" in text
    assert "leave the two fields above empty" in text and "signing in again replaces the earlier list" in text
    assert " required" not in text          # the two fields may be empty when the list is used
    # Browsers must not offer the list to a spelling service or remember it.
    assert 'spellcheck="false"' in text and 'autocomplete="off"' in text and "email_2" not in text


def test_rerendered_form_never_shows_the_list_again(env):
    c, req, _ = env
    r = c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "bad", "more": "accounts@x.co.za pw2"})
    assert "></textarea>" in r.text and "pw2" not in r.text


def test_list_lines_take_blank_lines_tabs_and_spaces_inside_passwords(tmp_path):
    seen = []
    c, req, store, _ = make_env(tmp_path, accept_all(seen))
    more = "\r\n\r\n  Accounts@X.co.za\t  pw2  \r\n\n sales@x.co.za   my secret  pass \n\n"
    r = c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "pw", "more": more})
    assert connected(r) and store.list_grants()[0]["mailboxes"] == "me@x.co.za accounts@x.co.za sales@x.co.za"
    assert {(a, p) for a, p, _ in seen} == {("me@x.co.za", "pw"), ("accounts@x.co.za", "pw2"),
                                            ("sales@x.co.za", "my secret  pass")}


def test_a_wrong_password_names_its_line_and_address_and_nothing_is_connected(tmp_path):
    c, req, store, lim = make_env(tmp_path, lambda a, p, server: a != "box13@x.co.za", limit=50)
    lines = [f"box{i}@x.co.za pw{i}" for i in range(2, 12)] + [""] + [f"box{i}@x.co.za pw{i}" for i in range(13, 21)]
    r = c.post("/mail/login", data={"req": req, "email": "box1@x.co.za", "password": "pw1", "more": "\n".join(lines)})
    assert r.status_code == 200 and "Line 12 (box13@x.co.za): address or password incorrect." in r.text
    assert "paste the corrected list again" in r.text and "pw13" not in r.text and "pw2" not in r.text
    assert store.list_grants() == []
    assert lim.count("addr:box13@x.co.za") == 1 and lim.count("ip:testclient") == 1
    assert all(lim.count(f"addr:box{i}@x.co.za") == 0 for i in (1, 2, 12, 14, 20))   # the right ones get theirs back


def test_the_main_mailbox_is_checked_alone_first(tmp_path):
    calls = []
    def verify(a, p, server):
        calls.append(a); return False
    c, req, _, _ = make_env(tmp_path, verify, limit=50)
    r = c.post("/mail/login", data={"req": req, **boxes(88)})
    assert calls == ["box1@x.co.za"] and GENERIC in r.text


def test_a_wrong_listed_password_stops_further_checks(tmp_path):
    calls = []
    def verify(a, p, server):
        calls.append(a); return a != "box5@x.co.za"
    c, req, store, _ = make_env(tmp_path, verify, limit=50)
    r = c.post("/mail/login", data={"req": req, **boxes(88)})
    assert "Line 4 (box5@x.co.za): address or password incorrect." in r.text and store.list_grants() == []
    # The main mailbox, the four lines up to the wrong one, and at most one round already under way.
    assert len(calls) <= 1 + 4 + login_mod.VERIFY_WORKERS


def test_listed_passwords_are_checked_a_few_at_a_time(tmp_path, monkeypatch):
    monkeypatch.setattr(login_mod, "VERIFY_WORKERS", 3)
    lock, state = threading.Lock(), {"now": 0, "max": 0}
    def slow(a, p, server):
        with lock:
            state["now"] += 1; state["max"] = max(state["max"], state["now"])
        time.sleep(0.02)
        with lock:
            state["now"] -= 1
        return True
    c, req, _, _ = make_env(tmp_path, slow)
    assert connected(c.post("/mail/login", data={"req": req, **boxes(20)}))
    assert state["max"] == 3


def test_the_time_budget_stops_the_checks_and_gives_every_attempt_back(tmp_path, monkeypatch):
    monkeypatch.setattr(login_mod, "VERIFY_BUDGET_BASE", 0.3)
    monkeypatch.setattr(login_mod, "VERIFY_BUDGET_PER_MAILBOX", 0.0)
    calls = []
    def slow(a, p, server):
        calls.append(a); time.sleep(0.1); return True
    c, req, store, lim = make_env(tmp_path, slow, limit=50)
    r = c.post("/mail/login", data={"req": req, **boxes(88)})
    assert r.status_code == 503 and login_mod.TOO_SLOW in r.text
    assert 1 < len(calls) < 88 and store.list_grants() == [] and len(lim) == 0


def test_the_time_budget_covers_dns(tmp_path, monkeypatch):
    monkeypatch.setattr(login_mod, "VERIFY_BUDGET_BASE", 0.0)
    monkeypatch.setattr(login_mod, "VERIFY_BUDGET_PER_MAILBOX", 0.0)
    calls = []
    c, req, store, lim = make_env(tmp_path, accept_all(calls))
    r = c.post("/mail/login", data={"req": req, **boxes(3)})
    assert r.status_code == 503 and login_mod.TOO_SLOW in r.text and calls == []
    assert lim.count("ip:testclient") == 1 and len(lim) == 1      # like a DNS failure: the client's attempt stands


def test_limiter_keys_stay_bounded_when_every_listed_password_is_wrong(tmp_path):
    keys = []
    c, req, _, lim = make_env(tmp_path, lambda a, p, server: a == "box1@x.co.za", limit=50,
                              request_login_failures=1000)
    real = lim.try_acquire
    lim.try_acquire = lambda ks: (keys.append(list(ks)), real(ks))[1]
    r = c.post("/mail/login", data={"req": req, **boxes(200)})
    tried = [k for ks in keys for k in ks]
    assert tried[:2] == ["ip:testclient", "addr:box1@x.co.za"] and "address or password incorrect" in r.text
    wrong = len(tried) - 2
    assert 1 <= wrong <= login_mod.VERIFY_WORKERS            # one round of the list at most, never all 199
    assert lim.count("ip:testclient") == wrong               # each wrong password counts against the client
    assert len(lim) == 1 + wrong                             # the main mailbox's reservation was given back


def test_a_locked_listed_mailbox_is_named_and_the_client_is_not_charged(tmp_path):
    calls = []
    c, req, _, lim = make_env(tmp_path, accept_all(calls))
    for _ in range(3):
        lim.hit("addr:box3@x.co.za")
    r = c.post("/mail/login", data={"req": req, **boxes(5)})
    assert r.status_code == 429 and "Too many failed sign-ins for box3@x.co.za (line 2)" in r.text
    assert calls == [] and lim.count("ip:testclient") == 0


def test_an_oversized_form_is_refused_whether_or_not_its_size_is_declared(tmp_path, monkeypatch):
    monkeypatch.setattr(login_mod, "MAX_FORM_BYTES", 1000)
    calls = []
    c, req, store, lim = make_env(tmp_path, accept_all(calls))
    r = c.post("/mail/login", data={"req": req, **boxes(100)})
    assert r.status_code == 413 and r.headers["x-frame-options"] == "DENY"
    body = urlencode({"req": req, **boxes(100)}).encode()
    chunked = c.post("/mail/login", content=iter([body[:600], body[600:]]),
                     headers={"content-type": "application/x-www-form-urlencoded"})
    assert chunked.status_code == 413
    assert calls == [] and store.list_grants() == [] and len(lim) == 0
    assert connected(c.post("/mail/login", data={"req": req, **boxes(3)}))      # a small form still works


@pytest.mark.parametrize("dup", ["ME@x.co.za", "  me@x.co.za"])
def test_duplicate_mailbox_with_another_password_is_refused_before_any_check(tmp_path, dup):
    calls = []
    c, req, store, lim = make_env(tmp_path, accept_all(calls))
    r = c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "pw",
                               "more": f"accounts@x.co.za pw2\n{dup} other"})
    assert r.status_code == 200
    assert ("Line 2 (me@x.co.za): this mailbox is already listed with another password. "
            "A mailbox is listed twice with different passwords; keep the right one.") in r.text
    assert calls == [] and store.list_grants() == [] and lim.count("ip:testclient") == 1


@pytest.mark.parametrize("dup", ["ME@x.co.za", "  me@x.co.za"])
def test_duplicate_mailbox_with_the_same_password_is_dropped(tmp_path, dup):
    calls = []
    c, req, store, _ = make_env(tmp_path, accept_all(calls))
    r = c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "pw",
                               "more": f"{dup} pw\naccounts@x.co.za pw2\naccounts@x.co.za pw2\n"})
    assert connected(r) and "2 mailboxes connected" in r.text
    assert store.list_grants()[0]["mailboxes"] == "me@x.co.za accounts@x.co.za"
    assert len(calls) == 2                  # each password checked once


def test_list_alone_signs_in_with_its_first_line_as_the_main_mailbox(tmp_path):
    calls = []
    c, req, store, _ = make_env(tmp_path, accept_all(calls))
    more = "\n".join(f"staff{i}@x.co.za pw{i}" for i in range(1, 88))
    r = c.post("/mail/login", data={"req": req, "email": "", "password": "", "more": "\n" + more + "\n\n"})
    assert connected(r) and "87 mailboxes connected" in r.text and "starting with staff1@x.co.za" in r.text
    grant = store.list_grants()[0]
    assert grant["subject"] == "staff1@x.co.za" and len(grant["mailboxes"].split()) == 87


@pytest.mark.parametrize("email,password", [("me@x.co.za", ""), ("", "pw")])
def test_half_filled_fields_are_refused_even_with_a_list(tmp_path, email, password):
    calls = []
    c, req, store, _ = make_env(tmp_path, accept_all(calls))
    r = c.post("/mail/login", data={"req": req, "email": email, "password": password, "more": "accounts@x.co.za pw2"})
    assert "Address or password incorrect." in r.text and calls == [] and store.list_grants() == []


def test_bad_list_line_is_named_when_the_fields_are_empty(env):
    c, req, _ = env
    r = c.post("/mail/login", data={"req": req, "email": "", "password": "", "more": "a@x.co.za pw\nnospace"})
    assert "Line 2: put the address, a space, then the password." in r.text and GENERIC not in r.text


def test_empty_form_is_refused(env):
    c, req, store = env
    r = c.post("/mail/login", data={"req": req, "email": "", "password": "", "more": "\n \n"})
    assert "Address or password incorrect." in r.text and store.list_grants() == []


def test_connected_page_counts_mailboxes_and_continues_to_the_app(env):
    c, req, _ = env
    r = c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "pw"})
    assert "1 mailbox connected" in r.text and "An AI app can now use 1 mailbox: me@x.co.za." in r.text
    url = location(r)
    assert url.startswith("https://claude.ai/api/mcp/auth_callback?code=") and "&state=st" in url
    assert f'content="2;url={html.escape(url)}"' in r.text       # moves on by itself
    assert "http://127.0.0.1:8765/mail/manage" in r.text


def test_idna_duplicate_is_refused(tmp_path):
    calls = []
    resolver = Resolver((MailServer("mail1.hosting.example", domains=("*",), match_mx=False),))
    c, req, store, _ = make_env(tmp_path, accept_all(calls), resolver=resolver)
    r = c.post("/mail/login", data={"req": req, "email": "me@bücher.co.za", "password": "pw",
                               "more": "me@xn--bcher-kva.co.za pw"})
    assert connected(r) and "1 mailbox connected" in r.text and len(calls) == 1     # the same mailbox twice


def test_unserved_domain_shows_the_operator_message_and_costs_the_ip_only(tmp_path):
    calls = []
    c, req, store, lim = make_env(tmp_path, accept_all(calls))
    r = c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "pw", "more": "someone@gmail.com SeCrEt"})
    assert r.status_code == 200 and "Line 1: Mail for gmail.com is not hosted by Acme Hosting." in r.text
    assert "SeCrEt" not in r.text
    assert calls == [] and store.list_grants() == []         # no password tried, not even the hosted one's
    assert lim.count("ip:testclient") == 1
    assert lim.count("addr:me@x.co.za") == 0 and lim.count("addr:someone@gmail.com") == 0


def test_operator_name_defaults_to_a_neutral_phrase(tmp_path):
    s = Settings(issuer_url="http://i", mail_resource_url="http://i/mail", mail_servers=(MAIL1,), db_path=tmp_path)
    assert s.operator_name == "the operator"


def test_each_mailbox_is_checked_and_sealed_on_its_own_server(tmp_path):
    seen = []
    c, req, store, _ = make_env(tmp_path, accept_all(seen), resolver=TWO)
    r = c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "pw", "more": "ops@client.example pw2"})
    assert connected(r)
    assert seen == [("me@x.co.za", "pw", "mail1.hosting.example"), ("ops@client.example", "pw2", "mail.client.example")]
    code = parse_qs(urlsplit(location(r)).query)["code"][0]
    (grant,) = store.list_grants()
    sealed = store.open_mailboxes(grant["id"], store.consume_code(code))
    assert {a: (c.password, c.server.host) for a, c in sealed.items()} == {
        "me@x.co.za": ("pw", "mail1.hosting.example"), "ops@client.example": ("pw2", "mail.client.example")}


def test_dns_outage_is_503_and_refunds_the_address_keys_only(tmp_path):
    def down(domain):
        raise ResolveUnavailable("timeout")
    calls = []
    c, req, store, lim = make_env(tmp_path, accept_all(calls), resolver=Resolver((MailServer("mail1.hosting.example"),),
                                                                                    mx_lookup=down))
    r = c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "SeCrEt"})
    assert r.status_code == 503 and DOWN in r.text and "SeCrEt" not in r.text
    assert calls == [] and store.list_grants() == []
    assert lim.count("ip:testclient") == 1 and lim.count("addr:me@x.co.za") == 0


def test_dns_failure_is_remembered_so_repeated_sign_ins_fail_fast(tmp_path):
    lookups = []
    def down(domain):
        lookups.append(domain); raise ResolveUnavailable("timeout")
    c, req, _, _ = make_env(tmp_path, accept_all([]), limit=50,
                            resolver=Resolver((MailServer("mail1.hosting.example"),), mx_lookup=down))
    for _ in range(4):
        assert c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "pw"}).status_code == 503
    assert lookups == ["x.co.za"]


def test_sign_in_dns_runs_in_a_private_bounded_thread_pool(tmp_path, monkeypatch):
    monkeypatch.setattr(login_mod, "DNS_WORKERS", 2)
    lock, release, state = threading.Lock(), threading.Event(), {"now": 0, "max": 0, "entered": 0}
    def slow_mx(domain):
        with lock:
            state["now"] += 1; state["entered"] += 1; state["max"] = max(state["max"], state["now"])
        release.wait(5)
        with lock:
            state["now"] -= 1
        return ["mail1.hosting.example."]
    neo_mx = MailServer("mail1.hosting.example")
    resolver = Resolver((neo_mx,), mx_lookup=slow_mx, ttl=0)
    c, req, _, _ = make_env(tmp_path, accept_all([]), limit=50, resolver=resolver)
    results = []
    def go(n):
        results.append(c.post("/mail/login", data={"req": req, "email": f"u{n}@d{n}.co.za", "password": "pw"}).status_code)
    with c:                                          # one event loop for every request, as in production
        ts = [threading.Thread(target=go, args=(n,)) for n in range(6)]
        [t.start() for t in ts]
        deadline = time.time() + 5
        while time.time() < deadline and state["entered"] < 2:
            time.sleep(0.01)
        time.sleep(0.2)
        assert state["max"] == 2 and state["entered"] == 2     # the other four wait for a DNS worker
        release.set()
        [t.join(10) for t in ts]
    assert state["max"] == 2 and state["entered"] == 6 and len(results) == 6


def test_mx_resolution_picks_the_server(tmp_path):
    seen = []
    neo_mx = MailServer("mail1.hosting.example")
    resolver = Resolver((neo_mx,), mx_lookup=lambda d: ["mx1.mail1.hosting.example."] if d == "client.co.za" else [])
    c, req, _, _ = make_env(tmp_path, accept_all(seen), resolver=resolver)
    assert connected(c.post("/mail/login", data={"req": req, "email": "me@client.co.za", "password": "pw"}))
    assert seen == [("me@client.co.za", "pw", "mail1.hosting.example")]


def test_a_wrong_main_password_reserves_no_listed_mailbox(tmp_path):
    keys = []
    c, req, _, lim = make_env(tmp_path, lambda a, p, server: False, limit=50)
    real = lim.try_acquire
    lim.try_acquire = lambda ks: (keys.append(list(ks)), real(ks))[1]
    c.post("/mail/login", data={"req": req, **boxes(200)})
    # The client's key first, then each mailbox only as its password is tried: the main one is wrong, so
    # none of the 199 listed is ever reserved.
    assert keys == [["ip:testclient"], ["addr:box1@x.co.za"]]
    assert len(lim) == 2


@pytest.mark.parametrize("variant", ["bob@x。co。za", "bob@ｘ.co.za", "BOB@X.CO.ZA", "bob@x.co.za.", "bob@x．co．za"])
def test_address_variants_share_one_limiter_key(tmp_path, variant):
    keys = []
    c, req, _, lim = make_env(tmp_path, lambda a, p, server: False, limit=50)
    real = lim.try_acquire
    lim.try_acquire = lambda ks: (keys.append(list(ks)), real(ks))[1]
    c.post("/mail/login", data={"req": req, "email": variant, "password": "bad"})
    assert keys == [["ip:testclient"], ["addr:bob@x.co.za"]]
    assert lim.count("addr:bob@x.co.za") == 1


def test_variants_cannot_bypass_the_address_lockout(tmp_path):
    calls = []
    def spy(a, p, server):
        calls.append(a); return False
    c, req, _, lim = make_env(tmp_path, spy, limit=3)
    for v in ("bob@x.co.za", "bob@x。co。za", "bob@ｘ.co.za"):
        lim.reset("ip:testclient")
        assert c.post("/mail/login", data={"req": req, "email": v, "password": "bad"}).status_code == 200
    lim.reset("ip:testclient")
    assert c.post("/mail/login", data={"req": req, "email": "BOB@x.co.za.", "password": "bad"}).status_code == 429
    assert calls == ["bob@x.co.za"] * 3


@pytest.mark.parametrize("bad", ["not-an-address", "a@b", "a b@x.co.za", "me@x.co.za\u0000"])
def test_malformed_input_counts_against_the_ip_only(tmp_path, bad):
    keys = []
    c, req, _, lim = make_env(tmp_path, accept_all([]), limit=50)
    real = lim.try_acquire
    lim.try_acquire = lambda ks: (keys.append(list(ks)), real(ks))[1]
    r = c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "pw", "more": f"ok@x.co.za pw\n{bad} x"})
    assert "Line 2: the first part is not an email address." in r.text
    assert keys == [["ip:testclient"]] and len(lim) == 1


def test_page_copy_comes_from_settings_and_is_escaped(tmp_path):
    c, req, _, _ = make_env(tmp_path)
    text = c.get(f"/mail/login?req={req}").text
    assert "<title>Connect your mailbox · Mail Connector</title>" in text
    assert "your email hosted by Acme Hosting." in text and "Need help?" not in text
    s = Settings(issuer_url="http://127.0.0.1:8765", mail_resource_url="http://127.0.0.1:8765/mail",
                 mail_servers=(MAIL1,), db_path=tmp_path / "t.sqlite", operator_name="A&B <Hosting>",
                 product_name="AB Mail", support_url="https://ab.example/help?a=1&b=2", support_email="help@ab.example")
    store = Store(s.db_path)
    req2 = store.create_pending("c1", AuthorizationParams(state="st", scopes=None, code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        redirect_uri=AnyUrl("https://claude.ai/api/mcp/auth_callback"), redirect_uri_provided_explicitly=True,
        resource=s.mail_resource_url), ttl=600)
    c2 = TestClient(Starlette(routes=login_routes(GatewayProvider(s, store), RES, verifier, RateLimiter(3, 900), s)))
    text = c2.get(f"/mail/login?req={req2}").text
    assert "hosted by A&amp;B &lt;Hosting&gt;." in text and "<title>Connect your mailbox · AB Mail</title>" in text
    assert '<a href="https://ab.example/help?a=1&amp;b=2">' in text and '<a href="mailto:help@ab.example">' in text
    r = c2.post("/mail/login", data={"req": req2, "email": "me@gmail.com", "password": "x"})
    assert "Mail for gmail.com is not hosted by A&amp;B &lt;Hosting&gt;." in r.text


def test_pages_live_under_the_service_path_and_old_paths_redirect(env):
    c, req, _ = env
    r = c.get(f"/login?req={req}")
    assert r.status_code == 308 and r.headers["location"] == f"/mail/login?req={req}"
    r = c.post("/login", data={"req": req, "email": "me@x.co.za", "password": "pw"})
    assert r.status_code == 308 and r.headers["location"] == "/mail/login"     # a POST stays a POST
    r = c.get("/manage")
    assert r.status_code == 308 and r.headers["location"] == "/mail/manage"
    assert r.headers["x-frame-options"] == "DENY"
    assert c.get("/mail/manage").status_code == 200


def test_service_at_the_site_root_has_no_redirects(tmp_path):
    s = Settings(issuer_url="http://127.0.0.1:8765", mail_resource_url="http://127.0.0.1:8765/",
                 mail_servers=RES.servers, db_path=tmp_path / "s.sqlite")
    paths = sorted({r.path for r in login_routes(GatewayProvider(s, Store(s.db_path)), RES, verifier,
                                                RateLimiter(5, 900), s)})
    assert paths == ["/login", "/manage"] and s.service_url == "http://127.0.0.1:8765"


def test_an_untrusted_mail_server_certificate_is_logged(caplog, monkeypatch):
    err = ssl.SSLCertVerificationError(1, "certificate verify failed")
    err.verify_message = "unable to get local issuer certificate"

    def boom(*a, **k):
        raise err
    monkeypatch.setattr(login_mod.ImapClient, "open", classmethod(lambda cls, *a, **k: boom()))
    caplog.set_level("WARNING")
    with pytest.raises(MailUnavailable):
        imap_verifier("me@x.co.za", "s3cret-pw", MAIL1)
    assert "could not reach mail1.hosting.example: unable to get local issuer certificate" in caplog.text
    assert "s3cret-pw" not in caplog.text and "me@x.co.za" not in caplog.text


@pytest.mark.parametrize("seconds, text", [(900, "15 minutes"), (60, "1 minute"), (3600, "1 hour"),
                                           (7200, "2 hours"), (90, "2 minutes"), (45, "45 seconds"), (1, "1 second"),
                                           (86399, "24 hours"), (5400, "90 minutes"), (0, "1 second")])
def test_wait_text(seconds, text):
    from mcp_server_imap_smtp.auth.login import wait_text
    assert wait_text(seconds) == text


def test_lockout_text_follows_login_window(tmp_path):
    c, req, _, _ = make_env(tmp_path, login_window=3600)
    for _ in range(3):
        c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "bad"})
    r = c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "pw"})
    assert r.status_code == 429 and "Try again in 1 hour." in r.text and "15 minutes" not in r.text


def test_daily_lockout_names_the_daily_wait(tmp_path):
    """login_daily_failures is a 24-hour sliding window: the text and Retry-After say so, not 15 minutes."""
    c, req, _, _ = make_env(tmp_path, limit=100, login_daily_failures=3, request_login_failures=100)
    for _ in range(3):
        c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "bad"})
    r = c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "pw"})
    assert r.status_code == 429
    assert "Try again in 24 hours." in r.text and 86000 < int(r.headers["retry-after"]) <= 86400


def test_manage_page_network_block_names_the_page_window(tmp_path):
    c, _, _, _ = make_env(tmp_path, limit=1000, request_login_failures=2)
    for i in range(2):
        c.post("/mail/manage", data={"action": "signin", "email": f"u{i}@x.co.za", "password": "bad"})
    r = c.post("/mail/manage", data={"action": "signin", "email": "z@x.co.za", "password": "bad"})
    assert r.status_code == 429
    assert "Try again in 5 minutes." in r.text and 0 < int(r.headers["retry-after"]) <= 300


def test_retry_after_counts_down_the_sliding_window(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    lim = RateLimiter(2, 900)
    lim.hit("k"); clock[0] += 100; lim.hit("k")
    assert lim.retry_after("k") == 800        # the first hit ages out 900 s after it was made
    clock[0] += 750                           # the first hit is 850 s old: 50 s to go
    assert lim.retry_after("k") == 50 and lim.retry_after("other") == 0
    clock[0] += 51
    assert lim.retry_after("k") == 0 and not lim.blocked("k")


def test_retry_after_with_a_zero_limit(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    lim = RateLimiter(0, 900)
    assert lim.retry_after("k") == 0
    lim.hit("k")
    assert lim.retry_after("k") == 900
