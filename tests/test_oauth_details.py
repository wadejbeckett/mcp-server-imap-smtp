# SPDX-License-Identifier: AGPL-3.0-or-later
"""Security review 2026-10-20, finding 18 (OAuth sub-report L1, L2, L3, L5, L6, L7)."""
import time
from dataclasses import replace
from urllib.parse import parse_qs, urlsplit

import pytest
from mcp.server.auth.provider import AuthorizationParams, AuthorizeError
from mcp.shared.auth import OAuthClientInformationFull
from pydantic import AnyHttpUrl, AnyUrl
from starlette.testclient import TestClient

from mcp_server_imap_smtp import ratelimit
from mcp_server_imap_smtp.app import build_app
from mcp_server_imap_smtp.auth.provider import GatewayProvider
from mcp_server_imap_smtp.config import Settings, redirect_allowed
from mcp_server_imap_smtp.mail.hosts import MailServer
from mcp_server_imap_smtp.ratelimit import RateLimiter
from mcp_server_imap_smtp.store import Store

MAIL1 = MailServer("mail1.hosting.example")
RES = "http://127.0.0.1:8765/mail"
CB = "https://claude.ai/api/mcp/auth_callback"
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"     # RFC 7636 appendix B


@pytest.fixture
def anyio_backend():
    return "asyncio"


def settings(tmp_path, **kw):
    return Settings(issuer_url="http://127.0.0.1:8765", mail_resource_url=RES, mail_servers=(MAIL1,),
                    db_path=tmp_path / "s.sqlite", **kw)


def params(challenge=CHALLENGE, redirect=CB):
    return AuthorizationParams(state="st", scopes=None, code_challenge=challenge, redirect_uri=AnyUrl(redirect),
                               redirect_uri_provided_explicitly=True, resource=RES)


def client(uris, cid="c1"):
    return OAuthClientInformationFull(client_id=cid, redirect_uris=[AnyUrl(u) for u in uris],
                                      token_endpoint_auth_method="none")


# L1: a stored client's redirect URI that the allowlist no longer accepts is never used, even for errors.
@pytest.mark.anyio
async def test_stored_client_loses_redirects_no_longer_allowed(tmp_path):
    s = settings(tmp_path)
    store = Store(s.db_path)
    store.save_client(client(["http://127.0.0.1:53280/callback", CB]))
    strict = GatewayProvider(replace(s, allow_loopback_redirects=False), store)
    c = await strict.get_client("c1")
    assert [str(u) for u in c.redirect_uris] == [CB]
    store.save_client(client(["http://127.0.0.1:53280/callback"], cid="c2"))
    assert await strict.get_client("c2") is None


# L2: prefix entries are explicit ("*"), Grok's callback is exact, and encoded escapes are refused.
def test_grok_callback_is_exact(tmp_path):
    s = settings(tmp_path)
    assert redirect_allowed("https://grok.com/connectors-oauth-exchange-code/", s)
    assert not redirect_allowed("https://grok.com/connectors-oauth-exchange-code/anything/else?x=1", s)


def test_prefix_entries_refuse_encoded_escapes(tmp_path):
    s = settings(tmp_path)
    assert redirect_allowed("https://chatgpt.com/connector/oauth/abc123", s)
    for bad in ("%252e%252e/%252e%252e/evil", "a;b", "a%2fb", "a%2Fb", "a%5cb"):
        assert not redirect_allowed("https://chatgpt.com/connector/oauth/" + bad, s), bad


def test_star_marks_a_prefix_and_slash_alone_is_exact(tmp_path):
    s = settings(tmp_path, redirect_allowlist=("https://app.example/cb/*", "https://other.example/cb/"))
    assert redirect_allowed("https://app.example/cb/x", s) and redirect_allowed("https://app.example/cb/", s)
    assert redirect_allowed("https://other.example/cb/", s)
    assert not redirect_allowed("https://other.example/cb/x", s)


# L3: the PKCE challenge must be an S256 value: 43 base64url characters.
@pytest.mark.anyio
@pytest.mark.parametrize("bad", ["c", "x" * 42, "x" * 44, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw+cM"])
async def test_malformed_code_challenge_is_refused(tmp_path, bad):
    s = settings(tmp_path)
    prov = GatewayProvider(s, Store(s.db_path))
    with pytest.raises(AuthorizeError):
        await prov.authorize(client([CB]), params(challenge=bad))


# L5: RFC 9207 iss on the authorization response, advertised in the metadata.
@pytest.mark.anyio
async def test_authorization_response_carries_iss(tmp_path):
    s = settings(tmp_path)
    prov = GatewayProvider(s, Store(s.db_path))
    c = client([CB])
    await prov.register_client(c)
    req = (await prov.authorize(c, params())).split("req=")[1]
    q = parse_qs(urlsplit(prov.complete_login(req, [("me@x.co.za", "pw", MAIL1)])).query)
    assert q["iss"] == ["http://127.0.0.1:8765"] == [prov.issuer]


def test_metadata_advertises_iss_and_matches_it(tmp_path):
    s = settings(tmp_path)
    meta = TestClient(build_app(s)).get("/.well-known/oauth-authorization-server").json()
    assert meta["authorization_response_iss_parameter_supported"] is True
    assert meta["issuer"] == GatewayProvider(s, Store(s.db_path)).issuer


# L6: the limiter's key table is bounded; past the bound new keys are refused, known keys still count.
def test_rate_limiter_key_table_is_bounded(monkeypatch):
    monkeypatch.setattr(RateLimiter, "MAX_KEYS", 3)
    lim = RateLimiter(5, 900)
    assert all(lim.try_acquire([f"ip:{i}"]) for i in range(3))
    assert not lim.try_acquire(["ip:new"]) and len(lim) == 3
    assert lim.try_acquire(["ip:0"])


# L7: a grant ends grant_max_age after sign-in, however often its tokens are refreshed.
def test_grant_lifetime_is_absolute(tmp_path, monkeypatch):
    store = Store(tmp_path / "s.sqlite", grant_max_age=100)
    gid, key = store.create_grant("c1", RES, [("me@x.co.za", "pw", MAIL1)])
    at, rt = store.issue_tokens(gid, key, "c1", [], RES, 3600, 86400)
    assert store.load_token(rt, "refresh").expires <= time.time() + 100
    assert store.load_token(at, "access").expires <= time.time() + 100
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + 101)
    assert store.rotate_and_issue(rt, "c1", None, 3600, 86400) is None


def test_grant_max_age_setting(tmp_path):
    assert settings(tmp_path).grant_max_age == 90 * 86400
    with pytest.raises(ValueError):
        settings(tmp_path, grant_max_age=-1)
