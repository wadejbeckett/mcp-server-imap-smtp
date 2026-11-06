# SPDX-License-Identifier: AGPL-3.0-or-later
"""End to end through the real ASGI app: OAuth discovery, registration, sign-in, token exchange, MCP.
No network: the sign-in verifier is a fake and the mail layer's opener/sender raise if ever called."""
import base64
import hashlib
import json
import secrets
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from starlette.testclient import TestClient

from mcp_server_imap_smtp.auth.cimd import MetadataPatch
from mcp_server_imap_smtp.app import build_app, uvicorn_kwargs
from mcp_server_imap_smtp.config import Settings
from mcp_server_imap_smtp.store import Store
from mcp_server_imap_smtp.mail.hosts import MailServer
from tests._signin import connected, location
MAIL1 = MailServer("mail1.hosting.example")

BASE = "http://127.0.0.1:8765"
MAIL = f"{BASE}/mail"
CB = "http://127.0.0.1:53280/callback"
ACCEPT = {"accept": "application/json, text/event-stream"}
INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}}
# The default send_mode is "send": both mail_draft and mail_send are offered.
TOOLS = {"mail_accounts", "mail_folders", "mail_search", "mail_read", "mail_thread", "mail_attachment",
         "mail_flag", "mail_move", "mail_draft", "mail_send"}


def make_settings(tmp_path, **kw):
    # Explicit domains and no MX matching: the sign-in page resolves without DNS.
    return Settings(issuer_url=BASE, mail_resource_url=MAIL,
                    mail_servers=(MailServer("mail1.hosting.example", domains=("x.co.za",), match_mx=False),),
                    db_path=tmp_path / "s.sqlite", **kw)


def no_network(*a, **k):
    raise AssertionError("the end-to-end test must not reach the mail server")


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "s.sqlite")


@pytest.fixture
def client(tmp_path, store):
    app = build_app(make_settings(tmp_path), store=store, opener=no_network, sender=no_network,
                    verifier=lambda a, p, server: (a, p) == ("me@x.co.za", "pw"))
    with TestClient(app, base_url=BASE, follow_redirects=False) as c:
        yield c


def register(c, redirect=CB, **extra):
    return c.post("/register", json={"redirect_uris": [redirect], "token_endpoint_auth_method": "none",
                                     "grant_types": ["authorization_code", "refresh_token"], "client_name": "Test",
                                     **extra})


def authorize(c, client_id, redirect=CB, scope=None, challenge="c" * 43):
    params = {"response_type": "code", "client_id": client_id, "redirect_uri": redirect, "code_challenge": challenge,
              "code_challenge_method": "S256", "state": "xyz", "resource": MAIL}
    if scope is not None:
        params["scope"] = scope
    return c.get("/authorize", params=params)


def authorize_and_login(c, client_id, redirect=CB, scope=None):
    """Run authorize and login for a registered client; return (code, verifier)."""
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    r = authorize(c, client_id, redirect, scope, challenge)
    assert r.status_code == 302
    login = urlparse(r.headers["location"])
    assert login.path == "/mail/login", r.headers["location"]
    req = parse_qs(login.query)["req"][0]
    r = c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "pw"})
    assert connected(r)
    assert location(r).startswith(redirect)
    q = parse_qs(urlparse(location(r)).query)
    assert q["state"] == ["xyz"]
    return q["code"][0], verifier


def sign_in(c, scope=None, **registration):
    """Run register, authorize and login; return (client_id, code, verifier)."""
    reg = register(c, **registration).json()
    code, verifier = authorize_and_login(c, reg["client_id"], scope=scope)
    return reg["client_id"], code, verifier


def exchange(c, client_id, code, verifier, redirect=CB):
    return c.post("/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": redirect,
                                  "client_id": client_id, "code_verifier": verifier, "resource": MAIL})


def refresh(c, client_id, refresh_token, scope=None):
    data = {"grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": client_id}
    if scope is not None:
        data["scope"] = scope
    return c.post("/token", data=data)


def rpc(c, token, body):
    return c.post("/mail", json=body, headers={**ACCEPT, "authorization": f"Bearer {token}"})


def test_unauthenticated_mail_is_401_with_resource_metadata(client):
    r = client.post("/mail", json=INIT, headers=ACCEPT)
    assert r.status_code == 401
    assert "oauth-protected-resource/mail" in r.headers["www-authenticate"]
    assert "resource_metadata" in r.headers["www-authenticate"]


def test_login_page_is_not_behind_bearer_auth(client):
    r = client.get("/mail/login", params={"req": "nope"})
    assert r.status_code == 400 and "expired" in r.text          # our page, not the bearer 401
    assert "www-authenticate" not in r.headers


def test_metadata_documents(client):
    prm = client.get("/.well-known/oauth-protected-resource/mail").json()
    assert prm["resource"] == MAIL
    assert prm["authorization_servers"] in ([BASE + "/"], [BASE])
    asm = client.get("/.well-known/oauth-authorization-server").json()
    assert asm["code_challenge_methods_supported"] == ["S256"]
    assert asm["registration_endpoint"]
    assert asm["client_id_metadata_document_supported"] is True
    assert "none" in asm["token_endpoint_auth_methods_supported"]


def test_patched_metadata_content_length_matches_body(client):
    r = client.get("/.well-known/oauth-authorization-server")
    assert int(r.headers["content-length"]) == len(r.content)
    assert r.headers["content-type"].startswith("application/json")
    assert json.loads(r.content)["issuer"].rstrip("/") == BASE


def test_other_paths_pass_through_the_patch_byte_identical(tmp_path, client):
    path = "/.well-known/oauth-protected-resource"          # no resource suffix: not a patched document
    unwrapped_app = build_app(make_settings(tmp_path), opener=no_network, sender=no_network)
    inner = unwrapped_app.app                     # the SDK app, without the patch
    with TestClient(inner, base_url=BASE) as raw:
        expected = raw.get(path)
        expected_401 = raw.post("/mail", json=INIT, headers=ACCEPT)
    got = client.get(path)
    assert got.status_code == expected.status_code
    assert got.content == expected.content
    assert dict(got.headers) == dict(expected.headers)
    got_401 = client.post("/mail", json=INIT, headers=ACCEPT)
    assert got_401.status_code == expected_401.status_code == 401
    assert got_401.content == expected_401.content
    assert dict(got_401.headers) == dict(expected_401.headers)


def test_cors_preflight_on_metadata_is_not_broken_by_the_patch(client):
    hdrs = {"Origin": "https://claude.ai", "Access-Control-Request-Method": "GET"}
    r = client.options("/.well-known/oauth-authorization-server", headers=hdrs)
    assert r.status_code == 200
    assert r.headers["access-control-allow-origin"] in ("*", "https://claude.ai")
    assert "GET" in r.headers["access-control-allow-methods"]
    r = client.get("/.well-known/oauth-authorization-server", headers={"Origin": "https://claude.ai"})
    assert r.json()["client_id_metadata_document_supported"] is True
    assert int(r.headers["content-length"]) == len(r.content)


def test_non_json_or_non_200_metadata_responses_pass_through_untouched():
    import asyncio

    def inner_for(status, ctype, body):
        async def inner(scope, receive, send):
            await send({"type": "http.response.start", "status": status, "headers": [(b"content-type", ctype)]})
            await send({"type": "http.response.body", "body": body})
        return inner

    async def call(inner, method="GET"):
        sent = []
        async def send(m): sent.append(m)
        async def receive(): return {"type": "http.request"}
        await MetadataPatch(inner)({"type": "http", "method": method,
                                    "path": "/.well-known/oauth-authorization-server"}, receive, send)
        return sent

    err = asyncio.run(call(inner_for(500, b"text/plain", b"boom")))
    assert err == [{"type": "http.response.start", "status": 500, "headers": [(b"content-type", b"text/plain")]},
                   {"type": "http.response.body", "body": b"boom"}]
    text = asyncio.run(call(inner_for(200, b"text/plain; charset=utf-8", b"OK"), method="OPTIONS"))
    assert text[1]["body"] == b"OK" and text[0]["status"] == 200
    bad = asyncio.run(call(inner_for(200, b"application/json", b"not json")))
    assert bad[0]["status"] == 200 and bad[1]["body"] == b"not json"


def test_registration_allows_loopback_and_refuses_others(client):
    assert register(client).status_code == 201
    r = register(client, "https://evil.com/cb")
    assert r.status_code == 400


def test_login_page_renders_for_a_pending_request(client):
    reg = register(client).json()
    r = client.get("/authorize", params={"response_type": "code", "client_id": reg["client_id"], "redirect_uri": CB,
                                         "code_challenge": "c" * 43, "code_challenge_method": "S256", "state": "s",
                                         "resource": MAIL})
    page = client.get(r.headers["location"])
    assert page.status_code == 200 and "Connect your mailbox" in page.text


def test_bad_password_does_not_redirect(client):
    reg = register(client).json()
    r = client.get("/authorize", params={"response_type": "code", "client_id": reg["client_id"], "redirect_uri": CB,
                                         "code_challenge": "c" * 43, "code_challenge_method": "S256", "state": "s",
                                         "resource": MAIL})
    req = parse_qs(urlparse(r.headers["location"]).query)["req"][0]
    r = client.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "wrong"})
    assert r.status_code == 200 and "incorrect" in r.text


def test_full_flow_initialize_tools_and_refresh_rotation(client):
    client_id, code, verifier = sign_in(client)
    resp = exchange(client, client_id, code, verifier)
    assert resp.status_code == 200
    tok = resp.json()
    assert tok["token_type"].lower() == "bearer" and tok["refresh_token"]

    init = rpc(client, tok["access_token"], INIT)
    assert init.status_code == 200
    assert init.json()["result"]["serverInfo"]["name"] == "Mail Connector"          # product_name default
    assert init.json()["result"]["instructions"].startswith("Mail Connector: the user's mailboxes hosted by the operator.")
    listed = rpc(client, tok["access_token"], {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    assert listed.status_code == 200
    assert {t["name"] for t in listed.json()["result"]["tools"]} == TOOLS
    called = rpc(client, tok["access_token"], {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                               "params": {"name": "mail_accounts", "arguments": {}}})
    assert called.status_code == 200 and "me@x.co.za" in called.text

    first = refresh(client, client_id, tok["refresh_token"])
    assert first.status_code == 200
    replay = refresh(client, client_id, tok["refresh_token"])     # within the retry grace: refused only
    assert replay.status_code == 400 and replay.json()["error"] == "invalid_grant"
    # the rotated access token works
    assert rpc(client, first.json()["access_token"], INIT).status_code == 200

    # the code is single use, and presenting it again ends the grant it opened (RFC 6749 section 4.1.2)
    assert exchange(client, client_id, code, verifier).status_code == 400
    assert rpc(client, first.json()["access_token"], INIT).status_code == 401
    assert refresh(client, client_id, first.json()["refresh_token"]).status_code == 400


def test_token_with_wrong_audience_is_rejected(client, store):
    client_id, code, verifier = sign_in(client)
    exchange(client, client_id, code, verifier)
    gid, key = store.create_grant(client_id, f"{BASE}/other", [("me@x.co.za", "pw", MAIL1)])
    access, _ = store.issue_tokens(gid, key, client_id, [], f"{BASE}/other", 3600, 3600)
    r = rpc(client, access, INIT)
    assert r.status_code == 401


def test_garbage_bearer_is_rejected(client):
    assert rpc(client, "not-a-token", INIT).status_code == 401


def test_uvicorn_kwargs_honours_trusted_proxy(tmp_path):
    direct = uvicorn_kwargs(make_settings(tmp_path))
    assert direct["proxy_headers"] is False
    assert direct["host"] == "127.0.0.1" and direct["port"] == 8765
    proxied = uvicorn_kwargs(make_settings(tmp_path, trusted_proxy=True))
    assert proxied["proxy_headers"] is True and proxied["forwarded_allow_ips"] == "127.0.0.1"
    custom = uvicorn_kwargs(make_settings(tmp_path, trusted_proxy=True, forwarded_allow_ips="10.0.0.2"))
    assert custom["forwarded_allow_ips"] == "10.0.0.2"


def test_uvicorn_waits_only_briefly_for_calls_in_flight_when_stopping(tmp_path):
    """Without a bound uvicorn waits for every open request, however long, before it stops (and systemd
    then kills it); calls still running after the grace are cut."""
    from mcp_server_imap_smtp.app import STOP_SECONDS
    from mcp_server_imap_smtp.mail.sessions import STOP_LOGOUT_SECONDS
    grace = uvicorn_kwargs(make_settings(tmp_path))["timeout_graceful_shutdown"]
    assert 0 < grace <= 5
    assert grace + STOP_LOGOUT_SECONDS < STOP_SECONDS < 10


# Client ID Metadata Documents: the client_id is an https URL whose document the gateway fetches (here, a fake).
CIMD_ID = "https://chatgpt.com/oauth/client.json"
CIMD_CB = "https://chatgpt.com/connector_platform_oauth_redirect"


@pytest.fixture
def cimd_fetches():
    return []


@pytest.fixture
def cimd_doc_extra():
    return {}


@pytest.fixture
def cimd_client(tmp_path, store, cimd_fetches, cimd_doc_extra):
    def handler(req):
        cimd_fetches.append(str(req.url))
        return httpx.Response(200, json={"client_id": CIMD_ID, "client_name": "ChatGPT",
                                         "redirect_uris": [CIMD_CB], "token_endpoint_auth_method": "none",
                                         **cimd_doc_extra})
    app = build_app(make_settings(tmp_path), store=store, opener=no_network, sender=no_network,
                    verifier=lambda a, p, server: (a, p) == ("me@x.co.za", "pw"),
                    cimd_http=httpx.Client(transport=httpx.MockTransport(handler)))
    with TestClient(app, base_url=BASE, follow_redirects=False) as c:
        yield c


def test_cimd_authorization_code_flow_with_pkce_and_no_secret(cimd_client, cimd_fetches):
    c = cimd_client
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    r = c.get("/authorize", params={"response_type": "code", "client_id": CIMD_ID, "redirect_uri": CIMD_CB,
                                    "code_challenge": challenge, "code_challenge_method": "S256", "state": "xyz",
                                    "resource": MAIL})
    assert r.status_code == 302 and urlparse(r.headers["location"]).path == "/mail/login"
    req = parse_qs(urlparse(r.headers["location"]).query)["req"][0]
    r = c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "pw"})
    assert connected(r) and location(r).startswith(CIMD_CB)
    code = parse_qs(urlparse(location(r)).query)["code"][0]
    resp = c.post("/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": CIMD_CB,
                                  "client_id": CIMD_ID, "code_verifier": verifier, "resource": MAIL,
                                  "token_endpoint_auth_method": "none"})
    assert resp.status_code == 200, resp.text
    assert rpc(c, resp.json()["access_token"], INIT).status_code == 200
    assert cimd_fetches == [CIMD_ID]            # fetched once; /authorize and /token reuse the 24 h cache


def test_cimd_client_from_a_host_off_the_allowlist_is_refused_without_a_fetch(cimd_client, cimd_fetches):
    r = cimd_client.get("/authorize", params={"response_type": "code", "client_id": "http://169.254.169.254/x",
                                              "redirect_uri": CIMD_CB, "code_challenge": "c" * 43,
                                              "code_challenge_method": "S256", "resource": MAIL})
    assert r.status_code == 400
    r = cimd_client.get("/authorize", params={"response_type": "code", "client_id": "https://internal.lan/c.json",
                                              "redirect_uri": CIMD_CB, "code_challenge": "c" * 43,
                                              "code_challenge_method": "S256", "resource": MAIL})
    assert r.status_code == 400 and cimd_fetches == []


def test_malformed_cimd_client_ids_are_a_400_not_a_500(cimd_client, cimd_fetches):
    for bad in ("https://chatgpt.com%09/x", "https://chatgpt.com\t/x", "https://evil.com\\.chatgpt.com/x"):
        r = cimd_client.get("/authorize", params={"response_type": "code", "client_id": bad, "redirect_uri": CIMD_CB,
                                                  "code_challenge": "c" * 43, "code_challenge_method": "S256",
                                                  "resource": MAIL})
        assert r.status_code == 400, bad
    assert cimd_fetches == []


# Scopes. The gateway has one scope, offline_access: ChatGPT keeps a connection alive across access-token
# expiry only when the authorization server advertises it, and Claude asks for what is advertised. Refresh
# tokens are issued whether or not it is requested, so clients that send no scope still work. Scopes gate
# nothing, so an unknown scope is dropped rather than refused (RFC 6749 section 3.3).
SCOPES = ["offline_access"]


def test_metadata_advertises_offline_access(client):
    asm = client.get("/.well-known/oauth-authorization-server")
    assert asm.status_code == 200 and int(asm.headers["content-length"]) == len(asm.content)
    assert asm.json()["scopes_supported"] == SCOPES
    assert "refresh_token" in asm.json()["grant_types_supported"]
    prm = client.get("/.well-known/oauth-protected-resource/mail")
    assert prm.status_code == 200 and int(prm.headers["content-length"]) == len(prm.content)
    assert prm.json()["scopes_supported"] == SCOPES
    assert prm.json()["resource"] == MAIL


@pytest.mark.parametrize("path", ["/.well-known/oauth-authorization-server", "/.well-known/oauth-protected-resource/mail"])
def test_head_on_patched_metadata_matches_get(client, path):
    get, head = client.get(path), client.head(path)
    assert head.status_code == 200 and head.content == b""
    assert head.headers["content-length"] == get.headers["content-length"] == str(len(get.content))
    assert head.headers["content-type"] == get.headers["content-type"]


def test_head_on_a_missing_metadata_path_passes_through(client):
    r = client.head("/.well-known/oauth-protected-resource/nope")
    assert r.status_code == 404 and r.content == b""


def test_mail_401_does_not_demand_a_scope(client):
    r = client.post("/mail", json=INIT, headers=ACCEPT)
    assert r.status_code == 401 and "scope=" not in r.headers["www-authenticate"]


def full_token(c, client_id, scope, redirect=CB):
    code, verifier = authorize_and_login(c, client_id, redirect, scope)
    resp = exchange(c, client_id, code, verifier, redirect)
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_dcr_client_registered_without_scope_can_ask_for_offline_access_or_nothing(client):
    reg = register(client)
    assert reg.status_code == 201 and reg.json()["scope"] == "offline_access"
    cid = reg.json()["client_id"]
    tok = full_token(client, cid, "offline_access")
    assert tok["scope"] == "offline_access" and tok["refresh_token"]
    assert rpc(client, tok["access_token"], INIT).status_code == 200
    bare = full_token(client, cid, None)
    assert "scope" not in bare and bare["refresh_token"]                         # no scope asked, none granted
    assert rpc(client, bare["access_token"], INIT).status_code == 200


def test_client_stored_before_scopes_existed_can_ask_for_offline_access(client, store):
    from mcp.shared.auth import OAuthClientInformationFull
    store.save_client(OAuthClientInformationFull(client_id="legacy", redirect_uris=[CB],
                                                 token_endpoint_auth_method="none"))
    assert store.get_client("legacy").scope is None
    tok = full_token(client, "legacy", "offline_access")
    assert tok["scope"] == "offline_access"


@pytest.mark.parametrize("registered", ["offline_access", "openid offline_access", "openid email",
                                        "offline_access offline_access", "  offline_access ", ""])
def test_registration_records_the_gateway_scope_whatever_was_registered(client, store, registered):
    reg = register(client, scope=registered)
    assert reg.status_code == 201, reg.text
    assert reg.json()["scope"] == "offline_access"
    assert store.get_client(reg.json()["client_id"]).scope == "offline_access"
    tok = full_token(client, reg.json()["client_id"], "offline_access")
    assert tok["scope"] == "offline_access"
    assert rpc(client, tok["access_token"], INIT).status_code == 200


@pytest.mark.parametrize("asked, granted", [
    ("openid offline_access", "offline_access"), ("offline_access mail:admin", "offline_access"),
    ("openid", None), ("profile email", None), ("offline_access offline_access", "offline_access"),
    (" offline_access  ", "offline_access"), ("", None), ("x" * 5000, None)])
def test_authorize_drops_unknown_scopes_and_grants_the_rest(client, asked, granted):
    cid = register(client).json()["client_id"]
    r = authorize(client, cid, scope=asked)
    assert r.status_code == 302 and urlparse(r.headers["location"]).path == "/mail/login"
    tok = full_token(client, cid, asked)
    assert tok.get("scope") == granted and tok["refresh_token"]
    assert rpc(client, tok["access_token"], INIT).status_code == 200
    again = refresh(client, cid, tok["refresh_token"])
    assert again.status_code == 200 and again.json().get("scope") == granted


def test_authorize_with_unknown_client_is_still_a_400(client):
    r = authorize(client, "no-such-client", scope="openid")
    assert r.status_code == 400


def test_refresh_preserves_offline_access_and_refuses_new_scopes(client):
    cid = register(client).json()["client_id"]
    tok = full_token(client, cid, "offline_access")
    first = refresh(client, cid, tok["refresh_token"])
    assert first.status_code == 200 and first.json()["scope"] == "offline_access"
    second = refresh(client, cid, first.json()["refresh_token"], scope="offline_access")
    assert second.status_code == 200 and second.json()["scope"] == "offline_access"
    # RFC 6749 section 6: a refresh cannot widen the grant; the SDK refuses before the provider runs.
    bad = refresh(client, cid, second.json()["refresh_token"], scope="openid")
    assert bad.status_code == 400 and bad.json()["error"] == "invalid_scope"
    # a refused scope does not burn the refresh token
    third = refresh(client, cid, second.json()["refresh_token"])
    assert third.status_code == 200 and third.json()["scope"] == "offline_access"
    assert rpc(client, third.json()["access_token"], INIT).status_code == 200


def test_refresh_with_a_repeated_scope_is_collapsed(client, store):
    cid = register(client).json()["client_id"]
    tok = full_token(client, cid, "offline_access")
    r = refresh(client, cid, tok["refresh_token"], scope="offline_access offline_access")
    assert r.status_code == 200 and r.json()["scope"] == "offline_access"
    assert store.load_token(r.json()["access_token"], "access").scopes == ["offline_access"]
    assert store.load_token(r.json()["refresh_token"], "refresh").scopes == ["offline_access"]


@pytest.mark.parametrize("padded", [" offline_access", "offline_access "])
def test_refresh_with_a_padded_scope_is_refused_by_the_sdk(client, padded):
    # Known limit: the SDK splits the refresh scope on single spaces, so the empty piece is unknown to the
    # refresh token. A clean 400 that leaves the refresh token usable, never a 500.
    cid = register(client).json()["client_id"]
    tok = full_token(client, cid, "offline_access")
    bad = refresh(client, cid, tok["refresh_token"], scope=padded)
    assert bad.status_code == 400 and bad.json()["error"] == "invalid_scope"
    assert refresh(client, cid, tok["refresh_token"]).status_code == 200


def test_refresh_of_a_scopeless_grant_cannot_gain_offline_access(client):
    cid = register(client).json()["client_id"]
    tok = full_token(client, cid, None)
    bad = refresh(client, cid, tok["refresh_token"], scope="offline_access")
    assert bad.status_code == 400 and bad.json()["error"] == "invalid_scope"
    ok = refresh(client, cid, tok["refresh_token"])
    assert ok.status_code == 200 and "scope" not in ok.json()


@pytest.mark.parametrize("cimd_doc_extra", [{}, {"scope": "offline_access"}, {"scope": "openid email"}])
@pytest.mark.parametrize("scope", [None, "offline_access"])
def test_cimd_client_with_or_without_a_document_scope(cimd_client, cimd_doc_extra, scope):
    verifier_tok = full_token(cimd_client, CIMD_ID, scope, CIMD_CB)
    assert verifier_tok.get("scope") == scope
    r = refresh(cimd_client, CIMD_ID, verifier_tok["refresh_token"])
    assert r.status_code == 200 and r.json().get("scope") == scope
    assert rpc(cimd_client, r.json()["access_token"], INIT).status_code == 200


def test_cimd_client_asking_for_an_unknown_scope_gets_the_known_ones(cimd_client):
    tok = full_token(cimd_client, CIMD_ID, "openid offline_access", CIMD_CB)
    assert tok["scope"] == "offline_access"
    tok = full_token(cimd_client, CIMD_ID, "openid", CIMD_CB)
    assert "scope" not in tok and tok["refresh_token"]


def test_operator_values_reach_the_server_name_and_instructions(tmp_path, store):
    settings = make_settings(tmp_path, operator_name="Acme", product_name="Acme Mail")
    app = build_app(settings, store=store, opener=no_network, sender=no_network,
                    verifier=lambda a, p, server: (a, p) == ("me@x.co.za", "pw"))
    with TestClient(app, base_url=BASE, follow_redirects=False) as c:
        client_id, code, verifier = sign_in(c)
        tok = exchange(c, client_id, code, verifier).json()
        result = rpc(c, tok["access_token"], INIT).json()["result"]
    assert result["serverInfo"]["name"] == "Acme Mail"
    assert result["instructions"].startswith("Acme Mail: the user's mailboxes hosted by Acme.")
