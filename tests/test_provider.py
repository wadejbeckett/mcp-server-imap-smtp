# SPDX-License-Identifier: AGPL-3.0-or-later
import logging
import pytest
from mcp.server.auth.provider import AuthorizationParams, AuthorizeError, RegistrationError, TokenError
from mcp.shared.auth import OAuthClientInformationFull
from pydantic import AnyUrl

from mcp_server_imap_smtp.auth.provider import GatewayProvider
from mcp_server_imap_smtp.config import Settings
from mcp_server_imap_smtp.store import Store
from mcp_server_imap_smtp.mail.hosts import MailServer
MAIL1 = MailServer("mail1.hosting.example")

CB = "https://claude.ai/api/mcp/auth_callback"
RES = "http://127.0.0.1:8765/mail"


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def prov(tmp_path):
    s = Settings(issuer_url="http://127.0.0.1:8765", mail_resource_url=RES,
                 mail_servers=(MailServer("mail1.hosting.example"),), db_path=tmp_path / "s.sqlite")
    return GatewayProvider(s, Store(s.db_path))


def client(uri=CB, cid="c1"):
    return OAuthClientInformationFull(client_id=cid, redirect_uris=[AnyUrl(uri)], token_endpoint_auth_method="none")


def params(resource=RES):
    return AuthorizationParams(state="st", scopes=None, code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", redirect_uri=AnyUrl(CB),
                               redirect_uri_provided_explicitly=True, resource=resource)


async def login(prov, c=None, resource=RES):
    """Run register -> authorize -> complete_login; return (client, req, code)."""
    c = c or client()
    await prov.register_client(c)
    req = (await prov.authorize(c, params(resource))).split("req=")[1]
    redirect = prov.complete_login(req, [("me@x.co.za", "pw", MAIL1)])
    return c, req, redirect.split("code=")[1].split("&")[0]


async def tokens(prov, c=None):
    c, _, code = await login(prov, c)
    return c, await prov.exchange_authorization_code(c, await prov.load_authorization_code(c, code))


@pytest.mark.anyio
async def test_register_refuses_unknown_redirect(prov):
    with pytest.raises(RegistrationError):
        await prov.register_client(client("https://evil.com/cb"))


@pytest.mark.anyio
async def test_authorize_refuses_other_resource(prov):
    await prov.register_client(client())
    with pytest.raises(AuthorizeError):
        await prov.authorize(client(), params("https://elsewhere.example/mcp"))


@pytest.mark.anyio
async def test_full_flow(prov):
    await prov.register_client(client())
    url = await prov.authorize(client(), params())
    req = url.split("req=")[1]
    redirect = prov.complete_login(req, [("me@x.co.za", "pw", MAIL1)])
    assert redirect.startswith(CB) and "state=st" in redirect
    code = redirect.split("code=")[1].split("&")[0]
    ac = await prov.load_authorization_code(client(), code)
    assert ac.subject == "me@x.co.za" and ac.resource == RES
    tok = await prov.exchange_authorization_code(client(), ac)
    assert tok.expires_in == 3600 and tok.refresh_token
    at = await prov.load_access_token(tok.access_token)
    assert at.resource == RES and at.subject == "me@x.co.za"
    rt = await prov.load_refresh_token(client(), tok.refresh_token)
    tok2 = await prov.exchange_refresh_token(client(), rt, [])
    assert await prov.load_refresh_token(client(), tok.refresh_token) is None
    assert await prov.load_access_token(tok2.access_token)
    with pytest.raises(LookupError):
        prov.complete_login(req, [("me@x.co.za", "pw", MAIL1)])   # single use


@pytest.mark.anyio
async def test_authorization_code_used_twice(prov):
    c, _, code = await login(prov)
    ac = await prov.load_authorization_code(c, code)
    await prov.exchange_authorization_code(c, ac)
    with pytest.raises(TokenError) as e:
        await prov.exchange_authorization_code(c, ac)
    assert e.value.error == "invalid_grant"
    assert await prov.load_authorization_code(c, code) is None


@pytest.mark.anyio
async def test_authorization_code_bound_to_client(prov):
    c, _, code = await login(prov)
    assert await prov.load_authorization_code(client(cid="c2"), code) is None


@pytest.mark.anyio
async def test_refresh_replay_is_invalid_grant(prov):
    c, tok = await tokens(prov)
    rt = await prov.load_refresh_token(c, tok.refresh_token)
    await prov.exchange_refresh_token(c, rt, [])
    with pytest.raises(TokenError) as e:
        await prov.exchange_refresh_token(c, rt, [])      # replay of the already-rotated token
    assert e.value.error == "invalid_grant"


@pytest.mark.anyio
async def test_refresh_token_of_another_client_is_refused(prov):
    c, tok = await tokens(prov)
    other = client(cid="c2")
    await prov.register_client(other)
    assert await prov.load_refresh_token(other, tok.refresh_token) is None
    rt = await prov.load_refresh_token(c, tok.refresh_token)
    with pytest.raises(TokenError) as e:
        await prov.exchange_refresh_token(other, rt, [])  # even handed the object directly
    assert e.value.error == "invalid_grant"
    # the refusal happened before rotation, so the rightful client can still use the token
    assert (await prov.exchange_refresh_token(c, rt, [])).access_token


@pytest.mark.anyio
async def test_refresh_carries_resource_and_subject(prov):
    c, tok = await tokens(prov)
    rt = await prov.load_refresh_token(c, tok.refresh_token)
    assert rt.resource == RES and rt.subject == "me@x.co.za"
    at = await prov.load_access_token((await prov.exchange_refresh_token(c, rt, [])).access_token)
    assert at.resource == RES and at.subject == "me@x.co.za"


@pytest.mark.anyio
async def test_load_access_token_rejects_other_resource(prov):
    c, _ = await tokens(prov)
    gid, key = prov.store.create_grant("c1", "https://elsewhere.example/mcp", [("me@x.co.za", "pw", MAIL1)])
    at, _ = prov.store.issue_tokens(gid, key, "c1", [], "https://elsewhere.example/mcp", 3600, 3600)
    assert prov.store.load_token(at, "access") is not None     # valid in the store...
    assert await prov.load_access_token(at) is None            # ...but not for this resource


@pytest.mark.anyio
async def test_revoke_access_token(prov):
    c, tok = await tokens(prov)
    at = await prov.load_access_token(tok.access_token)
    await prov.revoke_token(at)
    assert await prov.load_access_token(tok.access_token) is None


@pytest.mark.anyio
async def test_revoke_access_token_leaves_the_refresh_token(prov):
    c, tok = await tokens(prov)
    await prov.revoke_token(await prov.load_access_token(tok.access_token))
    assert await prov.load_refresh_token(c, tok.refresh_token) is not None


@pytest.mark.anyio
async def test_revoke_refresh_token_revokes_the_whole_grant(prov):
    c, tok = await tokens(prov)
    rt = await prov.load_refresh_token(c, tok.refresh_token)
    await prov.revoke_token(rt)
    assert await prov.load_refresh_token(c, tok.refresh_token) is None
    assert await prov.load_access_token(tok.access_token) is None       # its access token dies too
    assert prov.store.list_grants()[0]["revoked"] == 1


@pytest.mark.anyio
async def test_revoke_refresh_token_with_wrong_secret_revokes_nothing(prov):
    from mcp.server.auth.provider import RefreshToken
    c, tok = await tokens(prov)
    ident, _, secret = tok.refresh_token.partition(".")
    forged = RefreshToken(token=ident + ".wrong" + secret, client_id="c1", scopes=[])
    await prov.revoke_token(forged)
    assert await prov.load_access_token(tok.access_token) is not None
    assert prov.store.list_grants()[0]["revoked"] == 0


@pytest.mark.anyio
async def test_refresh_rotation_is_a_single_store_transaction(prov, monkeypatch):
    c, tok = await tokens(prov)
    rt = await prov.load_refresh_token(c, tok.refresh_token)
    calls = []
    real = prov.store.rotate_and_issue
    monkeypatch.setattr(prov.store, "rotate_and_issue", lambda *a: calls.append(a) or real(*a))
    await prov.exchange_refresh_token(c, rt, ["x"])
    assert len(calls) == 1 and calls[0][1] == "c1" and calls[0][2] == ["x"]


@pytest.mark.anyio
async def test_authorize_refuses_redirect_not_on_allowlist(prov):
    await prov.register_client(client())
    bad = params().model_copy(update={"redirect_uri": AnyUrl("https://evil.com/cb")})
    with pytest.raises(AuthorizeError) as e:
        await prov.authorize(client(), bad)
    assert e.value.error == "invalid_request"


@pytest.mark.anyio
async def test_authorize_unknown_resource_is_invalid_target(prov):
    await prov.register_client(client())
    with pytest.raises(AuthorizeError) as e:
        await prov.authorize(client(), params("https://elsewhere.example/mcp"))
    assert e.value.error == "invalid_target"


@pytest.mark.anyio
async def test_authorize_without_resource_defaults_to_mail_resource(prov):
    await prov.register_client(client())
    req = (await prov.authorize(client(), params(None))).split("req=")[1]
    assert prov.store.peek_pending(req)[1].resource == RES


@pytest.mark.anyio
async def test_authorize_accepts_trailing_slash_and_stores_canonical_resource(prov):
    await prov.register_client(client())
    req = (await prov.authorize(client(), params(RES + "/"))).split("req=")[1]
    assert prov.store.peek_pending(req)[1].resource == RES


@pytest.mark.anyio
async def test_revoke_with_unverified_token_deletes_nothing(prov):
    from mcp.server.auth.provider import AccessToken
    c, tok = await tokens(prov)
    ident, _, secret = tok.access_token.partition(".")
    forged = AccessToken(token=ident + ".wrong" + secret, client_id="c1", scopes=[])
    await prov.revoke_token(forged)                             # wrong secret, right id
    assert await prov.load_access_token(tok.access_token) is not None


@pytest.mark.anyio
async def test_identity_assertion_unsupported(prov):
    with pytest.raises(TokenError) as e:
        await prov.exchange_identity_assertion(client(), None)
    assert e.value.error == "unsupported_grant_type"


GROK = "https://grok.com/connectors-oauth-exchange-code/"


@pytest.mark.anyio
@pytest.mark.parametrize("uri", [GROK])
async def test_grok_callback_registers_and_authorizes(prov, uri):
    c = client(uri, cid="grok")
    await prov.register_client(c)
    p = params().model_copy(update={"redirect_uri": AnyUrl(uri)})
    assert (await prov.authorize(c, p)).startswith("http://127.0.0.1:8765/mail/login?req=")


@pytest.mark.anyio
async def test_refused_registration_is_logged_with_client_name(prov, caplog):
    c = OAuthClientInformationFull(client_id="c9", client_name="NewAI", redirect_uris=[AnyUrl("https://new.ai/cb")],
                                   token_endpoint_auth_method="none", client_secret="s3cr3t-value")
    with caplog.at_level(logging.WARNING, logger="mcp_server_imap_smtp.auth.provider"):
        with pytest.raises(RegistrationError):
            await prov.register_client(c)
    (rec,) = [r for r in caplog.records if r.name == "mcp_server_imap_smtp.auth.provider"]
    assert rec.levelno == logging.WARNING
    assert "https://new.ai/cb" in rec.getMessage() and "NewAI" in rec.getMessage()
    assert "s3cr3t" not in caplog.text


@pytest.mark.anyio
async def test_refresh_reuse_within_the_retry_grace_is_refused_but_keeps_the_grant(prov, caplog):
    import logging
    caplog.set_level(logging.WARNING, logger="mcp_server_imap_smtp.auth.provider")
    c, tok = await tokens(prov)
    new = await prov.exchange_refresh_token(c, await prov.load_refresh_token(c, tok.refresh_token), [])
    assert await prov.load_refresh_token(c, tok.refresh_token) is None          # refused
    assert await prov.load_refresh_token(c, new.refresh_token) is not None      # the grant lives on
    (line,) = [r.getMessage() for r in caplog.records if "presented again" in r.getMessage()]
    assert "within 30s" in line and "not revoked" in line and tok.refresh_token not in line


@pytest.mark.anyio
async def test_refresh_reuse_after_the_grace_revokes_the_grant(prov, monkeypatch):
    """RFC 9700 section 4.14.2: a rotated-out refresh token presented again ends the grant, so an attacker
    who refreshed first loses it too."""
    import time as time_mod
    from mcp_server_imap_smtp.auth import provider as provider_mod
    c, tok = await tokens(prov)
    new = await prov.exchange_refresh_token(c, await prov.load_refresh_token(c, tok.refresh_token), [])
    later = time_mod.time() + provider_mod.REFRESH_RETRY_GRACE + 1
    monkeypatch.setattr(time_mod, "time", lambda: later)
    assert await prov.load_refresh_token(c, tok.refresh_token) is None
    assert await prov.load_refresh_token(c, new.refresh_token) is None          # every token of the grant ended
    assert await prov.load_access_token(new.access_token) is None


@pytest.mark.anyio
async def test_a_wrong_refresh_token_is_not_logged_as_reuse(prov, caplog):
    import logging
    caplog.set_level(logging.WARNING, logger="mcp_server_imap_smtp.auth.provider")
    c, _ = await tokens(prov)
    assert await prov.load_refresh_token(c, "rt_nothing_like_a_token") is None
    assert not [r for r in caplog.records if "presented again" in r.getMessage()]
