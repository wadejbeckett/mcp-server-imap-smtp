# SPDX-License-Identifier: AGPL-3.0-or-later
from dataclasses import replace
from pathlib import Path

import httpx
import pytest

from mcp_server_imap_smtp.auth.cimd import MAX_BYTES, fetch_client_document
from mcp_server_imap_smtp.auth.provider import GatewayProvider
from mcp_server_imap_smtp.config import Settings, redirect_allowed
from mcp_server_imap_smtp.store import Store
from mcp_server_imap_smtp.mail.hosts import MailServer

S = Settings(issuer_url="http://127.0.0.1:8765", mail_resource_url="http://127.0.0.1:8765/mail",
             mail_servers=(MailServer("mail1.hosting.example"),), db_path="/tmp/x")
URL = "https://chatgpt.com/oauth/client.json"
REDIRECT = "https://chatgpt.com/connector_platform_oauth_redirect"


def good_doc(url=URL):
    return {"client_id": url, "client_name": "ChatGPT", "redirect_uris": [REDIRECT],
            "token_endpoint_auth_method": "none"}


class Recorder:
    """A MockTransport handler that counts how often the network was reached."""
    def __init__(self, response=None):
        self.calls, self.requests = 0, []
        self.response = response or (lambda req: httpx.Response(200, json=good_doc(str(req.url))))

    def __call__(self, req):
        self.calls += 1
        self.requests.append(req)
        return self.response(req)

    def client(self):
        return httpx.Client(transport=httpx.MockTransport(self))


def client_for(doc, status=200):
    return Recorder(lambda req: httpx.Response(status, json=doc)).client()


def test_valid_document():
    info = fetch_client_document(URL, S, client_for(good_doc()))
    assert info.client_id == URL and info.token_endpoint_auth_method == "none"


def test_rejects_mismatch_and_bad_redirects():
    assert fetch_client_document(URL, S, client_for({"client_id": "https://other/x", "redirect_uris": [REDIRECT]})) is None
    assert fetch_client_document(URL, S, client_for({"client_id": URL, "redirect_uris": ["https://evil.com/cb"]})) is None
    assert fetch_client_document("http://chatgpt.com/x", S, client_for({})) is None      # https only
    assert fetch_client_document("https://127.0.0.1/x", S, client_for({})) is None       # no IP literals


def test_rejects_non_none_auth_method_and_non_object_documents():
    assert fetch_client_document(URL, S, client_for({**good_doc(), "token_endpoint_auth_method": "client_secret_basic"})) is None
    assert fetch_client_document(URL, S, client_for([good_doc()])) is None
    assert fetch_client_document(URL, S, client_for(good_doc(), status=404)) is None


@pytest.mark.parametrize("url", [
    "https://internal.example.com/client.json",     # not on the allowlist
    "https://chatgpt.com.evil.com/client.json",     # suffix trick
    "https://evilchatgpt.com/client.json",          # not a subdomain
    "https://localhost/client.json",
    "https://user:pw@chatgpt.com/client.json",      # userinfo
    "https://user@chatgpt.com/client.json",
    "https://chatgpt.com:8443/client.json",         # non-443 port
    "https://chatgpt.com/client.json#frag",         # fragment
    "https://[::1]/client.json",                    # IPv6 literal
    "https://chatgpt.com%09/x",                     # httpx.InvalidURL-style / encoded junk in the host
    "https://chatgpt.com\t/x",                      # raw control character (httpx.InvalidURL)
    "https://evil.com\\.chatgpt.com/x",             # backslash: parsers disagree about the host
    "https://evil.com\\@chatgpt.com/x",
    "https://chatgpt.com\\@evil.com/x",
    "https://evil.com%2f.chatgpt.com/x",
    "https://a b.chatgpt.com/x",
    "https://chatgpt.com./x",                       # trailing dot
    "https://.chatgpt.com/x",
    "https://chatgpt.com:/x" + "\x00",
])
def test_refused_urls_never_reach_the_network(url):
    rec = Recorder()
    assert fetch_client_document(url, S, rec.client()) is None
    assert rec.calls == 0


def test_allowlisted_subdomain_and_explicit_443_are_fetched():
    sub = "https://auth.openai.com/client.json"
    rec = Recorder(lambda req: httpx.Response(200, json=good_doc(sub)))
    assert fetch_client_document(sub, S, rec.client()).client_id == sub
    explicit = "https://chatgpt.com:443/client.json"
    rec2 = Recorder(lambda req: httpx.Response(200, json=good_doc(explicit)))
    assert fetch_client_document(explicit, S, rec2.client()).client_id == explicit


def test_allowlist_is_configurable():
    s = Settings(issuer_url=S.issuer_url, mail_resource_url=S.mail_resource_url, mail_servers=S.mail_servers,
                 db_path=S.db_path, cimd_allowed_hosts=("example.org",))
    url = "https://example.org/c.json"
    rec = Recorder(lambda req: httpx.Response(200, json={"client_id": url, "redirect_uris": [REDIRECT]}))
    assert fetch_client_document(url, s, rec.client()) is not None
    assert fetch_client_document(URL, s, Recorder().client()) is None


def test_oversize_body_is_refused_while_streaming():
    big = b'{"client_id": "' + b"x" * (MAX_BYTES + 1) + b'"}'
    assert fetch_client_document(URL, S, Recorder(lambda req: httpx.Response(200, content=big)).client()) is None

    class Endless(httpx.SyncByteStream):
        def __init__(self):
            self.yielded = 0
        def __iter__(self):
            while True:
                self.yielded += 1
                yield b"x" * 1024
                assert self.yielded < 1000, "the body was read without a cap"

    stream = Endless()
    assert fetch_client_document(URL, S, Recorder(lambda req: httpx.Response(200, stream=stream)).client()) is None
    assert stream.yielded <= MAX_BYTES // 1024 + 2


def test_redirects_are_not_followed():
    rec = Recorder(lambda req: httpx.Response(302, headers={"location": "https://chatgpt.com/other.json"})
                   if req.url.path == "/oauth/client.json" else httpx.Response(200, json=good_doc()))
    assert fetch_client_document(URL, S, rec.client()) is None
    assert rec.calls == 1


def test_slow_drip_body_hits_the_total_deadline():
    now = [0.0]

    class Drip(httpx.SyncByteStream):
        def __init__(self):
            self.yielded = 0
        def __iter__(self):
            while True:
                self.yielded += 1
                now[0] += 1.0                # each tiny chunk "takes" one second
                yield b" "

    stream = Drip()
    rec = Recorder(lambda req: httpx.Response(200, stream=stream))
    assert fetch_client_document(URL, S, rec.client(), clock=lambda: now[0]) is None
    assert stream.yielded <= 7               # gave up at the 5 s deadline, long before the size cap


def test_fetch_sets_a_timeout_and_accepts_json():
    rec = Recorder()
    fetch_client_document(URL, S, rec.client())
    assert rec.requests[0].headers["accept"] == "application/json"
    assert rec.requests[0].extensions["timeout"]["read"] == 5.0


# provider: in-memory 24 h cache, not persisted
@pytest.fixture
def anyio_backend():
    return "asyncio"


def make_provider(tmp_path, rec, now):
    s = Settings(issuer_url=S.issuer_url, mail_resource_url=S.mail_resource_url, mail_servers=S.mail_servers,
                 db_path=tmp_path / "s.sqlite")
    store = Store(s.db_path)
    return GatewayProvider(s, store, cimd_http=rec.client(), clock=lambda: now[0]), store


@pytest.mark.anyio
async def test_get_client_caches_for_24h_without_persisting(tmp_path):
    rec, now = Recorder(), [1000.0]
    prov, store = make_provider(tmp_path, rec, now)
    first = await prov.get_client(URL)
    assert first.client_id == URL and rec.calls == 1
    now[0] += 86400 - 1
    assert (await prov.get_client(URL)).client_id == URL and rec.calls == 1   # within TTL: no refetch
    assert store.get_client(URL) is None                                      # never persisted
    now[0] += 2
    await prov.get_client(URL)
    assert rec.calls == 2                                                      # expired: refetched


@pytest.mark.anyio
async def test_failures_are_cached_for_60s_and_plain_ids_skip_the_network(tmp_path):
    rec, now = Recorder(lambda req: httpx.Response(500)), [0.0]
    prov, _ = make_provider(tmp_path, rec, now)
    assert await prov.get_client(URL) is None and await prov.get_client(URL) is None
    assert rec.calls == 1                      # the second attempt within 60 s never fetches
    now[0] += 59
    assert await prov.get_client(URL) is None and rec.calls == 1
    now[0] += 2
    assert await prov.get_client(URL) is None and rec.calls == 2
    assert await prov.get_client("not-a-url") is None
    assert await prov.get_client("https://internal.example.com/x") is None
    assert rec.calls == 2


@pytest.mark.anyio
async def test_refused_urls_do_not_raise_from_get_client(tmp_path):
    rec, now = Recorder(), [0.0]
    prov, _ = make_provider(tmp_path, rec, now)
    for bad in ("https://chatgpt.com%09/x", "https://chatgpt.com\t/x", "https://evil.com\\.chatgpt.com/x"):
        assert await prov.get_client(bad) is None
    assert rec.calls == 0


@pytest.mark.anyio
async def test_cimd_fetches_use_their_own_small_worker_limiter(tmp_path):
    import threading
    import time
    import anyio
    lock, live, peak = threading.Lock(), [0], [0]

    def handler(req):
        with lock:
            live[0] += 1
            peak[0] = max(peak[0], live[0])
        time.sleep(0.05)
        with lock:
            live[0] -= 1
        return httpx.Response(200, json=good_doc(str(req.url)))

    prov, _ = make_provider(tmp_path, Recorder(handler), [0.0])
    urls = [f"https://c{i}.chatgpt.com/c.json" for i in range(12)]
    async with anyio.create_task_group() as tg:
        for u in urls:
            tg.start_soon(prov.get_client, u)
    assert 1 < peak[0] <= 4


@pytest.mark.anyio
async def test_cache_size_is_bounded(tmp_path):
    rec, now = Recorder(lambda req: httpx.Response(404)), [0.0]
    prov, _ = make_provider(tmp_path, rec, now)
    for i in range(1500):
        await prov.get_client(f"https://c.chatgpt.com/{i}.json")
    assert len(prov._cimd_failures) <= 1024


CLAUDE_CODE = "https://claude.ai/oauth/claude-code-client-metadata"


def claude_code_doc(req):
    # Claude Code's published client metadata document lists loopback redirects with no port and picks a
    # free port at run time (RFC 8252 section 7.3).
    return httpx.Response(200, json={"client_id": CLAUDE_CODE, "client_name": "Claude Code",
                                     "redirect_uris": ["http://localhost/callback", "http://127.0.0.1/callback"],
                                     "token_endpoint_auth_method": "none",
                                     "grant_types": ["authorization_code", "refresh_token"],
                                     "response_types": ["code"]})


@pytest.mark.anyio
async def test_claude_code_loopback_redirect_on_any_port(tmp_path):
    from pydantic import AnyUrl
    from mcp.shared.auth import InvalidRedirectUriError
    prov, _ = make_provider(tmp_path, Recorder(claude_code_doc), [1000.0])
    client = await prov.get_client(CLAUDE_CODE)
    for ok in ("http://localhost:64766/callback", "http://127.0.0.1:50000/callback", "http://localhost/callback"):
        assert str(client.validate_redirect_uri(AnyUrl(ok))) == ok
    for bad in ("http://localhost:64766/other",          # path must match
                "https://localhost:64766/callback",      # http only for loopback
                "http://127.0.0.2:64766/callback",        # not a loopback host we accept
                "http://[::1]:64766/callback",            # host must match a registered one
                "http://localhost:64766/callback?x=1",    # query must match
                "http://evil.example:64766/callback"):
        with pytest.raises(InvalidRedirectUriError):
            client.validate_redirect_uri(AnyUrl(bad))


@pytest.mark.anyio
async def test_non_loopback_redirects_stay_exact(tmp_path):
    from pydantic import AnyUrl
    from mcp.shared.auth import InvalidRedirectUriError
    prov, _ = make_provider(tmp_path, Recorder(), [1000.0])
    client = await prov.get_client(URL)
    assert str(client.validate_redirect_uri(AnyUrl(REDIRECT))) == REDIRECT
    with pytest.raises(InvalidRedirectUriError):
        client.validate_redirect_uri(AnyUrl("https://chatgpt.com:8443/connector_platform_oauth_redirect"))


@pytest.mark.parametrize("uri", ["cursor://anysphere.cursor-mcp/oauth/callback",
                                 "https://www.cursor.com/agents/mcp/oauth/callback"])
def test_cursor_callbacks_are_on_the_default_list(uri):
    s = Settings(issuer_url="https://mcp.example", mail_resource_url="https://mcp.example/mail",
                 mail_servers=(MailServer("mail.example"),), db_path=Path("/nonexistent"))
    assert redirect_allowed(uri, s)
    assert not redirect_allowed(uri, replace(s, redirect_allowlist=()))      # an operator can drop them
    assert not redirect_allowed(uri + "x", s)
