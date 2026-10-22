# SPDX-License-Identifier: AGPL-3.0-or-later
"""Gateway middleware: housekeeping (database purge), per-IP request limits, and the access-log filter."""
import logging
import time

import pytest
from pydantic import AnyUrl
from starlette.testclient import TestClient
from mcp.server.auth.provider import AuthorizationParams

from mcp_server_imap_smtp import middleware
from mcp_server_imap_smtp.app import build_app
from mcp_server_imap_smtp.ratelimit import RateLimiter
from tests.test_e2e import BASE, CB, MAIL, MAIL1, make_settings, no_network, register


@pytest.fixture
def anyio_backend():
    return "asyncio"


async def ok_app(scope, receive, send):
    if scope["type"] == "http":
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


async def call(app, scope):
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)
    await app({"type": "http", "path": "/", "method": "GET", "headers": [], "client": ("1.1.1.1", 1), **scope},
              receive, send)
    return sent


# --- housekeeping -------------------------------------------------------------------------------

@pytest.mark.anyio
async def test_maintenance_purges_on_first_traffic_then_hourly():
    clock = [1000.0]
    runs = []
    app = middleware.Maintenance(ok_app, lambda: runs.append(clock[0]), every=3600, clock=lambda: clock[0])
    await call(app, {})
    await call(app, {})
    clock[0] += 3599
    await call(app, {})
    assert runs == [1000.0]
    clock[0] += 2
    sent = await call(app, {})
    assert runs == [1000.0, 4601.0] and sent[0]["status"] == 200


@pytest.mark.anyio
async def test_maintenance_failure_is_logged_and_never_breaks_a_request(caplog):
    def boom():
        raise RuntimeError("disk full")
    app = middleware.Maintenance(ok_app, boom, every=3600, clock=lambda: 0.0)
    with caplog.at_level(logging.ERROR, logger="mcp_server_imap_smtp.maintenance"):
        sent = await call(app, {})
    assert sent[0]["status"] == 200 and "purge failed" in caplog.text


def test_app_startup_purges_expired_rows(tmp_path):
    from mcp_server_imap_smtp.store import Store
    store = Store(tmp_path / "s.sqlite")
    stale = store.create_pending("c1", AuthorizationParams(state="s", scopes=None, code_challenge="c",
                                 redirect_uri=AnyUrl(CB), redirect_uri_provided_explicitly=True, resource=MAIL), ttl=-1)
    app = build_app(make_settings(tmp_path), store=store, opener=no_network, sender=no_network,
                    verifier=lambda a, p, server: False)
    with TestClient(app, base_url=BASE):
        assert store._q("SELECT COUNT(*) AS n FROM pending")[0]["n"] == 0, stale


def test_app_purge_drops_abandoned_grants_after_refresh_ttl(tmp_path):
    from mcp_server_imap_smtp.store import Store
    store = Store(tmp_path / "s.sqlite")
    settings = make_settings(tmp_path)
    gone, _ = store.create_grant("c1", MAIL, [("me@x.co.za", "pw", MAIL1)])
    kept, _ = store.create_grant("c1", MAIL, [("you@x.co.za", "pw", MAIL1)])
    store._q("UPDATE grants SET created=? WHERE id=?", (time.time() - settings.refresh_ttl - 60, gone))
    app = build_app(settings, store=store, opener=no_network, sender=no_network, verifier=lambda a, p, server: False)
    with TestClient(app, base_url=BASE):
        assert [g["id"] for g in store.list_grants()] == [kept]


# --- per-IP request limits ----------------------------------------------------------------------

@pytest.mark.anyio
async def test_request_limits_are_per_ip_per_route_and_send_retry_after():
    reg, auth = RateLimiter(2, 900), RateLimiter(2, 900)
    app = middleware.RequestLimits(ok_app, {("POST", "/register"): reg, ("GET", "/authorize"): auth,
                                            ("POST", "/authorize"): auth}, retry_after=900)
    post_reg = {"method": "POST", "path": "/register"}
    assert [(await call(app, post_reg))[0]["status"] for _ in range(3)] == [200, 200, 429]
    blocked = await call(app, post_reg)
    assert blocked[0]["status"] == 429 and (b"retry-after", b"900") in blocked[0]["headers"]
    assert (await call(app, {**post_reg, "client": ("2.2.2.2", 1)}))[0]["status"] == 200     # another IP
    assert (await call(app, {"method": "GET", "path": "/register"}))[0]["status"] == 200       # not limited
    assert (await call(app, {"method": "POST", "path": "/mail/login"}))[0]["status"] == 200         # not limited
    assert (await call(app, {"method": "GET", "path": "/authorize"}))[0]["status"] == 200
    assert (await call(app, {"method": "POST", "path": "/authorize"}))[0]["status"] == 200     # GET and POST share
    assert (await call(app, {"method": "GET", "path": "/authorize"}))[0]["status"] == 429


def test_register_and_authorize_are_limited_in_the_app(tmp_path):
    app = build_app(make_settings(tmp_path, register_limit=2, authorize_limit=3), opener=no_network,
                    sender=no_network, verifier=lambda a, p, server: False)
    with TestClient(app, base_url=BASE, follow_redirects=False) as c:
        assert [register(c).status_code for _ in range(3)] == [201, 201, 429]
        r = register(c)
        assert r.status_code == 429 and r.headers["retry-after"] == "900"
        q = {"response_type": "code", "client_id": "nobody", "redirect_uri": CB, "code_challenge": "c" * 43,
             "code_challenge_method": "S256", "resource": MAIL}
        assert [c.get("/authorize", params=q).status_code != 429 for _ in range(3)] == [True] * 3
        assert c.post("/authorize", data=q).status_code == 429
        assert c.get("/.well-known/oauth-authorization-server").status_code == 200


def test_token_endpoint_is_limited_per_ip_in_the_app(tmp_path):
    app = build_app(make_settings(tmp_path, token_limit=2), opener=no_network, sender=no_network,
                    verifier=lambda a, p, server: False)
    form = {"grant_type": "refresh_token", "refresh_token": "rt_nope", "client_id": "nobody"}
    with TestClient(app, base_url=BASE, follow_redirects=False) as c:
        assert [c.post("/token", data=form).status_code for _ in range(2)] == [401, 401]   # reached the SDK handler
        r = c.post("/token", data=form)
        assert r.status_code == 429 and r.headers["retry-after"] == "900"
        assert c.get("/.well-known/oauth-authorization-server").status_code == 200
        assert register(c).status_code == 201                  # its own budget, not the token one


def test_limit_defaults():
    s = make_settings(__import__("pathlib").Path("/tmp/unused"))
    assert (s.register_limit, s.authorize_limit, s.token_limit, s.login_window) == (30, 30, 120, 900)


# --- access log ---------------------------------------------------------------------------------

def access_record(path):
    return logging.LogRecord("uvicorn.access", logging.INFO, __file__, 1, '%s - "%s %s HTTP/%s" %d',
                             ("1.2.3.4:5", "GET", path, "1.1", 200), None)


@pytest.mark.parametrize("path,shown", [("/mail/login?req=SECRETREQ", "/mail/login"), ("/authorize?code_challenge=x&state=y", "/authorize"),
                                        ("/mail", "/mail"), ("/?", "/")])
def test_access_log_filter_strips_query_strings(path, shown):
    rec = access_record(path)
    assert middleware.StripQuery().filter(rec) is True
    assert rec.getMessage() == f'1.2.3.4:5 - "GET {shown} HTTP/1.1" 200'


def test_access_log_filter_leaves_other_records_alone():
    rec = logging.LogRecord("uvicorn.access", logging.INFO, __file__, 1, "plain %s", ("x?y",), None)
    middleware.StripQuery().filter(rec)
    assert rec.getMessage() == "plain x?y"


def test_install_access_log_filter_is_idempotent():
    log = logging.getLogger("uvicorn.access")
    before = list(log.filters)
    try:
        middleware.install_access_log_filter()
        middleware.install_access_log_filter()
        assert sum(isinstance(f, middleware.StripQuery) for f in log.filters) == 1
    finally:
        log.filters[:] = before
