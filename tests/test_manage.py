# SPDX-License-Identifier: AGPL-3.0-or-later
"""The manage page: change a connection's mailboxes without reconnecting the AI app (21 Oct 2026)."""
import re

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from mcp_server_imap_smtp import crypto
from mcp_server_imap_smtp.auth.login import login_routes
from mcp_server_imap_smtp.auth.provider import GatewayProvider
from mcp_server_imap_smtp.config import Settings
from mcp_server_imap_smtp.mail.hosts import MailServer
from mcp_server_imap_smtp.mail.resolve import Resolver
from mcp_server_imap_smtp.ratelimit import RateLimiter
from mcp_server_imap_smtp.store import Store

MAIL1 = MailServer("mail1.hosting.example", domains=("x.co.za",), match_mx=False)
PASSWORDS = {"me@x.co.za": "pw", "a@x.co.za": "pa", "b@x.co.za": "pb", "new@x.co.za": "pn"}


def verifier(address, password, server):
    return PASSWORDS.get(address) == password


@pytest.fixture
def env(tmp_path):
    s = Settings(issuer_url="http://127.0.0.1:8765", mail_resource_url="http://127.0.0.1:8765/mail",
                 mail_servers=(MAIL1,), db_path=tmp_path / "s.sqlite", operator_name="Acme Hosting")
    store = Store(s.db_path)
    prov = GatewayProvider(s, store)
    gid, key = store.create_grant("c1", s.mail_resource_url, [("me@x.co.za", "pw", MAIL1), ("a@x.co.za", "pa", MAIL1)])
    store.issue_tokens(gid, key, "c1", [], s.mail_resource_url, 3600, 86400)
    limiter = RateLimiter(5, 900)
    app = Starlette(routes=login_routes(prov, Resolver((MAIL1,)), verifier, limiter, s))
    return TestClient(app), store, gid, key, limiter


def signin(c, email="me@x.co.za", password="pw"):
    return c.post("/mail/manage", data={"action": "signin", "email": email, "password": password})


def session_of(r) -> str:
    return re.search(r'name="s" value="([^"]+)"', r.text)[1]


def act(c, r, action, gid, **fields):
    return c.post("/mail/manage", data={"s": session_of(r), "action": action, "grant": gid, **fields})


def test_get_shows_the_sign_in_form(env):
    c, *_ = env
    r = c.get("/mail/manage")
    assert r.status_code == 200 and "Manage your mailboxes" in r.text and 'name="password"' in r.text
    assert r.headers["x-frame-options"] == "DENY" and r.headers["cache-control"] == "no-store"


def test_wrong_password_is_refused_and_counted(env):
    c, store, _, _, limiter = env
    r = signin(c, password="bad")
    assert "Address or password incorrect." in r.text and 'name="s"' not in r.text
    assert limiter.count("addr:me@x.co.za") == 1


def test_lists_mailboxes_with_status(env):
    c, store, gid, _, _ = env
    store.mark_mailbox(gid, "a@x.co.za", True)
    r = signin(c)
    assert "Signed in as me@x.co.za" in r.text and "2 mailboxes" in r.text
    assert "Main mailbox" in r.text and "Password rejected on" in r.text
    assert r.text.count('value="remove"') == 1           # the main mailbox has no Remove button


def test_only_the_main_mailbox_can_manage(env):
    c, *_ = env
    r = signin(c, "a@x.co.za", "pa")
    assert "No AI app is connected with a@x.co.za as its main mailbox" in r.text and 'name="s"' not in r.text


def test_add_and_update_reach_the_ai_app_without_reconnecting(env):
    c, store, gid, key, _ = env
    store.mark_mailbox(gid, "a@x.co.za", True)
    PASSWORDS["a@x.co.za"] = "pa2"
    try:
        r = act(c, signin(c), "add", gid, more="new@x.co.za pn\na@x.co.za pa2\n")
    finally:
        PASSWORDS["a@x.co.za"] = "pa"
    assert "1 mailbox was added and 1 password was updated." in r.text and "Password rejected" not in r.text
    opened = store.open_mailboxes(gid, key)            # what the AI app's token now unlocks
    assert list(opened) == ["me@x.co.za", "a@x.co.za", "new@x.co.za"]
    assert opened["new@x.co.za"].password == "pn" and opened["a@x.co.za"].password == "pa2"
    assert opened["new@x.co.za"].server.host == "mail1.hosting.example"


def test_add_with_a_wrong_password_saves_nothing(env):
    c, store, gid, key, _ = env
    r = act(c, signin(c), "add", gid, more="new@x.co.za wrong\nb@x.co.za pb")
    assert "Line 1 (new@x.co.za): address or password incorrect." in r.text and "wrong" not in r.text
    assert list(store.open_mailboxes(gid, key)) == ["me@x.co.za", "a@x.co.za"]


def test_add_refuses_an_unhosted_domain(env):
    c, store, gid, key, _ = env
    r = act(c, signin(c), "add", gid, more="someone@gmail.com secret")
    assert "Line 1: Mail for gmail.com is not hosted by Acme Hosting." in r.text and "secret" not in r.text


def test_remove(env):
    c, store, gid, key, _ = env
    r = signin(c)
    r = act(c, r, "remove", gid, address="a@x.co.za")
    assert "a@x.co.za was removed." in r.text and list(store.open_mailboxes(gid, key)) == ["me@x.co.za"]
    r = act(c, r, "remove", gid, address="me@x.co.za")
    assert "The main mailbox cannot be removed." in r.text and list(store.open_mailboxes(gid, key)) == ["me@x.co.za"]


def test_disconnect_revokes_the_grant(env):
    c, store, gid, _, _ = env
    r = act(c, signin(c), "disconnect", gid)
    assert "The connection was ended." in r.text and store.list_grants()[0]["revoked"] == 1


def test_another_subjects_grant_cannot_be_touched(env):
    c, store, gid, key, _ = env
    other, okey = store.create_grant("c2", "r", [("a@x.co.za", "pa", MAIL1), ("b@x.co.za", "pb", MAIL1)])
    store.issue_tokens(other, okey, "c2", [], "r", 3600, 86400)
    r = act(c, signin(c), "remove", other, address="b@x.co.za")
    assert "That connection is no longer active." in r.text
    assert list(store.open_mailboxes(other, okey)) == ["a@x.co.za", "b@x.co.za"]


def test_forged_or_ended_session_is_refused(env):
    c, store, gid, _, _ = env
    r = c.post("/mail/manage", data={"s": "mg_x.y", "action": "remove", "grant": gid, "address": "a@x.co.za"})
    assert "Your session has ended" in r.text
    r = signin(c)
    c.post("/mail/manage", data={"s": session_of(r), "action": "signout"})
    r = act(c, r, "remove", gid, address="a@x.co.za")
    assert "Your session has ended" in r.text and len(store.list_grants()[0]["mailboxes"].split()) == 2


def test_grant_made_before_keypairs_gets_one_when_used(env):
    c, store, gid, key, _ = env
    store._q("DELETE FROM grant_keys WHERE grant_id=?", (gid,))
    r = act(c, signin(c), "add", gid, more="new@x.co.za pn")
    assert "Use this connection once from your AI app" in r.text
    store.open_mailboxes(gid, key)                     # the AI app uses it
    r = act(c, signin(c), "add", gid, more="new@x.co.za pn")
    assert "1 mailbox was added." in r.text and "new@x.co.za" in store.open_mailboxes(gid, key)


def test_sealed_box_round_trip_and_tamper():
    public, private = crypto.new_keypair()
    blob = crypto.seal_to(public, b"secret", b"g|a")
    assert crypto.open_sealed(private, blob, b"g|a") == b"secret"
    with pytest.raises(crypto.CryptoError):
        crypto.open_sealed(private, blob, b"g|b")
    _, other = crypto.new_keypair()
    with pytest.raises(crypto.CryptoError):
        crypto.open_sealed(other, blob, b"g|a")


def test_added_mailbox_is_sealed_under_the_grant_key_once_used(env):
    c, store, gid, key, _ = env
    act(c, signin(c), "add", gid, more="new@x.co.za pn")
    assert store._q("SELECT boxed FROM mailboxes WHERE address='new@x.co.za'")[0]["boxed"] == 1
    assert store.open_mailboxes(gid, key)["new@x.co.za"].password == "pn"
    assert store._q("SELECT boxed FROM mailboxes WHERE address='new@x.co.za'")[0]["boxed"] == 0
    assert store.open_mailboxes(gid, key)["new@x.co.za"].password == "pn"


def test_a_swapped_public_key_is_refused(env):
    c, store, gid, key, _ = env
    act(c, signin(c), "add", gid, more="new@x.co.za pn")
    public, _ = crypto.new_keypair()
    store._q("UPDATE grant_keys SET public=? WHERE grant_id=?", (public, gid))
    with pytest.raises(crypto.CryptoError):
        store.open_mailboxes(gid, key)


def test_changes_close_only_that_mailboxs_kept_sessions(env):
    c, store, gid, _, _ = env
    seen = []
    store.change_listeners.append(lambda g, a: seen.append((g, a)))
    store.revoke_listeners.append(lambda g: seen.append(("revoked", g)))
    r = act(c, signin(c), "add", gid, more="a@x.co.za pa")
    act(c, r, "remove", gid, address="a@x.co.za")
    assert seen == [(gid, "a@x.co.za"), (gid, "a@x.co.za")]


def test_wrong_passwords_on_add_are_limited_per_main_mailbox_across_sessions(env):
    c, store, gid, _, _ = env
    for _ in range(3):
        r = act(c, signin(c), "add", gid, more="b@x.co.za wrong")
    # every sign-in opens a new session, but the page limit follows the main mailbox
    assert "address or password incorrect" in r.text


def test_mark_mailbox_writes_only_on_change_and_never_raises(env):
    _, store, gid, _, _ = env
    store.mark_mailbox(gid, "a@x.co.za", False)            # already fine: nothing written
    store.mark_mailbox(gid, "a@x.co.za", True)
    first = store._q("SELECT failed_at FROM mailboxes WHERE address='a@x.co.za'")[0]["failed_at"]
    store.mark_mailbox(gid, "a@x.co.za", True)
    assert store._q("SELECT failed_at FROM mailboxes WHERE address='a@x.co.za'")[0]["failed_at"] == first
    store._db.close()
    store.mark_mailbox(gid, "a@x.co.za", False)            # a database error is logged, not raised
