# SPDX-License-Identifier: AGPL-3.0-or-later
"""Security review 2026-10-20, finding 11 (consent phishing on the sign-in page) and finding 18 / L10
(cross-site posts to the sign-in and manage forms)."""
from mcp_server_imap_smtp.config import Settings
from tests.test_login import make_env


def test_long_app_name_is_cut_and_labelled(tmp_path):
    c, req, _, _ = make_env(tmp_path, client_name="Claude " + "x" * 200)
    r = c.get(f"/mail/login?req={req}")
    assert r.status_code == 200
    assert "x" * 61 not in r.text and "Claude " + "x" * 52 + "…" in r.text
    assert "name supplied by the app" in r.text


def test_page_names_where_the_user_returns(tmp_path):
    c, req, _, _ = make_env(tmp_path, redirect="https://grok.com/connectors-oauth-exchange-code/")
    r = c.get(f"/mail/login?req={req}")
    assert "you will return to <strong>grok.com</strong>" in r.text
    assert "Only continue if you started this from your own AI app just now." in r.text


def test_custom_scheme_return_is_named_in_full(tmp_path):
    c, req, _, _ = make_env(tmp_path, redirect="cursor://anysphere.cursor-mcp/oauth/callback")
    assert "<strong>cursor://anysphere.cursor-mcp</strong>" in c.get(f"/mail/login?req={req}").text


def test_pending_sign_in_lasts_five_minutes_by_default():
    s = Settings(issuer_url="https://mcp.example", mail_resource_url="https://mcp.example/mail",
                 mail_servers=make_servers(), db_path="x")
    assert s.pending_ttl == 300


def make_servers():
    from mcp_server_imap_smtp.mail.hosts import MailServer
    return (MailServer("mail1.hosting.example", domains=("x.co.za",), match_mx=False),)


def test_cross_site_login_post_is_refused(tmp_path):
    c, req, store, lim = make_env(tmp_path)
    data = {"req": req, "email": "me@x.co.za", "password": "pw"}
    for origin in ("https://evil.example", "null"):
        r = c.post("/mail/login", data=data, headers={"Origin": origin})
        assert r.status_code == 403
    assert lim.count("ip:testclient") == 0 and not store.list_grants()
    ok = c.post("/mail/login", data=data, headers={"Origin": "http://127.0.0.1:8765"})
    assert ok.status_code == 200 and store.list_grants()


def test_login_post_without_origin_still_works(tmp_path):
    c, req, store, _ = make_env(tmp_path)
    c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "pw"})
    assert store.list_grants()


def test_cross_site_manage_post_is_refused(tmp_path):
    c, _, _, _ = make_env(tmp_path)
    r = c.post("/mail/manage", data={"action": "signin", "email": "me@x.co.za", "password": "pw"},
               headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


def test_same_origin_referrer_policy_so_browsers_send_origin(tmp_path):
    c, req, _, _ = make_env(tmp_path)
    assert c.get(f"/mail/login?req={req}").headers["referrer-policy"] == "same-origin"
