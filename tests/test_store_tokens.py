# SPDX-License-Identifier: AGPL-3.0-or-later
import sqlite3
import threading

import pytest
from mcp.server.auth.provider import AuthorizationParams
from pydantic import AnyUrl

from mcp_server_imap_smtp.store import Store
from mcp_server_imap_smtp.mail.hosts import MailServer as _MailServer
MAIL1 = _MailServer("mail1.hosting.example")


def flat(unlocked):
    """(grant, {address: (password, host, imap_port, smtp_port)}) for comparison."""
    gid, boxes = unlocked
    return gid, {a: (c.password, c.server.host, c.server.imap_port, c.server.smtp_port) for a, c in boxes.items()}


def P():
    return AuthorizationParams(state=None, scopes=None, code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        redirect_uri=AnyUrl("https://claude.ai/api/mcp/auth_callback"),
        redirect_uri_provided_explicitly=True, resource="r")


def setup(tmp_path):
    s = Store(tmp_path / "s.sqlite")
    gid, key = s.create_grant("c1", "r", [("me@x.co.za", "pw", MAIL1)])
    return s, gid, key


def race(fn, n=8):
    """Run fn in n threads released together; return the list of results."""
    barrier = threading.Barrier(n)
    results, errors = [], []

    def run():
        barrier.wait()
        try:
            results.append(fn())
        except Exception as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    threads = [threading.Thread(target=run) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    return results


def test_code_single_use(tmp_path):
    s, gid, key = setup(tmp_path)
    code = s.issue_code(gid, key, "c1", P(), ttl=300)
    assert s.load_code(code).grant_id == gid
    assert s.load_code(code + "x") is None
    assert s.consume_code(code) == key
    assert s.consume_code(code) is None


def test_code_wrong_secret_does_not_delete(tmp_path):
    s, gid, key = setup(tmp_path)
    code = s.issue_code(gid, key, "c1", P(), ttl=300)
    head, _, _ = code.partition(".")
    assert s.consume_code(head + ".wrongsecret") is None
    assert s.load_code(code) is not None
    assert s.consume_code(code) == key


def test_expired_code(tmp_path):
    s, gid, key = setup(tmp_path)
    code = s.issue_code(gid, key, "c1", P(), ttl=-1)
    assert s.load_code(code) is None
    assert s.consume_code(code) is None


def test_code_consume_concurrent_exactly_one_wins(tmp_path):
    s, gid, key = setup(tmp_path)
    code = s.issue_code(gid, key, "c1", P(), ttl=300)
    results = race(lambda: s.consume_code(code))
    assert results.count(key) == 1
    assert results.count(None) == len(results) - 1


def test_access_token_unlocks_mailboxes(tmp_path):
    s, gid, key = setup(tmp_path)
    at, rt = s.issue_tokens(gid, key, "c1", [], "r", 3600, 86400)
    assert s.load_token(at, "access").resource == "r"
    assert s.load_token(at, "refresh") is None           # wrong kind
    assert flat(s.unlock(at)) == (gid, {"me@x.co.za": ("pw", "mail1.hosting.example", 993, 465)})
    assert s.unlock(rt) is None


def test_refresh_rotation_single_use(tmp_path):
    s, gid, key = setup(tmp_path)
    at, rt = s.issue_tokens(gid, key, "c1", [], "r", 3600, 86400)
    k2 = s.key_for(rt, "refresh"); s.delete_token(rt)
    at2, rt2 = s.issue_tokens(gid, k2, "c1", [], "r", 3600, 86400)
    assert s.load_token(rt, "refresh") is None            # replay refused
    assert flat(s.unlock(at2))[1] == {"me@x.co.za": ("pw", "mail1.hosting.example", 993, 465)}


def test_revoked_grant_kills_tokens(tmp_path):
    s, gid, key = setup(tmp_path)
    at, rt = s.issue_tokens(gid, key, "c1", [], "r", 3600, 86400)
    s.revoke_grant(gid)
    assert s.load_token(at, "access") is None and s.unlock(at) is None


def test_expired_access_token(tmp_path):
    s, gid, key = setup(tmp_path)
    at, _ = s.issue_tokens(gid, key, "c1", [], "r", -1, 86400)
    assert s.load_token(at, "access") is None


def test_tx_rolls_back_on_base_exception(tmp_path):
    s, gid, key = setup(tmp_path)
    with pytest.raises(KeyboardInterrupt):
        with s._tx():
            s._q("UPDATE grants SET revoked=1 WHERE id=?", (gid,))
            raise KeyboardInterrupt
    assert s._q("SELECT revoked FROM grants WHERE id=?", (gid,))[0]["revoked"] == 0
    assert not s._db.in_transaction


def test_tx_begin_failure_is_not_masked_by_rollback(tmp_path):
    s, gid, key = setup(tmp_path)
    with s._tx():
        s._q("UPDATE grants SET revoked=1 WHERE id=?", (gid,))
        with pytest.raises(sqlite3.OperationalError, match="within a transaction"):
            with s._tx():
                pass
        assert s._db.in_transaction            # the failed BEGIN did not roll back the outer work
    assert s._q("SELECT revoked FROM grants WHERE id=?", (gid,))[0]["revoked"] == 1


def test_tx_rollback_skipped_when_transaction_already_ended(tmp_path):
    s, gid, key = setup(tmp_path)
    with pytest.raises(RuntimeError, match="boom"):
        with s._tx():
            s._db.execute("COMMIT")           # something ended the transaction early
            raise RuntimeError("boom")        # must surface, not be masked by a failing ROLLBACK


def test_records_do_not_repr_their_secrets(tmp_path):
    s, gid, key = setup(tmp_path)
    code = s.issue_code(gid, key, "c1", P(), ttl=300)
    at, rt = s.issue_tokens(gid, key, "c1", [], "r", 3600, 86400)
    assert code not in repr(s.load_code(code))
    assert at not in repr(s.load_token(at, "access"))
    secret = rt.rsplit(".", 1)[1]
    assert secret not in repr(s.load_token(rt, "refresh"))
    assert rt not in repr(s.rotate_and_issue(rt, "c1", None, 3600, 86400))


def test_grant_subject(tmp_path):
    s, gid, key = setup(tmp_path)
    assert s.grant_subject(gid) == "me@x.co.za"
    assert s.grant_subject("nope") is None


def test_rotate_and_issue_swaps_the_pair_in_one_step(tmp_path):
    s, gid, key = setup(tmp_path)
    at, rt = s.issue_tokens(gid, key, "c1", ["a"], "r", 3600, 86400)
    rec, at2, rt2 = s.rotate_and_issue(rt, "c1", ["b"], 3600, 86400)
    assert (rec.kind, rec.grant_id, rec.client_id, rec.scopes, rec.resource) == ("refresh", gid, "c1", ["a"], "r")
    assert s.load_token(rt, "refresh") is None                           # old refresh token gone
    assert s.load_token(at, "access") is not None                        # old access token left to expire
    assert s.load_token(at2, "access").scopes == ["b"] and s.load_token(rt2, "refresh").scopes == ["b"]
    assert flat(s.unlock(at2)) == (gid, {"me@x.co.za": ("pw", "mail1.hosting.example", 993, 465)})
    assert s.rotate_and_issue(rt, "c1", [], 3600, 86400) is None         # replay refused
    assert s.rotate_and_issue(at2, "c1", [], 3600, 86400) is None        # access token is not a refresh token


def test_rotate_and_issue_wrong_client_keeps_token(tmp_path):
    s, gid, key = setup(tmp_path)
    _, rt = s.issue_tokens(gid, key, "c1", [], "r", 3600, 86400)
    assert s.rotate_and_issue(rt, "c2", [], 3600, 86400) is None
    assert s.load_token(rt, "refresh") is not None                       # NOT deleted by the failed attempt
    assert s.rotate_and_issue(rt, "c1", [], 3600, 86400) is not None


def test_rotate_and_issue_wrong_secret_expired_and_revoked(tmp_path):
    s, gid, key = setup(tmp_path)
    _, rt = s.issue_tokens(gid, key, "c1", [], "r", 3600, 86400)
    head, _, _ = rt.partition(".")
    assert s.rotate_and_issue(head + ".wrongsecret", "c1", [], 3600, 86400) is None
    assert s.load_token(rt, "refresh") is not None
    _, expired = s.issue_tokens(gid, key, "c1", [], "r", 3600, -1)
    assert s.rotate_and_issue(expired, "c1", [], 3600, 86400) is None
    s.revoke_grant(gid)
    assert s.rotate_and_issue(rt, "c1", [], 3600, 86400) is None


def test_rotate_and_issue_concurrent_exactly_one_wins(tmp_path):
    s, gid, key = setup(tmp_path)
    _, rt = s.issue_tokens(gid, key, "c1", [], "r", 3600, 86400)
    results = race(lambda: s.rotate_and_issue(rt, "c1", [], 3600, 86400))
    assert len([r for r in results if r is not None]) == 1
    assert s._q("SELECT count(*) AS n FROM tokens WHERE kind='refresh'")[0]["n"] == 1


def test_rotate_and_issue_none_scopes_inherits(tmp_path):
    s, gid, key = setup(tmp_path)
    _, rt = s.issue_tokens(gid, key, "c1", ["a", "b"], "r", 3600, 86400)
    _, at2, _ = s.rotate_and_issue(rt, "c1", None, 3600, 86400)
    assert s.load_token(at2, "access").scopes == ["a", "b"]
