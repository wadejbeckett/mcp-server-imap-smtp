# SPDX-License-Identifier: AGPL-3.0-or-later
import sqlite3
import threading
import time
from pathlib import Path
from pydantic import AnyUrl
from mcp.server.auth.provider import AuthorizationParams
from mcp.shared.auth import OAuthClientInformationFull
import json
import pytest
from mcp_server_imap_smtp import crypto
from mcp_server_imap_smtp.store import MailboxCred, Store
from mcp_server_imap_smtp.mail.hosts import MailServer as _MailServer
MAIL1 = _MailServer("mail1.hosting.example")

def params():
    return AuthorizationParams(state="st", scopes=None, code_challenge="cc",
        redirect_uri=AnyUrl("https://claude.ai/api/mcp/auth_callback"),
        redirect_uri_provided_explicitly=True, resource="http://127.0.0.1:8765/mail")

def test_client_roundtrip(tmp_path):
    s = Store(tmp_path / "s.sqlite")
    info = OAuthClientInformationFull(client_id="c1", redirect_uris=[AnyUrl("https://claude.ai/api/mcp/auth_callback")],
                                      token_endpoint_auth_method="none")
    s.save_client(info)
    assert s.get_client("c1").client_id == "c1"
    assert s.get_client("nope") is None

def test_pending_is_single_use_and_expires(tmp_path):
    s = Store(tmp_path / "s.sqlite")
    req = s.create_pending("c1", params(), ttl=600)
    assert s.peek_pending(req)[0] == "c1"
    assert s.take_pending(req)[1].state == "st"
    assert s.take_pending(req) is None
    old = s.create_pending("c1", params(), ttl=-1)
    assert s.peek_pending(old) is None

def test_grant_seals_passwords(tmp_path):
    s = Store(tmp_path / "s.sqlite")
    # Use unique passwords to avoid false positives
    gid, key = s.create_grant("c1", "r", [("me@x.co.za", "pw-ALPHA-7f3a91", MAIL1), ("accounts@x.co.za", "pw-BRAVO-c02e55", MAIL1)])
    mailboxes = s.open_mailboxes(gid, key)
    assert {a: c.password for a, c in mailboxes.items()} == {"me@x.co.za": "pw-ALPHA-7f3a91",
                                                             "accounts@x.co.za": "pw-BRAVO-c02e55"}
    # Assert insertion order is preserved
    assert list(mailboxes.keys()) == ["me@x.co.za", "accounts@x.co.za"]
    # Read main file plus any WAL/SHM siblings (WAL mode might have data in -wal/-shm files)
    raw = (tmp_path / "s.sqlite").read_bytes()
    for sibling in [(tmp_path / "s.sqlite-wal"), (tmp_path / "s.sqlite-shm")]:
        if sibling.exists():
            raw += sibling.read_bytes()
    # Positive control: address is present (not vacuous absence check)
    assert b"me@x.co.za" in raw
    # Passwords are sealed and not present
    assert b"pw-ALPHA-7f3a91" not in raw and b"pw-BRAVO-c02e55" not in raw
    assert s.revoke_address("accounts@x.co.za") == 1
    assert s.list_grants()[0]["revoked"] == 1

def test_file_permissions_secure(tmp_path):
    """Verify main, WAL, and SHM files have secure 0o600 permissions."""
    db_path = tmp_path / "s.sqlite"
    s = Store(db_path)
    # Write a grant to ensure WAL/SHM files are created
    s.create_grant("c1", "r", [("test@x.co.za", "password", MAIL1)])
    # Check main file
    assert (db_path.stat().st_mode & 0o777) == 0o600
    # Check WAL and SHM files if they exist
    for suffix in ["-wal", "-shm"]:
        p = Path(str(db_path) + suffix)
        if p.exists():
            assert (p.stat().st_mode & 0o777) == 0o600, f"{p.name} has insecure permissions"

def test_take_pending_atomic(tmp_path):
    """Verify take_pending is atomic (no race condition with concurrent calls)."""
    s = Store(tmp_path / "s.sqlite")
    req = s.create_pending("c1", params(), ttl=600)
    results = []

    def take_it():
        result = s.take_pending(req)
        results.append(result)

    # Two threads try to take the same pending request
    t1 = threading.Thread(target=take_it)
    t2 = threading.Thread(target=take_it)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    # Exactly one should get a result, the other None
    assert sum(1 for r in results if r is not None) == 1
    assert sum(1 for r in results if r is None) == 1

def test_create_grant_duplicate_address_within_grant_rolls_back(tmp_path):
    """Verify create_grant with duplicate address within same grant raises and leaves no orphan grant."""
    s = Store(tmp_path / "s.sqlite")

    # Try to create a grant with duplicate address in the mailboxes list (will fail on second mailbox insert)
    try:
        s.create_grant("c1", "r", [("me@x.co.za", "pw1", MAIL1), ("me@x.co.za", "pw2", MAIL1)])
        assert False, "should have raised IntegrityError"
    except sqlite3.IntegrityError:
        pass

    # Verify no grant was created (transaction rolled back completely)
    grants = s.list_grants()
    assert len(grants) == 0


def test_list_grants_orders_mailboxes_by_position(tmp_path):
    s = Store(tmp_path / "s.sqlite")
    s.create_grant("c1", "r", [("zed@x.co.za", "1", MAIL1), ("alpha@x.co.za", "2", MAIL1), ("mid@x.co.za", "3", MAIL1)])
    s.create_grant("c2", "r", [("solo@x.co.za", "1", MAIL1)])
    got = [g["mailboxes"] for g in s.list_grants()]
    assert got == ["zed@x.co.za alpha@x.co.za mid@x.co.za", "solo@x.co.za"]


DAY = 86400


def count(s, table):
    return s._q(f"SELECT COUNT(*) AS n FROM {table}")[0]["n"]


def test_purge_removes_expired_pending_codes_and_tokens_only(tmp_path):
    s = Store(tmp_path / "s.sqlite")
    live_req = s.create_pending("c1", params(), ttl=600)
    s.create_pending("c1", params(), ttl=-1)
    gid, key = s.create_grant("c1", "r", [("me@x.co.za", "pw", MAIL1)])
    live_code = s.issue_code(gid, key, "c1", params(), ttl=300)
    s.issue_code(gid, key, "c1", params(), ttl=-1)
    at, rt = s.issue_tokens(gid, key, "c1", [], "r", access_ttl=-1, refresh_ttl=3600)
    assert s.purge_expired() == {"pending": 1, "codes": 1, "tokens": 1, "spent": 0, "manage": 0, "grants": 0, "abandoned": 0,
                                 "clients": 0}
    assert s.peek_pending(live_req) and s.load_code(live_code) and s.load_token(rt, "refresh")
    assert count(s, "pending") == 1 and count(s, "codes") == 1 and count(s, "tokens") == 1
    assert s.purge_expired() == {"pending": 0, "codes": 0, "tokens": 0, "spent": 0, "manage": 0, "grants": 0, "abandoned": 0, "clients": 0}


def test_purge_deletes_revoked_grants_older_than_30_days_with_their_mailboxes(tmp_path):
    s = Store(tmp_path / "s.sqlite")
    now = time.time()
    revoked, _ = s.create_grant("c1", "r", [("a@x.co.za", "pw", MAIL1), ("b@x.co.za", "pw", MAIL1)])
    active, key = s.create_grant("c1", "r", [("c@x.co.za", "pw", MAIL1)])
    s.issue_tokens(active, key, "c1", [], "r", access_ttl=3600, refresh_ttl=90 * DAY)
    s.revoke_grant(revoked)
    assert s.purge_expired(now + 29 * DAY)["grants"] == 0 and count(s, "grants") == 2
    out = s.purge_expired(now + 31 * DAY)
    assert out["grants"] == 1
    assert [g["id"] for g in s.list_grants()] == [active]
    assert [r["address"] for r in s._q("SELECT address FROM mailboxes")] == ["c@x.co.za"]


def test_purge_deletes_old_registered_clients_without_grants(tmp_path):
    s = Store(tmp_path / "s.sqlite")
    now = time.time()
    for cid in ("unused", "used", "https://chatgpt.com/oauth/client.json"):
        s.save_client(OAuthClientInformationFull(client_id=cid, redirect_uris=[AnyUrl("https://claude.ai/api/mcp/auth_callback")],
                                                 token_endpoint_auth_method="none"))
    s.create_grant("used", "r", [("me@x.co.za", "pw", MAIL1)])
    assert s.purge_expired(now + 0.9 * DAY)["clients"] == 0
    assert s.purge_expired(now + 1.1 * DAY)["clients"] == 1
    assert s.get_client("unused") is None and s.get_client("used") and s.get_client("https://chatgpt.com/oauth/client.json")


def test_revoking_records_revoked_at_once(tmp_path, monkeypatch):
    s = Store(tmp_path / "s.sqlite")
    gid, _ = s.create_grant("c1", "r", [("me@x.co.za", "pw", MAIL1)])
    other, _ = s.create_grant("c1", "r", [("you@x.co.za", "pw", MAIL1)])
    assert {g["id"]: g["revoked_at"] for g in s.list_grants()} == {gid: None, other: None}
    clock = [time.time() + 5 * DAY]
    monkeypatch.setattr("mcp_server_imap_smtp.store.time.time", lambda: clock[0])
    s.revoke_grant(gid)
    s.revoke_address("you@x.co.za")
    first = {g["id"]: g["revoked_at"] for g in s.list_grants()}
    assert first == {gid: clock[0], other: clock[0]}
    clock[0] += DAY      # revoking again neither counts nor restarts the clock
    assert s.revoke_grant(gid) == 0 and s.revoke_address("you@x.co.za") == 0
    assert {g["id"]: g["revoked_at"] for g in s.list_grants()} == first


def test_purge_ages_revoked_grants_from_revocation_not_creation(tmp_path, monkeypatch):
    s = Store(tmp_path / "s.sqlite")
    now = time.time()
    gid, _ = s.create_grant("c1", "r", [("me@x.co.za", "pw", MAIL1)])
    monkeypatch.setattr("mcp_server_imap_smtp.store.time.time", lambda: now + 60 * DAY)
    s.revoke_grant(gid)                                   # created 60 days ago, revoked "today"
    assert s.purge_expired(now + 61 * DAY)["grants"] == 0 and count(s, "grants") == 1
    assert s.purge_expired(now + 89 * DAY)["grants"] == 0
    assert s.purge_expired(now + 91 * DAY)["grants"] == 1
    assert count(s, "grants") == 0 and count(s, "mailboxes") == 0


def test_existing_database_gains_revoked_at_and_old_revoked_grants_age_from_created(tmp_path):
    path = tmp_path / "old.sqlite"
    db = sqlite3.connect(path)
    db.executescript("""
        CREATE TABLE grants (id TEXT PRIMARY KEY, client_id TEXT NOT NULL, resource TEXT NOT NULL,
            subject TEXT NOT NULL, created REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE mailboxes (grant_id TEXT NOT NULL, position INTEGER NOT NULL, address TEXT NOT NULL,
            sealed BLOB NOT NULL, PRIMARY KEY (grant_id, address));""")
    now = time.time()
    db.execute("INSERT INTO grants VALUES ('old', 'c1', 'r', 'me@x.co.za', ?, 1)", (now - 40 * DAY,))
    db.execute("INSERT INTO grants VALUES ('live', 'c1', 'r', 'you@x.co.za', ?, 0)", (now,))
    db.execute("INSERT INTO mailboxes VALUES ('old', 0, 'me@x.co.za', x'00')")
    db.commit(); db.close()
    s = Store(path)
    Store(path)                                           # opening twice must not try to add the column again
    cols = [r["name"] for r in s._q("PRAGMA table_info(grants)")]
    assert "revoked_at" in cols
    assert {g["id"]: g["revoked_at"] for g in s.list_grants()} == {"old": None, "live": None}
    s.revoke_grant("live")
    assert s.list_grants()[1]["revoked_at"] is not None
    assert s.purge_expired(now)["grants"] == 1                  # NULL revoked_at falls back to created
    assert [g["id"] for g in s.list_grants()] == ["live"] and count(s, "mailboxes") == 0


def test_purge_deletes_abandoned_grants_older_than_refresh_ttl(tmp_path):
    s = Store(tmp_path / "s.sqlite")
    now = time.time()
    ttl = 30 * DAY
    abandoned, key_a = s.create_grant("c1", "r", [("a@x.co.za", "pw", MAIL1), ("b@x.co.za", "pw", MAIL1)])
    s.issue_code(abandoned, key_a, "c1", params(), ttl=300)           # never exchanged; expires
    s.issue_tokens(abandoned, key_a, "c1", [], "r", access_ttl=3600, refresh_ttl=ttl)   # never refreshed
    live, key_l = s.create_grant("c1", "r", [("c@x.co.za", "pw", MAIL1)])
    s.issue_tokens(live, key_l, "c1", [], "r", access_ttl=3600, refresh_ttl=60 * DAY)   # still refreshable
    pending, key_p = s.create_grant("c1", "r", [("d@x.co.za", "pw", MAIL1)])
    s.issue_code(pending, key_p, "c1", params(), ttl=40 * DAY)       # an unused code still holds it
    revoked, _ = s.create_grant("c1", "r", [("e@x.co.za", "pw", MAIL1)])
    s.revoke_grant(revoked)                                            # handled by the revoked rule only
    assert s.purge_expired(now + 29 * DAY, refresh_ttl=ttl)["abandoned"] == 0
    assert s.purge_expired(now + ttl - 60, refresh_ttl=ttl)["abandoned"] == 0
    out = s.purge_expired(now + 31 * DAY, refresh_ttl=ttl)
    assert out["abandoned"] == 1 and out["grants"] == 1
    assert sorted(g["id"] for g in s.list_grants()) == sorted([live, pending])
    assert sorted(r["address"] for r in s._q("SELECT address FROM mailboxes")) == ["c@x.co.za", "d@x.co.za"]
    assert count(s, "tokens") == 1 and count(s, "codes") == 1          # the live refresh token, the unused code


def test_purge_without_refresh_ttl_keeps_abandoned_grants(tmp_path):
    s = Store(tmp_path / "s.sqlite")
    s.create_grant("c1", "r", [("a@x.co.za", "pw", MAIL1)])
    assert s.purge_expired(time.time() + 365 * DAY)["abandoned"] == 0 and count(s, "grants") == 1


ISP = _MailServer("mail.client.example", imap_port=1993, smtp_port=587, domains=("client.example",), match_mx=False)


def test_each_mailbox_keeps_its_own_server(tmp_path):
    s = Store(tmp_path / "s.sqlite")
    gid, key = s.create_grant("c1", "r", [("me@x.co.za", "pw1", MAIL1), ("ops@client.example", "pw2", ISP)])
    boxes = s.open_mailboxes(gid, key)
    assert [(a, c.password, c.server.host, c.server.imap_port, c.server.smtp_port) for a, c in boxes.items()] == [
        ("me@x.co.za", "pw1", "mail1.hosting.example", 993, 465),
        ("ops@client.example", "pw2", "mail.client.example", 1993, 587)]
    assert "pw1" not in repr(boxes["me@x.co.za"])          # the password never shows in a repr or log line


def test_sealed_blob_is_json_with_password_and_server(tmp_path):
    s = Store(tmp_path / "s.sqlite")
    gid, key = s.create_grant("c1", "r", [("me@x.co.za", "pw1", ISP)])
    (row,) = s._q("SELECT sealed FROM mailboxes")
    assert b"ispconfig" not in row["sealed"]                # the server is sealed too
    assert json.loads(crypto.unseal(key, row["sealed"], f"{gid}|me@x.co.za".encode())) == {
        "password": "pw1", "host": "mail.client.example", "imap_port": 1993, "smtp_port": 587}


def _legacy_grant(s):
    """A grant written before servers were sealed: the blob is the bare password."""
    gid, key = s.create_grant("c1", "r", [("me@x.co.za", "placeholder", MAIL1)])
    sealed = crypto.seal(key, b"old-pw", f"{gid}|me@x.co.za".encode())
    s._q("UPDATE mailboxes SET sealed=? WHERE grant_id=?", (sealed, gid))
    return gid, key


def test_legacy_row_opens_on_the_first_configured_server(tmp_path):
    s = Store(tmp_path / "s.sqlite", legacy_server=ISP)
    gid, key = _legacy_grant(s)
    assert s.open_mailboxes(gid, key) == {"me@x.co.za": MailboxCred("old-pw", ISP)}


def test_legacy_row_without_a_legacy_server_refuses(tmp_path):
    s = Store(tmp_path / "s.sqlite")
    gid, key = _legacy_grant(s)
    with pytest.raises(ValueError, match="legacy server") as ei:
        s.open_mailboxes(gid, key)
    from mcp_server_imap_smtp.store import MailboxNeedsReconnect
    assert isinstance(ei.value, MailboxNeedsReconnect)


def test_legacy_password_that_looks_like_json_stays_a_password(tmp_path):
    s = Store(tmp_path / "s.sqlite", legacy_server=MAIL1)
    gid, key = s.create_grant("c1", "r", [("me@x.co.za", "x", MAIL1)])
    sealed = crypto.seal(key, b'{"password": "a"}', f"{gid}|me@x.co.za".encode())
    s._q("UPDATE mailboxes SET sealed=? WHERE grant_id=?", (sealed, gid))
    assert s.open_mailboxes(gid, key)["me@x.co.za"] == MailboxCred('{"password": "a"}', MAIL1)


def test_tampered_rows_fail_to_unseal(tmp_path):
    """A blob swapped between rows or grants, or edited, fails authentication: the server cannot be redirected."""
    s = Store(tmp_path / "s.sqlite")
    gid, key = s.create_grant("c1", "r", [("me@x.co.za", "pw1", MAIL1), ("ops@x.co.za", "pw2", ISP)])
    rows = {r["address"]: r["sealed"] for r in s._q("SELECT address, sealed FROM mailboxes")}
    s._q("UPDATE mailboxes SET sealed=? WHERE address='me@x.co.za'", (rows["ops@x.co.za"],))   # swap in the ISP blob
    with pytest.raises(crypto.CryptoError):
        s.open_mailboxes(gid, key)
    flipped = bytearray(rows["me@x.co.za"]); flipped[-1] ^= 1
    s._q("UPDATE mailboxes SET sealed=? WHERE address='me@x.co.za'", (bytes(flipped),))
    with pytest.raises(crypto.CryptoError):
        s.open_mailboxes(gid, key)
    other, other_key = s.create_grant("c1", "r", [("me@x.co.za", "pw3", MAIL1)])
    s._q("UPDATE mailboxes SET sealed=? WHERE grant_id=?", (rows["me@x.co.za"], other))   # another grant's blob
    with pytest.raises(crypto.CryptoError):
        s.open_mailboxes(other, other_key)
