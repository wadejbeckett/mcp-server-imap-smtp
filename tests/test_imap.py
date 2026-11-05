# SPDX-License-Identifier: AGPL-3.0-or-later
"""Integration tests against the real mail1 mailboxes (skipped without the test secrets file).

Only the folder `mcp-imap-smtp-tests` (and children) is written to; every message is tagged
`mcp-imap-smtp-test <ns>`; nothing is expunged."""
import time
import warnings
from contextlib import contextmanager
from email.message import EmailMessage
import pytest
from mcp_server_imap_smtp.mail.imap import ImapClient, MailAuthError, SearchQuery, MailError
from tests._mailtest import TEST_FOLDER

pytestmark = pytest.mark.integration

def msg(subject, body="hello", mid=None):
    m = EmailMessage(); m["From"] = "x@y.co.za"; m["To"] = "test@example.invalid"; m["Subject"] = subject
    m["Message-ID"] = mid or f"<{time.time_ns()}@t>"; m["Date"] = "Mon, 05 Oct 2026 10:00:00 +0200"; m.set_content(body)
    return m.as_bytes()

def tagged(label):
    return f"mcp-imap-smtp-test {label} {time.time_ns()}"

def child(c, name):
    top = c.ensure_folder(TEST_FOLDER)
    delim = next(f.delimiter for f in c.folders() if f.name == top)
    return f"{top}{delim}{name}"

@contextmanager
def session(mailserver):
    """Open a client; on exit move every tagged message in the test folder tree to Trash (never EXPUNGE)."""
    server, addr, pw = mailserver
    with ImapClient.open(server, addr, pw) as c:
        try:
            yield c
        finally:
            try:
                _cleanup(c)
            except Exception as exc:  # never mask the test's own failure
                warnings.warn(f"mcp-imap-smtp-tests cleanup failed: {type(exc).__name__}")

def _cleanup(c):
    trash = c.special("trash")
    if not trash:
        return
    top = c.resolve_folder(TEST_FOLDER)
    for f in c.folders():
        if f.name == top or f.name.startswith(top + f.delimiter):
            _, rows = c.search(f.name, SearchQuery(subject="mcp-imap-smtp-test"), limit=500)
            if rows:
                c.move(f.name, [r["uid"] for r in rows], trash)

def test_bad_password(mailserver):
    server, addr, _ = mailserver
    with pytest.raises(MailAuthError):
        ImapClient.open(server, addr, "wrong")

def test_append_search_read_flag_move(mailserver):
    with session(mailserver) as c:
        c.ensure_folder(TEST_FOLDER)
        tag = tagged("Quote")
        c.append(TEST_FOLDER, msg(tag, "price R4053.75"), ())
        total, rows = c.search(TEST_FOLDER, SearchQuery(subject=tag))
        assert total == 1 and rows[0]["subject"] == tag and "\\Seen" not in rows[0]["flags"]
        uid = rows[0]["uid"]
        assert b"R4053.75" in c.fetch_raw(TEST_FOLDER, uid)
        c.set_flags(TEST_FOLDER, [uid], add=["\\Seen", "\\Flagged"], remove=[])
        assert c.search(TEST_FOLDER, SearchQuery(subject=tag, flagged=True))[0] == 1
        dest = c.ensure_folder(child(c, "Archive-Test"))      # move never creates its destination
        c.move(TEST_FOLDER, [uid], dest)
        assert c.search(dest, SearchQuery(subject=tag))[0] == 1

def test_folder_roundtrip_nonascii(mailserver):
    with session(mailserver) as c:
        c.ensure_folder(TEST_FOLDER)
        tag = tagged("x")
        c.append(TEST_FOLDER, msg(tag), ())
        uid = c.search(TEST_FOLDER, SearchQuery(subject=tag))[1][0]["uid"]
        dest = c.ensure_folder(child(c, "Entwürfe ✓"))
        c.move(TEST_FOLDER, [uid], dest)
        assert any(f.name == dest for f in c.folders())
        assert c.search(dest, SearchQuery(subject=tag))[0] == 1

def test_append_returns_the_new_uid(mailserver):
    with session(mailserver) as c:
        c.ensure_folder(TEST_FOLDER)
        tag, mid = tagged("uid"), f"<{time.time_ns()}@t>"
        uid = c.append(TEST_FOLDER, msg(tag, mid=mid), (), message_id=mid)
        assert [r["uid"] for r in c.search(TEST_FOLDER, SearchQuery(subject=tag))[1]] == [uid]


def test_move_to_a_missing_folder_is_refused_and_creates_nothing(mailserver):
    with session(mailserver) as c:
        c.ensure_folder(TEST_FOLDER)
        tag = tagged("nowhere")
        uid = c.append(TEST_FOLDER, msg(tag), ())
        missing = child(c, f"missing-{time.time_ns()}")
        with pytest.raises(MailError, match="does not exist"):
            c.move(TEST_FOLDER, [uid], missing)
        c._folders = None
        assert not any(f.name == missing for f in c.folders())
        assert c.search(TEST_FOLDER, SearchQuery(subject=tag))[0] == 1


def test_fetch_refuses_oversize(mailserver):
    with session(mailserver) as c:
        c.ensure_folder(TEST_FOLDER)
        tag = tagged("big")
        c.append(TEST_FOLDER, msg(tag, "z" * 20_000), ())
        uid = c.search(TEST_FOLDER, SearchQuery(subject=tag))[1][0]["uid"]
        with pytest.raises(MailError, match="too large"):
            c.fetch_raw(TEST_FOLDER, uid, max_bytes=10_000)

def test_paging_newest_first(mailserver):
    with session(mailserver) as c:
        c.ensure_folder(TEST_FOLDER)
        tag = tagged("page")
        for i in range(5):
            c.append(TEST_FOLDER, msg(f"{tag} {i}"), ())
        total, first = c.search(TEST_FOLDER, SearchQuery(subject=tag), limit=2)
        _, second = c.search(TEST_FOLDER, SearchQuery(subject=tag), limit=2, offset=2)
        assert total == 5 and first[0]["uid"] > first[1]["uid"] > second[0]["uid"]
