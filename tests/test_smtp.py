# SPDX-License-Identifier: AGPL-3.0-or-later
"""Integration tests: real SMTPS submission on mail1 (skipped without the test secrets file).

Mail is only ever sent to the test mailbox itself. Each message is tagged
`mcp-imap-smtp-test <ns>` and, once it arrives, moved from INBOX into `mcp-imap-smtp-tests`.
Nothing is expunged."""
import time
import pytest
from mcp_server_imap_smtp.mail import compose, smtp
from mcp_server_imap_smtp.mail.imap import ImapClient, MailAuthError, SearchQuery
from tests._mailtest import TEST_FOLDER

pytestmark = pytest.mark.integration


def tagged(label):
    return f"mcp-imap-smtp-test {label} {time.time_ns()}"


def file_delivered(c, tag, wait=30):
    """Wait for the tagged message to reach INBOX, move it into the test folder, return its uid there."""
    c.ensure_folder(TEST_FOLDER)
    deadline = time.monotonic() + wait
    while True:
        _, rows = c.search("INBOX", SearchQuery(subject=tag))
        if rows or time.monotonic() > deadline:
            break
        time.sleep(1)
    assert rows, f"message {tag!r} did not arrive in INBOX within {wait}s"
    c.move("INBOX", [r["uid"] for r in rows], TEST_FOLDER)
    total, moved = c.search(TEST_FOLDER, SearchQuery(subject=tag))
    assert total == 1
    return moved[0]["uid"]


def test_send_to_self(mailserver):
    server, addr, pw = mailserver
    tag = tagged("smtp")
    m = compose.new(addr, [addr], tag, "hello from the smtp integration test")
    assert smtp.send(server, addr, pw, m) == [addr]
    with ImapClient.open(server, addr, pw) as c:
        uid = file_delivered(c, tag)
        raw = c.fetch_raw(TEST_FOLDER, uid)
        if c.special("trash"):  # leave nothing behind; Trash, never EXPUNGE
            c.move(TEST_FOLDER, [uid], c.special("trash"))
    assert b"hello from the smtp integration test" in raw and m["Message-ID"].encode() in raw


def test_send_bad_password(mailserver):
    server, addr, _ = mailserver
    m = compose.new(addr, [addr], tagged("badpw"), "never delivered")
    with pytest.raises(MailAuthError):
        smtp.send(server, addr, "nope", m)
