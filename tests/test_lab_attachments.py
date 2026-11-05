# SPDX-License-Identifier: AGPL-3.0-or-later
"""Lab checks for ticket 08: a message with attachments goes through Postfix and Dovecot intact, a draft with
attachments reads back with the same parts, and the lab Postfix's SIZE refuses an oversized message before AUTH."""
import time

import pytest

from mcp_server_imap_smtp.mail import compose, render, smtp
from mcp_server_imap_smtp.mail.imap import ImapClient, MailError, SearchQuery
from tests._lab import FLAT, PROFILES, record_commands, require_lab, users
from tests.test_lab import lab_ca  # noqa: F401  (fixture)

pytestmark = pytest.mark.lab
ALICE, BOB = "alice@example.test", "bob@example.test"
PDF = b"%PDF-1.4\n" + bytes(range(256)) * 40
NAME = "Rechnung für Oktober – endgültig.pdf"


def files():
    return [compose.file(NAME, "application/pdf", PDF),
            compose.file("notes.txt", "text/plain", "Grüße\n".encode())]


@pytest.mark.parametrize("profile", PROFILES, ids=lambda p: p.name)
def test_draft_with_attachments_reads_back_part_for_part(lab_ca, profile):
    tag = f"t08-{time.time_ns()}"
    m = compose.new(ALICE, [BOB], tag, "see attached", html='<p>see <img src="cid:dot@lab"></p>',
                    files=[*files(), compose.file("dot.gif", "image/gif", b"GIF89a\x01\x00", disposition="inline",
                                                  content_id="dot@lab")])
    with ImapClient.open(profile.server(), ALICE, users()[ALICE]) as c:
        drafts = c.special("drafts")
        assert c.append_limit(drafts) is None or c.append_limit(drafts) > compose.wire_size(m)
        uid = c.append(drafts, m.as_bytes(), ("\\Draft",), message_id=m["Message-ID"])
        raw = c.fetch_raw(drafts, uid)
    rows = render.summarise(raw)["attachments"]
    assert [(r["filename"], r["part_id"]) for r in rows] == [("dot.gif", "1.2.2"), (NAME, "2"), ("notes.txt", "3")]
    assert render.find_part(raw, part="2").data() == PDF
    assert render.find_part(raw, content_id="dot@lab").data() == b"GIF89a\x01\x00"
    assert b'type="text/html"' in raw


def test_sent_attachments_arrive_intact(lab_ca):
    tag = f"t08-{time.time_ns()}"
    m = compose.new(ALICE, [BOB], tag, "see attached", files=files())
    assert smtp.send(FLAT.server(), ALICE, users()[ALICE], m) == [BOB]
    with ImapClient.open(FLAT.server(), BOB, users()[BOB]) as c:
        for _ in range(50):
            _, found = c.search("INBOX", SearchQuery(subject=tag))
            if found:
                break
            time.sleep(0.2)
        assert found, "the message did not arrive"
        raw = c.fetch_raw("INBOX", found[0]["uid"])
    got = {r["filename"]: render.find_part(raw, part=r["part_id"]).data() for r in render.summarise(raw)["attachments"]}
    assert got == {NAME: PDF, "notes.txt": "Grüße\n".encode()}


def test_lab_postfix_size_refuses_before_auth(lab_ca, monkeypatch):
    seen = []
    real = smtp._login
    monkeypatch.setattr(smtp, "_login", lambda *a: seen.append("auth") or real(*a))
    big = compose.new(ALICE, [BOB], "big", "x", files=[compose.file("big.bin", "application/octet-stream",
                                                                    b"\0" * 20_000_000)])
    with pytest.raises(MailError, match=r"accepts at most 25.0 MB \(26214400 bytes\)"):
        smtp.send(FLAT.server(), ALICE, users()[ALICE], big)
    assert seen == []


@pytest.mark.parametrize("profile", PROFILES, ids=lambda p: p.name)
def test_append_limit_is_read_from_the_server(lab_ca, profile):
    """Dovecot names APPENDLIMIT only when a mail size limit is set; either way the connector reads it, never
    assumes, and asks CAPABILITY once."""
    with ImapClient.open(profile.server(), ALICE, users()[ALICE]) as c:
        with record_commands(c.c) as sent:
            first = c.append_limit("INBOX")
            assert c.append_limit("INBOX") == first
        assert [n for n, _ in sent].count("CAPABILITY") <= 1
        assert (first is None) == (not any(cap.startswith("APPENDLIMIT") for cap in c.capabilities()))
