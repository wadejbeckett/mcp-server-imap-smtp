# SPDX-License-Identifier: AGPL-3.0-or-later
"""Integration tests: the mail tools end to end against the real mail1 mailboxes (skipped without the
test secrets file).

Mail is only ever sent to the test mailbox itself. Every message is tagged `mcp-imap-smtp-test <ns>`
and, when the test ends, any copy still in INBOX, Sent or Drafts is moved into `mcp-imap-smtp-tests`
(or Trash, where the test itself moves it). Nothing is expunged and untagged messages are never touched.
The shared mailbox is only read."""
import time

import anyio
import pytest
from mcp.server.mcpserver import MCPServer

from mcp_server_imap_smtp.config import Settings
from mcp_server_imap_smtp.mail import tools as tools_mod
from mcp_server_imap_smtp.mail.imap import ImapClient, SearchQuery
from mcp_server_imap_smtp.store import Store
from mcp_server_imap_smtp.mail.hosts import MailServer
from tests._mailtest import TEST_FOLDER

pytestmark = pytest.mark.integration


def tagged(label):
    return f"mcp-imap-smtp-test {label} {time.time_ns()}"


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def live(tmp_path, monkeypatch, mailserver, shared_mailbox):
    """A server wired to the real opener and sender, signed in to the test mailbox and the shared one."""
    server, addr, pw = mailserver
    shared_addr, shared_pw = shared_mailbox
    MAIL1 = server
    s = Settings(issuer_url="http://127.0.0.1:8765", mail_resource_url="http://127.0.0.1:8765/mail",
                 mail_servers=(server,), db_path=tmp_path / "s.sqlite",
                 send_mode="send")
    store = Store(s.db_path)
    gid, key = store.create_grant("c1", s.mail_resource_url, [(addr, pw, MAIL1), (shared_addr, shared_pw, MAIL1)])
    at, _ = store.issue_tokens(gid, key, "c1", [], s.mail_resource_url, 3600, 86400)

    class Tok:
        token = at
    monkeypatch.setattr(tools_mod, "get_access_token", lambda: Tok)
    with ImapClient.open(server, addr, pw) as c:
        c.ensure_folder(TEST_FOLDER)  # mail_move only moves into folders that exist
    srv = MCPServer("live")
    tools_mod.register_mail_tools(srv, store, s)
    tags = []

    def tag(label):
        t = tagged(label)
        tags.append(t)
        return t
    yield srv, addr, shared_addr, tag
    try:  # leave nothing tagged in INBOX, Sent or Drafts, whatever the test did
        with ImapClient.open(server, addr, pw) as c:
            c.ensure_folder(TEST_FOLDER)
            for folder in filter(None, ("INBOX", c.special("sent"), c.special("drafts"))):
                for t in tags:
                    _, rows = c.search(folder, SearchQuery(subject=t))
                    if rows:
                        c.move(folder, [r["uid"] for r in rows], TEST_FOLDER)
    except Exception as exc:  # never mask the test's own failure
        import warnings
        warnings.warn(f"mcp-imap-smtp-tests cleanup failed: {type(exc).__name__}")


async def call(srv, name, **args):
    return (await srv.call_tool(name, args)).structured_content


async def find(srv, folder, tag, wait=30, **extra):
    """Poll mail_search until the tagged message shows up in `folder`; return its row."""
    deadline = time.monotonic() + wait
    while True:
        out = await call(srv, "mail_search", folder=folder, subject=tag, **extra)
        if out["messages"] or time.monotonic() > deadline:
            break
        await anyio.sleep(1)
    assert out["messages"], f"{tag!r} did not appear in {folder} within {wait}s"
    return out["messages"][0]


@pytest.mark.anyio
async def test_accounts_and_folders(live):
    srv, addr, shared_addr, _ = live
    assert (await call(srv, "mail_accounts"))["mailboxes"] == [addr, shared_addr]
    folders = (await call(srv, "mail_folders"))["folders"]
    roles = {f["role"] for f in folders}
    assert {"inbox", "sent", "trash"} <= roles
    assert all(isinstance(f["messages"], int) for f in folders if f["name"] == "INBOX")


@pytest.mark.anyio
async def test_shared_mailbox_is_searchable(live):
    srv, _, shared_addr, _ = live
    out = await call(srv, "mail_search", mailbox=shared_addr, limit=3)
    assert out["folder"] == "INBOX" and out["total"] >= len(out["messages"])
    assert (await call(srv, "mail_folders", mailbox=shared_addr))["folders"]


@pytest.mark.anyio
async def test_send_read_flag_reply_thread_move(live):
    srv, addr, _, tag = live
    t = tag("tools")
    sent = await call(srv, "mail_send", to=[addr], subject=t, text="hello from the tools integration test")
    assert sent["sent_to"] == [addr] and sent["saved_to_sent"] is True and "warning" not in sent
    assert sent["message_id"].startswith("<") and sent["message_id"].endswith(">")

    inbox = await find(srv, "INBOX", t)
    assert inbox["message_id"] == sent["message_id"]
    await call(srv, "mail_move", folder="INBOX", uids=[inbox["uid"]], destination=TEST_FOLDER)
    row = await find(srv, TEST_FOLDER, t)
    uid = row["uid"]
    assert "\\Seen" not in row["flags"]

    read = await call(srv, "mail_read", folder=TEST_FOLDER, uid=uid)
    assert read["subject"] == t and "hello from the tools integration test" in read["text"]
    assert read["truncated"] is False and "note" not in read

    await call(srv, "mail_flag", folder=TEST_FOLDER, uids=[uid], seen=True, flagged=True)
    assert {"\\Seen", "\\Flagged"} <= set((await find(srv, TEST_FOLDER, t))["flags"])
    await call(srv, "mail_flag", folder=TEST_FOLDER, uids=[uid], flagged=False)
    assert "\\Flagged" not in (await find(srv, TEST_FOLDER, t))["flags"]

    replied = await call(srv, "mail_send", text="a reply", reply_to_folder=TEST_FOLDER, reply_to_uid=uid)
    assert replied["subject"] == f"Re: {t}" and replied["sent_to"] == [addr]
    assert "\\Answered" in (await find(srv, TEST_FOLDER, t))["flags"]
    await find(srv, "INBOX", f"Re: {t}")  # delivered; the fixture files it away afterwards

    thread = await call(srv, "mail_thread", folder=TEST_FOLDER, uid=uid)
    assert {m["subject"] for m in thread["messages"]} >= {t, f"Re: {t}"}
    assert any(m["folder"] != TEST_FOLDER for m in thread["messages"])  # the Sent copies

    moved = await call(srv, "mail_move", folder=TEST_FOLDER, uids=[uid], destination="trash")
    trash = moved["to"]
    assert (await find(srv, trash, t))["subject"] == t
    gone = await call(srv, "mail_search", folder=TEST_FOLDER, subject=t)
    assert all(m["subject"] != t for m in gone["messages"])


@pytest.mark.anyio
async def test_draft_then_replace_it(live):
    srv, addr, _, tag = live
    t = tag("draft")
    first = await call(srv, "mail_draft", to=[addr], subject=t, text="first draft")
    drafts = first["saved_to"]
    row = await find(srv, drafts, t)
    assert "\\Draft" in row["flags"]
    assert first["uid"] == row["uid"] and first["message_id"] == row["message_id"]     # APPENDUID or search
    second = await call(srv, "mail_draft", to=[addr], subject=t, text="second draft", replace_draft_uid=row["uid"])
    assert second["saved_to"] == drafts
    out = await call(srv, "mail_search", folder=drafts, subject=t)
    assert out["total"] == 1 and out["messages"][0]["uid"] != row["uid"]
    assert out["messages"][0]["uid"] == second["uid"]


@pytest.mark.anyio
async def test_draft_with_images_is_saved_as_multipart_related(live, mailserver):
    import base64
    from email import policy
    from email.parser import BytesParser
    from tests.test_inline import animated_gif, png
    srv, addr, _, tag = live
    t = tag("images")
    uri = lambda kind, data: f"data:image/{kind};base64," + base64.b64encode(data).decode()
    html = f'<p>Hello</p><img src="{uri("png", png())}"><img src="{uri("gif", animated_gif())}">'
    drafts = (await call(srv, "mail_draft", to=[addr], subject=t, text="Hello", html=html))["saved_to"]
    row = await find(srv, drafts, t)
    server, address, password = mailserver
    with ImapClient.open(server, address, password) as c:
        raw = c.fetch_raw(drafts, row["uid"])
    m = BytesParser(policy=policy.default).parsebytes(raw)
    related = next(p for p in m.walk() if p.get_content_type() == "multipart/related")
    body, *images = related.get_payload()
    assert [p.get_content_type() for p in images] == ["image/png", "image/gif"]
    assert images[1].get_content() == animated_gif()
    for p in images:
        assert f'src="cid:{p["Content-ID"].strip("<>")}"' in body.get_content()


@pytest.mark.anyio
async def test_search_everywhere_finds_the_sent_copy(live):
    srv, addr, _, tag = live
    t = tag("all")
    await call(srv, "mail_send", to=[addr], subject=t, text="search everywhere")
    await find(srv, "INBOX", t)
    out = await call(srv, "mail_search", folder="*", subject=t)
    assert {m["folder"] for m in out["messages"]} >= {"INBOX"} and out["total"] >= 2  # INBOX and Sent


@pytest.mark.anyio
async def test_draft_with_two_attachments_reads_back_as_raw_mime(live, mailserver):
    """Ticket 08: a draft with two base64 attachments (one with a non-ASCII name) and an HTML body is stored
    as mixed(alternative(text, html), pdf, txt) with RFC 2231 filenames, and the bytes come back unchanged."""
    import base64
    from email import policy
    from email.parser import BytesParser
    srv, addr, _, tag = live
    t = tag("attachments")
    pdf = b"%PDF-1.4\n" + bytes(range(256)) * 20
    name = "Rechnung für Oktober – endgültig.pdf"
    out = await call(srv, "mail_draft", to=[addr], subject=t, text="see attached", html="<p>see attached</p>",
                     attachments=[{"filename": name, "content_type": "application/pdf",
                                   "base64": base64.b64encode(pdf).decode()},
                                  {"filename": "notes.txt", "content_type": "text/plain",
                                   "base64": base64.b64encode("Grüße\n".encode()).decode()}])
    assert [a["filename"] for a in out["attachments"]] == [name, "notes.txt"]
    row = await find(srv, out["saved_to"], t)
    server, address, password = mailserver
    with ImapClient.open(server, address, password) as c:
        raw = c.fetch_raw(out["saved_to"], row["uid"])
    assert b"filename*" in raw                                           # RFC 2231 on the wire
    m = BytesParser(policy=policy.default).parsebytes(raw)
    assert m.get_content_type() == "multipart/mixed"
    assert [p.get_content_type() for p in m.iter_parts()] == ["multipart/alternative", "application/pdf",
                                                              "text/plain"]
    files = {p.get_filename(): p.get_payload(decode=True) for p in m.iter_attachments()}
    assert files == {name: pdf, "notes.txt": "Grüße\n".encode()}
    read = await call(srv, "mail_read", folder=out["saved_to"], uid=row["uid"])
    assert [(a["part_id"], a["filename"]) for a in read["attachments"]] == [("2", name), ("3", "notes.txt")]
    got = await call(srv, "mail_attachment", folder=out["saved_to"], uid=row["uid"], part="3")
    assert got["text"] == "Grüße\n"


@pytest.mark.anyio
async def test_sent_attachment_reattached_by_reference(live, mailserver):
    """Send a file to the test mailbox, then attach that part to a draft by source reference (no bytes
    through the AI) and forward the message inline into a draft that carries the original's file."""
    import base64
    from email import policy
    from email.parser import BytesParser
    srv, addr, _, tag = live
    t = tag("by-reference")
    pdf = b"%PDF-1.4 by reference\n" * 50
    await call(srv, "mail_send", to=[addr], subject=t, text="original",
               attachments=[{"filename": "ref.pdf", "content_type": "application/pdf",
                             "base64": base64.b64encode(pdf).decode()}])
    row = await find(srv, "INBOX", t)
    part = (await call(srv, "mail_read", folder="INBOX", uid=row["uid"]))["attachments"][0]["part_id"]
    t2 = tag("by-reference-draft")
    draft = await call(srv, "mail_draft", to=[addr], subject=t2, text="again",
                       attachments=[{"source_folder": "INBOX", "source_uid": row["uid"], "source_part": part}])
    fwd = await call(srv, "mail_draft", to=[addr], text="see below", forward_folder="INBOX",
                     forward_uid=row["uid"], forward_mode="inline")
    server, address, password = mailserver
    with ImapClient.open(server, address, password) as c:
        for out in (draft, fwd):
            raw = c.fetch_raw(out["saved_to"], out["uid"])
            m = BytesParser(policy=policy.default).parsebytes(raw)
            assert [(p.get_filename(), p.get_payload(decode=True)) for p in m.iter_attachments()] == [("ref.pdf", pdf)]
        c.ensure_folder(TEST_FOLDER)
        c.move(fwd["saved_to"], [fwd["uid"]], TEST_FOLDER)        # its subject is "Fwd: <tag>": not found by tag
