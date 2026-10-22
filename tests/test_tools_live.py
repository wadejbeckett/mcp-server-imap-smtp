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

    inbox = await find(srv, "INBOX", t)
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
    second = await call(srv, "mail_draft", to=[addr], subject=t, text="second draft", replace_draft_uid=row["uid"])
    assert second["saved_to"] == drafts
    out = await call(srv, "mail_search", folder=drafts, subject=t)
    assert out["total"] == 1 and out["messages"][0]["uid"] != row["uid"]


@pytest.mark.anyio
async def test_search_everywhere_finds_the_sent_copy(live):
    srv, addr, _, tag = live
    t = tag("all")
    await call(srv, "mail_send", to=[addr], subject=t, text="search everywhere")
    await find(srv, "INBOX", t)
    out = await call(srv, "mail_search", folder="*", subject=t)
    assert {m["folder"] for m in out["messages"]} >= {"INBOX"} and out["total"] >= 2  # INBOX and Sent
