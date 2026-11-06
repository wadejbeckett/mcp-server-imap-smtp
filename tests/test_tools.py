# SPDX-License-Identifier: AGPL-3.0-or-later
"""Mail tools against fakes: no network. A fake opener hands out a FakeImap that records what the
tools ask of it; a fake sender captures what would have gone to SMTP."""
import base64
import json
import logging
import shutil
import socket
import subprocess
from email import message_from_bytes, policy
from email.message import EmailMessage
from email.parser import BytesParser

import pytest
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from mcp_server_imap_smtp.config import Settings
from mcp_server_imap_smtp.mail import smtp
from mcp_server_imap_smtp.mail.hosts import Connector, MailServer
from mcp_server_imap_smtp.mail import tools as tools_mod
from mcp_server_imap_smtp.mail.imap import Folder, MailAuthError, MailError
from mcp_server_imap_smtp.store import Store
from tests.test_smtp_offline import ScriptedServer
from mcp_server_imap_smtp.mail.hosts import MailServer as _MailServer
MAIL1 = _MailServer("mail1.hosting.example")


def raw_message(subject="Quote", body="hello world", frm="Cust <c@x.co.za>", to="me@x.co.za", mid="<1@x>",
                extra=None, attachments=()):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"], m["Message-ID"] = frm, to, subject, mid
    m["Date"] = "Mon, 05 Oct 2026 10:00:00 +0200"
    for k, v in (extra or {}).items():
        m[k] = v
    m.set_content(body)
    for name, ctype, data in attachments:
        maintype, subtype = ctype.split("/")
        m.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
    return m.as_bytes()


FOLDERS = [
    Folder("INBOX", "/", (), "inbox"),
    Folder("Sent", "/", ("\\Sent",), "sent"),
    Folder("Drafts", "/", ("\\Drafts",), "drafts"),
    Folder("Trash", "/", ("\\Trash",), "trash"),
    Folder("Junk", "/", ("\\Junk",), "junk"),
    Folder("Old", "/", (), None),
    Folder("Gone", "/", ("\\Noselect",), None),
    Folder("Shared/Team", "/", (), None),
]


class FakeImap:
    """Records every call as (method, args); `messages` maps (folder, uid) to raw bytes."""

    def __init__(self, messages=None):
        self.messages = messages or {}
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *e):
        self.calls.append(("close",))

    def _row(self, uid, folder=None):
        row = {"uid": uid, "subject": "Quote", "from": "c@x", "date": "Mon, 05 Oct 2026 10:00:00 +0200",
               "flags": [], "size": 10, "message_id": "<1@x>"}
        return row

    def folders(self):
        return FOLDERS

    def special(self, kind):
        return next((f.name for f in FOLDERS if f.special == kind), None)

    def status(self, folder):
        return {"messages": 3, "unseen": 1}

    def namespaces(self):
        return {"personal": [["", "/"]], "other": [], "shared": [["Shared/", "/"]]}

    def myrights(self, folder):
        return "lrs"

    def search(self, folder, q, limit=25, offset=0):
        self.calls.append(("search", folder, q, limit, offset))
        return 1, [self._row(7)]

    def _summaries(self, uids):
        return [self._row(u) for u in uids]

    def fetch_raw(self, folder, uid):
        self.calls.append(("fetch_raw", folder, uid))
        return self.messages[(folder, uid)]

    def find_by_message_id(self, folder, mid):
        self.calls.append(("find", folder, mid))
        return [7]

    def set_flags(self, folder, uids, add, remove):
        self.calls.append(("set_flags", folder, list(uids), list(add), list(remove)))

    def ensure_folder(self, name):
        self.calls.append(("ensure_folder", name))
        return name

    def resolve_folder(self, name):
        return name

    def move(self, folder, uids, dest, copy=False):
        self.calls.append(("move", folder, list(uids), dest, copy))

    def append_limit(self, folder):
        return None

    def append(self, folder, raw, flags, message_id=None):
        self.calls.append(("append", folder, raw, tuple(flags)))
        return 11

    def named(self, name):
        return [c for c in self.calls if c[0] == name]


class FakeSender:
    def __init__(self, accepted=None, exc=None):
        self.sent, self.accepted, self.exc = [], accepted, exc

    def __call__(self, server, address, password, msg, bcc=(), local_hostname=None):
        if self.exc:
            raise self.exc
        self.sent.append({"server": server, "address": address, "password": password, "msg": msg,
                          "port": server.smtp_port, "bcc": tuple(bcc)})
        return self.accepted if self.accepted is not None else [a for a in str(msg["To"]).split(", ")] + list(bcc)


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def env(tmp_path, monkeypatch):
    s = Settings(issuer_url="http://127.0.0.1:8765", mail_resource_url="http://127.0.0.1:8765/mail",
                 mail_servers=(MailServer("mail1.hosting.example"),), db_path=tmp_path / "s.sqlite",
                 send_mode="send", send_allow_bcc=True)
    store = Store(s.db_path)
    gid, key = store.create_grant("c1", s.mail_resource_url, [("me@x.co.za", "pw", MAIL1), ("accounts@x.co.za", "pw2", MAIL1)])
    at, _ = store.issue_tokens(gid, key, "c1", [], s.mail_resource_url, 3600, 86400)

    class Tok:
        token = at
    monkeypatch.setattr(tools_mod, "get_access_token", lambda: Tok)
    return s, store, gid


def build(env, fake=None, sender=None, fetch_image=None):
    """Server whose opener always hands out `fake`; opened (address, password) pairs go to .opened."""
    s, store, _ = env
    fake = fake or FakeImap()
    srv = MCPServer("t")
    srv.opened = []

    def opener(server, address, password):
        srv.opened.append((address, password, server.imap_port))
        return fake
    extra = {"fetch_image": fetch_image} if fetch_image else {}
    tools_mod.register_mail_tools(srv, store, s, opener=opener, sender=sender, **extra)
    return srv, fake


def payload(result):
    return result.structured_content


# --- mailboxes -----------------------------------------------------------------------------

@pytest.mark.anyio
async def test_search_uses_selected_mailbox(env):
    srv, fake = build(env)
    out = await srv.call_tool("mail_search", {"subject": "Quote", "mailbox": "accounts@x.co.za"})
    assert srv.opened == [("accounts@x.co.za", "pw2", 993)] and "Quote" in str(out)
    (_, folder, q, limit, offset), = fake.named("search")
    assert (folder, q.subject, limit, offset) == ("INBOX", "Quote", 25, 0)


@pytest.mark.anyio
async def test_each_mailbox_uses_the_server_sealed_in_its_grant(tmp_path, monkeypatch, caplog):
    """IMAP and SMTP go to each mailbox's own server, and the audit line names it."""
    caplog.set_level(logging.INFO, logger="mcp_server_imap_smtp.audit")
    isp = MailServer("mail.client.example", imap_port=1993, smtp_port=587, domains=("client.example",),
                     match_mx=False)
    s = Settings(issuer_url="http://127.0.0.1:8765", mail_resource_url="http://127.0.0.1:8765/mail",
                 mail_servers=(MAIL1, isp), db_path=tmp_path / "s.sqlite", send_mode="send")
    store = Store(s.db_path)
    gid, key = store.create_grant("c1", s.mail_resource_url, [("me@x.co.za", "pw", MAIL1), ("ops@client.example", "pw2", isp)])
    at, _ = store.issue_tokens(gid, key, "c1", [], s.mail_resource_url, 3600, 86400)

    class Tok:
        token = at
    monkeypatch.setattr(tools_mod, "get_access_token", lambda: Tok)
    srv, fake = build((s, store, gid), sender=(sender := FakeSender()))
    await srv.call_tool("mail_search", {"mailbox": "ops@client.example"})
    await srv.call_tool("mail_search", {})
    await srv.call_tool("mail_send", {"mailbox": "ops@client.example", "to": ["c@y.co.za"], "subject": "s", "text": "t"})
    assert srv.opened[:2] == [("ops@client.example", "pw2", 1993), ("me@x.co.za", "pw", 993)]
    assert (sender.sent[0]["server"].host, sender.sent[0]["port"], sender.sent[0]["password"]) == \
        ("mail.client.example", 587, "pw2")
    assert [(l["mailbox"], l["host"]) for l in audit_lines(caplog)] == [
        ("ops@client.example", "mail.client.example"), ("me@x.co.za", "mail1.hosting.example"),
        ("ops@client.example", "mail.client.example")]


@pytest.mark.anyio
async def test_default_mailbox_is_the_first(env):
    srv, _ = build(env)
    await srv.call_tool("mail_search", {})
    assert srv.opened[0][0] == "me@x.co.za"


@pytest.mark.anyio
async def test_unknown_mailbox(env):
    srv, _ = build(env)
    with pytest.raises(ToolError, match="not connected"):
        await srv.call_tool("mail_search", {"mailbox": "boss@x.co.za"})
    assert srv.opened == []


@pytest.mark.anyio
async def test_not_signed_in(env, monkeypatch):
    srv, _ = build(env)
    monkeypatch.setattr(tools_mod, "get_access_token", lambda: None)
    with pytest.raises(ToolError, match="Reconnect Mail Connector in your AI app"):
        await srv.call_tool("mail_search", {})


@pytest.mark.anyio
async def test_auth_failure_revokes_grant(env):
    s, store, gid = env
    srv = MCPServer("t")

    def opener(*a, **k):
        raise MailAuthError("no")
    tools_mod.register_mail_tools(srv, store, s, opener=opener, sender=None)
    # The fixture's connection holds two mailboxes: the rejected one fails alone, the connection stays.
    with pytest.raises(ToolError, match="other mailboxes in this connection still work"):
        await srv.call_tool("mail_search", {})
    assert store.list_grants()[0]["revoked"] == 0


@pytest.mark.anyio
async def test_auth_failure_revokes_single_mailbox_grant(tmp_path, monkeypatch):
    s = Settings(issuer_url="http://127.0.0.1:8765", mail_resource_url="http://127.0.0.1:8765/mail",
                 mail_servers=(MailServer("mail1.hosting.example"),), db_path=tmp_path / "one.sqlite")
    store = Store(s.db_path)
    gid, key = store.create_grant("c1", s.mail_resource_url, [("me@x.co.za", "pw", MAIL1)])
    at, _ = store.issue_tokens(gid, key, "c1", [], s.mail_resource_url, 3600, 86400)

    class Tok:
        token = at
    monkeypatch.setattr(tools_mod, "get_access_token", lambda: Tok)
    srv = MCPServer("t")

    def opener(*a, **k):
        raise MailAuthError("no")
    tools_mod.register_mail_tools(srv, store, s, opener=opener, sender=None)
    with pytest.raises(ToolError, match="reconnect Mail Connector in your AI app and sign in again"):
        await srv.call_tool("mail_search", {})
    assert store.list_grants()[0]["revoked"] == 1


@pytest.mark.anyio
async def test_mail_accounts(env):
    srv, _ = build(env)
    out = payload(await srv.call_tool("mail_accounts", {}))
    assert out == {"mailboxes": ["me@x.co.za", "accounts@x.co.za"], "default": "me@x.co.za", "count": 2}


@pytest.mark.anyio
async def test_mail_folders_marks_shared_and_skips_unselectable(env):
    srv, _ = build(env)
    out = payload(await srv.call_tool("mail_folders", {}))
    rows = {r["name"]: r for r in out["folders"]}
    assert "Gone" not in rows
    assert rows["INBOX"]["role"] == "inbox" and rows["INBOX"]["unseen"] == 1 and "shared" not in rows["INBOX"]
    assert rows["Shared/Team"]["shared"] is True and rows["Shared/Team"]["rights"] == "lrs"
    assert out["namespaces"]["shared"] == [["Shared/", "/"]]


@pytest.mark.anyio
async def test_mail_folders_survives_a_folder_that_refuses_status(env):
    class Picky(FakeImap):
        def status(self, folder):
            if folder == "Old":
                raise MailError("STATUS failed: no permission")
            return super().status(folder)
    srv, _ = build(env, Picky())
    rows = {r["name"]: r for r in payload(await srv.call_tool("mail_folders", {}))["folders"]}
    assert rows["Old"]["messages"] is None and rows["INBOX"]["messages"] == 3


# --- search ----------------------------------------------------------------------------------

@pytest.mark.anyio
async def test_search_dates_and_paging(env):
    srv, fake = build(env)
    await srv.call_tool("mail_search", {"since": "2026-01-02", "before": "2026-02-03", "limit": 100, "offset": 5,
                                        "unread": True, "from_": "a@b"})
    (_, _, q, limit, offset), = fake.named("search")
    assert (q.since.isoformat(), q.before.isoformat(), q.unread, q.from_) == ("2026-01-02", "2026-02-03", True, "a@b")
    assert (limit, offset) == (100, 5)


@pytest.mark.anyio
@pytest.mark.parametrize("args", [{"limit": 0}, {"limit": 101}, {"offset": -1}])
async def test_search_rejects_bad_paging(env, args):
    srv, fake = build(env)
    with pytest.raises(ToolError, match="limit|offset"):
        await srv.call_tool("mail_search", args)
    assert srv.opened == []


@pytest.mark.anyio
async def test_search_rejects_bad_date(env):
    srv, _ = build(env)
    with pytest.raises(ToolError, match="since"):
        await srv.call_tool("mail_search", {"since": "yesterday"})
    assert srv.opened == []


@pytest.mark.anyio
async def test_search_all_folders_skips_trash_junk_and_unselectable(env):
    srv, fake = build(env)
    out = payload(await srv.call_tool("mail_search", {"folder": "*", "limit": 10, "offset": 0}))
    searched = [c[1] for c in fake.named("search")]
    assert searched == ["INBOX", "Sent", "Drafts", "Old", "Shared/Team"]
    assert {m["folder"] for m in out["messages"]} == set(searched)
    assert out["total"] == 5


@pytest.mark.anyio
@pytest.mark.parametrize("limit,offset,ok", [(100, 900, True), (100, 901, False), (1, 1000, False)])
async def test_search_all_folders_caps_how_deep_it_pages(env, limit, offset, ok):
    srv, fake = build(env)
    args = {"folder": "*", "limit": limit, "offset": offset}
    if ok:
        await srv.call_tool("mail_search", args)
        assert fake.named("search")
    else:
        with pytest.raises(ToolError, match="1000"):
            await srv.call_tool("mail_search", args)
        assert srv.opened == []


@pytest.mark.anyio
async def test_search_one_folder_is_not_capped(env):
    srv, fake = build(env)
    await srv.call_tool("mail_search", {"folder": "INBOX", "limit": 100, "offset": 5000})
    assert fake.named("search")[0][3:] == (100, 5000)


@pytest.mark.anyio
async def test_search_all_folders_reports_folders_it_could_not_search(env):
    class Picky(FakeImap):
        def search(self, folder, q, limit=25, offset=0):
            if folder == "Shared/Team":
                raise MailError("SELECT failed: no access")
            return super().search(folder, q, limit, offset)
    srv, _ = build(env, Picky())
    out = payload(await srv.call_tool("mail_search", {"folder": "*"}))
    assert out["skipped"] == ["Shared/Team"] and len(out["messages"]) == 4


# --- read / thread / attachment ---------------------------------------------------------------

@pytest.mark.anyio
async def test_read_returns_message(env):
    srv, _ = build(env, FakeImap({("INBOX", 5): raw_message(body="the body")}))
    out = payload(await srv.call_tool("mail_read", {"folder": "INBOX", "uid": 5}))
    assert out["subject"] == "Quote" and out["text"].strip() == "the body" and out["truncated"] is False
    assert "note" not in out and out["uid"] == 5


@pytest.mark.anyio
async def test_read_states_truncation(env):
    srv, _ = build(env, FakeImap({("INBOX", 5): raw_message(body="x" * 60_000)}))
    out = payload(await srv.call_tool("mail_read", {"folder": "INBOX", "uid": 5}))
    assert out["truncated"] is True and len(out["text"]) == 50_000
    assert out["note"] == "Body truncated at 50,000 characters."


@pytest.mark.anyio
async def test_read_missing_message_is_a_tool_error(env):
    class Missing(FakeImap):
        def fetch_raw(self, folder, uid):
            raise MailError(f"message {uid} not found in {folder}")
    srv, _ = build(env, Missing())
    with pytest.raises(ToolError, match="not found"):
        await srv.call_tool("mail_read", {"folder": "INBOX", "uid": 5})


@pytest.mark.anyio
@pytest.mark.parametrize("uid", [0, -3])
async def test_read_rejects_non_positive_uid(env, uid):
    srv, _ = build(env)
    with pytest.raises(ToolError, match="positive"):
        await srv.call_tool("mail_read", {"folder": "INBOX", "uid": uid})


@pytest.mark.anyio
async def test_thread_searches_folder_and_sent_by_message_ids(env):
    raw = raw_message(mid="<3@x>", extra={"In-Reply-To": "<2@x>", "References": "<1@x> <2@x>"})
    srv, fake = build(env, FakeImap({("INBOX", 5): raw}))
    out = payload(await srv.call_tool("mail_thread", {"folder": "INBOX", "uid": 5}))
    finds = {(c[1], c[2]) for c in fake.named("find")}
    assert finds == {(f, i) for f in ("INBOX", "Sent") for i in ("<1@x>", "<2@x>", "<3@x>")}
    assert {m["folder"] for m in out["messages"]} == {"INBOX", "Sent"}


@pytest.mark.anyio
async def test_attachment_text(env):
    raw = raw_message(attachments=[("a.txt", "text/plain", b"plain contents")])
    srv, _ = build(env, FakeImap({("INBOX", 5): raw}))
    out = payload(await srv.call_tool("mail_attachment", {"folder": "INBOX", "uid": 5, "index": 0}))
    assert out["filename"] == "a.txt" and out["text"].strip() == "plain contents"


@pytest.mark.anyio
async def test_attachment_text_uses_its_declared_charset(env):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = "c@x.co.za", "me@x.co.za", "s"
    m.set_content("body")
    m.add_attachment("café crème".encode("latin-1"), maintype="text", subtype="plain", filename="l1.txt",
                     params={"charset": "iso-8859-1"})
    srv, _ = build(env, FakeImap({("INBOX", 5): m.as_bytes()}))
    out = payload(await srv.call_tool("mail_attachment", {"folder": "INBOX", "uid": 5, "index": 0}))
    assert out["text"] == "café crème"


@pytest.mark.anyio
async def test_attachment_text_with_unknown_charset_falls_back_to_utf8(env):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = "c@x.co.za", "me@x.co.za", "s"
    m.set_content("body")
    m.add_attachment("naïve".encode("utf-8"), maintype="text", subtype="plain", filename="u.txt",
                     params={"charset": "x-no-such-charset"})
    srv, _ = build(env, FakeImap({("INBOX", 5): m.as_bytes()}))
    out = payload(await srv.call_tool("mail_attachment", {"folder": "INBOX", "uid": 5, "index": 0}))
    assert out["text"] == "naïve"


@pytest.mark.anyio
async def test_attachment_binary_is_base64(env):
    raw = raw_message(attachments=[("a.bin", "application/octet-stream", b"\x00\x01\x02")])
    srv, _ = build(env, FakeImap({("INBOX", 5): raw}))
    out = payload(await srv.call_tool("mail_attachment", {"folder": "INBOX", "uid": 5, "index": 0}))
    assert base64.b64decode(out["base64"]) == b"\x00\x01\x02"


@pytest.mark.anyio
async def test_attachment_over_cap_is_not_returned(env, monkeypatch):
    monkeypatch.setattr(tools_mod, "ATTACH_CAP", 10)
    raw = raw_message(attachments=[("a.bin", "application/octet-stream", b"x" * 11)])
    srv, _ = build(env, FakeImap({("INBOX", 5): raw}))
    out = payload(await srv.call_tool("mail_attachment", {"folder": "INBOX", "uid": 5, "index": 0}))
    assert out["size"] == 11 and "base64" not in out and "too large" in out["note"]


@pytest.mark.anyio
@pytest.mark.parametrize("index", [1, -1])
async def test_attachment_bad_index(env, index):
    raw = raw_message(attachments=[("a.txt", "text/plain", b"x")])
    srv, _ = build(env, FakeImap({("INBOX", 5): raw}))
    with pytest.raises(ToolError, match="no attachment"):
        await srv.call_tool("mail_attachment", {"folder": "INBOX", "uid": 5, "index": index})


@pytest.mark.anyio
@pytest.mark.skipif(not shutil.which("pdftotext") or not shutil.which("gs"),
                    reason="needs pdftotext and ghostscript to make a PDF")
async def test_attachment_pdf_is_text(env, tmp_path):  # pragma: no cover - environment dependent
    ps = tmp_path / "a.ps"
    ps.write_text("%!PS\n/Helvetica findfont 20 scalefont setfont 72 700 moveto (Invoice 4242) show showpage\n")
    pdf = tmp_path / "a.pdf"
    subprocess.run(["gs", "-q", "-dNOPAUSE", "-dBATCH", "-sDEVICE=pdfwrite", f"-sOutputFile={pdf}", str(ps)], check=True)
    raw = raw_message(attachments=[("a.pdf", "application/pdf", pdf.read_bytes())])
    srv, _ = build(env, FakeImap({("INBOX", 5): raw}))
    out = payload(await srv.call_tool("mail_attachment", {"folder": "INBOX", "uid": 5, "index": 0}))
    assert "Invoice 4242" in out["text"]


@pytest.mark.anyio
async def test_attachment_pdf_falls_back_to_base64_when_pdftotext_fails(env, monkeypatch):
    raw = raw_message(attachments=[("a.pdf", "application/pdf", b"not really a pdf")])
    srv, _ = build(env, FakeImap({("INBOX", 5): raw}))

    def boom(*a, **k):
        raise subprocess.TimeoutExpired("pdftotext", 30)
    monkeypatch.setattr(tools_mod.shutil, "which", lambda n: "/usr/bin/pdftotext")
    monkeypatch.setattr(tools_mod.subprocess, "run", boom)
    out = payload(await srv.call_tool("mail_attachment", {"folder": "INBOX", "uid": 5, "index": 0}))
    assert base64.b64decode(out["base64"]) == b"not really a pdf"


# --- flag / move -----------------------------------------------------------------------------

@pytest.mark.anyio
async def test_flag(env):
    srv, fake = build(env)
    out = payload(await srv.call_tool("mail_flag", {"folder": "INBOX", "uids": [4, 5], "seen": True, "flagged": False}))
    assert fake.named("set_flags") == [("set_flags", "INBOX", [4, 5], ["\\Seen"], ["\\Flagged"])]
    assert out == {"updated": [4, 5]}


@pytest.mark.anyio
@pytest.mark.parametrize("uids", [[], [0], [-1]])
async def test_flag_rejects_bad_uids(env, uids):
    srv, fake = build(env)
    with pytest.raises(ToolError, match="uids"):
        await srv.call_tool("mail_flag", {"folder": "INBOX", "uids": uids, "seen": True})
    assert srv.opened == []


@pytest.mark.anyio
async def test_flag_needs_something_to_change(env):
    srv, _ = build(env)
    with pytest.raises(ToolError, match="seen, flagged or answered"):
        await srv.call_tool("mail_flag", {"folder": "INBOX", "uids": [1]})


@pytest.mark.anyio
async def test_move_trash_resolves_special_folder(env):
    srv, fake = build(env)
    out = payload(await srv.call_tool("mail_move", {"folder": "INBOX", "uids": [4], "destination": "Trash"}))
    assert fake.named("move") == [("move", "INBOX", [4], "Trash", False)] and out == {"moved": [4], "to": "Trash"}


@pytest.mark.anyio
async def test_move_copy_to_named_folder(env):
    srv, fake = build(env)
    out = payload(await srv.call_tool("mail_move", {"folder": "INBOX", "uids": [4], "destination": "Old", "copy": True}))
    assert fake.named("move") == [("move", "INBOX", [4], "Old", True)] and out == {"copied": [4], "to": "Old"}


@pytest.mark.anyio
async def test_move_to_missing_folder_does_not_create_it(env):
    srv, fake = build(env)
    with pytest.raises(ToolError, match="no folder named"):
        await srv.call_tool("mail_move", {"folder": "INBOX", "uids": [4], "destination": "Typo"})
    assert fake.named("move") == [] and fake.named("ensure_folder") == []


@pytest.mark.anyio
async def test_move_to_archive_is_refused_when_the_mailbox_has_none(env):
    srv, fake = build(env)          # FOLDERS has no archive folder, by flag or by name
    assert fake.special("archive") is None
    with pytest.raises(ToolError, match=": no archive folder found$"):
        await srv.call_tool("mail_move", {"folder": "INBOX", "uids": [4], "destination": "archive"})
    assert fake.named("move") == [] and fake.named("ensure_folder") == []


@pytest.mark.anyio
async def test_move_rejects_bad_uids(env):
    srv, _ = build(env)
    with pytest.raises(ToolError, match="uids"):
        await srv.call_tool("mail_move", {"folder": "INBOX", "uids": [], "destination": "trash"})


# --- draft -----------------------------------------------------------------------------------

@pytest.mark.anyio
async def test_draft_is_appended_to_drafts_with_draft_flag(env):
    srv, fake = build(env)
    out = payload(await srv.call_tool("mail_draft", {"to": ["c@x.co.za"], "subject": "Hi", "text": "body",
                                                       "cc": ["d@x.co.za"]}))
    (_, folder, raw, flags), = fake.named("append")
    m = message_from_bytes(raw)
    assert (folder, flags) == ("Drafts", ("\\Draft", "\\Seen"))
    assert (m["From"], m["To"], m["Cc"], m["Subject"]) == ("me@x.co.za", "c@x.co.za", "d@x.co.za", "Hi")
    assert out == {"saved_to": "Drafts", "uid": 11, "message_id": m["Message-ID"], "subject": "Hi",
                   "size": len(raw.replace(b"\n", b"\r\n"))}


@pytest.mark.anyio
async def test_draft_with_a_signature_saves_its_images_as_cid_parts(env):
    from tests.test_inline import ASSETS, CURSOR, SIGNATURE, WORDMARK, gif_frames
    fetched = []
    srv, fake = build(env, fetch_image=lambda u: fetched.append(u) or ASSETS[u])
    await srv.call_tool("mail_draft", {"to": ["c@x.co.za"], "subject": "Hi", "text": "Hello,", "html": SIGNATURE})
    raw = fake.named("append")[0][2]
    m = BytesParser(policy=policy.default).parsebytes(raw)
    assert fetched == [WORDMARK, CURSOR]
    related = next(p for p in m.walk() if p.get_content_type() == "multipart/related")
    html, png, gif = related.get_payload()
    assert (png.get_content_type(), gif.get_content_type()) == ("image/png", "image/gif")
    body = html.get_content()
    for part in (png, gif):
        assert f'src="cid:{part["Content-ID"].strip("<>")}"' in body
    assert "https://" not in body.replace("https://www.example.org", "")
    assert gif.get_content() == ASSETS[CURSOR] and gif_frames(gif.get_content()) == 2
    assert m.get_body(("plain",)).get_content().strip() == "Hello,"


@pytest.mark.anyio
async def test_draft_with_an_image_that_cannot_be_embedded_is_not_saved(env):
    srv, fake = build(env, fetch_image=lambda u: pytest.fail("http is never fetched"))
    with pytest.raises(ToolError, match="cannot be embedded"):
        await srv.call_tool("mail_draft", {"to": ["c@x.co.za"], "subject": "Hi", "text": "t",
                                           "html": '<img src="http://h.example/a.png">'})
    assert fake.named("append") == []


@pytest.mark.anyio
async def test_send_embeds_images_in_the_sent_message_and_its_copy(env):
    from tests.test_inline import ASSETS, SIGNATURE
    sender = FakeSender()
    srv, fake = build(env, sender=sender, fetch_image=ASSETS.__getitem__)
    await srv.call_tool("mail_send", {"to": ["c@x.co.za"], "subject": "Hi", "text": "Hello,", "html": SIGNATURE})
    for raw in (sender.sent[0]["msg"].as_bytes(), fake.named("append")[0][2]):
        m = BytesParser(policy=policy.default).parsebytes(raw)
        assert [p.get_content_type() for p in m.walk() if p.get_content_maintype() == "image"] == ["image/png", "image/gif"]


@pytest.mark.anyio
async def test_draft_reply_is_threaded_and_replaces_old_draft(env):
    srv, fake = build(env, FakeImap({("INBOX", 5): raw_message(mid="<9@x>")}))
    out = payload(await srv.call_tool("mail_draft", {"to": ["other@x.co.za"], "text": "answer", "reply_to_folder": "INBOX",
                                                       "reply_to_uid": 5, "replace_draft_uid": 2}))
    m = message_from_bytes(fake.named("append")[0][2])
    assert m["In-Reply-To"] == "<9@x>" and m["To"] == "other@x.co.za" and m["Subject"] == "Re: Quote"
    assert fake.named("move") == [("move", "Drafts", [2], "Trash", False)]
    assert out == {"saved_to": "Drafts", "uid": 11, "message_id": m["Message-ID"], "subject": "Re: Quote",
                   "size": out["size"]}


@pytest.mark.anyio
async def test_draft_reply_refuses_a_subject_it_would_ignore(env):
    srv, fake = build(env, FakeImap({("INBOX", 5): raw_message()}))
    with pytest.raises(ToolError, match="`subject` is not supported on a reply"):
        await srv.call_tool("mail_draft", {"to": ["c@x.co.za"], "subject": "New subject", "text": "t",
                                           "reply_to_folder": "INBOX", "reply_to_uid": 5})
    assert fake.named("append") == [] and srv.opened == []


@pytest.mark.anyio
async def test_new_draft_needs_a_subject(env):
    srv, fake = build(env)
    with pytest.raises(ToolError, match="a new draft needs `subject`"):
        await srv.call_tool("mail_draft", {"to": ["c@x.co.za"], "text": "t"})
    assert fake.named("append") == [] and srv.opened == []


@pytest.mark.anyio
async def test_draft_reply_recipients_are_validated(env):
    srv, fake = build(env, FakeImap({("INBOX", 5): raw_message()}))
    with pytest.raises(ToolError, match="recipient"):
        await srv.call_tool("mail_draft", {"to": ["a@x.co.za\r\nBcc: evil@x.co.za"], "text": "t",
                                           "reply_to_folder": "INBOX", "reply_to_uid": 5})
    assert fake.named("append") == []


@pytest.mark.anyio
async def test_draft_creates_drafts_folder_when_missing(env, monkeypatch):
    class NoDrafts(FakeImap):
        def special(self, kind):
            return None if kind == "drafts" else super().special(kind)
    srv, fake = build(env, NoDrafts())
    await srv.call_tool("mail_draft", {"to": ["c@x.co.za"], "subject": "Hi", "text": "body"})
    assert fake.named("ensure_folder") == [("ensure_folder", "Drafts")] and fake.named("append")[0][1] == "Drafts"


# --- send ------------------------------------------------------------------------------------

@pytest.mark.anyio
async def test_send_new_from_signed_in_mailbox_saves_sent_without_bcc(env):
    sender = FakeSender()
    srv, fake = build(env, sender=sender)
    out = payload(await srv.call_tool("mail_send", {"to": ["c@x.co.za"], "subject": "Hello", "text": "body",
                                                     "cc": ["d@x.co.za"], "bcc": ["secret@x.co.za"],
                                                     "mailbox": "accounts@x.co.za"}))
    (sent,) = sender.sent
    assert (sent["address"], sent["password"], sent["port"], sent["bcc"]) == \
        ("accounts@x.co.za", "pw2", 465, ("secret@x.co.za",))
    assert sent["msg"]["From"] == "accounts@x.co.za"
    (_, folder, raw, flags), = fake.named("append")
    assert (folder, flags) == ("Sent", ("\\Seen",))
    assert b"secret@x.co.za" not in raw and message_from_bytes(raw)["Bcc"] is None
    assert message_from_bytes(raw)["Message-ID"] == sent["msg"]["Message-ID"]
    assert out["saved_to_sent"] is True and out["subject"] == "Hello" and "secret@x.co.za" in out["sent_to"]


@pytest.mark.anyio
async def test_send_reply_marks_original_answered(env):
    sender = FakeSender()
    srv, fake = build(env, FakeImap({("INBOX", 5): raw_message(mid="<9@x>")}), sender)
    await srv.call_tool("mail_send", {"text": "thanks", "reply_to_folder": "INBOX", "reply_to_uid": 5})
    msg = sender.sent[0]["msg"]
    assert msg["To"] == "Cust <c@x.co.za>" and msg["In-Reply-To"] == "<9@x>" and msg["From"] == "me@x.co.za"
    assert fake.named("set_flags") == [("set_flags", "INBOX", [5], ["\\Answered"], [])]
    assert len(fake.named("append")) == 1


@pytest.mark.anyio
async def test_send_reply_all_and_cc(env):
    sender = FakeSender()
    raw = raw_message(to="me@x.co.za, other@x.co.za")
    srv, _ = build(env, FakeImap({("INBOX", 5): raw}), sender)
    await srv.call_tool("mail_send", {"text": "t", "reply_to_folder": "INBOX", "reply_to_uid": 5,
                                      "reply_all": True, "cc": ["extra@x.co.za"]})
    cc = sender.sent[0]["msg"]["Cc"]
    assert "other@x.co.za" in cc and "extra@x.co.za" in cc and "me@x.co.za" not in cc


@pytest.mark.anyio
async def test_send_forward(env):
    sender = FakeSender()
    srv, fake = build(env, FakeImap({("INBOX", 5): raw_message(subject="Invoice")}), sender)
    await srv.call_tool("mail_send", {"to": ["boss@x.co.za"], "text": "see below",
                                      "forward_folder": "INBOX", "forward_uid": 5})
    msg = sender.sent[0]["msg"]
    assert msg["Subject"] == "Fwd: Invoice" and msg["To"] == "boss@x.co.za"
    assert any(p.get_content_type() == "message/rfc822" for p in msg.iter_attachments())
    assert fake.named("set_flags") == []


@pytest.mark.anyio
@pytest.mark.parametrize("args,match", [
    ({"subject": "s", "text": "t"}, "to"),
    ({"to": ["a@x.co.za"], "text": "t"}, "subject"),
    ({"reply_to_folder": "INBOX", "text": "t"}, "reply_to_folder and reply_to_uid"),
    ({"reply_to_uid": 5, "to": ["a@x.co.za"], "subject": "s"}, "reply_to_folder and reply_to_uid"),
    ({"forward_folder": "INBOX", "to": ["a@x.co.za"]}, "forward_folder and forward_uid"),
    ({"reply_to_folder": "INBOX", "reply_to_uid": 5, "forward_folder": "INBOX", "forward_uid": 5,
      "to": ["a@x.co.za"]}, "either"),
    ({"forward_folder": "INBOX", "forward_uid": 5, "text": "t"}, "to"),
])
async def test_send_rejects_incomplete_requests(env, args, match):
    sender = FakeSender()
    srv, fake = build(env, FakeImap({("INBOX", 5): raw_message()}), sender)
    with pytest.raises(ToolError, match=match):
        await srv.call_tool("mail_send", args)
    assert sender.sent == []


@pytest.mark.anyio
@pytest.mark.parametrize("args,match", [
    ({"reply_to_folder": "INBOX", "reply_to_uid": 5, "subject": "New subject"}, "subject"),
    ({"forward_folder": "INBOX", "forward_uid": 5, "to": ["a@x.co.za"], "subject": "New subject"}, "subject"),
    ({"forward_folder": "INBOX", "forward_uid": 5, "to": ["a@x.co.za"], "html": "<p>hi</p>"}, "html"),
])
async def test_send_refuses_options_a_reply_or_forward_would_ignore(env, args, match):
    sender = FakeSender()
    srv, _ = build(env, FakeImap({("INBOX", 5): raw_message()}), sender)
    with pytest.raises(ToolError, match=f"`{match}` is not supported"):
        await srv.call_tool("mail_send", {"text": "t", **args})
    assert sender.sent == [] and srv.opened == []


@pytest.mark.anyio
async def test_send_reply_with_html_is_still_allowed(env):
    sender = FakeSender()
    srv, _ = build(env, FakeImap({("INBOX", 5): raw_message()}), sender)
    await srv.call_tool("mail_send", {"text": "t", "html": "<p>t</p>", "reply_to_folder": "INBOX", "reply_to_uid": 5})
    assert len(sender.sent) == 1


@pytest.mark.anyio
async def test_send_refuses_header_injection(env):
    sender = FakeSender()
    srv, _ = build(env, sender=sender)
    with pytest.raises(ToolError, match="CR, LF and NUL are not allowed in the Subject header"):
        await srv.call_tool("mail_send", {"to": ["a@x.co.za"], "subject": "s\r\nBcc: evil@x.co.za", "text": "t"})
    assert sender.sent == []


@pytest.mark.anyio
async def test_send_succeeds_even_if_saving_to_sent_fails(env):
    class SentFails(FakeImap):
        def append(self, folder, raw, flags, message_id=None):
            raise MailError("APPEND failed: over quota")
    sender = FakeSender()
    srv, _ = build(env, SentFails(), sender)
    out = payload(await srv.call_tool("mail_send", {"to": ["c@x.co.za"], "subject": "s", "text": "t"}))
    assert len(sender.sent) == 1 and out["saved_to_sent"] is False and "not saved" in out["warning"]


def smtp_server(monkeypatch, auth_code):
    """The real smtp.send over a socketpair to a scripted SMTP server that answers AUTH with auth_code."""
    client, server_end = socket.socketpair()
    server = ScriptedServer(server_end, password="pw", auth_code=auth_code)
    monkeypatch.setattr(Connector, "tls_connect", lambda self, port, timeout=10.0: client)
    server.start()
    return server


def build_with_real_smtp(env):
    s, store, _ = env
    srv, fake = MCPServer("t"), FakeImap()
    tools_mod.register_mail_tools(srv, store, s, opener=lambda *a, **k: fake,
                                  sender=smtp.send)
    return srv


@pytest.mark.anyio
async def test_send_smtp_auth_failure_revokes_grant(env, monkeypatch):
    _, store, _ = env
    server = smtp_server(monkeypatch, "535 5.7.8 Authentication credentials invalid")
    srv = build_with_real_smtp(env)
    with pytest.raises(ToolError, match="rejected the password for me@x.co.za.*other mailboxes"):
        await srv.call_tool("mail_send", {"to": ["c@x.co.za"], "subject": "s", "text": "t"})
    server.join(timeout=5)
    assert store.list_grants()[0]["revoked"] == 0                    # two mailboxes: the connection stays


@pytest.mark.anyio
@pytest.mark.parametrize("reply", ["504 5.5.4 Unrecognized authentication type",
                                   "530 5.7.0 Must issue a STARTTLS command first"])
async def test_send_smtp_auth_refusal_that_is_not_bad_credentials_keeps_grant(env, monkeypatch, reply):
    _, store, _ = env
    server = smtp_server(monkeypatch, reply)
    srv = build_with_real_smtp(env)
    with pytest.raises(ToolError, match=f"SMTP AUTH failed with {reply[:3]}"):
        await srv.call_tool("mail_send", {"to": ["c@x.co.za"], "subject": "s", "text": "t"})
    server.join(timeout=5)
    assert store.list_grants()[0]["revoked"] == 0


# --- errors and audit ------------------------------------------------------------------------

@pytest.mark.anyio
async def test_network_errors_become_tool_errors_without_detail(env):
    import ssl
    for exc in (ConnectionRefusedError("10.0.0.1 secret-host"), ssl.SSLError("bad cert for pw")):
        def opener(*a, _e=exc, **k):
            raise _e
        srv = MCPServer("t")
        tools_mod.register_mail_tools(srv, env[1], env[0], opener=opener, sender=None)
        with pytest.raises(ToolError, match="Could not reach the mail server") as info:
            await srv.call_tool("mail_search", {})
        assert "secret-host" not in str(info.value) and "pw" not in str(info.value).replace("Could", "")
    assert env[1].list_grants()[0]["revoked"] == 0


@pytest.mark.anyio
async def test_imap_protocol_errors_become_tool_errors(env):
    import imaplib

    class Broken(FakeImap):
        def search(self, *a, **k):
            raise imaplib.IMAP4.abort("socket error: EOF")
    srv, _ = build(env, Broken())
    with pytest.raises(ToolError, match="mail server"):
        await srv.call_tool("mail_search", {})
    assert env[1].list_grants()[0]["revoked"] == 0


@pytest.mark.anyio
async def test_password_never_reaches_a_tool_error(env):
    def opener(*a, **k):
        raise ValueError("bad value pw2 in login")
    srv = MCPServer("t")
    tools_mod.register_mail_tools(srv, env[1], env[0], opener=opener, sender=None)
    with pytest.raises(ToolError) as info:
        await srv.call_tool("mail_search", {"mailbox": "accounts@x.co.za"})
    assert "pw2" not in str(info.value)


def audit_lines(caplog):
    return [json.loads(r.getMessage()) for r in caplog.records if r.name == "mcp_server_imap_smtp.audit"]


@pytest.mark.anyio
async def test_audit_lines_have_only_the_allowed_fields(env, caplog):
    caplog.set_level(logging.INFO, logger="mcp_server_imap_smtp.audit")
    srv, _ = build(env)
    await srv.call_tool("mail_search", {"subject": "Quote"})
    (line,) = audit_lines(caplog)
    assert set(line) == {"ts", "grant", "mailbox", "host", "tool", "folder", "count", "outcome"}
    assert (line["tool"], line["mailbox"], line["folder"], line["count"], line["outcome"]) == \
        ("mail_search", "me@x.co.za", "INBOX", 1, "ok")


@pytest.mark.anyio
async def test_audit_never_holds_recipients_subjects_or_bodies(env, caplog):
    caplog.set_level(logging.DEBUG)
    sender = FakeSender()
    srv, _ = build(env, sender=sender)
    await srv.call_tool("mail_send", {"to": ["victim@y.co.za"], "subject": "Confidential merger", "text": "launch codes",
                                      "bcc": ["hidden@y.co.za"]})
    sender.exc = MailError("SMTP refused: 550 victim@y.co.za unknown")
    with pytest.raises(ToolError, match="victim@y.co.za"):  # the caller sees the server's reason ...
        await srv.call_tool("mail_send", {"to": ["victim@y.co.za"], "subject": "Confidential merger", "text": "launch codes"})
    lines = audit_lines(caplog)
    assert [(l["tool"], l["outcome"], l["count"]) for l in lines] == [("mail_send", "ok", 2), ("mail_send", "error", None)]
    text = "\n".join(r.getMessage() for r in caplog.records)  # ... but no log line carries it
    for secret in ("victim", "hidden", "Confidential", "launch codes", "pw", "550"):
        assert secret not in text


@pytest.mark.anyio
async def test_audit_records_auth_failure(env, caplog):
    caplog.set_level(logging.INFO, logger="mcp_server_imap_smtp.audit")
    srv = MCPServer("t")

    def opener(*a, **k):
        raise MailAuthError("no")
    tools_mod.register_mail_tools(srv, env[1], env[0], opener=opener, sender=None)
    with pytest.raises(ToolError):
        await srv.call_tool("mail_move", {"folder": "INBOX", "uids": [1], "destination": "trash"})
    (line,) = audit_lines(caplog)
    assert (line["outcome"], line["tool"], line["folder"], line["grant"]) == ("auth_failed", "mail_move", "INBOX", env[2])


def test_tool_annotations(env):
    srv, _ = build(env)
    import asyncio
    tools = {t.name: t for t in asyncio.run(srv.list_tools())}
    assert set(tools) == {"mail_accounts", "mail_folders", "mail_search", "mail_read", "mail_thread", "mail_attachment",
                          "mail_flag", "mail_move", "mail_draft", "mail_send"}
    assert tools["mail_read"].annotations.read_only_hint is True
    assert tools["mail_send"].annotations.destructive_hint is True and tools["mail_send"].annotations.open_world_hint is True
    assert tools["mail_move"].annotations.read_only_hint is False


@pytest.mark.anyio
async def test_unexpected_error_is_audited_and_reported_without_its_text(env, caplog):
    caplog.set_level(logging.INFO, logger="mcp_server_imap_smtp.audit")

    class Exploding(FakeImap):
        def search(self, *a, **k):
            raise KeyError("internal detail pw2 /srv/secret")
    srv, _ = build(env, Exploding())
    with pytest.raises(ToolError) as info:
        await srv.call_tool("mail_search", {"mailbox": "accounts@x.co.za"})
    assert str(info.value).endswith(": Unexpected error; the operation may not have completed.")
    ours = info.value.__cause__ or info.value          # the SDK re-wraps a tool's ToolError
    assert ours.__cause__ is None and ours.__suppress_context__
    (line,) = audit_lines(caplog)
    assert set(line) == {"ts", "grant", "mailbox", "host", "tool", "folder", "count", "outcome"}
    assert (line["outcome"], line["tool"], line["grant"], line["mailbox"]) == \
        ("error", "mail_search", env[2], "accounts@x.co.za")
    assert "internal detail" not in caplog.text and env[1].list_grants()[0]["revoked"] == 0


@pytest.mark.anyio
@pytest.mark.parametrize("tool,args,folder", [
    ("mail_search", {"limit": 0}, "INBOX"),
    ("mail_read", {"folder": "INBOX", "uid": 0}, "INBOX"),
    ("mail_flag", {"folder": "Old", "uids": [1]}, "Old"),
    ("mail_send", {"subject": "s", "text": "t"}, None),
])
async def test_validation_refusals_are_audited(env, caplog, tool, args, folder):
    caplog.set_level(logging.INFO, logger="mcp_server_imap_smtp.audit")
    srv, _ = build(env)
    with pytest.raises(ToolError):
        await srv.call_tool(tool, args)
    (line,) = audit_lines(caplog)
    assert set(line) == {"ts", "grant", "mailbox", "host", "tool", "folder", "count", "outcome"}
    assert (line["outcome"], line["tool"], line["grant"], line["mailbox"], line["folder"], line["count"]) == \
        ("refused", tool, env[2], None, folder, None)


@pytest.mark.anyio
async def test_unknown_mailbox_refusal_is_audited_without_the_address(env, caplog):
    caplog.set_level(logging.INFO, logger="mcp_server_imap_smtp.audit")
    srv, _ = build(env)
    with pytest.raises(ToolError, match="not connected"):
        await srv.call_tool("mail_search", {"mailbox": "boss@x.co.za"})
    (line,) = audit_lines(caplog)
    assert (line["outcome"], line["grant"], line["mailbox"]) == ("refused", env[2], None)
    assert "boss@x.co.za" not in caplog.text


@pytest.mark.anyio
async def test_not_signed_in_refusal_is_audited_with_no_grant(env, caplog, monkeypatch):
    caplog.set_level(logging.INFO, logger="mcp_server_imap_smtp.audit")
    srv, _ = build(env)
    monkeypatch.setattr(tools_mod, "get_access_token", lambda: None)
    with pytest.raises(ToolError, match="Reconnect"):
        await srv.call_tool("mail_accounts", {})
    (line,) = audit_lines(caplog)
    assert (line["outcome"], line["tool"], line["grant"], line["mailbox"]) == ("refused", "mail_accounts", None, None)


@pytest.mark.anyio
async def test_mail_errors_are_audited_once(env, caplog):
    caplog.set_level(logging.INFO, logger="mcp_server_imap_smtp.audit")
    srv, _ = build(env)
    with pytest.raises(ToolError, match="no folder named"):
        await srv.call_tool("mail_move", {"folder": "INBOX", "uids": [4], "destination": "Typo"})
    assert [l["outcome"] for l in audit_lines(caplog)] == ["error"]


# --- servers removed or changed since sign-in (review fix 5) and legacy rows (fix 4) ----------

def _grant_on(tmp_path, monkeypatch, sealed_server, configured, legacy_row=False, **settings_kw):
    s = Settings(issuer_url="http://127.0.0.1:8765", mail_resource_url="http://127.0.0.1:8765/mail",
                 mail_servers=configured, db_path=tmp_path / "s.sqlite",
                 **{"send_mode": "send", **settings_kw})
    store = Store(s.db_path, legacy_server=s.legacy_server)
    gid, key = store.create_grant("c1", s.mail_resource_url, [("me@x.co.za", "pw", sealed_server)])
    if legacy_row:
        from mcp_server_imap_smtp import crypto
        store._q("UPDATE mailboxes SET sealed=?, host=NULL WHERE grant_id=?",
                 (crypto.seal(key, b"old-pw", f"{gid}|me@x.co.za".encode()), gid))
    at, _ = store.issue_tokens(gid, key, "c1", [], s.mail_resource_url, 3600, 86400)

    class Tok:
        token = at
    monkeypatch.setattr(tools_mod, "get_access_token", lambda: Tok)
    return s, store, gid


@pytest.mark.anyio
async def test_mailbox_on_a_removed_server_is_refused_and_audited(tmp_path, monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger="mcp_server_imap_smtp.audit")
    gone = MailServer("old.example.net")
    env = _grant_on(tmp_path, monkeypatch, gone, (MAIL1,))
    srv, _ = build(env, sender=(sender := FakeSender()))
    for tool, args in (("mail_search", {}), ("mail_send", {"to": ["c@y.co.za"], "subject": "s", "text": "t"})):
        with pytest.raises(ToolError, match="Please reconnect Mail Connector in your AI app"):
            await srv.call_tool(tool, args)
    assert srv.opened == [] and sender.sent == []          # nothing was opened on the removed server
    assert [(l["tool"], l["outcome"], l["host"]) for l in audit_lines(caplog)] == [
        ("mail_search", "server_removed", "old.example.net"), ("mail_send", "server_removed", "old.example.net")]


@pytest.mark.anyio
async def test_ports_come_from_the_current_configuration_not_the_seal(tmp_path, monkeypatch):
    sealed = MailServer("mail.client.example", imap_port=993, smtp_port=465)
    now = MailServer("mail.client.example", imap_port=1993, smtp_port=587, domains=("client.example",),
                     match_mx=False)
    env = _grant_on(tmp_path, monkeypatch, sealed, (MAIL1, now))
    srv, _ = build(env, sender=(sender := FakeSender()))
    await srv.call_tool("mail_search", {})
    await srv.call_tool("mail_send", {"to": ["c@y.co.za"], "subject": "s", "text": "t"})
    assert srv.opened[0] == ("me@x.co.za", "pw", 1993)
    assert (sender.sent[0]["server"].host, sender.sent[0]["port"]) == ("mail.client.example", 587)
    (_, boxes) = env[1].unlock(tools_mod.get_access_token().token)
    assert (boxes["me@x.co.za"].server.imap_port, boxes["me@x.co.za"].server.smtp_port) == (993, 465)  # seal unchanged


@pytest.mark.anyio
async def test_security_modes_come_from_the_current_configuration(tmp_path, monkeypatch):
    """Every tool path (one mailbox, mailbox="*", sending) opens the server as configured now: STARTTLS when
    the operator set it, whatever the seal recorded at sign-in (ticket 09)."""
    sealed = MailServer("mail.client.example")
    now = MailServer("mail.client.example", imap_security="starttls", smtp_security="starttls",
                     domains=("client.example",), match_mx=False)
    env = _grant_on(tmp_path, monkeypatch, sealed, (MAIL1, now))
    s, store, _ = env
    srv, servers = MCPServer("t"), []
    sender = FakeSender()

    def opener(server, address, password):
        servers.append(server)
        return FakeImap()
    tools_mod.register_mail_tools(srv, store, s, opener=opener, sender=sender)
    await srv.call_tool("mail_search", {})
    await srv.call_tool("mail_search", {"mailbox": "*"})
    await srv.call_tool("mail_send", {"to": ["c@y.co.za"], "subject": "s", "text": "t"})
    assert servers and {(m.imap_security, m.imap_port) for m in servers} == {("starttls", 143)}
    assert (sender.sent[0]["server"].smtp_security, sender.sent[0]["port"]) == ("starttls", 587)
    assert sender.sent[0]["server"].ehlo_name == "[127.0.0.1]"     # from the issuer URL, never getfqdn()


@pytest.mark.anyio
async def test_legacy_row_with_several_servers_and_no_legacy_host_must_reconnect(tmp_path, monkeypatch):
    isp = MailServer("mail.client.example", domains=("client.example",), match_mx=False)
    env = _grant_on(tmp_path, monkeypatch, MAIL1, (MAIL1, isp), legacy_row=True)
    srv, _ = build(env)
    for tool in ("mail_search", "mail_accounts"):
        with pytest.raises(ToolError, match="Please reconnect Mail Connector in your AI app"):
            await srv.call_tool(tool, {})
    assert srv.opened == []


@pytest.mark.anyio
@pytest.mark.parametrize("legacy_host,expected", [("mail.client.example", "mail.client.example"), ("", None)])
async def test_legacy_row_uses_legacy_mail_host_or_the_only_server(tmp_path, monkeypatch, legacy_host, expected):
    isp = MailServer("mail.client.example", imap_port=1993, domains=("client.example",), match_mx=False)
    configured = (MAIL1, isp) if expected else (isp,)
    env = _grant_on(tmp_path, monkeypatch, MAIL1, configured, legacy_row=True, legacy_mail_host=legacy_host)
    srv, _ = build(env)
    await srv.call_tool("mail_search", {})
    assert srv.opened == [("me@x.co.za", "old-pw", 1993)]


# --- every mailbox in one grant: mailbox="*" and per-mailbox tools (20 October) -------------------------

STAFF = [f"staff{i}@client.example" for i in range(1, 88)]
ISP = MailServer("mail.client.example", domains=("client.example",), match_mx=False)


def big_grant(tmp_path, monkeypatch, addresses, isp=ISP, **settings_kw):
    """A grant holding `addresses` (each password "pw-<address>") on ISP, the caller signed in to it.
    isp: the configuration's entry for ISP's host (for example with another max_sessions)."""
    s = Settings(issuer_url="http://127.0.0.1:8765", mail_resource_url="http://127.0.0.1:8765/mail",
                 mail_servers=(MAIL1, isp), db_path=tmp_path / "s.sqlite", **settings_kw)
    store = Store(s.db_path)
    gid, key = store.create_grant("c1", s.mail_resource_url, [(a, f"pw-{a}", ISP) for a in addresses])
    at, _ = store.issue_tokens(gid, key, "c1", [], s.mail_resource_url, 3600, 86400)

    class Tok:
        token = at
    monkeypatch.setattr(tools_mod, "get_access_token", lambda: Tok)
    return s, store, gid


class DatedImap(FakeImap):
    """One mailbox whose search returns `n` rows dated by `day` (newest first, like the real client)."""

    def __init__(self, address, day, n=2, total=None):
        super().__init__()
        self.address, self.day, self.n, self.total = address, day, n, total if total is not None else n

    def search(self, folder, q, limit=25, offset=0):
        self.calls.append(("search", folder, q, limit, offset))
        rows = [{**self._row(100 + k), "date": f"Mon, {self.day:02d} Oct 2026 {10 - k:02d}:00:00 +0200",
                 "subject": f"{self.address} {k}"} for k in range(self.n)]
        return self.total, rows[:limit]


def fan_out(env, make_imap, sessions=None):
    """Server whose opener builds an IMAP fake per address with make_imap(address, password)."""
    s, store, _ = env
    srv = MCPServer("t")
    srv.opened, srv.fakes = [], {}

    def opener(server, address, password):
        srv.opened.append((address, password, server.host))
        fake = make_imap(address, password)
        srv.fakes[address] = fake
        return fake
    tools_mod.register_mail_tools(srv, store, s, opener=opener, sender=FakeSender(), sessions=sessions)
    return srv


@pytest.mark.anyio
async def test_mail_accounts_lists_every_mailbox_of_a_large_grant(tmp_path, monkeypatch):
    env = big_grant(tmp_path, monkeypatch, ["owner@client.example", *STAFF])
    out = payload(await fan_out(env, lambda a, p: FakeImap()).call_tool("mail_accounts", {}))
    assert out["count"] == 88 and out["mailboxes"] == ["owner@client.example", *STAFF]


@pytest.mark.anyio
async def test_search_every_mailbox_merges_newest_first_with_the_mailbox_named(tmp_path, monkeypatch):
    addresses = ["owner@client.example", *STAFF]
    env = big_grant(tmp_path, monkeypatch, addresses)
    day = {a: 1 + i % 28 for i, a in enumerate(addresses)}
    srv = fan_out(env, lambda a, p: DatedImap(a, day[a], total=3))
    out = payload(await srv.call_tool("mail_search", {"mailbox": "*", "subject": "Quote", "limit": 10, "offset": 5}))
    assert {(a, p) for a, p, _ in srv.opened} == {(a, f"pw-{a}") for a in addresses}       # each its own password
    assert out["mailbox"] == "*" and out["searched"] == 88 and out["total"] == 88 * 3 and "errors" not in out
    expected = [{**r, "mailbox": a} for a in addresses for r in DatedImap(a, day[a]).search("INBOX", None)[1]]
    expected.sort(key=tools_mod._when, reverse=True)
    assert [(r["mailbox"], r["date"]) for r in out["messages"]] == [(r["mailbox"], r["date"]) for r in expected[5:15]]
    # Each mailbox was asked for the newest offset + limit rows, from the start.
    assert {c[3:] for f in srv.fakes.values() for c in f.named("search")} == {(15, 0)}


@pytest.mark.anyio
async def test_search_every_mailbox_reports_failures_and_keeps_the_grant(tmp_path, monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger="mcp_server_imap_smtp.audit")
    addresses = ["owner@client.example", "left@client.example", "down@client.example", "odd@client.example"]
    s, store, gid = env = big_grant(tmp_path, monkeypatch, addresses)

    def make(a, p):
        if a == "left@client.example":
            raise MailAuthError("no")          # a staff member changed their password
        if a == "down@client.example":
            raise ConnectionRefusedError()
        if a == "odd@client.example":
            raise MailError(f"SEARCH failed for {p}")     # a server message that happens to hold the password
        return DatedImap(a, 5)
    srv = fan_out(env, make)
    out = payload(await srv.call_tool("mail_search", {"mailbox": "*"}))
    assert out["searched"] == 1 and [m["mailbox"] for m in out["messages"]] == ["owner@client.example"] * 2
    assert out["errors"] == [
        {"mailbox": "left@client.example",
         "error": "the mail server rejected the password (it may have changed); update it at http://127.0.0.1:8765/mail/manage"},
        {"mailbox": "down@client.example",
         "error": "Could not reach the mail server (ConnectionRefusedError). Try again shortly."},
        {"mailbox": "odd@client.example", "error": "The request was refused."}]
    assert "pw-" not in json.dumps(out)
    assert store.list_grants()[0]["revoked"] == 0                    # one changed password does not end the grant
    assert {(l["mailbox"], l["outcome"]) for l in audit_lines(caplog)} == {
        ("owner@client.example", "ok"), ("left@client.example", "auth_failed"),
        ("down@client.example", "network"), ("odd@client.example", "error")}
    # Named on its own, the mailbox with the changed password fails alone: the connection holds other
    # mailboxes, so it stays and the owner keeps the rest.
    with pytest.raises(ToolError, match="rejected the password for left@client.example.*other mailboxes"):
        await srv.call_tool("mail_search", {"mailbox": "left@client.example"})
    assert store.list_grants()[0]["revoked"] == 0
    out = payload(await srv.call_tool("mail_search", {"mailbox": "owner@client.example"}))
    assert out["messages"]


@pytest.mark.anyio
async def test_search_every_mailbox_across_all_folders(tmp_path, monkeypatch):
    env = big_grant(tmp_path, monkeypatch, ["a@client.example", "b@client.example"])
    srv = fan_out(env, lambda a, p: FakeImap())
    out = payload(await srv.call_tool("mail_search", {"mailbox": "*", "folder": "*", "limit": 100}))
    assert out["total"] == 10 and len(out["messages"]) == 10       # 5 searchable folders in each of 2 mailboxes
    assert {(m["mailbox"], m["folder"]) for m in out["messages"]} == {
        (a, f) for a in ("a@client.example", "b@client.example") for f in ("INBOX", "Sent", "Drafts", "Old", "Shared/Team")}


@pytest.mark.anyio
@pytest.mark.parametrize("limit,offset,ok", [(100, 400, True), (100, 401, False), (1, 500, False)])
async def test_search_every_mailbox_caps_how_deep_it_pages(tmp_path, monkeypatch, limit, offset, ok):
    env = big_grant(tmp_path, monkeypatch, ["a@client.example"])
    srv = fan_out(env, lambda a, p: FakeImap())
    args = {"mailbox": "*", "limit": limit, "offset": offset}
    if ok:
        await srv.call_tool("mail_search", args)
    else:
        with pytest.raises(ToolError, match="500"):
            await srv.call_tool("mail_search", args)
        assert srv.opened == []


@pytest.mark.anyio
async def test_search_every_mailbox_honours_the_operators_mailbox_cap(tmp_path, monkeypatch):
    addresses = ["a@client.example", "b@client.example", "c@client.example"]
    env = big_grant(tmp_path, monkeypatch, addresses, search_max_mailboxes=2)
    srv = fan_out(env, lambda a, p: DatedImap(a, 3))
    out = payload(await srv.call_tool("mail_search", {"mailbox": "*"}))
    assert out["searched"] == 2 and {a for a, _, _ in srv.opened} == set(addresses[:2])
    assert out["errors"] == [{"mailbox": "c@client.example", "error": "not searched: at most 2 mailboxes are searched at once"}]


@pytest.mark.anyio
async def test_search_every_mailbox_stops_starting_mailboxes_after_its_time_budget(tmp_path, monkeypatch):
    monkeypatch.setattr(tools_mod, "ALL_MAILBOXES_SECONDS", 0.0)
    env = big_grant(tmp_path, monkeypatch, ["a@client.example", "b@client.example"])
    srv = fan_out(env, lambda a, p: DatedImap(a, 3))
    out = payload(await srv.call_tool("mail_search", {"mailbox": "*"}))
    assert srv.opened == [] and out["searched"] == 0 and out["messages"] == []
    assert [e["mailbox"] for e in out["errors"]] == ["a@client.example", "b@client.example"]
    assert all("ran out of time" in e["error"] for e in out["errors"])


@pytest.mark.anyio
async def test_search_every_mailbox_stays_under_the_servers_session_cap(tmp_path, monkeypatch):
    """Two mailbox="*" calls at once on 20 mailboxes: never more than the server's max_sessions open (kept
    sessions included), and every mailbox is still searched by both calls."""
    import threading
    import time as _time
    import anyio
    lock, state = threading.Lock(), {"now": 0, "max": 0, "searches": 0}

    class Slow(DatedImap):
        def __enter__(self):
            with lock:
                state["now"] += 1; state["max"] = max(state["max"], state["now"])
            return self

        def search(self, *a, **k):
            _time.sleep(0.02)
            with lock:
                state["searches"] += 1
            return super().search(*a, **k)

        def __exit__(self, *e):
            with lock:
                state["now"] -= 1
    isp3 = MailServer(ISP.host, domains=ISP.domains, match_mx=False, max_sessions=3)
    env = big_grant(tmp_path, monkeypatch, STAFF[:20], isp=isp3)
    sessions = tools_mod.Sessions.from_settings(env[0])
    sessions._closer = lambda done, told: ([d.__exit__(None, None, None) for d in done], told())  # at once, for the count
    srv = fan_out(env, lambda a, p: Slow(a, 3), sessions=sessions)
    async with anyio.create_task_group() as tg:
        for _ in range(2):
            tg.start_soon(srv.call_tool, "mail_search", {"mailbox": "*"})
    assert state["max"] == 3 and state["searches"] == 40
    assert 20 <= len(srv.opened) <= 40           # a mailbox's second search may reuse the first one's session
    assert sessions.counts(ISP.host)["used"] <= 3 and sessions.counts(ISP.host)["waiting"] == 0


@pytest.mark.anyio
@pytest.mark.parametrize("tool,args", [
    ("mail_folders", {}), ("mail_read", {"folder": "INBOX", "uid": 1}),
    ("mail_thread", {"folder": "INBOX", "uid": 1}), ("mail_attachment", {"folder": "INBOX", "uid": 1, "index": 0}),
    ("mail_flag", {"folder": "INBOX", "uids": [1], "seen": True}),
    ("mail_move", {"folder": "INBOX", "uids": [1], "destination": "trash"}),
    ("mail_draft", {"to": ["c@y.co.za"], "subject": "s", "text": "t"}),
    ("mail_send", {"to": ["c@y.co.za"], "subject": "s", "text": "t"}),
])
async def test_every_tool_works_on_any_mailbox_of_the_grant_and_refuses_star(tmp_path, monkeypatch, tool, args):
    env = big_grant(tmp_path, monkeypatch, ["owner@client.example", *STAFF])
    msg = raw_message(attachments=[("a.txt", "text/plain", b"hi")])
    srv = fan_out(env, lambda a, p: FakeImap({("INBOX", 1): msg}))
    await srv.call_tool(tool, {**args, "mailbox": "staff77@client.example"})
    assert srv.opened == [("staff77@client.example", "pw-staff77@client.example", "mail.client.example")]
    with pytest.raises(ToolError, match='mailbox="\\*" works with mail_search only'):
        await srv.call_tool(tool, {**args, "mailbox": "*"})


def test_folder_tools_say_role_names_work(env):
    import asyncio
    from mcp_server_imap_smtp.mail.tools import FOLDER_NOTE
    srv, _ = build(env)
    tools = {t.name: t for t in asyncio.run(srv.list_tools())}
    for name in ("mail_search", "mail_read", "mail_move", "mail_flag", "mail_thread", "mail_attachment"):
        assert FOLDER_NOTE in tools[name].description, name
    assert FOLDER_NOTE not in tools["mail_folders"].description
