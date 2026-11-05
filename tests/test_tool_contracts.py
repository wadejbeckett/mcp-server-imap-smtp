# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tool contracts fixed by ticket 33: annotation sets, the `from` search parameter, no hidden Trash folder,
and the ids mail_draft and mail_send return."""
import asyncio
from email import message_from_bytes

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from tests.test_tools import FakeImap, FakeSender, build, env, payload, raw_message  # noqa: F401  (env fixture)

from mcp_server_imap_smtp.mail.imap import Folder


def tools(env):
    srv, _ = build(env)
    return {t.name: t for t in asyncio.run(srv.list_tools())}


def hints(tool):
    a = tool.annotations
    return (a.read_only_hint, a.destructive_hint, a.idempotent_hint, a.open_world_hint)


def test_every_tool_states_its_annotation_set(env):
    t = tools(env)
    for name in ("mail_accounts", "mail_folders", "mail_search", "mail_read", "mail_thread", "mail_attachment"):
        assert hints(t[name]) == (True, False, True, False), name           # READ
    assert hints(t["mail_flag"]) == (False, False, True, False)             # WRITE, idempotent
    assert hints(t["mail_draft"]) == (False, False, False, False)           # WRITE
    assert hints(t["mail_move"]) == (False, True, False, False)             # DESTROY: it moves mail to Trash
    assert hints(t["mail_send"]) == (False, True, False, True)              # OUTSIDE


def test_search_parameter_is_called_from(env):
    props = tools(env)["mail_search"].input_schema["properties"]
    assert "from" in props and "from_" not in props


@pytest.mark.anyio
@pytest.mark.parametrize("key", ["from", "from_"])
async def test_search_from_reaches_the_query(env, key):
    srv, fake = build(env)
    await srv.call_tool("mail_search", {key: "alice@x.co.za"})
    (_, _, q, _, _), = fake.named("search")
    assert q.from_ == "alice@x.co.za"


class NoTrash(FakeImap):
    def special(self, kind):
        return None if kind == "trash" else super().special(kind)


@pytest.mark.anyio
async def test_replacing_a_draft_without_a_trash_folder_creates_none_and_saves_nothing(env):
    srv, fake = build(env, NoTrash())
    with pytest.raises(ToolError, match="no trash folder found"):
        await srv.call_tool("mail_draft", {"to": ["c@x.co.za"], "subject": "Hi", "text": "t", "replace_draft_uid": 2})
    assert fake.named("append") == [] and fake.named("move") == [] and fake.named("ensure_folder") == []


@pytest.mark.anyio
async def test_draft_uid_is_null_when_the_server_cannot_say(env):
    class NoUid(FakeImap):
        def append(self, folder, raw, flags, message_id=None):
            super().append(folder, raw, flags)
            return None
    srv, fake = build(env, NoUid())
    out = payload(await srv.call_tool("mail_draft", {"to": ["c@x.co.za"], "subject": "Hi", "text": "t"}))
    assert out["uid"] is None and out["message_id"].startswith("<")


@pytest.mark.anyio
async def test_draft_passes_its_message_id_for_the_uid_lookup(env):
    seen = []

    class Records(FakeImap):
        def append(self, folder, raw, flags, message_id=None):
            seen.append((message_id, message_from_bytes(raw)["Message-ID"]))
            return 5
    srv, _ = build(env, Records())
    out = payload(await srv.call_tool("mail_draft", {"to": ["c@x.co.za"], "subject": "Hi", "text": "t"}))
    (passed, header), = seen
    assert str(passed) == header == out["message_id"] and out["uid"] == 5


@pytest.mark.anyio
async def test_send_returns_the_message_id(env):
    sender = FakeSender()
    srv, _ = build(env, sender=sender)
    out = payload(await srv.call_tool("mail_send", {"to": ["c@x.co.za"], "subject": "s", "text": "t"}))
    assert out["message_id"] == sender.sent[0]["msg"]["Message-ID"] and out["message_id"].startswith("<")
