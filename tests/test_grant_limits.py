# SPDX-License-Identifier: AGPL-3.0-or-later
"""Security review 2026-10-20, finding 10: one connection cannot occupy the connector. Calls per grant
are capped, and folder="*" and mail_folders stop at a folder cap and a time budget."""
import threading
import time

import anyio
import pytest
from mcp.server.mcpserver.exceptions import ToolError

from mcp_server_imap_smtp.config import Settings
from mcp_server_imap_smtp.mail import tools as tools_mod
from mcp_server_imap_smtp.mail.imap import Folder
from tests.test_tools import FakeImap, MAIL1, anyio_backend, build, payload  # noqa: F401
from mcp_server_imap_smtp.mail.hosts import MailServer
from mcp_server_imap_smtp.store import Store


@pytest.fixture
def env1(tmp_path, monkeypatch):
    s = Settings(issuer_url="http://127.0.0.1:8765", mail_resource_url="http://127.0.0.1:8765/mail",
                 mail_servers=(MailServer("mail1.hosting.example"),), db_path=tmp_path / "s.sqlite",
                 max_calls_per_grant=1)
    store = Store(s.db_path)
    gid, key = store.create_grant("c1", s.mail_resource_url, [("me@x.co.za", "pw", MAIL1)])
    at, _ = store.issue_tokens(gid, key, "c1", [], s.mail_resource_url, 3600, 86400)

    class Tok:
        token = at
    monkeypatch.setattr(tools_mod, "get_access_token", lambda: Tok)
    return s, store, gid


def test_max_calls_per_grant_must_be_positive():
    with pytest.raises(ValueError):
        Settings(issuer_url="https://m.example", mail_resource_url="https://m.example/mail",
                 mail_servers=(MAIL1,), db_path="x", max_calls_per_grant=0)
    assert Settings(issuer_url="https://m.example", mail_resource_url="https://m.example/mail",
                    mail_servers=(MAIL1,), db_path="x").max_calls_per_grant == 4


class Slow(FakeImap):
    def __init__(self):
        super().__init__()
        self.release = threading.Event()
        self.running = 0
        self.most = 0
        self.lock = threading.Lock()

    def status(self, folder):
        with self.lock:
            self.running += 1
            self.most = max(self.most, self.running)
        self.release.wait(5)
        with self.lock:
            self.running -= 1
        return super().status(folder)


@pytest.mark.anyio
async def test_second_call_waits_for_the_first(env1, monkeypatch):
    srv, fake = build(env1, Slow())
    done = []

    async def call():
        done.append(payload(await srv.call_tool("mail_folders", {})))
    async with anyio.create_task_group() as tg:
        tg.start_soon(call)
        tg.start_soon(call)
        await anyio.sleep(0.3)
        fake.release.set()
    assert len(done) == 2 and fake.most == 1


@pytest.mark.anyio
async def test_call_that_cannot_start_in_time_is_told_busy(env1, monkeypatch):
    monkeypatch.setattr(tools_mod, "GRANT_WAIT_SECONDS", 0.2)
    srv, fake = build(env1, Slow())
    errors = []

    async def first():
        await srv.call_tool("mail_folders", {})

    async def second():
        await anyio.sleep(0.05)
        try:
            await srv.call_tool("mail_folders", {})
        except ToolError as exc:
            errors.append(str(exc))
        fake.release.set()
    async with anyio.create_task_group() as tg:
        tg.start_soon(first)
        tg.start_soon(second)
    assert errors and "at once" in errors[0]


MANY = [Folder("INBOX", "/", (), "inbox")] + [Folder(f"F{i}", "/", (), None) for i in range(300)]


class ManyFolders(FakeImap):
    def folders(self):
        return MANY

    def special(self, kind):
        return "INBOX" if kind == "inbox" else None


@pytest.mark.anyio
async def test_all_folder_search_visits_at_most_the_folder_cap(env1):
    srv, fake = build(env1, ManyFolders())
    out = payload(await srv.call_tool("mail_search", {"folder": "*"}))
    assert len(fake.named("search")) == tools_mod.ALL_FOLDERS_MAX
    assert out["not_searched"] == len(MANY) - tools_mod.ALL_FOLDERS_MAX


@pytest.mark.anyio
async def test_all_folder_search_stops_at_its_time_budget(env1, monkeypatch):
    monkeypatch.setattr(tools_mod, "CALL_SECONDS", 0.0)
    srv, fake = build(env1, ManyFolders())
    out = payload(await srv.call_tool("mail_search", {"folder": "*"}))
    assert len(fake.named("search")) == 1 and out["not_searched"] == len(MANY) - 1


@pytest.mark.anyio
async def test_folder_list_stops_counting_at_its_time_budget(env1, monkeypatch):
    monkeypatch.setattr(tools_mod, "CALL_SECONDS", 0.0)
    srv, _ = build(env1, ManyFolders())
    out = payload(await srv.call_tool("mail_folders", {}))
    assert len(out["folders"]) == len(MANY)
    assert out["folders"][0]["messages"] == 3 and out["folders"][-1]["messages"] is None
    assert "note" in out
