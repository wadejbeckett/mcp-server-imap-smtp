# SPDX-License-Identifier: AGPL-3.0-or-later
"""Per-server session caps, the fair queue and IMAP session reuse (mail/sessions.py), on their own and
through the mail tools and the sign-in page. No network: fakes and a scripted IMAP server on a socket pair."""
import contextvars
import imaplib
import json
import logging
import threading
import time
from pathlib import Path

import anyio
import pytest
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import AnyUrl
from starlette.applications import Starlette
from starlette.testclient import TestClient

from mcp_server_imap_smtp.auth.login import login_routes
from mcp_server_imap_smtp.auth.provider import GatewayProvider
from mcp_server_imap_smtp.config import Settings, load_settings
from mcp_server_imap_smtp.mail import imap as imap_mod
from mcp_server_imap_smtp.mail import sessions as sessions_mod
from mcp_server_imap_smtp.mail import tools as tools_mod
from mcp_server_imap_smtp.mail.hosts import Connector, MailServer
from mcp_server_imap_smtp.mail.imap import ImapClient, MailAuthError, MailError, SearchQuery
from mcp_server_imap_smtp.mail.resolve import Resolver
from mcp_server_imap_smtp.mail.sessions import Lease, ServerBusy, Sessions
from mcp_server_imap_smtp.ratelimit import RateLimiter
from mcp_server_imap_smtp.store import Store
from tests.test_imap_parsing import ScriptedServer, logout_ok
from tests.test_tools import ISP, STAFF, DatedImap, FakeImap, FakeSender, big_grant, fan_out, raw_message
from tests._signin import connected

HOST = "mail.example.net"


@pytest.fixture
def anyio_backend():
    return "asyncio"


def at_once(close):
    """A closer that closes each session at once with close(session) and reports it done."""
    def closer(sessions, done):
        for session in sessions:
            close(session)
        done()
    return closer


EXIT = at_once(lambda d: d.__exit__(None, None, None))


def make(cap=3, per_mailbox=4, idle=60, clock=None, closer=None, **kw):
    """Sessions for one server; closed sessions are recorded instead of logged out."""
    server = MailServer(HOST, max_sessions=cap)
    closed = []
    s = Sessions([server], per_mailbox=per_mailbox, idle_seconds=idle, clock=clock or time.monotonic,
                 closer=closer or at_once(closed.append), **kw)
    return s, server, closed


class Kept:
    """Stands in for a logged-in session handed back to the pool."""

    def __init__(self, name):
        self.name = name
        self.closed = self.dropped = False

    def __repr__(self):
        return f"Kept({self.name})"

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.closed = True

    def drop(self):
        self.dropped = True


async def keep(s, server, grant, address, session):
    """One call on (grant, address) that leaves `session` in the pool, as a worker thread would."""
    async with s.lease(server, grant, address, pool_key=(grant, address)) as lease:
        lease.keep = session


# --- caps and the fair queue -------------------------------------------------------------------------

@pytest.mark.anyio
async def test_cap_per_server_is_never_exceeded():
    s, server, _ = make(cap=3)
    state = {"now": 0, "max": 0}

    async def call(i):
        async with s.lease(server, f"g{i}", f"a{i}@x.example"):
            state["now"] += 1
            state["max"] = max(state["max"], state["now"])
            await anyio.sleep(0.01)
            state["now"] -= 1
    async with anyio.create_task_group() as tg:
        for i in range(10):
            tg.start_soon(call, i)
    assert state["max"] == 3
    assert s.counts(HOST) == {"used": 0, "idle": 0, "boxes": {}, "waiting": 0}


@pytest.mark.anyio
async def test_cap_per_mailbox_across_grants_while_other_mailboxes_go_ahead():
    s, server, _ = make(cap=8, per_mailbox=2)
    now: dict[str, int] = {}
    most: dict[str, int] = {}

    async def call(grant, address):
        async with s.lease(server, grant, address):
            now[address] = now.get(address, 0) + 1
            most[address] = max(most.get(address, 0), now[address])
            most["all"] = max(most.get("all", 0), sum(now.values()))
            await anyio.sleep(0.02)
            now[address] -= 1
    async with anyio.create_task_group() as tg:
        for i in range(6):               # six staff connections that all hold info@
            tg.start_soon(call, f"g{i}", "info@x.example")
        for i in range(3):
            tg.start_soon(call, f"h{i}", f"other{i}@x.example")
    assert most["info@x.example"] == 2 and most["all"] == 5


@pytest.mark.anyio
async def test_the_least_recently_served_grant_goes_next():
    s, server, _ = make(cap=2)
    order = []

    async def call(grant, name, hold=0.0):
        async with s.lease(server, grant, f"{name}@x.example"):
            order.append(name)
            await anyio.sleep(hold)
    async with s.lease(server, "Z", "z@x.example"):   # one of the two sessions stays taken
        async with anyio.create_task_group() as tg:
            tg.start_soon(call, "A", "a1", 0.05)      # A holds the only session ...
            await anyio.sleep(0.01)
            for name in ("a2", "a3", "a4"):           # ... and queues three more before B asks once
                tg.start_soon(call, "A", name, 0.01)
            await anyio.sleep(0.01)
            tg.start_soon(call, "B", "b1", 0.01)
    assert order == ["a1", "b1", "a2", "a3", "a4"]


@pytest.mark.anyio
async def test_two_busy_grants_take_turns():
    s, server, _ = make(cap=2)
    order = []
    gate = anyio.Event()

    async def call(grant, name):
        async with s.lease(server, grant, f"{name}@x.example"):
            order.append(name)
            if name == "x":
                await gate.wait()
            await anyio.sleep(0.001)
    async with s.lease(server, "Z", "z@x.example"):   # one of the two sessions stays taken
        async with anyio.create_task_group() as tg:
            tg.start_soon(call, "X", "x")
            await anyio.sleep(0.01)
            for name in ("a1", "a2", "a3"):
                tg.start_soon(call, "A", name)
            await anyio.sleep(0.01)
            for name in ("b1", "b2", "b3"):
                tg.start_soon(call, "B", name)
            await anyio.sleep(0.01)
            gate.set()
    assert order == ["x", "a1", "b1", "a2", "b2", "a3", "b3"]


@pytest.mark.anyio
async def test_a_grants_single_mailbox_calls_go_before_its_star_work():
    s, server, _ = make(cap=2)
    order = []
    gate = anyio.Event()

    async def call(grant, name, priority=True):
        async with s.lease(server, grant, f"{name}@x.example", priority=priority):
            order.append(name)
            if name == "x":
                await gate.wait()
    async with s.lease(server, "Z", "z@x.example"):   # one of the two sessions stays taken
        async with anyio.create_task_group() as tg:
            tg.start_soon(call, "X", "x")
            await anyio.sleep(0.01)
            tg.start_soon(call, "A", "star1", False)
            tg.start_soon(call, "A", "star2", False)
            await anyio.sleep(0.01)
            tg.start_soon(call, "A", "read")
            await anyio.sleep(0.01)
            gate.set()
    assert order == ["x", "read", "star1", "star2"]


@pytest.mark.anyio
async def test_waiting_past_the_budget_is_server_busy_and_leaves_no_trace():
    s, server, _ = make(cap=2)
    async with s.lease(server, "A", "a@x.example"), s.lease(server, "B", "b@x.example"):
        started = anyio.current_time()
        with pytest.raises(ServerBusy, match="busy right now. Try again shortly"):
            async with s.lease(server, "C", "c@x.example", wait=0.05):
                pass
        assert 0.04 <= anyio.current_time() - started < 1
        assert s.counts(HOST)["waiting"] == 0 and s.counts(HOST)["used"] == 2
    async with s.lease(server, "C", "c@x.example", wait=0.05):
        assert s.counts(HOST)["used"] == 1


@pytest.mark.anyio
async def test_a_send_needs_two_sessions_and_is_not_overtaken():
    s, server, _ = make(cap=2)
    order = []
    gates = {"A": anyio.Event(), "B": anyio.Event()}

    async def call(grant, extra=0):
        async with s.lease(server, grant, f"{grant}@x.example", extra=extra):
            order.append((grant, s.counts(HOST)["used"]))
            if grant in gates:
                await gates[grant].wait()
    async with anyio.create_task_group() as tg:
        tg.start_soon(call, "A")
        await anyio.sleep(0.01)
        tg.start_soon(call, "B", 1)      # IMAP + SMTP: one session is free, two are needed
        await anyio.sleep(0.01)
        tg.start_soon(call, "C")         # would fit in the free one, but B asked first
        await anyio.sleep(0.02)
        assert order == [("A", 1)]
        gates["A"].set()
        await anyio.sleep(0.02)
        assert order == [("A", 1), ("B", 2)]
        gates["B"].set()
    assert order == [("A", 1), ("B", 2), ("C", 1)]


@pytest.mark.anyio
async def test_a_cancelled_wait_leaves_the_queue():
    s, server, _ = make(cap=2)
    async with s.lease(server, "Z", "z@x.example"), s.lease(server, "A", "a@x.example"):
        with anyio.move_on_after(0.02):
            async with s.lease(server, "B", "b@x.example", wait=5):
                pass
        assert s.counts(HOST)["waiting"] == 0
    assert s.counts(HOST) == {"used": 0, "idle": 0, "boxes": {}, "waiting": 0}


# --- the pool --------------------------------------------------------------------------------------

@pytest.mark.anyio
async def test_kept_sessions_count_toward_the_cap_and_make_room_when_needed():
    s, server, closed = make(cap=2)
    a, b = Kept("a"), Kept("b")
    await keep(s, server, "g1", "a@x.example", a)
    await keep(s, server, "g1", "b@x.example", b)
    assert s.counts(HOST)["used"] == 2 and s.counts(HOST)["idle"] == 2
    async with s.lease(server, "g2", "c@x.example", pool_key=("g2", "c@x.example")) as lease:
        assert closed == [a] and lease.handed is None      # the oldest kept session made room
    async with s.lease(server, "g1", "b@x.example", pool_key=("g1", "b@x.example")) as lease:
        assert lease.handed is b                           # reused, no new login
        lease.keep = b
    assert s.counts(HOST) == {"used": 1, "idle": 1, "boxes": {"b@x.example": 1}, "waiting": 0}


@pytest.mark.anyio
async def test_a_kept_session_of_another_grant_makes_room_under_the_mailbox_cap():
    s, server, closed = make(cap=8, per_mailbox=1)
    staff = Kept("staff")
    await keep(s, server, "staff-grant", "info@x.example", staff)
    async with s.lease(server, "owner-grant", "info@x.example", pool_key=("owner-grant", "info@x.example")) as lease:
        assert closed == [staff] and lease.handed is None
        assert s.counts(HOST)["boxes"] == {"info@x.example": 1}


@pytest.mark.anyio
async def test_kept_sessions_are_closed_after_the_idle_time():
    now = [100.0]
    s, server, closed = make(idle=60, clock=lambda: now[0])
    a = Kept("a")
    await keep(s, server, "g", "a@x.example", a)
    now[0] += 59
    s.sweep()
    assert closed == []
    now[0] += 2
    s.sweep()
    assert closed == [a] and s.counts(HOST) == {"used": 0, "idle": 0, "boxes": {}, "waiting": 0}


@pytest.mark.anyio
async def test_kept_sessions_are_closed_on_time_without_another_call():
    server = MailServer(HOST)
    closed = []
    s = Sessions([server], idle_seconds=0.05, closer=at_once(closed.append))
    a = Kept("a")
    await keep(s, server, "g", "a@x.example", a)
    await anyio.sleep(0.3)
    assert closed == [a] and s.counts(HOST)["used"] == 0


@pytest.mark.anyio
async def test_no_reuse_when_idle_seconds_is_zero():
    s, server, closed = make(idle=0)
    a = Kept("a")
    await keep(s, server, "g", "a@x.example", a)
    assert closed == [a] and s.counts(HOST)["used"] == 0


@pytest.mark.anyio
async def test_revoking_a_grant_closes_its_kept_sessions_from_any_thread():
    s, server, closed = make()
    a, b, other = Kept("a"), Kept("b"), Kept("other")
    await keep(s, server, "g1", "a@x.example", a)
    await keep(s, server, "g1", "b@x.example", b)
    await keep(s, server, "g2", "a@x.example", other)
    await anyio.to_thread.run_sync(s.forget_grant, "g1")     # e.g. from a worker thread
    for _ in range(5):
        await anyio.sleep(0)
    assert sorted(closed, key=repr) == [a, b] and s.counts(HOST)["idle"] == 1
    # A call still running when its grant is revoked never leaves its session behind.
    async with s.lease(server, "g2", "c@x.example", pool_key=("g2", "c@x.example")) as lease:
        s.forget_grant("g2")
        lease.keep = c = Kept("c")
    assert closed[-1] is c and closed.count(other) == 1 and s.counts(HOST)["used"] == 0


# --- maximum session age and rejected passwords ----------------------------------------------------------

async def use(s, server, grant, address, logins):
    """One call on (grant, address) that uses its session as a worker thread would. A login (a new Kept
    session) is recorded in `logins` with the time; returns the session the call ran on."""
    async with s.lease(server, grant, address, pool_key=(grant, address)) as lease:
        def login():
            logins.append((address, s.clock()))
            return Kept(f"{address}#{len(logins)}")
        with lease.session(address, login) as session:
            return session


def rejected():
    raise MailAuthError("mailbox rejected the address or password")


@pytest.mark.anyio
async def test_a_kept_session_is_not_reused_past_the_maximum_age_however_busy():
    """Calls every 59 s keep a session from ever idling out; it is still replaced 300 s after its login,
    so a password changed on the mail server takes effect for the connector."""
    now = [0.0]
    s, server, closed = make(idle=60, clock=lambda: now[0], max_age=300)
    logins = []
    first = await use(s, server, "g", "a@x.example", logins)
    for _ in range(5):                       # t = 59 ... 295: the same logged-in session
        now[0] += 59
        assert await use(s, server, "g", "a@x.example", logins) is first
    now[0] += 59                             # t = 354: 354 s after its login
    second = await use(s, server, "g", "a@x.example", logins)
    assert second is not first and closed == [first]
    assert [at for _, at in logins] == [0.0, 354.0]


@pytest.mark.anyio
async def test_a_session_that_reaches_the_maximum_age_during_a_call_is_closed_not_kept():
    now = [0.0]
    s, server, closed = make(clock=lambda: now[0], max_age=300)
    async with s.lease(server, "g", "a@x.example", pool_key=("g", "a@x.example")) as lease:
        with lease.session("a@x.example", lambda: Kept("a")) as a:
            now[0] += 300
    assert closed == [a] and s.counts(HOST) == {"used": 0, "idle": 0, "boxes": {}, "waiting": 0}


@pytest.mark.anyio
async def test_a_kept_session_is_closed_at_its_maximum_age_without_another_call():
    server = MailServer(HOST)
    closed = []
    s = Sessions([server], idle_seconds=60, max_age=0.1, closer=at_once(closed.append))
    a = await use(s, server, "g", "a@x.example", [])
    assert s.counts(HOST)["idle"] == 1
    await anyio.sleep(0.4)
    assert closed == [a] and s.counts(HOST)["used"] == 0


@pytest.mark.anyio
async def test_a_rejected_password_closes_every_connections_kept_sessions_for_that_mailbox_on_that_server():
    server, elsewhere = MailServer(HOST, max_sessions=8), MailServer("other.example.net")
    closed = []
    s = Sessions([server, elsewhere], closer=at_once(closed.append))
    logins = []
    one = await use(s, server, "g1", "info@x.example", logins)
    two = await use(s, server, "g2", "info@x.example", logins)
    await use(s, server, "g1", "me@x.example", logins)
    await use(s, elsewhere, "g3", "info@x.example", logins)
    async with s.lease(server, "g4", "info@x.example", pool_key=("g4", "info@x.example")) as lease:
        with pytest.raises(MailAuthError):
            with lease.session("info@x.example", rejected):
                pass
    assert sorted(closed, key=repr) == sorted([one, two], key=repr)
    assert s.counts(HOST) == {"used": 1, "idle": 1, "boxes": {"me@x.example": 1}, "waiting": 0}
    assert s.counts("other.example.net")["idle"] == 1      # another server's session for the address stays


@pytest.mark.anyio
async def test_a_session_logged_in_before_a_rejected_password_is_not_kept_after_it():
    """Another connection's call was under way with a session from before the rejection: it is closed when
    that call ends, not kept. A login after the rejection is kept as usual."""
    now = [100.0]
    s, server, closed = make(cap=8, clock=lambda: now[0])
    async with s.lease(server, "g1", "info@x.example", pool_key=("g1", "info@x.example")) as busy:
        with busy.session("info@x.example", lambda: Kept("old")) as old:      # logged in at t = 100
            now[0] += 1
            async with s.lease(server, "g2", "info@x.example", pool_key=("g2", "info@x.example")) as lease:
                with pytest.raises(MailAuthError):
                    with lease.session("info@x.example", rejected):
                        pass
            now[0] += 1
    assert closed == [old] and s.counts(HOST) == {"used": 0, "idle": 0, "boxes": {}, "waiting": 0}
    now[0] += 1
    new = await use(s, server, "g1", "info@x.example", [])
    assert s.counts(HOST)["idle"] == 1 and new not in closed


# --- closing sessions: slots held until LOGOUT has finished, failures never leak a slot -----------------

@pytest.mark.anyio
async def test_an_evicted_session_keeps_its_slot_until_its_close_has_finished():
    pending = []
    s, server, _ = make(cap=2, closer=lambda sessions, done: pending.append((sessions, done)))
    a, b = Kept("a"), Kept("b")
    await keep(s, server, "g1", "a@x.example", a)
    await keep(s, server, "g1", "b@x.example", b)
    served = []

    async def call():
        async with s.lease(server, "g2", "c@x.example", wait=5):
            served.append(s.counts(HOST)["used"])
    async with anyio.create_task_group() as tg:
        tg.start_soon(call)
        await anyio.sleep(0.02)
        assert [sessions for sessions, _ in pending] == [[a]] and served == []    # a is logging out ...
        assert s.counts(HOST)["used"] == 2 and s.counts(HOST)["idle"] == 1       # ... and still counted
        await anyio.sleep(0.02)
        assert len(pending) == 1                     # b is not closed as well: a's slot is on its way
        await anyio.to_thread.run_sync(pending[0][1])      # LOGOUT answered, in the closer's thread
    assert served == [2] and s.counts(HOST) == {"used": 1, "idle": 1, "boxes": {"b@x.example": 1}, "waiting": 0}


@pytest.mark.anyio
async def test_the_caps_hold_while_sessions_are_logged_out_in_the_background():
    """Many connections churn through a small server with the real background closer: a session still
    logging out is never replaced before its LOGOUT has finished."""
    lock, state = threading.Lock(), {"open": 0, "max": 0}

    class Conn(Kept):
        def __enter__(self):
            with lock:
                state["open"] += 1
                state["max"] = max(state["max"], state["open"])
            return self

        def __exit__(self, *exc):
            time.sleep(0.01)                 # the LOGOUT round trip: the server still counts the session
            with lock:
                state["open"] -= 1
    server = MailServer(HOST, max_sessions=3)
    s = Sessions([server], per_mailbox=1, idle_seconds=60, closer=sessions_mod._Closer(workers=2))

    async def call(i):
        grant = f"g{i % 8}"
        address = f"{grant}@x.example"
        async with s.lease(server, grant, address, pool_key=(grant, address), wait=10) as lease:
            def work():
                with lease.session(address, lambda: Conn(address)):
                    time.sleep(0.002)
            await anyio.to_thread.run_sync(work)
    async with anyio.create_task_group() as tg:
        for i in range(40):
            tg.start_soon(call, i)
    srv = s._servers[HOST]
    for _ in range(200):
        if not srv.closing:
            break
        await anyio.sleep(0.01)
    assert 2 <= state["max"] <= 3 and srv.closing == 0
    assert s.counts(HOST)["used"] == s.counts(HOST)["idle"] == state["open"]


@pytest.mark.anyio
async def test_a_closer_that_fails_never_leaks_a_slot():
    """Closing an evicted session fails (e.g. no thread can be started): it is dropped without LOGOUT, its
    slots come free, the waiting call is served and every later call too."""
    failures = [RuntimeError("can't start new thread")]

    def closer(sessions, done):
        if failures:
            raise failures.pop()
        done()
    s, server, _ = make(cap=2, closer=closer)
    a, b = Kept("a"), Kept("b")
    await keep(s, server, "a", "a@x.example", a)
    await keep(s, server, "b", "b@x.example", b)
    async with s.lease(server, "c", "c@x.example", pool_key=("c", "c@x.example"), wait=0.1):
        assert s.counts(HOST)["used"] == 2
    assert a.dropped and not b.dropped
    for i in range(3):
        async with s.lease(server, f"d{i}", f"d{i}@x.example", wait=0.1):
            pass
    assert s.counts(HOST) == {"used": 1, "idle": 1, "boxes": {"b@x.example": 1}, "waiting": 0}
    assert s._servers[HOST].active == {} and s._servers[HOST].closing == 0


@pytest.mark.anyio
async def test_a_failure_while_queueing_leaves_nothing_behind(monkeypatch):
    """The call fails in the bookkeeping before it is served: it leaves the queue at once, so no later
    hand-back can grant it a session nobody will give back."""
    s, server, _ = make(cap=2)
    real, failed = s._try_grant, []

    def try_grant(srv, lease):
        if not failed:
            failed.append(lease)
            raise RuntimeError("bookkeeping failed")
        return real(srv, lease)
    monkeypatch.setattr(s, "_try_grant", try_grant)
    with pytest.raises(RuntimeError, match="bookkeeping failed"):
        async with s.lease(server, "A", "a@x.example", wait=0.1):
            pass
    assert s.counts(HOST) == {"used": 0, "idle": 0, "boxes": {}, "waiting": 0}
    for i in range(3):
        async with s.lease(server, f"B{i}", "b@x.example", wait=0.1):
            assert s.counts(HOST)["used"] == 1
    assert s.counts(HOST) == {"used": 0, "idle": 0, "boxes": {}, "waiting": 0} and s._servers[HOST].active == {} and s._servers[HOST].served == {}


def test_the_background_closer_drops_the_sessions_when_no_thread_can_start(monkeypatch):
    def refuse(self):
        raise RuntimeError("can't start new thread")
    monkeypatch.setattr(threading.Thread, "start", refuse)
    closer = sessions_mod._Closer(workers=2)
    a, b = Kept("a"), Kept("b")
    told = []
    closer([a, b], lambda: told.append(1))          # never raises
    assert told == [1] and a.dropped and b.dropped and not a.closed and closer._running == 0


def test_the_background_closer_runs_only_a_few_closes_at_once():
    lock, state = threading.Lock(), {"now": 0, "max": 0}
    release, finished = threading.Event(), threading.Semaphore(0)

    class Slow(Kept):
        def __exit__(self, *exc):
            with lock:
                state["now"] += 1
                state["max"] = max(state["max"], state["now"])
            release.wait(5)
            with lock:
                state["now"] -= 1
            self.closed = True
    closer = sessions_mod._Closer(workers=2)
    slow = [Slow(i) for i in range(8)]
    for session in slow:
        closer([session], finished.release)
    time.sleep(0.05)
    with lock:
        assert state["now"] == 2
    release.set()
    assert all(finished.acquire(timeout=5) for _ in slow)
    assert state["max"] == 2 and all(session.closed for session in slow)


# --- one IMAP session per call ---------------------------------------------------------------------------

class Checked(Kept):
    def __init__(self, name):
        super().__init__(name)
        self.resets = 0

    def reset(self):
        self.resets += 1


@pytest.mark.anyio
async def test_a_second_session_block_in_one_call_uses_the_calls_session():
    s, server, closed = make()
    logins = []

    def login():
        logins.append(1)
        return Checked("a")
    async with s.lease(server, "g", "a@x.example", pool_key=("g", "a@x.example")) as lease:
        with lease.session("a@x.example", login) as first:
            pass
        with lease.session("a@x.example", login) as second:
            assert s.counts(HOST)["used"] == 1
    assert second is first and len(logins) == 1 and first.resets == 1 and closed == []
    assert s.counts(HOST) == {"used": 1, "idle": 1, "boxes": {"a@x.example": 1}, "waiting": 0}


@pytest.mark.anyio
async def test_a_session_for_another_mailbox_or_inside_another_one_is_refused():
    s, server, closed = make()
    logins = []

    def login():
        logins.append(1)
        return Kept("a")
    async with s.lease(server, "g", "a@x.example", pool_key=("g", "a@x.example")) as lease:
        with pytest.raises(RuntimeError, match="another mailbox"):
            with lease.session("b@x.example", login):
                pass
        with lease.session("a@x.example", login):
            with pytest.raises(RuntimeError, match="already open"):
                with lease.session("a@x.example", login):
                    pass
    assert len(logins) == 1 and closed == []
    assert s.counts(HOST) == {"used": 1, "idle": 1, "boxes": {"a@x.example": 1}, "waiting": 0}


# --- through the mail tools ---------------------------------------------------------------------------

NEO2 = MailServer("mail1.hosting.example", max_sessions=2)
PASSWORDS = {"me@x.co.za": "S3cret-one", "accounts@x.co.za": "S3cret-two"}


class Tok:
    def __init__(self, token):
        self.token = token


def tool_env(tmp_path, monkeypatch, server=NEO2, mailboxes=("me@x.co.za", "accounts@x.co.za"), **settings_kw):
    """A grant on `server`; returns (settings, store, grant id, token var). Set the var in a task to call
    as another grant (grant())."""
    s = Settings(issuer_url="http://127.0.0.1:8765", mail_resource_url="http://127.0.0.1:8765/mail",
                 mail_servers=(server,), db_path=tmp_path / "s.sqlite", send_mode="send", **settings_kw)
    store = Store(s.db_path)
    gid, key = store.create_grant("c1", s.mail_resource_url, [(a, PASSWORDS.get(a, f"pw-{a}"), server)
                                                               for a in mailboxes])
    at, _ = store.issue_tokens(gid, key, "c1", [], s.mail_resource_url, 3600, 86400)
    var = contextvars.ContextVar("token", default=at)
    monkeypatch.setattr(tools_mod, "get_access_token", lambda: Tok(var.get()))
    return s, store, gid, var


def grant(env, mailboxes):
    s, store, _, _ = env
    server = s.mail_servers[0]
    gid, key = store.create_grant("c1", s.mail_resource_url, [(a, PASSWORDS.get(a, f"pw-{a}"), server)
                                                               for a in mailboxes])
    at, _ = store.issue_tokens(gid, key, "c1", [], s.mail_resource_url, 3600, 86400)
    return gid, at


class PoolImap(FakeImap):
    """A fake session that records checks (reset) and closing; `stale` makes the next check fail."""

    def __init__(self, label, messages=None, delay=0.0):
        super().__init__(messages or {("INBOX", 5): raw_message()})
        self.label, self.delay = label, delay
        self.resets, self.closed, self.stale, self.broken = 0, False, False, False

    def reset(self):
        if self.stale:
            raise imaplib.IMAP4.abort("socket error: EOF")
        self.resets += 1

    def search(self, folder, q, limit=25, offset=0):
        if self.delay:
            time.sleep(self.delay)
        return super().search(folder, q, limit, offset)

    def __exit__(self, *e):
        self.closed = True


def pooled(env, make_session=None, sender=None, clock=time.monotonic):
    """A tools server whose opener records each login (srv.opened) and the sessions made (srv.made)."""
    s, store = env[0], env[1]
    srv = MCPServer("t")
    srv.opened, srv.made = [], []
    srv.failures = []          # exceptions the next logins raise, in order

    def opener(server, address, password):
        srv.opened.append((address, password))
        if srv.failures:
            raise srv.failures.pop(0)
        session = (make_session or (lambda a: PoolImap(f"{a}#{len(srv.made)}")))(address)
        srv.made.append(session)
        return session
    srv.sessions = Sessions(s.mail_servers, per_mailbox=s.max_sessions_per_mailbox, idle_seconds=s.imap_idle_seconds,
                            clock=clock, closer=EXIT, max_age=s.imap_max_session_age)
    tools_mod.register_mail_tools(srv, store, s, opener=opener, sender=sender or FakeSender(), sessions=srv.sessions)
    return srv


def audit_lines(caplog):
    return [json.loads(r.getMessage()) for r in caplog.records if r.name == "mcp_server_imap_smtp.audit"]


@pytest.mark.anyio
async def test_one_login_serves_several_calls_on_a_mailbox(tmp_path, monkeypatch):
    srv = pooled(env := tool_env(tmp_path, monkeypatch))
    await srv.call_tool("mail_search", {})
    await srv.call_tool("mail_read", {"folder": "INBOX", "uid": 5})
    await srv.call_tool("mail_folders", {})
    await srv.call_tool("mail_flag", {"folder": "INBOX", "uids": [5], "seen": True})
    assert srv.opened == [("me@x.co.za", "S3cret-one")]
    (session,) = srv.made
    assert session.resets == 3 and not session.closed          # checked before each reuse, still open
    await srv.call_tool("mail_search", {"mailbox": "accounts@x.co.za"})   # another mailbox: its own login
    assert srv.opened[-1] == ("accounts@x.co.za", "S3cret-two") and len(srv.opened) == 2
    assert srv.sessions.counts("mail1.hosting.example") == {"used": 2, "idle": 2, "waiting": 0,
                                                      "boxes": {"me@x.co.za": 1, "accounts@x.co.za": 1}}
    # Another connection holding the same mailbox never shares this one's session.
    _, other = grant(env, ["me@x.co.za"])
    env[3].set(other)
    await srv.call_tool("mail_search", {})
    assert len(srv.opened) == 3 and srv.made[0].closed          # it made room under max_sessions = 2


@pytest.mark.anyio
async def test_a_reused_session_reads_like_a_fresh_one(tmp_path, monkeypatch):
    """The tools ask a reused session for exactly what they ask a fresh one."""
    srv = pooled(tool_env(tmp_path, monkeypatch))
    for _ in range(2):
        await srv.call_tool("mail_read", {"folder": "INBOX", "uid": 5})
    (session,) = srv.made
    assert session.named("fetch_raw") == [("fetch_raw", "INBOX", 5)] * 2


@pytest.mark.anyio
async def test_a_session_that_failed_is_closed_and_the_next_call_logs_in_again(tmp_path, monkeypatch):
    class Dropping(PoolImap):
        def search(self, *a, **k):
            raise imaplib.IMAP4.abort("socket error: EOF")
    srv = pooled(tool_env(tmp_path, monkeypatch), lambda a: Dropping(a) if not srv.made else PoolImap(a))
    with pytest.raises(ToolError, match="dropped the connection"):
        await srv.call_tool("mail_search", {})
    assert srv.made[0].closed and srv.sessions.counts("mail1.hosting.example")["used"] == 0
    await srv.call_tool("mail_search", {})
    assert len(srv.opened) == 2 and not srv.made[1].closed


@pytest.mark.anyio
async def test_a_session_marked_broken_is_not_kept_even_when_the_call_succeeds(tmp_path, monkeypatch):
    class Swallowed(PoolImap):
        def search(self, *a, **k):
            self.broken = True        # e.g. the Sent copy failed on a dropped connection; the call still answered
            return super().search(*a, **k)
    srv = pooled(tool_env(tmp_path, monkeypatch), lambda a: Swallowed(a))
    await srv.call_tool("mail_search", {})
    assert srv.made[0].closed
    await srv.call_tool("mail_search", {})
    assert len(srv.opened) == 2


@pytest.mark.anyio
async def test_a_no_answer_keeps_the_session(tmp_path, monkeypatch):
    class Missing(PoolImap):
        def fetch_raw(self, folder, uid):
            raise MailError(f"message {uid} not found in {folder}")
    srv = pooled(tool_env(tmp_path, monkeypatch), lambda a: Missing(a))
    with pytest.raises(ToolError, match="not found"):
        await srv.call_tool("mail_read", {"folder": "INBOX", "uid": 9})
    await srv.call_tool("mail_search", {})
    assert len(srv.opened) == 1 and not srv.made[0].closed


@pytest.mark.anyio
async def test_a_stale_session_is_replaced_by_one_new_login(tmp_path, monkeypatch):
    srv = pooled(tool_env(tmp_path, monkeypatch))
    await srv.call_tool("mail_search", {})
    srv.made[0].stale = True                  # the server dropped it while it was kept
    out = (await srv.call_tool("mail_search", {})).structured_content
    assert out["messages"] and len(srv.opened) == 2 and srv.made[0].closed and not srv.made[1].closed


@pytest.mark.anyio
async def test_a_stale_session_is_retried_once_only(tmp_path, monkeypatch):
    srv = pooled(tool_env(tmp_path, monkeypatch))
    await srv.call_tool("mail_search", {})
    srv.made[0].stale = True
    srv.failures = [ConnectionRefusedError("10.0.0.1 S3cret-one")]
    with pytest.raises(ToolError, match="Could not reach the mail server") as info:
        await srv.call_tool("mail_search", {})
    assert len(srv.opened) == 2 and "S3cret" not in str(info.value)
    assert srv.sessions.counts("mail1.hosting.example")["used"] == 0


@pytest.mark.anyio
async def test_a_rejected_password_is_never_retried_and_closes_the_mailboxs_kept_sessions(tmp_path, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    s, store, gid, _ = env = tool_env(tmp_path, monkeypatch)
    srv = pooled(env, lambda a: PoolImap(a, delay=0.05))
    async with anyio.create_task_group() as tg:        # two calls at once: two kept sessions for me@
        for _ in range(2):
            tg.start_soon(srv.call_tool, "mail_search", {})
    assert len(srv.made) == 2 and srv.sessions.counts("mail1.hosting.example")["idle"] == 2
    for m in srv.made:
        m.stale = True                                    # the password changed and the server dropped them
    srv.failures = [MailAuthError("mailbox rejected the address or password")]
    with pytest.raises(ToolError, match="rejected the password for me@x.co.za.*other mailboxes"):
        await srv.call_tool("mail_search", {})
    assert len(srv.opened) == 3                           # one fresh login after the stale session, not retried
    assert all(m.closed for m in srv.made)                # the one checked and the one still kept
    assert srv.sessions.counts("mail1.hosting.example") == {"used": 0, "idle": 0, "boxes": {}, "waiting": 0}
    assert store.list_grants()[0]["revoked"] == 0         # several mailboxes: the connection stays
    assert "S3cret" not in caplog.text


@pytest.mark.anyio
async def test_revoking_the_grant_closes_its_kept_sessions(tmp_path, monkeypatch):
    s, store, gid, _ = env = tool_env(tmp_path, monkeypatch, mailboxes=("me@x.co.za",))
    srv = pooled(env)
    await srv.call_tool("mail_search", {})
    assert not srv.made[0].closed
    store.revoke_grant(gid)                               # e.g. a reused authorization code
    assert srv.made[0].closed and srv.sessions.counts("mail1.hosting.example")["used"] == 0


@pytest.mark.anyio
async def test_a_rejected_password_on_a_single_mailbox_grant_revokes_it_and_closes_its_session(tmp_path, monkeypatch):
    s, store, gid, _ = env = tool_env(tmp_path, monkeypatch, mailboxes=("me@x.co.za",))
    srv = pooled(env)
    await srv.call_tool("mail_search", {})
    srv.made[0].stale = True
    srv.failures = [MailAuthError("mailbox rejected the address or password")]
    with pytest.raises(ToolError, match="sign in again"):
        await srv.call_tool("mail_search", {})
    assert store.list_grants()[0]["revoked"] == 1 and srv.made[0].closed
    assert srv.sessions.counts("mail1.hosting.example")["used"] == 0


@pytest.mark.anyio
async def test_a_kept_session_past_the_idle_time_is_not_reused(tmp_path, monkeypatch):
    now = [1000.0]
    srv = pooled(tool_env(tmp_path, monkeypatch), clock=lambda: now[0])
    await srv.call_tool("mail_search", {})
    now[0] += 61
    await srv.call_tool("mail_search", {})
    assert len(srv.opened) == 2 and srv.made[0].closed and srv.made[0].resets == 0


@pytest.mark.anyio
async def test_reuse_can_be_turned_off(tmp_path, monkeypatch):
    srv = pooled(tool_env(tmp_path, monkeypatch, imap_idle_seconds=0))
    for _ in range(3):
        await srv.call_tool("mail_search", {})
    assert len(srv.opened) == 3 and all(m.closed for m in srv.made)


@pytest.mark.anyio
async def test_a_kept_session_in_steady_use_is_replaced_at_the_maximum_age(tmp_path, monkeypatch):
    now = [1000.0]
    srv = pooled(tool_env(tmp_path, monkeypatch, imap_max_session_age=100), clock=lambda: now[0])
    for _ in range(3):           # t = 1000 logs in, t = 1050 reuses, t = 1100 (100 s after the login) logs in
        await srv.call_tool("mail_search", {})
        now[0] += 50
    assert len(srv.opened) == 2 and srv.made[0].closed and not srv.made[1].closed


@pytest.mark.anyio
async def test_a_rejected_password_also_closes_another_connections_kept_session(tmp_path, monkeypatch):
    srv = pooled(env := tool_env(tmp_path, monkeypatch))       # connection 1: me@ and accounts@
    await srv.call_tool("mail_search", {})
    _, other = grant(env, ["me@x.co.za", "accounts@x.co.za"])
    env[3].set(other)
    await srv.call_tool("mail_search", {})                     # connection 2's own session for me@
    assert len(srv.made) == 2 and srv.sessions.counts("mail1.hosting.example")["idle"] == 2
    srv.made[1].stale = True                                    # the password changed; the server dropped it
    srv.failures = [MailAuthError("mailbox rejected the address or password")]
    with pytest.raises(ToolError, match="rejected the password for me@x.co.za"):
        await srv.call_tool("mail_search", {})
    assert srv.made[0].closed                                   # connection 1's, logged in with the old password
    assert srv.sessions.counts("mail1.hosting.example") == {"used": 0, "idle": 0, "boxes": {}, "waiting": 0}


@pytest.mark.anyio
async def test_a_call_that_finds_the_server_full_is_told_it_is_busy(tmp_path, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    monkeypatch.setattr(tools_mod, "SESSION_WAIT_SECONDS", 0.05)
    s, store, gid, _ = env = tool_env(tmp_path, monkeypatch, mailboxes=("me@x.co.za",))
    srv = pooled(env)
    async with srv.sessions.lease(NEO2, "other", "a@y.example"), srv.sessions.lease(NEO2, "other2", "b@y.example"):
        with pytest.raises(ToolError, match="The mail server is busy right now. Try again shortly.") as info:
            await srv.call_tool("mail_search", {})
    assert srv.opened == [] and "S3cret" not in str(info.value) and "S3cret" not in caplog.text
    (line,) = audit_lines(caplog)
    assert (line["outcome"], line["tool"], line["mailbox"], line["grant"]) == ("busy", "mail_search", "me@x.co.za", gid)
    assert store.list_grants()[0]["revoked"] == 0
    await srv.call_tool("mail_search", {})                 # free again
    assert audit_lines(caplog)[-1]["outcome"] == "ok"


@pytest.mark.anyio
async def test_mail_send_holds_an_imap_and_an_smtp_session(tmp_path, monkeypatch):
    monkeypatch.setattr(tools_mod, "SESSION_WAIT_SECONDS", 0.05)
    seen = []

    class Recording(FakeSender):
        def __call__(self, server, *a, **k):
            seen.append(srv.sessions.counts(server.host)["used"])
            return super().__call__(server, *a, **k)
    srv = pooled(tool_env(tmp_path, monkeypatch), sender=Recording())
    msg = {"to": ["c@y.example"], "subject": "s", "text": "t"}
    async with srv.sessions.lease(NEO2, "other", "a@y.example"):          # one of the two sessions taken
        with pytest.raises(ToolError, match="busy"):
            await srv.call_tool("mail_send", msg)
        await srv.call_tool("mail_search", {})                            # a read still fits
    await srv.call_tool("mail_send", msg)
    assert seen == [2] and srv.sessions.counts("mail1.hosting.example")["used"] == 1   # the IMAP session is kept


@pytest.mark.anyio
async def test_an_attachment_is_converted_after_the_session_is_handed_back(tmp_path, monkeypatch):
    raw = raw_message(attachments=[("a.txt", "text/plain", b"plain contents")])
    srv = pooled(tool_env(tmp_path, monkeypatch), lambda a: PoolImap(a, {("INBOX", 5): raw}))
    held = []
    real = tools_mod.render.attachment

    def attachment(*a):
        held.append(srv.sessions.counts("mail1.hosting.example")["idle"])
        return real(*a)
    monkeypatch.setattr(tools_mod.render, "attachment", attachment)
    out = (await srv.call_tool("mail_attachment", {"folder": "INBOX", "uid": 5, "index": 0})).structured_content
    assert out["text"].strip() == "plain contents" and held == [1]


# --- mailbox="*" under the caps ----------------------------------------------------------------------

ISP2 = MailServer(ISP.host, domains=ISP.domains, match_mx=False, max_sessions=2)


def star_sessions(env):
    s = env[0]
    return Sessions(s.mail_servers, per_mailbox=s.max_sessions_per_mailbox, idle_seconds=s.imap_idle_seconds,
                    closer=EXIT)


@pytest.mark.anyio
async def test_star_search_reports_mailboxes_the_busy_server_never_reached(tmp_path, monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger="mcp_server_imap_smtp.audit")
    monkeypatch.setattr(tools_mod, "ALL_MAILBOXES_SECONDS", 0.1)
    env = big_grant(tmp_path, monkeypatch, STAFF[:4], isp=ISP2)
    sessions = star_sessions(env)
    srv = fan_out(env, lambda a, p: DatedImap(a, 3), sessions=sessions)
    async with sessions.lease(ISP2, "other", "a@y.example"), sessions.lease(ISP2, "other2", "b@y.example"):
        out = (await srv.call_tool("mail_search", {"mailbox": "*"})).structured_content
    assert srv.opened == [] and out["searched"] == 0 and out["messages"] == []
    assert out["errors"] == [{"mailbox": a, "error": tools_mod.SERVER_BUSY} for a in STAFF[:4]]
    assert {(l["mailbox"], l["outcome"]) for l in audit_lines(caplog)} == {(a, "busy") for a in STAFF[:4]}
    assert sessions.counts(ISP.host)["waiting"] == 0


@pytest.mark.anyio
async def test_star_search_queues_for_the_servers_sessions_instead_of_flooding_it(tmp_path, monkeypatch):
    env = big_grant(tmp_path, monkeypatch, STAFF[:6], isp=ISP2)
    sessions = star_sessions(env)
    lock, state = threading.Lock(), {"now": 0, "max": 0}

    class Counted(DatedImap):
        def search(self, *a, **k):
            with lock:
                state["now"] += 1
                state["max"] = max(state["max"], state["now"])
            time.sleep(0.01)
            with lock:
                state["now"] -= 1
            return super().search(*a, **k)
    srv = fan_out(env, lambda a, p: Counted(a, 3), sessions=sessions)
    gate = anyio.Event()

    async def hold():
        async with sessions.lease(ISP2, "other", "a@y.example"):
            await gate.wait()
    async with anyio.create_task_group() as tg:
        tg.start_soon(hold)                  # another connection holds one of the two sessions for a while
        await anyio.sleep(0.01)

        async def release():
            await anyio.sleep(0.05)
            gate.set()
        tg.start_soon(release)
        out = (await srv.call_tool("mail_search", {"mailbox": "*"})).structured_content
    assert out["searched"] == 6 and "errors" not in out and state["max"] <= 2
    assert sessions.counts(ISP.host)["used"] <= 2


@pytest.mark.anyio
async def test_another_connections_call_is_served_between_star_mailboxes(tmp_path, monkeypatch):
    isp1 = MailServer(ISP.host, domains=ISP.domains, match_mx=False, max_sessions=2)
    env = big_grant(tmp_path, monkeypatch, STAFF[:6], isp=isp1, max_sessions_per_mailbox=1)
    s, store, _ = env
    gid_b, key_b = store.create_grant("c1", s.mail_resource_url, [("solo@client.example", "pw-solo", ISP)])
    at_b, _ = store.issue_tokens(gid_b, key_b, "c1", [], s.mail_resource_url, 3600, 86400)
    at_a = tools_mod.get_access_token().token
    var = contextvars.ContextVar("token", default=at_a)
    monkeypatch.setattr(tools_mod, "get_access_token", lambda: Tok(var.get()))
    sessions = star_sessions(env)
    order, lock = [], threading.Lock()

    class Slow(DatedImap):
        def search(self, *a, **k):
            time.sleep(0.03)
            with lock:
                order.append(self.address)
            return super().search(*a, **k)
    srv = fan_out(env, lambda a, p: Slow(a, 3), sessions=sessions)

    async def as_b():
        await anyio.sleep(0.01)
        var.set(at_b)
        await srv.call_tool("mail_search", {})
    async with anyio.create_task_group() as tg:
        tg.start_soon(as_b)
        await srv.call_tool("mail_search", {"mailbox": "*"})
    # Two sessions: the "*" search had two mailboxes under way when B asked; B went next.
    assert order.index("solo@client.example") <= 3 and len(order) == 7


# --- the sign-in page ---------------------------------------------------------------------------------

def test_sign_in_password_checks_take_turns_under_the_servers_cap(tmp_path):
    mail1 = MailServer("mail1.hosting.example", domains=("x.co.za",), match_mx=False, max_sessions=2)
    s = Settings(issuer_url="http://127.0.0.1:8765", mail_resource_url="http://127.0.0.1:8765/mail",
                 mail_servers=(mail1,), db_path=tmp_path / "s.sqlite")
    store = Store(s.db_path)
    prov = GatewayProvider(s, store)
    from mcp.server.auth.provider import AuthorizationParams
    req = store.create_pending("c1", AuthorizationParams(
        state="st", scopes=None, code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", redirect_uri=AnyUrl("https://claude.ai/api/mcp/auth_callback"),
        redirect_uri_provided_explicitly=True, resource=s.mail_resource_url), ttl=600)
    lock, state = threading.Lock(), {"now": 0, "max": 0}

    def verify(address, password, server):
        with lock:
            state["now"] += 1
            state["max"] = max(state["max"], state["now"])
        time.sleep(0.03)
        with lock:
            state["now"] -= 1
        return password == "pw"
    sessions = Sessions(s.mail_servers, per_mailbox=4, idle_seconds=60)
    app = Starlette(routes=login_routes(prov, Resolver((mail1,)), verify, RateLimiter(5, 900), s, sessions=sessions))
    c = TestClient(app, follow_redirects=False)
    more = "\n".join(f"staff{i}@x.co.za pw" for i in range(8))
    r = c.post("/mail/login", data={"req": req, "email": "me@x.co.za", "password": "pw", "more": more})
    assert connected(r) and state["max"] == 2
    assert len(store.list_grants()[0]["mailboxes"].split()) == 9


# --- ImapClient.reset against a scripted server (real imaplib) -------------------------------------------

def scripted(monkeypatch, unselect=b"OK", noop_bye=False):
    def handler(tag, line, readline, send):
        cmd = line.split()[1].upper()
        if cmd == b"LOGIN":
            return tag + b" OK logged in\r\n"
        if cmd == b"EXAMINE":
            return b"* 3 EXISTS\r\n" + tag + b" OK [READ-ONLY] examined\r\n"
        if cmd == b"UID" and line.split()[2].upper() == b"SEARCH":
            return b"* SEARCH\r\n" + tag + b" OK searched\r\n"
        if cmd == b"UID" and b"RFC822.SIZE" in line:
            return b"* 1 FETCH (UID 7 RFC822.SIZE 5)\r\n" + tag + b" OK fetched\r\n"
        if cmd == b"UID" and b"BODY.PEEK[]" in line:
            return b"* 1 FETCH (UID 7 BODY[] {5}\r\nhello)\r\n" + tag + b" OK fetched\r\n"
        if cmd == b"UNSELECT":
            # A flag change by another client arrives with the answer; it must not leak into the next call.
            return b"* 2 FETCH (FLAGS (\\Seen))\r\n" + tag + b" " + unselect + b" done\r\n"
        if cmd == b"NOOP":
            return b"* BYE idle too long\r\n" if noop_bye else tag + b" OK noop\r\n"
        return logout_ok(tag, line, readline, send)
    srv = ScriptedServer(handler)
    monkeypatch.setattr(Connector, "tls_connect", lambda self, port, timeout=10.0: srv.client)
    return srv


def commands(srv):
    return [b" ".join(line.split()[1:3]).decode() for line in srv.seen]


def test_reset_unselects_and_the_next_call_examines_and_peeks_as_if_new(monkeypatch):
    srv = scripted(monkeypatch)
    try:
        c = ImapClient.open(MailServer(HOST), "me@x.example", "pw")
        c._ns = {"personal": [], "other": [], "shared": []}
        assert c.search("INBOX", SearchQuery()) == (0, [])
        c._folders = ["cached"]
        c.reset()
        assert c.c.state == "AUTH" and c.c.untagged_responses == {} and c.c.is_readonly is False
        assert c._folders is None and c._ns is None
        c.reset()                                   # nothing selected now: NOOP proves the line is alive
        c._ns = {"personal": [], "other": [], "shared": []}
        assert c.fetch_raw("INBOX", 7) == b"hello"
        assert not c.broken
        c.close()
    finally:
        srv.close()
    assert commands(srv) == ["LOGIN me@x.example", 'EXAMINE "INBOX"', "UID SEARCH", "UNSELECT", "NOOP",
                             'EXAMINE "INBOX"', "UID FETCH", "UID FETCH", "LOGOUT"]
    assert b"BODY.PEEK[]" in srv.seen[7]
    assert not any(line.split()[1].upper() in (b"SELECT", b"CLOSE", b"STORE", b"EXPUNGE") for line in srv.seen)


def test_reset_without_unselect_support_keeps_a_session_that_answers(monkeypatch):
    srv = scripted(monkeypatch, unselect=b"BAD")
    try:
        c = ImapClient.open(MailServer(HOST), "me@x.example", "pw")
        c.search("INBOX", SearchQuery())
        c.reset()                                   # BAD: no UNSELECT here, but the server answered
        assert not c.broken and c.c.untagged_responses == {}
        c._ns = {"personal": [], "other": [], "shared": []}
        assert c.fetch_raw("INBOX", 7) == b"hello"
        c.close()
    finally:
        srv.close()


def test_a_dropped_session_is_marked_broken_and_refuses_reuse(monkeypatch):
    srv = scripted(monkeypatch, noop_bye=True)
    try:
        c = ImapClient.open(MailServer(HOST), "me@x.example", "pw")
        with pytest.raises(imaplib.IMAP4.abort):
            c.reset()
        assert c.broken
        with pytest.raises(MailError, match="no longer usable"):
            c.reset()
        c.close()
    finally:
        srv.close()


def silent(tag, line, readline, send):
    """A server that accepts the login and then never answers again (a flow a NAT or firewall dropped)."""
    return tag + b" OK logged in\r\n" if line.split()[1].upper() == b"LOGIN" else b""


def test_a_silently_dropped_kept_session_fails_its_check_fast_and_its_socket_is_shut(monkeypatch):
    """The check gives up after CHECK_TIMEOUT, not the 30 s command timeout; the broken session gets no
    LOGOUT, its socket is shut, and the call logs in once more."""
    monkeypatch.setattr(imap_mod, "CHECK_TIMEOUT", 0.2)
    srv = ScriptedServer(silent)
    monkeypatch.setattr(Connector, "tls_connect", lambda self, port, timeout=10.0: srv.client)
    try:
        c = ImapClient.open(MailServer(HOST), "me@x.example", "pw")
        assert c.c.sock.gettimeout() == imap_mod.TIMEOUT
        lease = Lease("g", "me@x.example", ("g", "me@x.example"), 0, True)
        lease.handed = c
        started = time.monotonic()
        with lease.session("me@x.example", lambda: Kept("fresh")) as session:
            waited = time.monotonic() - started
        assert session.name == "fresh" and waited < 2 and c.broken
        assert srv.client.fileno() == -1
    finally:
        srv.close()
    assert commands(srv) == ["LOGIN me@x.example", "NOOP"]


def test_the_check_waits_briefly_and_the_session_keeps_the_normal_timeout(monkeypatch):
    during = []
    client = {}

    def handler(tag, line, readline, send):
        cmd = line.split()[1].upper()
        if cmd == b"LOGIN":
            return tag + b" OK logged in\r\n"
        if cmd == b"NOOP":
            during.append(client["sock"].gettimeout())
            return tag + b" OK noop\r\n"
        return logout_ok(tag, line, readline, send)
    srv = ScriptedServer(handler)
    client["sock"] = srv.client
    monkeypatch.setattr(Connector, "tls_connect", lambda self, port, timeout=10.0: srv.client)
    try:
        c = ImapClient.open(MailServer(HOST), "me@x.example", "pw")
        c.reset()
        assert during == [imap_mod.CHECK_TIMEOUT] and c.c.sock.gettimeout() == imap_mod.TIMEOUT == 30
        c.close()
        assert srv.client.fileno() == -1
    finally:
        srv.close()


def test_close_shuts_the_socket_even_when_logout_gets_no_answer(monkeypatch):
    monkeypatch.setattr(imap_mod, "CHECK_TIMEOUT", 0.2)
    srv = ScriptedServer(silent)
    monkeypatch.setattr(Connector, "tls_connect", lambda self, port, timeout=10.0: srv.client)
    try:
        c = ImapClient.open(MailServer(HOST), "me@x.example", "pw")
        started = time.monotonic()
        c.close()
        assert time.monotonic() - started < 2 and srv.client.fileno() == -1
    finally:
        srv.close()
    assert commands(srv) == ["LOGIN me@x.example", "LOGOUT"]


@pytest.mark.anyio
async def test_the_tools_on_the_real_imap_client_log_in_once_and_read_without_marking(tmp_path, monkeypatch):
    """The real opener over one scripted connection (a second login would have no socket): two reads,
    one LOGIN, each read EXAMINEs and PEEKs, and the session is UNSELECTed in between."""
    body = raw_message(body="the body")
    literal = b"* 1 FETCH (UID 5 BODY[] {%d}\r\n" % len(body) + body + b")\r\n"

    def handler(tag, line, readline, send):
        cmd = line.split()[1].upper()
        if cmd == b"LOGIN":
            return tag + b" OK logged in\r\n"
        if cmd == b"EXAMINE":
            return b"* 1 EXISTS\r\n" + tag + b" OK [READ-ONLY] examined\r\n"
        if cmd == b"UID" and b"RFC822.SIZE" in line:
            return b"* 1 FETCH (UID 5 RFC822.SIZE %d)\r\n" % len(body) + tag + b" OK fetched\r\n"
        if cmd == b"UID" and b"BODY.PEEK[]" in line:
            return literal + tag + b" OK fetched\r\n"
        if cmd in (b"UNSELECT", b"NOOP"):
            return tag + b" OK done\r\n"
        return logout_ok(tag, line, readline, send)
    srv = ScriptedServer(handler)
    monkeypatch.setattr(Connector, "tls_connect", lambda self, port, timeout=10.0: srv.client)
    s, store, gid, _ = env = tool_env(tmp_path, monkeypatch, mailboxes=("me@x.co.za",))
    tools = MCPServer("t")
    sessions = Sessions(s.mail_servers, closer=EXIT)
    tools_mod.register_mail_tools(tools, store, s, sender=FakeSender(), sessions=sessions)
    try:
        for _ in range(2):
            out = (await tools.call_tool("mail_read", {"folder": "INBOX", "uid": 5})).structured_content
            assert out["text"].strip() == "the body"
        store.revoke_grant(gid)                   # closes the kept session: LOGOUT
    finally:
        srv.close()
    names = [line.split()[1].decode() for line in srv.seen]
    assert names == ["LOGIN", "EXAMINE", "UID", "UID", "UNSELECT", "EXAMINE", "UID", "UID", "LOGOUT"]
    assert sum(b"BODY.PEEK[]" in line for line in srv.seen) == 2
    assert not any(line.split()[1].upper() in (b"SELECT", b"CLOSE", b"STORE", b"EXPUNGE") for line in srv.seen)


# --- settings ----------------------------------------------------------------------------------------

HEAD = '''
issuer_url = "http://127.0.0.1:8765"
mail_resource_url = "http://127.0.0.1:8765/mail"
db_path = "{db}"
'''


def load(tmp_path, body):
    p = tmp_path / "c.toml"
    p.write_text(body.replace("{db}", str(tmp_path / "x.sqlite")))
    return load_settings(p)


def test_session_settings_defaults_and_toml(tmp_path):
    s = load(tmp_path, HEAD + 'mail_host = "mail1.hosting.example"\n')
    assert (s.mail_servers[0].max_sessions, s.max_sessions_per_mailbox, s.imap_idle_seconds) == (8, 4, 60)
    assert s.imap_max_session_age == 300 and Sessions.from_settings(s).max_age == 300
    s = load(tmp_path, HEAD + "max_sessions_per_mailbox = 6\nimap_idle_seconds = 0\nimap_max_session_age = 120\n"
                       '[[mail_servers]]\nhost = "mail1.hosting.example"\n\n'
                       '[[mail_servers]]\nhost = "mail.client.example"\ndomains = ["client.example"]\n'
                       "max_sessions = 32\n")
    assert [m.max_sessions for m in s.mail_servers] == [8, 32]
    assert (s.max_sessions_per_mailbox, s.imap_idle_seconds, s.imap_max_session_age) == (6, 0, 120)


@pytest.mark.parametrize("body,match", [
    ('[[mail_servers]]\nhost = "mail1.hosting.example"\nmax_sessions = 1\n', "max_sessions must be a whole number, 2"),
    ('[[mail_servers]]\nhost = "mail1.hosting.example"\nmax_sessions = "8"\n', "max_sessions"),
    ('max_sessions_per_mailbox = 0\nmail_host = "mail1.hosting.example"\n', "max_sessions_per_mailbox"),
    ('imap_idle_seconds = -1\nmail_host = "mail1.hosting.example"\n', "imap_idle_seconds"),
    ('imap_idle_seconds = 1.5\nmail_host = "mail1.hosting.example"\n', "imap_idle_seconds"),
    ('imap_max_session_age = -1\nmail_host = "mail1.hosting.example"\n', "imap_max_session_age"),
    ('imap_max_session_age = 300.0\nmail_host = "mail1.hosting.example"\n', "imap_max_session_age"),
])
def test_session_settings_are_checked(tmp_path, body, match):
    with pytest.raises(ValueError, match=match):
        load(tmp_path, HEAD + body)


def test_shipped_configurations_load(tmp_path):
    root = Path(__file__).resolve().parents[1]
    prod = (root / "deploy" / "config.prod.toml.template").read_text().replace("@MCP_HOSTNAME@", "mcp.example.net")
    s = load(tmp_path, prod.replace('"/var/lib/@NAME@/mcp-server-imap-smtp.sqlite"', '"{db}"'))
    assert {m.host: m.max_sessions for m in s.mail_servers} == {"mail.example.com": 8, "mail.client.example": 16}
    assert s.imap_max_session_age == 300
    load(tmp_path, (root / "config.example.toml").read_text().replace('"./mcp-server-imap-smtp.sqlite"', '"{db}"'))