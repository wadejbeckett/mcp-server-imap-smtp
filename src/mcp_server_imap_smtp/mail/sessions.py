# SPDX-License-Identifier: AGPL-3.0-or-later
"""How many sessions the connector holds open on each mail server, who gets the next one, and reuse of
logged-in IMAP sessions.

Every client reaches the mail servers from the connector's one address, so a mail server sees all of them
as one very busy client. Each configured server gets a cap on sessions open at once (MailServer.max_sessions,
IMAP and SMTP together, idle pooled IMAP sessions and sessions still logging out included) and a cap per
mailbox (Settings.max_sessions_per_mailbox, IMAP only, below Dovecot's mail_max_userip_connections). A call
that finds the server full waits in that server's queue. The queue is fair between grants: the grant served
least recently goes next, so one connection searching 88 mailboxes cannot hold up everyone else's
single-mailbox calls. Within a grant, calls naming one mailbox go before its mailbox="*" work. A call
not served within its budget fails with ServerBusy ("busy" in the audit line), never silently.

A healthy IMAP session is kept logged in for imap_idle_seconds after a call, keyed by (grant, mailbox),
and handed to the next call for that key, so a search followed by two reads is one login, not three.
A kept session is never reused once imap_max_session_age has passed since its login, so a password changed
on the mail server takes effect for the connector within that time. An idle session holds its server and
mailbox slots but is closed whenever a waiting call needs them; its slots come free only when its LOGOUT
has finished, so the caps hold while sessions are being closed. A pooled session is checked (UNSELECT or
NOOP) before reuse; if the server dropped it, one fresh login is made (never after a rejected password).
It is closed, never pooled, after an error that may have left it broken, when the mail server rejects its
mailbox's password (every connection's kept sessions for that mailbox on that server), when its grant is
revoked, and when it has been idle or logged in too long.

When the service stops, close() ends it all within a short bound: calls still waiting on a mail server have
their sockets shut (they fail at once and their sessions are not kept), kept sessions get their LOGOUT,
and no new session is handed out.

All bookkeeping happens on the event loop thread (no locks): only the network work (log in, check,
log out and the tool's own commands) runs in worker threads. One session object is used by one call at
a time: it is handed to a call on the loop, used in that call's worker thread and handed back on the loop
after the thread has finished."""
from __future__ import annotations

import asyncio
import collections
import contextlib
import logging
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable

import anyio

from .hosts import MailServer
from .imap import MailAuthError, MailBusy, MailError

log = logging.getLogger(__name__)

SESSION_WAIT_SECONDS = 30.0      # how long a call waits for a session before it is told the server is busy
DROPPED_KEEP = 3600.0            # how long a revoked grant is remembered, so calls still running then never pool
MAX_SESSION_AGE = 300.0          # a kept session is not reused once this long after its login (Settings default)
CLOSE_WORKERS = 4                # threads logging out sessions the pool lets go; further closes wait their turn
STOP_LOGOUT_SECONDS = 2.0        # how long close() waits for kept sessions' LOGOUT when the service stops
STOPPING = "The connector is restarting. Try again in a moment."
BUSY = "The mail server is busy right now. Try again shortly."

_GRANTED, _NO_SERVER, _NO_MAILBOX = "granted", "server full", "mailbox full"


class ServerBusy(MailBusy):
    """No session on the mail server came free within the call's wait budget."""


def _close(session: Any) -> None:
    """Log out and drop the connection. The opener's object is a context manager whose exit closes it."""
    try:
        session.__exit__(None, None, None)
    except Exception:
        pass


def _drop(session: Any) -> None:
    """Shut the connection without a LOGOUT round trip, where the session offers that (ImapClient.drop)."""
    try:
        drop = getattr(session, "drop", None)
        if drop is not None:
            drop()
    except Exception:
        pass


def _notify(done: Callable[[], None]) -> None:
    try:
        done()
    except Exception:
        log.exception("session close callback failed")


class _Closer:
    """Logs out the sessions the pool lets go, in at most `workers` background threads: LOGOUT is a network
    round trip, so never on the event loop, and a burst of evictions never starts a thread per session.
    closer(sessions, done) calls done() once the sessions are closed. Never raises: if no thread can be
    started and none is running, the sessions are dropped without LOGOUT and done() is called at once."""

    def __init__(self, workers: int = CLOSE_WORKERS):
        self._max, self._lock = workers, threading.Lock()
        self._jobs: collections.deque = collections.deque()
        self._running = 0

    def __call__(self, sessions: list, done: Callable[[], None]) -> None:
        with self._lock:
            self._jobs.append((sessions, done))
            if self._running >= self._max:
                return
            self._running += 1
        try:
            threading.Thread(target=self._work, name="mcp-imap-smtp-session-close", daemon=True).start()
        except Exception:        # e.g. RuntimeError: can't start new thread
            with self._lock:
                self._running -= 1
                stranded = list(self._jobs) if not self._running else []
                if stranded:
                    self._jobs.clear()
            for left, told in stranded:
                for session in left:
                    _drop(session)
                _notify(told)

    def _work(self) -> None:
        while True:
            with self._lock:
                if not self._jobs:
                    self._running -= 1
                    return
                sessions, done = self._jobs.popleft()
            for session in sessions:
                _close(session)
            _notify(done)


_close_in_background = _Closer()


@dataclass(eq=False)
class _Idle:
    key: tuple[str, str]       # (grant, address)
    address: str
    session: Any
    since: float               # Sessions.clock() when it was handed back
    born: float                # Sessions.clock() just before its LOGIN


class Lease:
    """One call's claim on a mail server: one IMAP session for `address` (a pooled one when there is one)
    and `extra` more sessions (mail_send's SMTP), held from the moment it is granted until it is handed
    back. Created and granted on the event loop; session() is used in the call's worker thread."""

    def __init__(self, queue: str, address: str, pool_key: tuple[str, str] | None, extra: int, priority: bool,
                 clock: Callable[[], float] = time.monotonic):
        self.queue, self.address, self.pool_key, self.extra, self.priority = queue, address, pool_key, extra, priority
        self.clock = clock
        self.event = anyio.Event()
        self.granted = False
        self.granted_at = 0.0        # clock() when granted
        self.handed: Any = None      # an idle pooled session given to this call, not yet checked
        self.handed_born = 0.0       # ... and when it logged in
        self.keep: Any = None        # set in the worker thread: a healthy session to pool afterwards
        self.keep_born: float | None = None   # ... and when it logged in (None: during this call)
        self.auth_failed = False     # the mail server rejected this mailbox's password during the call
        self.reused = False          # the call ran on a pooled session (for tests and diagnostics)
        self._open = False           # session() is in use
        # Shared with the event loop when the service stops (cut): the session in use, and whether the call
        # was cut. The lock makes "cut" and "start using a session" exclusive, so none is missed.
        self._guard = threading.Lock()
        self._current: Any = None
        self._cut = False

    def cut(self) -> None:
        """The service is stopping (any thread): end the mail server work this call is waiting on, and open
        no further session. The call then fails as on a dropped connection."""
        with self._guard:
            self._cut = True
            session = self._current
        interrupt = getattr(session, "interrupt", None)
        if interrupt is not None:
            try:
                interrupt()
            except Exception:
                pass

    def _use(self, session: Any) -> None:
        """Record the session this call is about to use (None: none yet); MailError if the call was cut."""
        with self._guard:
            if self._cut:
                raise MailError(STOPPING)
            self._current = session

    def kept_born(self) -> float:
        return self.granted_at if self.keep_born is None else self.keep_born

    def _ready(self, open_fresh: Callable[[], Any]) -> tuple[Any, float]:
        """(session, login time): the pooled session handed to this call, or the one an earlier session()
        block of this call kept, once checked; otherwise a fresh login."""
        candidate, born, pooled = None, 0.0, False
        if self.handed is not None:
            candidate, born, pooled = self.handed, self.handed_born, True
            self.handed = None
        elif self.keep is not None:     # a second block in the same call: the session the first one kept
            candidate, born = self.keep, self.kept_born()
            self.keep = self.keep_born = None
        if candidate is not None:
            try:
                reset = getattr(candidate, "reset", None)
                if reset is not None:
                    reset()
                self.reused = self.reused or pooled
                return candidate, born
            except Exception:       # dropped or stale while idle: log in again, once
                _close(candidate)
        born = self.clock()         # before LOGIN, so a session's age is never understated
        try:
            return open_fresh().__enter__(), born
        except MailAuthError:       # never retried
            self.auth_failed = True
            raise

    @contextlib.contextmanager
    def session(self, address: str, open_fresh: Callable[[], Any]):
        """The call's IMAP session for `address`: a checked pooled one, the one an earlier block of this call
        kept, or open_fresh() (which logs in). A call holds one IMAP session: a block for another mailbox, or
        one opened inside another, raises. On the way out a healthy session is kept for the pool (and for a
        later block of this call); one that may be broken is closed."""
        if address != self.address:
            raise RuntimeError("this call holds a session for another mailbox")
        if self._open:
            raise RuntimeError("this call's mail session is already open")
        self._open = True
        try:
            self._use(None)                 # no login once the service is stopping
            session, born = self._ready(open_fresh)
            try:
                self._use(session)
            except MailError:
                _close(session)
                raise
            healthy = False
            try:
                yield session
                healthy = True
            except MailAuthError:       # SMTP refused the password (mail_send): do not keep sessions made with it
                self.auth_failed = True
                raise
            except MailError:           # a NO answer or a refused argument: the session itself is still in step
                healthy = True
                raise
            finally:
                with self._guard:
                    self._current = None
                if healthy and self.pool_key is not None and not getattr(session, "broken", False):
                    if self.keep is not None and self.keep is not session:
                        _close(self.keep)
                    self.keep, self.keep_born = session, born
                else:
                    _close(session)
        finally:
            self._open = False


class _Server:
    def __init__(self, server: MailServer):
        self.host, self.cap = server.host, server.max_sessions
        self.used = 0                                   # sessions open or promised: idle and closing ones included
        self.boxes: dict[str, int] = {}                 # address -> IMAP sessions open or promised (closing included)
        self.idle: list[_Idle] = []                     # oldest first
        self.closing = 0                                # sessions logging out: their slots come free when done
        self.closing_boxes: dict[str, int] = {}         # ... per address
        self.rejected: dict[str, float] = {}            # address -> when the server last rejected its password
        self.queues: dict[str, list[Lease]] = {}        # waiting calls per grant (or sign-in), oldest first
        self.active: dict[str, int] = {}                # granted, not yet handed back, per grant
        self.leases: set[Lease] = set()                 # granted, not yet handed back
        self.served: dict[str, int] = {}                # when each grant was last given a session (tick)
        self.tick = 0


class Sessions:
    """Session caps, fair queues and the IMAP session pool for every configured mail server.

    closer(sessions, done): closes sessions the pool lets go and calls done() when they are closed (from any
    thread, or before it returns); until then they keep their slots."""

    def __init__(self, servers: Iterable[MailServer], per_mailbox: int = 4, idle_seconds: float = 60,
                 wait_seconds: float = SESSION_WAIT_SECONDS, clock: Callable[[], float] = time.monotonic,
                 closer: Callable[[list, Callable[[], None]], None] = _close_in_background,
                 max_age: float = MAX_SESSION_AGE):
        self._servers = {s.host: _Server(s) for s in servers}
        self.per_mailbox, self.idle_seconds, self.wait_seconds = per_mailbox, idle_seconds, wait_seconds
        self.max_age = max_age
        self.clock, self._closer = clock, closer
        self._dropped: dict[str, float] = {}           # revoked grant -> when
        self._loop: asyncio.AbstractEventLoop | None = None
        self._timer: asyncio.TimerHandle | None = None
        self._timer_loop: asyncio.AbstractEventLoop | None = None
        self._timer_at = 0.0
        self._stopping = False

    @classmethod
    def from_settings(cls, settings) -> "Sessions":
        return cls(settings.mail_servers, per_mailbox=settings.max_sessions_per_mailbox,
                   idle_seconds=settings.imap_idle_seconds, max_age=settings.imap_max_session_age)

    @property
    def total(self) -> int:
        """Sessions all servers together may hold: enough worker threads for every one of them."""
        return sum(s.cap for s in self._servers.values())

    def _server(self, server: MailServer) -> _Server:
        srv = self._servers.get(server.host)
        if srv is None:          # not configured (callers check first); still capped
            srv = self._servers[server.host] = _Server(server)
        return srv

    # --- the call's side ---------------------------------------------------------------------------

    @contextlib.asynccontextmanager
    async def lease(self, server: MailServer, queue: str, address: str, *, pool_key: tuple[str, str] | None = None,
                    extra: int = 0, priority: bool = True, wait: float | None = None, deadline: float | None = None):
        """Wait (fairly) for a session on `server`, hold it for the block, then hand it back. `queue` is the
        fairness key (the grant id); pool_key (grant, address) lets the call reuse and leave a pooled IMAP
        session. Raises ServerBusy if nothing came free by `deadline` (anyio clock) or within `wait` seconds."""
        if self._stopping:
            raise ServerBusy(STOPPING)
        if self._loop is None:
            with contextlib.suppress(RuntimeError):
                self._loop = asyncio.get_running_loop()
        if deadline is None:
            deadline = anyio.current_time() + (self.wait_seconds if wait is None else wait)
        srv = self._server(server)
        lease = Lease(queue, address, pool_key, extra, priority, clock=self.clock)
        try:                    # whatever fails from here on, the call is never left queued or holding slots
            srv.queues.setdefault(queue, []).append(lease)
            self._sweep(srv)
            self._pump(srv)
            if not lease.granted:
                with anyio.move_on_after(max(0.0, deadline - anyio.current_time())):
                    await lease.event.wait()
        except BaseException:
            self._unqueue(srv, lease)
            if lease.granted:
                self._hand_back(srv, lease)
            else:
                self._forget_turn(srv, lease.queue)
                self._pump(srv)
            raise
        if not lease.granted:
            self._dequeue(srv, lease)
            raise ServerBusy(BUSY)
        try:
            yield lease
        finally:
            self._hand_back(srv, lease)

    def forget_grant(self, grant_id: str) -> None:
        """Close the grant's pooled sessions and never pool for it again (it was revoked). Safe from any
        thread: the work is done on the event loop."""
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is not None and (self._loop is None or running is self._loop):
            self._forget(grant_id)
        elif self._loop is not None and not self._loop.is_closed():
            with contextlib.suppress(RuntimeError):      # the loop closed meanwhile: nothing left to close
                self._loop.call_soon_threadsafe(self._forget, grant_id)

    def forget_mailbox(self, grant_id: str, address: str) -> None:
        """Close the idle sessions kept for one mailbox of a grant (its password was replaced or it was removed),
        without stopping pooling for the grant. Safe from any thread, like forget_grant."""
        def forget() -> None:
            for srv in self._servers.values():
                for entry in [e for e in srv.idle if e.key == (grant_id, address)]:
                    self._evict(srv, entry)
                self._pump(srv)
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is not None and (self._loop is None or running is self._loop):
            forget()
        elif self._loop is not None and not self._loop.is_closed():
            with contextlib.suppress(RuntimeError):
                self._loop.call_soon_threadsafe(forget)

    def sweep(self) -> None:
        """Close idle sessions past imap_idle_seconds or imap_max_session_age and serve whoever was waiting
        for their slots."""
        for srv in self._servers.values():
            self._sweep(srv)
            self._pump(srv)

    async def close(self, wait: float = STOP_LOGOUT_SECONDS) -> None:
        """The service is stopping (on the event loop, at the ASGI lifespan shutdown): cut every call still
        holding a session, so a call waiting on a silent mail server ends now rather than at its command
        timeout; log out every kept session; refuse new leases. Returns once every LOGOUT has finished, or
        after `wait` seconds: a mail server that does not answer cannot hold the stop. Sessions handed back
        by cut calls are closed, never kept."""
        self._stopping = True
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
        for srv in self._servers.values():
            for lease in list(srv.leases):
                lease.cut()
            for entry in list(srv.idle):
                self._evict(srv, entry)
        with anyio.move_on_after(wait):
            while any(srv.closing for srv in self._servers.values()):
                await anyio.sleep(0.02)

    def counts(self, host: str) -> dict[str, Any]:
        """Open (or promised) and idle sessions on a server, per mailbox and waiting: for tests and checks."""
        srv = self._servers[host]
        return {"used": srv.used, "idle": len(srv.idle), "boxes": dict(srv.boxes),
                "waiting": sum(len(q) for q in srv.queues.values())}

    # --- bookkeeping, on the event loop only ------------------------------------------------------------

    def _fresh(self, entry: _Idle, now: float) -> bool:
        """May this kept session still be handed to a call?"""
        return now - entry.since < self.idle_seconds and now - entry.born < self.max_age

    def _try_grant(self, srv: _Server, lease: Lease) -> str:
        now = self.clock()
        reuse = None
        if lease.pool_key is not None:
            reuse = next((e for e in reversed(srv.idle) if e.key == lease.pool_key and self._fresh(e, now)),
                         None)                                                       # the freshest
        need = lease.extra + (0 if reuse else 1)
        verdict = self._room(srv, lease, reuse, need)
        if verdict is not _GRANTED:
            return verdict
        if reuse is not None:
            srv.idle.remove(reuse)
            lease.handed, lease.handed_born = reuse.session, reuse.born
        srv.used += need
        if reuse is None:
            srv.boxes[lease.address] = srv.boxes.get(lease.address, 0) + 1
        srv.tick += 1
        srv.served[lease.queue] = srv.tick
        srv.active[lease.queue] = srv.active.get(lease.queue, 0) + 1
        srv.leases.add(lease)
        lease.granted, lease.granted_at = True, now
        lease.event.set()
        return _GRANTED

    def _room(self, srv: _Server, lease: Lease, reuse: _Idle | None, need: int) -> str:
        """_GRANTED if the call fits now. Otherwise starts closing as many idle sessions as it needs (oldest
        first, never `reuse`) and says what the call waits for: the slots of a session being closed come
        free only when its LOGOUT has finished."""
        def short() -> tuple[int, int]:
            box = 0 if reuse else srv.boxes.get(lease.address, 0) + 1 - self.per_mailbox
            return box, need - (srv.cap - srv.used)
        box_short, server_short = short()
        if box_short <= 0 and server_short <= 0:
            return _GRANTED
        others = [e for e in srv.idle if e is not reuse]
        same_box = [e for e in others if e.address == lease.address]
        box_closing = srv.closing_boxes.get(lease.address, 0)
        if box_short > box_closing + len(same_box):
            return _NO_MAILBOX
        if server_short > srv.closing + len(others):
            return _NO_SERVER
        for entry in same_box[:max(0, box_short - box_closing)]:
            self._evict(srv, entry)
        more = need - (srv.cap - srv.used) - srv.closing
        for entry in [e for e in srv.idle if e is not reuse][:max(0, more)]:
            self._evict(srv, entry)
        box_short, server_short = short()      # a closer that finished at once has made room already
        if box_short <= 0 and server_short <= 0:
            return _GRANTED
        return _NO_SERVER if server_short > 0 else _NO_MAILBOX

    def _pump(self, srv: _Server) -> None:
        """Serve waiting calls while sessions are free (or idle ones can be closed). The grant served least
        recently goes first; if its call needs more sessions than are free, nobody overtakes it."""
        while srv.queues:
            if srv.used >= srv.cap and not srv.idle:
                return
            for name in sorted(srv.queues, key=lambda q: srv.served.get(q, -1)):
                waiting = srv.queues[name]
                verdict = _NO_MAILBOX
                for want in (True, False):          # this grant's single-mailbox calls before its "*" work
                    if verdict is _NO_SERVER:       # ... and its "*" work never overtakes them
                        break
                    for lease in waiting:
                        if lease.priority is not want:
                            continue
                        result = self._try_grant(srv, lease)
                        if result is _GRANTED:
                            waiting.remove(lease)
                            if not waiting:
                                del srv.queues[name]
                            verdict = _GRANTED
                            break
                        if result is _NO_SERVER:
                            verdict = _NO_SERVER
                    if verdict is _GRANTED:
                        break
                if verdict is _GRANTED:
                    break           # start again from the least recently served grant
                if verdict is _NO_SERVER:
                    return          # wait for sessions to come free rather than let others overtake
            else:
                return              # every waiting call is held only by its mailbox's cap

    def _unqueue(self, srv: _Server, lease: Lease) -> None:
        waiting = srv.queues.get(lease.queue)
        if waiting is not None and lease in waiting:
            waiting.remove(lease)
            if not waiting:
                del srv.queues[lease.queue]

    def _dequeue(self, srv: _Server, lease: Lease) -> None:
        self._unqueue(srv, lease)
        self._forget_turn(srv, lease.queue)
        self._pump(srv)

    def _forget_turn(self, srv: _Server, queue: str) -> None:
        if not srv.active.get(queue) and queue not in srv.queues:
            srv.active.pop(queue, None)
            srv.served.pop(queue, None)

    def _hand_back(self, srv: _Server, lease: Lease) -> None:
        if not lease.granted:
            return
        lease.granted = False
        srv.leases.discard(lease)
        srv.used -= lease.extra
        srv.active[lease.queue] -= 1
        self._forget_turn(srv, lease.queue)
        if lease.keep is not None:
            session, born = lease.keep, lease.kept_born()
        else:
            session, born = lease.handed, lease.handed_born
        lease.keep = lease.handed = None
        now = self.clock()
        if lease.auth_failed:
            # The mail server rejected this mailbox's password (it may have changed): no session for it on
            # this server that logged in before now is used again, whichever connection it belongs to.
            srv.rejected[lease.address] = now
            for entry in [e for e in srv.idle if e.address == lease.address]:
                self._evict(srv, entry)
        grant = lease.pool_key[0] if lease.pool_key else None
        if (session is not None and grant is not None and self.idle_seconds > 0 and not lease.auth_failed
                and not self._stopping
                and grant not in self._dropped and now - born < self.max_age
                and born > srv.rejected.get(lease.address, float("-inf"))):
            srv.idle.append(_Idle(lease.pool_key, lease.address, session, now, born))
        elif session is not None:
            self._close_later(srv, lease.address, session)
        else:
            self._free(srv, lease.address)
        self._sweep(srv)
        self._pump(srv)
        self._arm()

    def _free(self, srv: _Server, address: str) -> None:
        srv.used -= 1
        srv.boxes[address] -= 1
        if not srv.boxes[address]:
            del srv.boxes[address]

    def _evict(self, srv: _Server, entry: _Idle) -> None:
        srv.idle.remove(entry)
        self._close_later(srv, entry.address, entry.session)

    def _close_later(self, srv: _Server, address: str, session: Any) -> None:
        """Close a session off the event loop. It keeps its server and mailbox slots until the close has
        finished: until its LOGOUT is answered the mail server still counts it."""
        srv.closing += 1
        srv.closing_boxes[address] = srv.closing_boxes.get(address, 0) + 1
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:     # not on asyncio: nothing could report back, so the slots come free now
            loop = None
        caller, once = threading.get_ident(), threading.Lock()
        state = {"calling": True, "inline": loop is None}
        if loop is None:
            once.acquire()

        def done() -> None:
            if not once.acquire(blocking=False):
                return                              # told twice
            if state["calling"] and threading.get_ident() == caller:
                state["inline"] = True              # closed before the closer returned: released below
            else:
                with contextlib.suppress(RuntimeError):     # the loop has closed: nothing left to count
                    loop.call_soon_threadsafe(self._closed, srv, address)
        try:
            self._closer([session], done)
        except Exception as exc:                    # never leave the slots taken for good
            log.warning("closing a mail session failed (%s); dropped without LOGOUT", exc.__class__.__name__)
            _drop(session)
            if once.acquire(blocking=False):
                state["inline"] = True
        state["calling"] = False
        if state["inline"]:
            self._release(srv, address)

    def _release(self, srv: _Server, address: str) -> None:
        srv.closing -= 1
        srv.closing_boxes[address] -= 1
        if not srv.closing_boxes[address]:
            del srv.closing_boxes[address]
        self._free(srv, address)

    def _closed(self, srv: _Server, address: str) -> None:
        """A background close has finished (on the event loop): its slots are free for whoever waits."""
        self._release(srv, address)
        self._pump(srv)

    def _sweep(self, srv: _Server) -> None:
        now = self.clock()
        for entry in [e for e in srv.idle if not self._fresh(e, now)]:
            self._evict(srv, entry)
        for address in [a for a, at in srv.rejected.items() if now - at >= self.max_age]:
            del srv.rejected[address]       # every session older than the rejection is past max_age by now
        for grant in [g for g, at in self._dropped.items() if now - at > DROPPED_KEEP]:
            del self._dropped[grant]

    def _forget(self, grant_id: str) -> None:
        self._dropped[grant_id] = self.clock()
        for srv in self._servers.values():
            for entry in [e for e in srv.idle if e.key[0] == grant_id]:
                self._evict(srv, entry)
            self._pump(srv)

    def _arm(self) -> None:
        """Close idle sessions on time even when no further call comes in to notice them."""
        if self.idle_seconds <= 0:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:     # not on asyncio: idle sessions are closed by the next call's sweep
            return
        due = [min(e.since + self.idle_seconds, e.born + self.max_age)
               for srv in self._servers.values() for e in srv.idle]
        if not due:
            return
        at = min(due)
        if self._timer is not None and self._timer_loop is loop:
            if self._timer_at <= at:
                return
            self._timer.cancel()
        delay = max(0.0, at - self.clock()) + 0.05
        self._timer, self._timer_loop, self._timer_at = loop.call_later(delay, self._on_timer), loop, at

    def _on_timer(self) -> None:
        self._timer = None
        self.sweep()
        self._arm()
