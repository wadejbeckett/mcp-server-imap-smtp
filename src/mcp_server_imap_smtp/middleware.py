# SPDX-License-Identifier: AGPL-3.0-or-later
"""ASGI middleware around the gateway: hourly database housekeeping, closing mail sessions on shutdown,
per-IP limits on the anonymous OAuth endpoints, and a filter that keeps query strings out of the access log."""
from __future__ import annotations

import logging
import time
from typing import Awaitable, Callable, Mapping

import anyio
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .ratelimit import RateLimiter, client_key

log = logging.getLogger("mcp_server_imap_smtp.maintenance")


class Maintenance:
    """Runs purge() (in a worker thread) when the process starts serving (the lifespan startup, or the
    first request when there is no lifespan) and then at most once per `every` seconds, piggybacking on
    incoming traffic. A failed purge is logged and never fails the request that triggered it."""

    def __init__(self, app: ASGIApp, purge: Callable[[], object], every: float = 3600,
                 clock: Callable[[], float] = time.monotonic):
        self.app, self.purge, self.every, self.clock = app, purge, every, clock
        self._due: float | None = None          # None: not yet run

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] in ("lifespan", "http") and (self._due is None or self.clock() >= self._due):
            self._due = self.clock() + self.every      # claimed before awaiting, so concurrent requests skip it
            try:
                counts = await anyio.to_thread.run_sync(self.purge)
                log.info("purged %s", counts)
            except Exception:
                log.exception("purge failed")
        await self.app(scope, receive, send)


class OnStop:
    """Runs stop() when the server announces the lifespan shutdown, before the app inside hears of it. The
    MCP SDK's shutdown cancels the calls still running and waits for them, and a call cannot end while its
    worker thread waits on a mail server; stop() (Sessions.close) ends that wait first. A failing stop() is
    logged by exception type only and the shutdown goes on."""

    def __init__(self, app: ASGIApp, stop: Callable[[], Awaitable[object]]):
        self.app, self.stop = app, stop

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "lifespan":
            await self.app(scope, receive, send)
            return

        async def receive_after_stop() -> Message:
            message = await receive()
            if message["type"] == "lifespan.shutdown":
                try:
                    await self.stop()
                except Exception as exc:
                    log.warning("closing mail sessions on shutdown failed (%s)", exc.__class__.__name__)
            return message
        await self.app(scope, receive_after_stop, send)


class RequestLimits:
    """Per-client limits on (method, path) pairs, keyed on the ASGI client host (which uvicorn rewrites
    from a trusted proxy's X-Forwarded-For; an IPv6 client counts as its /64, see client_key). Routes that
    share a RateLimiter share a budget. `overall` limiters count every client together on their route."""

    def __init__(self, app: ASGIApp, limits: Mapping[tuple[str, str], RateLimiter], retry_after: int,
                 overall: Mapping[tuple[str, str], RateLimiter] | None = None,
                 per_network: frozenset[tuple[str, str]] = frozenset()):
        self.app, self.limits, self.retry_after = app, dict(limits), retry_after
        self.overall = dict(overall or {})
        # Routes keyed on the client's /64 (client_key) rather than its exact address: those a person's own
        # device calls. Routes the AI platforms call from shared backends (/token, /register) keep exact
        # addresses, so one platform's backends spread over a /64 do not share a single budget.
        self.per_network = per_network

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        route = (scope.get("method", ""), scope.get("path", "")) if scope["type"] == "http" else None
        limiter = self.limits.get(route) if route else None
        if limiter is not None:
            client = scope.get("client")
            overall = self.overall.get(route)
            if overall is not None and overall.blocked("all"):
                log.warning("overall limit reached on %s %s", *route)
                allowed = False
            else:
                host = client[0] if client else "?"
                allowed = limiter.try_acquire([f"ip:{client_key(host) if route in self.per_network else host}"])
                if allowed and overall is not None:
                    overall.hit("all")
            if not allowed:
                body = b"Too many requests. Try again later."
                await send({"type": "http.response.start", "status": 429, "headers": [
                    (b"content-type", b"text/plain; charset=utf-8"), (b"content-length", str(len(body)).encode()),
                    (b"retry-after", str(self.retry_after).encode()), (b"cache-control", b"no-store")]})
                await send({"type": "http.response.body", "body": body})
                return
        await self.app(scope, receive, send)


async def _plain(send: Send, status: int, text: str) -> None:
    body = text.encode()
    await send({"type": "http.response.start", "status": status, "headers": [
        (b"content-type", b"text/plain; charset=utf-8"), (b"content-length", str(len(body)).encode()),
        (b"cache-control", b"no-store")]})
    await send({"type": "http.response.body", "body": body})


class BodyGuard:
    """Size and content-type limits on small anonymous JSON endpoints (dynamic client registration):
    a request whose body is larger than `max_bytes` (declared or streamed) gets 413, and one that is
    not application/json gets 415, so a web page cannot post to them from a visitor's browser with a
    CORS-simple text/plain request."""

    def __init__(self, app: ASGIApp, routes: Mapping[tuple[str, str], int]):
        self.app, self.routes = app, dict(routes)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        limit = self.routes.get((scope.get("method", ""), scope.get("path", ""))) if scope["type"] == "http" else None
        if limit is None:
            await self.app(scope, receive, send)
            return
        headers = {k.lower(): v for k, v in scope.get("headers", [])}
        ctype = headers.get(b"content-type", b"").split(b";", 1)[0].strip().lower()
        if ctype != b"application/json":
            await _plain(send, 415, "Content-Type must be application/json.")
            return
        try:
            declared = int(headers.get(b"content-length", b"0"))
        except ValueError:
            declared = limit + 1
        if declared > limit:
            await _plain(send, 413, "Request body too large.")
            return
        # Read the whole (small) body here, so a chunked body without Content-Length is held to the limit too.
        chunks, size = [], 0
        while True:
            message = await receive()
            if message["type"] != "http.request":
                return                                   # client went away
            size += len(message.get("body", b""))
            if size > limit:
                await _plain(send, 413, "Request body too large.")
                return
            chunks.append(message.get("body", b""))
            if not message.get("more_body", False):
                break
        sent = False

        async def replay() -> dict:
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
            return await receive()
        await self.app(scope, replay, send)


class StripQuery(logging.Filter):
    """uvicorn's access line is '%s - "%s %s HTTP/%s" %d' with the path (and query) as the third argument.
    The query can carry sign-in request ids, OAuth state and PKCE challenges, so only the path is kept."""

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) == 5 and isinstance(args[2], str) and "?" in args[2]:
            record.args = (*args[:2], args[2].split("?", 1)[0], *args[3:])
        return True


def install_access_log_filter() -> None:
    access = logging.getLogger("uvicorn.access")
    if not any(isinstance(f, StripQuery) for f in access.filters):
        access.addFilter(StripQuery())
