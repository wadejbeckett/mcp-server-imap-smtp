# SPDX-License-Identifier: AGPL-3.0-or-later
"""What the sign-in and manage pages share: limits, the form parser, the security headers and the
Content-Security-Policy, the Origin check, the rate-limit answers, and the mailbox password checks.

The tunables (form size, workers, time budget) and ImapClient are defined on auth/login.py, where tests
patch them, and read here through _surface() at call time; never import one by name
(tests/test_auth_package.py fails if a module here does)."""
from __future__ import annotations

import hmac
import html
import logging
import re
import ssl
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlsplit

import anyio
from starlette.requests import Request
from starlette.responses import Response

from ...config import Settings
from ...mail.hosts import HostNotAllowed, MailServer
from ...mail.imap import MailAuthError, MailBusy, MailError
from ...mail.resolve import ResolveUnavailable, Resolver
from ...mail.sessions import ServerBusy, Sessions
from ...ratelimit import RateLimiter, client_key, client_network
from ..provider import GatewayProvider

# The pages log under the name they had before the split (ticket 81), so journal filters see no change.
log = logging.getLogger("mcp_server_imap_smtp.auth.login")
DAY = 86400


def _surface():
    """auth/login.py, read at call time: importing it at the top would be circular, and a binding made at
    import time would not see a test's monkeypatch."""
    from .. import login
    return login


def wait_text(seconds: int) -> str:
    """A wait as people read it, never shorter than the real one: "15 minutes", "1 hour", "45 seconds";
    a wait that is not a whole number of hours is rounded up to minutes below two hours, to hours above."""
    def unit(n: int, name: str) -> str:
        return f"{n} {name}" + ("s" if n != 1 else "")
    if seconds < 60:
        return unit(max(seconds, 1), "second")
    if seconds % 3600 == 0:
        return unit(seconds // 3600, "hour")
    if seconds < 7200:
        return unit(-(-seconds // 60), "minute")
    return unit(-(-seconds // 3600), "hour")


@dataclass
class LoginLimits:
    """The sign-in limiters. `window` is the per-client (IPv6: per /64) and per-mailbox budget per
    login_window (keys ip:, addr:); `daily` the per-mailbox budget per 24 h (addr:); `host` all wrong
    passwords sent to one mail server per login_window (host:), so an attacker rotating addresses cannot
    spray a server through the gateway; `request` wrong passwords on one sign-in page (req:)."""
    window: RateLimiter
    daily: RateLimiter          # per mailbox and client network (addr:<a>|<net>)
    daily_total: RateLimiter    # per mailbox from everywhere, a higher ceiling (addr:<a>)
    host: RateLimiter
    request: RateLimiter

    @classmethod
    def from_settings(cls, settings: Settings, window: RateLimiter | None = None) -> "LoginLimits":
        return cls(window if window is not None else RateLimiter(settings.login_failures, settings.login_window),
                   RateLimiter(settings.login_daily_failures, DAY),
                   RateLimiter(settings.login_daily_failures * 5, DAY),
                   RateLimiter(settings.host_login_failures, settings.login_window),
                   RateLimiter(settings.request_login_failures, settings.pending_ttl))

class MailUnavailable(Exception):
    """The mail server could not be reached or answered badly. Not a verdict on the credentials."""


class MailboxBusy(MailUnavailable):
    """The server answered [INUSE] or [LIMIT]: possibly after accepting the password, so the mailbox's
    attempt is kept (a 503 must not reveal a right password for free)."""


# True: the mailbox accepted the login on that server. False: wrong credentials.
# Raises MailUnavailable when the mail server could not give an answer.
Verifier = Callable[[str, str, MailServer], bool]
MAX_EMAIL, MAX_PASSWORD = 254, 1024

MAX_SHOWN_NAME = 60   # characters of the name a registering app chose for itself, shown on the pages


def shown_name(name: str) -> str:
    """The app's self-chosen name, cut to MAX_SHOWN_NAME characters for display."""
    name = " ".join(name.split())
    return name if len(name) <= MAX_SHOWN_NAME else name[:MAX_SHOWN_NAME - 1].rstrip() + "…"


def return_target(redirect_uri: str) -> str:
    """Where the browser goes after sign-in, as the user should recognise it: the host for a web address,
    scheme and host for an app link (cursor://...)."""
    u = urlsplit(redirect_uri)
    if u.scheme in ("http", "https"):
        return u.hostname or redirect_uri
    return f"{u.scheme}://{u.netloc}" if u.netloc else f"{u.scheme}:"


def security_headers(redirect_uri: str | None = None) -> dict[str, str]:
    """form-action also governs the redirect after a submit, so the pending request's (already
    allowlisted) redirect origin must be named or Chrome and Safari block the final 302."""
    form_action = "'self'"
    if redirect_uri:
        u = urlsplit(redirect_uri)
        host = f"[{u.hostname}]" if u.hostname and ":" in u.hostname else u.hostname
        form_action += f" {u.scheme}://{host}" + (f":{u.port}" if u.port else "")
    # same-origin, not no-referrer: with no-referrer browsers send "Origin: null" on the form's own POST, and
    # the forms refuse posts from any other origin (cross_site). Nothing leaves for other sites either way.
    return {"X-Frame-Options": "DENY", "Cache-Control": "no-store", "Referrer-Policy": "same-origin",
            "Content-Security-Policy": ("default-src 'none'; style-src 'unsafe-inline'; "
                                        f"form-action {form_action}; frame-ancestors 'none'")}


ERROR = "Address or password incorrect."
DUPLICATE = "A mailbox is listed twice with different passwords; keep the right one."
UNAVAILABLE = "The mail server could not be reached. Please try again in a minute."
TOO_SLOW = ("Checking the mailboxes took too long, so nothing was connected. Please try again in a few minutes, "
            "or connect fewer mailboxes at once.")
NOT_HOSTED = "Mail for {domain} is not hosted by {operator}."
PASTE_AGAIN = "Nothing was connected. Passwords are never shown back, so paste the corrected list again."


@dataclass(frozen=True)
class Entry:
    """One mailbox on the form: line None is the main mailbox, otherwise its line in the list."""
    line: int | None
    address: str                       # as typed, lowercased; normalised separately
    password: str = field(repr=False)

    def label(self, address: str) -> str:
        return f"Line {self.line} ({address})" if self.line else address


_LINE_BREAK = re.compile(r"\r\n|\r|\n")


def parse_more(text: str, keep_spaces: bool = False) -> tuple[list[Entry], str | None]:
    """Mailboxes from the list: one per line, the address, whitespace (spaces or a tab, as a pasted
    spreadsheet gives), then the password (the rest of the line, trimmed). Blank lines are skipped.
    Returns (entries, None), or ([], a message naming the bad line). A message never quotes the line,
    since it may hold a password. keep_spaces (the operator command): the password is everything after the
    single space or tab that follows the address, spaces at either end included."""
    entries = []
    for n, raw in enumerate(_LINE_BREAK.split(text), 1):
        line = raw.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            return [], f"Line {n}: put the address, a space, then the password."
        address, password = parts[0].lower(), parts[1].strip()
        if keep_spaces:
            rest = raw.lstrip()[len(parts[0]):]
            password = rest[1:] if rest[:1] in (" ", "\t") else password
        if len(address) > MAX_EMAIL or len(password) > MAX_PASSWORD:
            return [], f"Line {n}: the address or password is too long."
        entries.append(Entry(n, address, password))
    return entries, None


def imap_verifier(address: str, password: str, server: MailServer) -> bool:
    try:
        with _surface().ImapClient.open(server, address, password):
            return True
    except MailAuthError:
        return False
    except MailBusy as exc:
        raise MailboxBusy("mailbox busy") from exc
    except (MailError, OSError, ssl.SSLError) as exc:   # outage: not the person's fault, must not count
        # The operator needs the reason (a certificate the system does not trust shows up here); never the
        # password, which no exception from connecting can hold before login, and never the address.
        reason = getattr(exc, "verify_message", None) or exc.__class__.__name__
        log.warning("sign-in check: could not reach %s: %s", server.host, reason)
        raise MailUnavailable("mail server unavailable") from exc


class FormTooLarge(Exception):
    pass


async def read_form(request: Request):
    """The posted form, refused (FormTooLarge) beyond MAX_FORM_BYTES whether or not the size was declared."""
    max_form_bytes = _surface().MAX_FORM_BYTES
    declared = request.headers.get("content-length")
    if declared is not None and (not declared.isdigit() or int(declared) > max_form_bytes):
        raise FormTooLarge
    size = 0

    async def receive():
        nonlocal size
        message = await request.receive()
        if message["type"] == "http.request":
            size += len(message.get("body", b""))
            if size > max_form_bytes:
                raise FormTooLarge
        return message
    return await Request(request.scope, receive).form(max_files=0, max_fields=100, max_part_size=max_form_bytes)


async def bounded(items: list, work: Callable, workers: int, stop: Callable[[], bool]) -> None:
    """await work(item) for each item in order, `workers` at a time, starting no new item once stop()."""
    it = iter(items)

    async def worker():
        for item in it:             # one shared iterator: each item goes to exactly one worker
            if stop():
                return
            await work(item)
    async with anyio.create_task_group() as tg:
        for _ in range(min(workers, len(items))):
            tg.start_soon(worker)


_UNAVAILABLE = object()      # a verdict or resolution: the mail server or DNS could not answer
_BUSY = object()             # a verdict: [INUSE] or [LIMIT], possibly after a right password


def moved(target: str):
    async def redirect(request: Request) -> Response:
        query = request.url.query
        return Response(status_code=308, headers={"Location": target + (f"?{query}" if query else ""),
                                                  **security_headers()})
    return redirect


def error_box(error: str | list[str]) -> str:
    """The error paragraph of the sign-in forms: every non-empty message, escaped, one per line."""
    errors = [e for e in ([error] if isinstance(error, str) else error) if e]
    return f'<p class="err" role="alert">{"<br>".join(html.escape(e) for e in errors)}</p>' if errors else ""


class Pages:
    """One set of pages as login_routes builds them: the services, settings and limits both pages use, and
    the answers and password checks they share."""

    def __init__(self, provider: GatewayProvider, resolver: Resolver, verifier: Verifier,
                 limiter: RateLimiter | LoginLimits, settings: Settings, sessions: Sessions | None = None):
        self.provider, self.resolver, self.verifier = provider, resolver, verifier
        self.settings, self.sessions = settings, sessions
        self.limits = limiter if isinstance(limiter, LoginLimits) else LoginLimits.from_settings(settings, limiter)
        self.limiter = self.limits.window
        help_links = [f'<a href="{html.escape(settings.support_url)}">{html.escape(settings.support_url)}</a>'
                      if settings.support_url else "",
                      f'<a href="mailto:{html.escape(settings.support_email)}">{html.escape(settings.support_email)}</a>'
                      if settings.support_email else ""]
        self.support = f"<p>Need help? {' or '.join(h for h in help_links if h)}</p>" if any(help_links) else ""
        self.cap = settings.max_mailboxes                 # 0: no limit
        self.limit_text = f" Up to {self.cap - 1} more." if self.cap > 1 else ""
        # Private, like the CIMD fetch's: every DNS lookup and password check for sign-in waits here, never in
        # the shared thread pool, so a sign-in with many mailboxes cannot hold up tool calls.
        self.dns_limiter = anyio.CapacityLimiter(_surface().DNS_WORKERS)
        self.verify_limiter = anyio.CapacityLimiter(_surface().VERIFY_THREADS)
        issuer = urlsplit(settings.issuer_url)
        self.own_origin = f"{issuer.scheme}://{issuer.netloc}"
        self.wait = wait_text(settings.login_window)     # the texts follow login_window, as Retry-After does

    def cross_site(self, request: Request) -> Response | None:
        """A form post from another site (or an opaque "null" origin) is refused before anything is read or
        counted, so a third-party page cannot make its visitors' browsers guess passwords. A request with no
        Origin header (not a browser form post) is let through."""
        origin = request.headers.get("origin")
        if origin is None or origin == self.own_origin:
            return None
        return Response("This form can only be sent from its own page.", 403, headers=security_headers())

    def expired(self) -> Response:
        return Response("This sign-in link has expired. Start again from your AI app.", 400, headers=security_headers())

    def too_large(self) -> Response:
        return Response("The form is too large.", 413, headers=security_headers())

    async def client_name(self, client_id: str) -> str:
        # The provider, not the store: a CIMD client (ChatGPT) lives only in the provider's metadata cache.
        info = await self.provider.get_client(client_id)
        return shown_name(info.client_name) if info and info.client_name and info.client_name.strip() else "An AI app"

    def ip(self, request: Request) -> str:
        # request.client.host only. Behind the reverse proxy uvicorn rewrites it from the trusted
        # proxy's X-Forwarded-For (proxy_headers / forwarded_allow_ips); never parse the header here.
        # An IPv6 client is keyed on its /64 (client_key).
        return client_key(request.client.host if request.client else None)

    def net(self, request: Request) -> str:
        return client_network(request.client.host if request.client else None)

    def too_many(self, redirect_uri: str | None, text: str | None = None, retry: int | None = None) -> Response:
        if text is None:
            text = f"Too many attempts. Try again in {self.wait}."
        headers = {**security_headers(redirect_uri), "Retry-After": str(retry or self.settings.login_window)}
        return Response(text, 429, headers=headers)

    def lock_wait(self, address: str, network: str) -> int:
        """How long the mailbox stays locked: the longest of its window, daily and all-networks locks."""
        key = f"addr:{address}"
        return max(self.limiter.retry_after(key), self.limits.daily.retry_after(f"{key}|{network}"),
                   self.limits.daily_total.retry_after(key)) or self.settings.login_window

    def locked_out(self, redirect_uri: str | None, entry: Entry, address: str, network: str) -> Response:
        retry = self.lock_wait(address, network)
        if entry.line is None:
            return self.too_many(redirect_uri, f"Too many attempts. Try again in {wait_text(retry)}.", retry=retry)
        return self.too_many(redirect_uri, f"Too many failed sign-ins for {address} (line {entry.line}). "
                                           f"Try again in {wait_text(retry)}, or leave it out.", retry=retry)

    def page_locked(self, key: str, text: str) -> Response:
        """A 429 for a key of the per-page limiter (window pending_ttl), naming the time left."""
        retry = self.limits.request.retry_after(key) or self.settings.pending_ttl
        return self.too_many(None, text.format(wait=wait_text(retry)), retry=retry)

    async def verify(self, request: Request, entries: list[Entry], normalised: list[str], page_key: str, ip_key: str,
                     again: Callable, redirect_uri: str | None) -> tuple[list[Entry], list[str], list[MailServer]] | Response:
        """Check every mailbox's password on its own server, under the sign-in limits (shared by the sign-in and
        manage pages). Returns (entries, addresses, servers) with repeated mailboxes dropped, or the Response
        to send instead (a refusal, an error page from again(), a 429)."""
        limits, limiter, settings, sessions = self.limits, self.limiter, self.settings, self.sessions
        verifier, resolver, provider, cap = self.verifier, self.resolver, self.provider, self.cap
        # A mailbox listed again with the same password (the main mailbox repeated in the list, a list pasted
        # twice) is dropped; with a different password nobody can tell which is meant, so the form is refused.
        # Keys come from the normalised address, so case, Unicode dot and fullwidth variants are one mailbox.
        first: dict[str, Entry] = {}
        for entry, address in zip(entries, normalised):
            if address not in first:
                first[address] = entry
            elif not hmac.compare_digest(first[address].password.encode(), entry.password.encode()):
                return await again(f"{entry.label(address)}: this mailbox is already listed with another password. "
                                   f"{DUPLICATE}")
        kept_entries = [first[a] for a in first]
        entries, normalised = kept_entries, list(first)
        if cap and len(entries) > cap:
            return await again(f"At most {cap} mailboxes can be connected at once; this form has {len(entries)}.")
        # A locked mailbox stops the whole form before any password is tried.
        network = self.net(request)
        for entry, address in zip(entries, normalised):
            key = f"addr:{address}"
            if limiter.blocked(key) or limits.daily.blocked(f"{key}|{network}") or limits.daily_total.blocked(key):
                limiter.refund(ip_key)      # refused for the mailbox's lock, not for this client's guesses
                return self.locked_out(redirect_uri, entry, address, network)
        surface = _surface()
        deadline = anyio.current_time() + surface.VERIFY_BUDGET_BASE + surface.VERIFY_BUDGET_PER_MAILBOX * len(entries)

        def out_of_time() -> bool:
            return anyio.current_time() >= deadline

        # Every address is mapped to its server before any password is tried, so a password is only ever
        # sent to a server configured for that address's domain. One lookup per domain; nothing new starts
        # after a domain that is not hosted here, a DNS failure or the time budget.
        first_of_domain: dict[str, str] = {}
        for address in normalised:
            first_of_domain.setdefault(address.rpartition("@")[2], address)
        by_domain: dict[str, object] = {}      # domain -> MailServer, None (not hosted) or _UNAVAILABLE

        def resolve(address: str) -> object:
            try:
                return resolver.resolve(address)[1]
            except HostNotAllowed:
                return None
            except ResolveUnavailable:
                return _UNAVAILABLE

        async def resolve_one(item: tuple[str, str]) -> None:
            # Results are recorded here, on the event loop, never by the worker thread.
            by_domain[item[0]] = await anyio.to_thread.run_sync(resolve, item[1], limiter=self.dns_limiter)
        await bounded(list(first_of_domain.items()), resolve_one, surface.DNS_PER_SIGN_IN,
                      lambda: out_of_time() or any(v is None or v is _UNAVAILABLE for v in by_domain.values()))
        for entry, address in zip(entries, normalised):
            domain = address.rpartition("@")[2]
            if domain in by_domain and by_domain[domain] is None:    # no password was tried: only the client's attempt counts
                text = NOT_HOSTED.format(domain=domain, operator=settings.operator_name)
                return await again(text if entry.line is None else f"Line {entry.line}: {text}")
        if any(v is _UNAVAILABLE for v in by_domain.values()):
            return await again(UNAVAILABLE, 503)     # DNS down: the addresses are not to blame, the client's attempt stands
        if len(by_domain) < len(first_of_domain):
            return await again(TOO_SLOW, 503)
        servers: list[MailServer] = [by_domain[a.rpartition("@")[2]] for a in normalised]   # type: ignore[misc]
        # While a server's cap is reached, only mailboxes that have signed in through the gateway before
        # get through, so an attacker spraying a server cannot also stop its known users reconnecting.
        blocked_hosts = {s.host for s in set(servers) if limits.host.blocked(f"host:{s.host}")}
        if blocked_hosts and any(s.host in blocked_hosts and not provider.store.known_mailbox(a, s.host)
                                 for a, s in zip(normalised, servers)):
            limiter.refund(ip_key)
            return self.too_many(redirect_uri, f"Too many failed sign-ins to this mail server. Try again in {self.wait}.")

        # Passwords: the main mailbox alone first, so only someone who knows one password gets checks run in
        # parallel; then the rest, VERIFY_WORKERS at a time. A mailbox's attempt is reserved only when its own
        # password is about to be tried, and nothing new starts after a wrong password, an outage, a locked
        # mailbox or the time budget: a wrong password does not spend the budgets of mailboxes not yet tried,
        # and at most VERIFY_WORKERS passwords are in flight when one turns out wrong.
        verdicts: dict[int, object] = {}       # index -> True, False, _BUSY or _UNAVAILABLE
        reserved: list[str] = []
        state: dict[str, object] = {"locked": None, "late": False}

        def check(i: int) -> object:
            try:
                return bool(verifier(normalised[i], entries[i].password, servers[i]))
            except MailboxBusy:
                return _BUSY
            except MailUnavailable:
                return _UNAVAILABLE

        def stop() -> bool:
            if state["locked"] is not None or any(v is not True for v in verdicts.values()):
                return True
            if out_of_time():
                state["late"] = True
                return True
            return False

        async def verify_one(i: int) -> None:
            key = f"addr:{normalised[i]}"
            if not limiter.try_acquire([key]):
                state["locked"] = i
                return
            reserved.append(key)
            if sessions is None:
                verdicts[i] = await anyio.to_thread.run_sync(check, i, limiter=self.verify_limiter)
                return
            # A password check is an IMAP session like any tool call's: it takes its turn under the mail
            # server's session caps (this sign-in is one more party in the fair queue). If none comes free
            # within the sign-in's time budget, no verdict: nothing is connected and nobody is penalised.
            try:
                async with sessions.lease(servers[i], f"signin:{page_key}", normalised[i], deadline=deadline):
                    verdicts[i] = await anyio.to_thread.run_sync(check, i, limiter=self.verify_limiter)
            except ServerBusy:
                state["late"] = True

        await bounded([0], verify_one, 1, stop)
        await bounded(list(range(1, len(entries))), verify_one, surface.VERIFY_WORKERS, stop)

        wrong = sorted(i for i, v in verdicts.items() if v is False)
        for n, i in enumerate(wrong):
            # Each wrong password that reached a mail server counts once: against its mailbox (the window key
            # keeps its reservation; the day), this page, the mail server and, after the first, the client.
            key, host_key = f"addr:{normalised[i]}", f"host:{servers[i].host}"
            limits.daily.hit(f"{key}|{network}")
            limits.daily_total.hit(key)
            limits.request.hit(f"req:{page_key}")
            limits.host.hit(host_key)
            if n:
                limiter.hit(ip_key)
            if limits.host.blocked(host_key):
                log.warning("sign-in limit reached for mail server %s: %d wrong passwords within %d s; "
                            "new sign-ins to it are refused until the window passes",
                            servers[i].host, limits.host.count(host_key), settings.login_window)
        complete = len(verdicts) == len(entries) and all(v is True for v in verdicts.values())
        if not complete:
            # A wrong password keeps its mailbox's attempt, and so does a busy answer (it may have come after
            # a right password); mailboxes whose password was right or got no answer get theirs back.
            kept = {f"addr:{normalised[i]}" for i, v in verdicts.items() if v is False or v is _BUSY}
            for k in reserved:
                if k not in kept:
                    limiter.refund(k)
        if wrong:
            return await again([ERROR if entries[i].line is None else
                                f"{entries[i].label(normalised[i])}: address or password incorrect." for i in wrong])
        if state["locked"] is not None:
            limiter.refund(ip_key)      # refused for the mailbox's lock, not for this client's guesses
            i = state["locked"]
            return self.locked_out(redirect_uri, entries[i], normalised[i], network)
        if not complete:                # an outage or the time budget: not the person's fault
            limiter.refund(ip_key)
            outage = any(v is _UNAVAILABLE or v is _BUSY for v in verdicts.values())
            return await again(TOO_SLOW if state["late"] and not outage else UNAVAILABLE, 503)
        limiter.refund(ip_key)                # a legitimate sign-in does not spend the IP's budget
        for address in normalised:
            limiter.reset(f"addr:{address}")
        return entries, normalised, servers
