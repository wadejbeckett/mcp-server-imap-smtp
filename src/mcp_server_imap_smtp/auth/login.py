# SPDX-License-Identifier: AGPL-3.0-or-later
"""Self-hosted sign-in page: one mailbox address and password, and/or any number of mailboxes pasted
one per line, each checked on its own server before anything is connected."""
from __future__ import annotations

import hmac
import html
import logging
import re
import ssl
import time
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlsplit

import anyio
from starlette.requests import Request
from starlette.responses import HTMLResponse, Response
from starlette.routing import Route

from ..config import Settings
from ..mail.hosts import HostNotAllowed, MailServer
from ..mail.imap import ImapClient, MailAuthError, MailBusy, MailError
from ..mail.resolve import ResolveUnavailable, Resolver, normalise_address
from ..mail.sessions import ServerBusy, Sessions
from ..ratelimit import RateLimiter, client_key, client_network
from .provider import GatewayProvider

log = logging.getLogger(__name__)
DAY = 86400


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
MAX_FORM_BYTES = 2 * 1024 * 1024   # the whole sign-in form, the same as nginx's client_max_body_size
DNS_WORKERS = 8           # sign-in DNS resolution threads at once, so slow DNS cannot take every worker thread
DNS_PER_SIGN_IN = 4       # domains one sign-in resolves at once
VERIFY_WORKERS = 8        # passwords one sign-in checks at once (after its main mailbox, which is checked alone)
VERIFY_THREADS = 32       # password-check threads for all sign-ins together, outside the shared thread pool
VERIFY_BUDGET_BASE = 60.0           # seconds a sign-in may spend on DNS and password checks ...
VERIFY_BUDGET_PER_MAILBOX = 2.0     # ... plus this much for each mailbox on the form


def security_headers(redirect_uri: str | None = None) -> dict[str, str]:
    """form-action also governs the redirect after a submit, so the pending request's (already
    allowlisted) redirect origin must be named or Chrome and Safari block the final 302."""
    form_action = "'self'"
    if redirect_uri:
        u = urlsplit(redirect_uri)
        host = f"[{u.hostname}]" if u.hostname and ":" in u.hostname else u.hostname
        form_action += f" {u.scheme}://{host}" + (f":{u.port}" if u.port else "")
    return {"X-Frame-Options": "DENY", "Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": ("default-src 'none'; style-src 'unsafe-inline'; "
                                        f"form-action {form_action}; frame-ancestors 'none'")}


ERROR = "Address or password incorrect."
DUPLICATE = "A mailbox is listed twice with different passwords; keep the right one."
UNAVAILABLE = "The mail server could not be reached. Please try again in a minute."
TOO_SLOW = ("Checking the mailboxes took too long, so nothing was connected. Please try again in a few minutes, "
            "or connect fewer mailboxes at once.")
NOT_HOSTED = "Mail for {domain} is not hosted by {operator}."
PASTE_AGAIN = "Nothing was connected. Passwords are never shown back, so paste the corrected list again."

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connect your mailbox · {product}</title><style>
:root{{--bg:#fff;--fg:#111;--mut:#555;--line:#ccc;--acc:#0b5}}@media (prefers-color-scheme:dark){{:root{{--bg:#111;--fg:#eee;--mut:#aaa;--line:#444}}}}
body{{font:16px system-ui,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:16px}}main{{max-width:420px;margin:8vh auto}}
label{{display:block;margin:12px 0 4px}}input,textarea{{width:100%;box-sizing:border-box;padding:10px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg)}}
textarea{{font:14px ui-monospace,monospace;min-height:10em;resize:vertical}}
button{{margin-top:20px;width:100%;padding:12px;border:0;border-radius:6px;background:var(--acc);color:#fff;font-weight:600}}
.err{{color:#c22;margin-top:12px}}details{{margin-top:16px;color:var(--mut)}}p{{color:var(--mut)}}</style></head>
<body><main><h1>Connect your mailbox</h1><p>{client} is asking to use your email hosted by {operator}. Sign in with the same address and password you use in your mail app.</p>
<form method="post" action="login"><input type="hidden" name="req" value="{req}">
<label for="e">Email address</label><input id="e" name="email" type="email" autocomplete="username" value="{email}">
<label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password">
<h2>Several mailboxes</h2><p>To connect several mailboxes, such as your staff's, paste the whole list here, one mailbox per line: the address, a space, then that mailbox's password. You can then leave the two fields above empty.{limit} Every mailbox you want must be in this one sign-in: signing in again replaces the earlier list in your AI app. Every password is checked before anything is connected, which can take a minute for many mailboxes.</p>
<label for="more">Mailboxes, one per line</label><textarea id="more" name="more" rows="8" wrap="off" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" placeholder="sales@example.com their-password"></textarea>
{error}<button type="submit">Connect</button></form>{support}</main></body></html>"""

DONE_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="2;url={url}"><title>Connected · {product}</title><style>
:root{{--bg:#fff;--fg:#111;--mut:#555;--acc:#0b5}}@media (prefers-color-scheme:dark){{:root{{--bg:#111;--fg:#eee;--mut:#aaa}}}}
body{{font:16px system-ui,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:16px}}main{{max-width:420px;margin:8vh auto}}
p{{color:var(--mut)}}a.b{{display:block;margin-top:20px;padding:12px;border-radius:6px;background:var(--acc);color:#fff;font-weight:600;text-align:center;text-decoration:none}}</style></head>
<body><main><h1>{count}</h1><p>{detail}</p><p>To add or remove mailboxes, or change a password, later: <a href="{manage}">{manage}</a></p>
<a class="b" href="{url}">Continue to {client}</a><p>If nothing happens, click Continue within 5 minutes.</p></main></body></html>"""


MANAGE_TTL = 900     # seconds a manage-page session lasts after the mailbox password was checked

_STYLE = """<style>
:root{{--bg:#fff;--fg:#111;--mut:#555;--line:#ccc;--acc:#0b5}}@media (prefers-color-scheme:dark){{:root{{--bg:#111;--fg:#eee;--mut:#aaa;--line:#444}}}}
body{{font:16px system-ui,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:16px}}main{{max-width:640px;margin:6vh auto}}
label{{display:block;margin:12px 0 4px}}input,textarea{{width:100%;box-sizing:border-box;padding:10px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg)}}
textarea{{font:14px ui-monospace,monospace;min-height:8em;resize:vertical}}
button{{margin-top:12px;padding:10px 16px;border:0;border-radius:6px;background:var(--acc);color:#fff;font-weight:600}}
button.minor{{margin:0;padding:4px 10px;background:none;color:var(--fg);border:1px solid var(--line);font-weight:400}}
table{{width:100%;border-collapse:collapse;margin-top:8px}}td{{padding:6px 4px;border-bottom:1px solid var(--line);vertical-align:middle;word-break:break-all}}
td form{{margin:0}}.err{{color:#c22}}.ok{{color:#0a4}}p{{color:var(--mut)}}section{{margin-top:32px}}</style>"""

MANAGE_SIGNIN = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Manage mailboxes · {product}</title>""" + _STYLE + """</head>
<body><main><h1>Manage your mailboxes</h1><p>Add or remove mailboxes in your {product} connection, or enter a mailbox's new password, without reconnecting your AI app. Sign in with the main mailbox of your connection: the first mailbox you connected.</p>
<form method="post" action="manage"><input type="hidden" name="action" value="signin">
<label for="e">Email address</label><input id="e" name="email" type="email" autocomplete="username" required value="{email}">
<label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password" required>
{error}<button type="submit">Sign in</button></form>{support}</main></body></html>"""

MANAGE_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Manage mailboxes · {product}</title>""" + _STYLE + """</head>
<body><main><h1>Manage your mailboxes</h1><p>Signed in as {subject}. Changes apply straight away: your AI app keeps its connection and uses the new list on its next request.</p>
{notice}{connections}
<form method="post" action="manage"><input type="hidden" name="s" value="{session}"><input type="hidden" name="action" value="signout">
<button class="minor" type="submit">Sign out</button></form>{support}</main></body></html>"""

CONNECTION = """<section><h2>{client}</h2><p>Connected on {created}. {count}.</p>
<table>{rows}</table>
<form method="post" action="manage"><input type="hidden" name="s" value="{session}"><input type="hidden" name="action" value="add"><input type="hidden" name="grant" value="{grant}">
<label for="more-{grant}">Add mailboxes, or enter a new password for one already here: one per line, the address, a space, then the password</label>
<textarea id="more-{grant}" name="more" rows="6" wrap="off" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" placeholder="sales@example.com their-password"></textarea>
<button type="submit">Check and save</button></form>
<form method="post" action="manage"><input type="hidden" name="s" value="{session}"><input type="hidden" name="action" value="disconnect"><input type="hidden" name="grant" value="{grant}">
<button class="minor" type="submit">Disconnect {client} from all these mailboxes</button></form></section>"""

ROW = """<tr><td>{address}</td><td>{status}</td><td>{remove}</td></tr>"""

REMOVE = """<form method="post" action="manage"><input type="hidden" name="s" value="{session}"><input type="hidden" name="action" value="remove"><input type="hidden" name="grant" value="{grant}"><input type="hidden" name="address" value="{address}"><button class="minor" type="submit">Remove</button></form>"""

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
        with ImapClient.open(server, address, password):
            return True
    except MailAuthError:
        return False
    except MailBusy as exc:
        raise MailboxBusy("mailbox busy") from exc
    except (MailError, OSError, ssl.SSLError) as exc:   # outage: not the person's fault, must not count
        raise MailUnavailable("mail server unavailable") from exc


class FormTooLarge(Exception):
    pass


async def read_form(request: Request):
    """The posted form, refused (FormTooLarge) beyond MAX_FORM_BYTES whether or not the size was declared."""
    declared = request.headers.get("content-length")
    if declared is not None and (not declared.isdigit() or int(declared) > MAX_FORM_BYTES):
        raise FormTooLarge
    size = 0

    async def receive():
        nonlocal size
        message = await request.receive()
        if message["type"] == "http.request":
            size += len(message.get("body", b""))
            if size > MAX_FORM_BYTES:
                raise FormTooLarge
        return message
    return await Request(request.scope, receive).form(max_files=0, max_fields=100, max_part_size=MAX_FORM_BYTES)


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


def login_routes(provider: GatewayProvider, resolver: Resolver, verifier: Verifier,
                 limiter: RateLimiter | LoginLimits, settings: Settings, sessions: Sessions | None = None) -> list[Route]:
    """sessions: the mail servers' session caps (mail/sessions.py), shared with the tools; password checks
    then wait their turn for a session like tool calls. None (tests): checks are limited only below."""
    limits = limiter if isinstance(limiter, LoginLimits) else LoginLimits.from_settings(settings, limiter)
    limiter = limits.window
    help_links = [f'<a href="{html.escape(settings.support_url)}">{html.escape(settings.support_url)}</a>'
                  if settings.support_url else "",
                  f'<a href="mailto:{html.escape(settings.support_email)}">{html.escape(settings.support_email)}</a>'
                  if settings.support_email else ""]
    support = f"<p>Need help? {' or '.join(h for h in help_links if h)}</p>" if any(help_links) else ""
    cap = settings.max_mailboxes                 # 0: no limit
    limit_text = f" Up to {cap - 1} more." if cap > 1 else ""
    # Private, like the CIMD fetch's: every DNS lookup and password check for sign-in waits here, never in
    # the shared thread pool, so a sign-in with many mailboxes cannot hold up tool calls.
    dns_limiter = anyio.CapacityLimiter(DNS_WORKERS)
    verify_limiter = anyio.CapacityLimiter(VERIFY_THREADS)

    def page(req, client, redirect_uri, email="", more_open=False, error: str | list[str] = "", status=200):
        errors = [e for e in ([error] if isinstance(error, str) else error) if e]
        body = PAGE.format(req=html.escape(req), client=html.escape(client), email=html.escape(email),
                           product=html.escape(settings.product_name), operator=html.escape(settings.operator_name),
                           support=support, open=" open" if more_open else "", limit=limit_text,
                           error=(f'<p class="err" role="alert">{"<br>".join(html.escape(e) for e in errors)}</p>'
                                  if errors else ""))
        return HTMLResponse(body, status_code=status, headers=security_headers(redirect_uri))

    def done(redirect: str, redirect_uri: str, client: str, subject: str, count: int) -> Response:
        """The sign-in worked: say how many mailboxes are connected and where to manage them, then hand the
        code to the app. The page moves on by itself after a moment and also has a link."""
        mailboxes = f"{count} mailbox" + ("" if count == 1 else "es")
        body = DONE_PAGE.format(url=html.escape(redirect), product=html.escape(settings.product_name),
                                count=f"{mailboxes} connected", client=html.escape(client),
                                manage=html.escape(f"{settings.service_url}/manage"),
                                detail=html.escape(f"{client} can now use {mailboxes}"
                                                   + (f", starting with {subject}." if count > 1 else f": {subject}.")))
        return HTMLResponse(body, headers=security_headers(redirect_uri))

    def expired() -> Response:
        return Response("This sign-in link has expired. Start again from your AI app.", 400, headers=security_headers())

    async def client_name(client_id: str) -> str:
        # The provider, not the store: a CIMD client (ChatGPT) lives only in the provider's metadata cache.
        info = await provider.get_client(client_id)
        return (info.client_name if info and info.client_name else "An AI app")

    def ip(request: Request) -> str:
        # request.client.host only. Behind the reverse proxy uvicorn rewrites it from the trusted
        # proxy's X-Forwarded-For (proxy_headers / forwarded_allow_ips); never parse the header here.
        # An IPv6 client is keyed on its /64 (client_key).
        return client_key(request.client.host if request.client else None)

    def net(request: Request) -> str:
        return client_network(request.client.host if request.client else None)

    def too_many(redirect_uri: str, text: str = "Too many attempts. Try again in 15 minutes.") -> Response:
        headers = {**security_headers(redirect_uri), "Retry-After": str(settings.login_window)}
        return Response(text, 429, headers=headers)

    def locked_out(redirect_uri: str, entry: Entry, address: str) -> Response:
        if entry.line is None:
            return too_many(redirect_uri)
        return too_many(redirect_uri, f"Too many failed sign-ins for {address} (line {entry.line}). "
                                      "Try again in 15 minutes, or leave it out.")

    async def verify(request: Request, entries: list[Entry], normalised: list[str], page_key: str, ip_key: str,
                     again: Callable, redirect_uri: str | None) -> tuple[list[Entry], list[str], list[MailServer]] | Response:
        """Check every mailbox's password on its own server, under the sign-in limits (shared by the sign-in and
        manage pages). Returns (entries, addresses, servers) with repeated mailboxes dropped, or the Response
        to send instead (a refusal, an error page from again(), a 429)."""
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
        network = net(request)
        for entry, address in zip(entries, normalised):
            key = f"addr:{address}"
            if limiter.blocked(key) or limits.daily.blocked(f"{key}|{network}") or limits.daily_total.blocked(key):
                limiter.refund(ip_key)      # refused for the mailbox's lock, not for this client's guesses
                return locked_out(redirect_uri, entry, address)
        deadline = anyio.current_time() + VERIFY_BUDGET_BASE + VERIFY_BUDGET_PER_MAILBOX * len(entries)

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
            by_domain[item[0]] = await anyio.to_thread.run_sync(resolve, item[1], limiter=dns_limiter)
        await bounded(list(first_of_domain.items()), resolve_one, DNS_PER_SIGN_IN,
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
            return too_many(redirect_uri, "Too many failed sign-ins to this mail server. Try again in 15 minutes.")

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
                verdicts[i] = await anyio.to_thread.run_sync(check, i, limiter=verify_limiter)
                return
            # A password check is an IMAP session like any tool call's: it takes its turn under the mail
            # server's session caps (this sign-in is one more party in the fair queue). If none comes free
            # within the sign-in's time budget, no verdict: nothing is connected and nobody is penalised.
            try:
                async with sessions.lease(servers[i], f"signin:{page_key}", normalised[i], deadline=deadline):
                    verdicts[i] = await anyio.to_thread.run_sync(check, i, limiter=verify_limiter)
            except ServerBusy:
                state["late"] = True

        await bounded([0], verify_one, 1, stop)
        await bounded(list(range(1, len(entries))), verify_one, VERIFY_WORKERS, stop)

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
            return locked_out(redirect_uri, entries[i], normalised[i])
        if not complete:                # an outage or the time budget: not the person's fault
            limiter.refund(ip_key)
            outage = any(v is _UNAVAILABLE or v is _BUSY for v in verdicts.values())
            return await again(TOO_SLOW if state["late"] and not outage else UNAVAILABLE, 503)
        limiter.refund(ip_key)                # a legitimate sign-in does not spend the IP's budget
        for address in normalised:
            limiter.reset(f"addr:{address}")
        return entries, normalised, servers

    async def get(request: Request) -> Response:
        req = request.query_params.get("req", "")
        found = provider.store.peek_pending(req)
        if not found:
            return expired()
        return page(req, await client_name(found[0]), str(found[1].redirect_uri))

    async def post(request: Request) -> Response:
        try:
            form = await read_form(request)
        except FormTooLarge:
            return Response("The form is too large.", 413, headers=security_headers())
        req = str(form.get("req", ""))
        found = provider.store.peek_pending(req)
        if not found:
            return expired()
        client_id, params = found
        redirect_uri = str(params.redirect_uri)
        # Only the named fields are read: the main pair and the "more" list.
        email, more = str(form.get("email", "")).strip().lower(), str(form.get("more", ""))
        main = Entry(None, email, str(form.get("password", "")))
        extra, problem = parse_more(more)
        if main.address or main.password or not more.strip():
            # The two fields may be left empty when the list has mailboxes; otherwise both are needed.
            if not main.address or not main.password or len(main.address) > MAX_EMAIL or len(main.password) > MAX_PASSWORD:
                problem = ERROR
            entries = [main, *extra]
        else:
            entries = extra
        normalised: list[str] = []
        for entry in entries if not problem else ():
            try:
                normalised.append(normalise_address(entry.address)[0])
            except HostNotAllowed:
                problem = ERROR if entry.line is None else (
                    f"Line {entry.line}: the first part is not an email address. "
                    "Put the address, a space, then the password.")
                break
        if limits.request.blocked(f"req:{req}"):
            return too_many(redirect_uri, "Too many wrong passwords on this page. Start again from your AI app.")
        # The client's attempt is reserved before the slow DNS and mail-server checks, so parallel requests
        # cannot all pass the limit. Malformed input and wrong credentials keep it; a mail-server outage or
        # a success gives it back.
        ip_key = f"ip:{ip(request)}"
        if not limiter.try_acquire([ip_key]):
            return too_many(redirect_uri)

        async def again(error: str | list[str], status: int = 200) -> Response:
            # The list is never sent back (it holds passwords); the main address is.
            errors = [error] if isinstance(error, str) else list(error)
            if more.strip():
                errors.append(PASTE_AGAIN)
            return page(req, await client_name(client_id), redirect_uri, email, bool(more.strip()), errors, status)

        if problem:
            return await again(problem)
        checked = await verify(request, entries, normalised, req, ip_key, again, redirect_uri)
        if isinstance(checked, Response):
            return checked
        entries, normalised, servers = checked
        try:
            redirect = provider.complete_login(
                req, [(address, entry.password, server) for address, entry, server in zip(normalised, entries, servers)])
        except LookupError:
            return expired()
        return done(redirect, redirect_uri, await client_name(client_id), normalised[0], len(entries))

    # The manage page: the main mailbox of a connection, checked over IMAP under the sign-in limits, opens a
    # short session in which that connection's mailboxes can be listed, added, given a new password or removed,
    # and the connection ended. New passwords are sealed to the connection's public key, so the page never
    # needs (or could use) the key in the AI app's tokens, and nothing it does can read mail.
    def manage_signin_page(email: str = "", error: str | list[str] = "", status: int = 200) -> Response:
        errors = [e for e in ([error] if isinstance(error, str) else error) if e]
        body = MANAGE_SIGNIN.format(product=html.escape(settings.product_name), email=html.escape(email),
                                    support=support,
                                    error=(f'<p class="err" role="alert">{"<br>".join(html.escape(e) for e in errors)}</p>'
                                           if errors else ""))
        return HTMLResponse(body, status_code=status, headers=security_headers())

    async def manage_page(session: str, subject: str, notice: str = "", error: str | list[str] = "",
                          status: int = 200) -> Response:
        errors = [e for e in ([error] if isinstance(error, str) else error) if e]
        parts = []
        for g in provider.store.live_grants(subject):
            rows = []
            for m in g["mailboxes"]:
                if m["address"] == subject:
                    state, remove = "Main mailbox", ""
                else:
                    remove = REMOVE.format(session=html.escape(session), grant=html.escape(g["id"]),
                                           address=html.escape(m["address"]))
                    state = "Working"
                if m["failed_at"]:
                    when = time.strftime("%d %b %Y %H:%M UTC", time.gmtime(m["failed_at"]))
                    state = f'<span class="err">Password rejected on {html.escape(when)}: enter the new one below</span>'
                rows.append(ROW.format(address=html.escape(m["address"]), status=state, remove=remove))
            n = len(g["mailboxes"])
            parts.append(CONNECTION.format(
                client=html.escape(await client_name(g["client_id"])), grant=html.escape(g["id"]),
                created=html.escape(time.strftime("%d %b %Y", time.gmtime(g["created"]))),
                count=f"{n} mailbox" + ("" if n == 1 else "es"), rows="".join(rows), session=html.escape(session)))
        if not parts:
            parts.append("<p>No AI app is connected with this mailbox as its main mailbox any more.</p>")
        messages = "".join(f'<p class="err" role="alert">{html.escape(e)}</p>' for e in errors)
        if notice:
            messages += f'<p class="ok" role="status">{html.escape(notice)}</p>'
        body = MANAGE_PAGE.format(product=html.escape(settings.product_name), subject=html.escape(subject),
                                  session=html.escape(session), notice=messages, connections="".join(parts),
                                  support=support)
        return HTMLResponse(body, status_code=status, headers=security_headers())

    async def manage_get(request: Request) -> Response:
        return manage_signin_page()

    async def manage_post(request: Request) -> Response:
        try:
            form = await read_form(request)
        except FormTooLarge:
            return Response("The form is too large.", 413, headers=security_headers())
        action = str(form.get("action", ""))
        ip_key = f"ip:{ip(request)}"
        if action == "signin":
            email = str(form.get("email", "")).strip().lower()
            entry = Entry(None, email, str(form.get("password", "")))
            if limits.request.blocked(f"req:manage:{ip(request)}"):
                return too_many(None)
            if not limiter.try_acquire([ip_key]):
                return too_many(None)
            try:
                address = normalise_address(entry.address)[0]
            except HostNotAllowed:
                return manage_signin_page(email, ERROR)
            if not entry.password or len(entry.address) > MAX_EMAIL or len(entry.password) > MAX_PASSWORD:
                return manage_signin_page(email, ERROR)

            async def signin_again(error, status: int = 200) -> Response:
                return manage_signin_page(email, error, status)
            checked = await verify(request, [entry], [address], f"manage:{ip(request)}", ip_key, signin_again, None)
            if isinstance(checked, Response):
                return checked
            if not provider.store.live_grants(address):
                return manage_signin_page(email, f"No AI app is connected with {address} as its main mailbox. The main "
                                                 "mailbox is the first one you entered when you connected. To make a new "
                                                 "connection, add the connector in your AI app.")
            session = provider.store.open_manage(address, MANAGE_TTL)
            return await manage_page(session, address)

        session = str(form.get("s", ""))
        subject = provider.store.manage_subject(session)
        if not subject:
            return manage_signin_page(error="Your session has ended. Please sign in again.")
        if action == "signout":
            provider.store.close_manage(session)
            return manage_signin_page()
        grant = next((g for g in provider.store.live_grants(subject) if g["id"] == str(form.get("grant", ""))), None)
        if grant is None:
            return await manage_page(session, subject, error="That connection is no longer active.")
        addresses = [m["address"] for m in grant["mailboxes"]]
        if action == "remove":
            target = str(form.get("address", "")).strip().lower()
            if target == subject:
                return await manage_page(session, subject, error="The main mailbox cannot be removed. To stop using "
                                                                 "it, disconnect the connection.")
            if provider.store.remove_mailbox(grant["id"], target):
                log.info("manage: mailbox removed from grant %s", grant["id"])
                return await manage_page(session, subject, notice=f"{target} was removed.")
            return await manage_page(session, subject, error=f"{target} is not in this connection.")
        if action == "disconnect":
            provider.store.revoke_grant(grant["id"])
            log.info("manage: grant %s disconnected", grant["id"])
            return await manage_page(session, subject, notice="The connection was ended. Remove the connector in "
                                                               "your AI app as well, or connect it again to start over.")
        if action != "add":
            return await manage_page(session, subject)
        if not grant["can_add"]:
            return await manage_page(session, subject, error="Use this connection once from your AI app (ask it "
                                                             "anything about your mail), then add mailboxes here.")
        more = str(form.get("more", ""))
        entries, problem = parse_more(more)
        if not entries and not problem:
            problem = "Put one mailbox per line: the address, a space, then the password."
        normalised: list[str] = []
        for entry in entries if not problem else ():
            try:
                normalised.append(normalise_address(entry.address)[0])
            except HostNotAllowed:
                problem = (f"Line {entry.line}: the first part is not an email address. "
                           "Put the address, a space, then the password.")
                break
        new = len(set(normalised) - set(addresses))
        if not problem and cap and len(addresses) + new > cap:
            problem = f"At most {cap} mailboxes can be in one connection; this would make {len(addresses) + new}."

        async def again(error, status: int = 200) -> Response:
            errors = [error] if isinstance(error, str) else list(error)
            if more.strip():
                errors.append(PASTE_AGAIN)
            return await manage_page(session, subject, error=errors, status=status)
        if problem:
            return await again(problem)
        page_key = f"manage-subject:{subject}"      # by subject, so signing in again does not reset it
        if limits.request.blocked(f"req:{page_key}"):
            return too_many(None, "Too many wrong passwords. Sign in again in 15 minutes.")
        if not limiter.try_acquire([ip_key]):
            return too_many(None)
        checked = await verify(request, entries, normalised, page_key, ip_key, again, None)
        if isinstance(checked, Response):
            return checked
        entries, normalised, servers = checked
        for entry, address, server in zip(entries, normalised, servers):
            if not provider.store.put_mailbox(grant["id"], address, entry.password, server):
                return await manage_page(session, subject, error="This connection cannot take new mailboxes yet. Use "
                                                                 "it once from your AI app, then try again.")
        updated = [a for a in normalised if a in addresses]
        added = len(normalised) - len(updated)
        log.info("manage: grant %s: %d mailboxes added, %d passwords updated", grant["id"], added, len(updated))
        said = []
        if added:
            said.append(f"{added} mailbox" + (" was" if added == 1 else "es were") + " added")
        if updated:
            said.append(f"{len(updated)} password" + (" was" if len(updated) == 1 else "s were") + " updated")
        return await manage_page(session, subject, notice=" and ".join(said).capitalize() + ".")

    base = settings.service_path
    routes = [Route(f"{base}/login", get, methods=["GET"]), Route(f"{base}/login", post, methods=["POST"]),
              Route(f"{base}/manage", manage_get, methods=["GET"]), Route(f"{base}/manage", manage_post, methods=["POST"])]
    if base:
        # Before 21 October 2026 the pages were at the site root. Links already sent (/manage) and sign-ins
        # in flight (/login?req=...) are sent on; 308 keeps a POST a POST.
        for page_name in ("login", "manage"):
            routes.append(Route(f"/{page_name}", moved(f"{base}/{page_name}"), methods=["GET", "POST"]))
    return routes


def moved(target: str):
    async def redirect(request: Request) -> Response:
        query = request.url.query
        return Response(status_code=308, headers={"Location": target + (f"?{query}" if query else ""),
                                                  **security_headers()})
    return redirect
