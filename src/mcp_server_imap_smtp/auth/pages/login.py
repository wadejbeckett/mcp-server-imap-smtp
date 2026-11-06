# SPDX-License-Identifier: AGPL-3.0-or-later
"""The sign-in page: one mailbox address and password, and/or any number of mailboxes pasted one per
line, each checked on its own server before anything is connected."""
from __future__ import annotations

import html

from starlette.requests import Request
from starlette.responses import HTMLResponse, Response
from starlette.routing import Route

from ...mail.hosts import HostNotAllowed
from ...mail.resolve import normalise_address
from .common import (ERROR, MAX_EMAIL, MAX_PASSWORD, PASTE_AGAIN, Entry, FormTooLarge, Pages, error_box,
                     parse_more, read_form, return_target, security_headers)

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connect your mailbox · {product}</title><style>
:root{{--bg:#fff;--fg:#111;--mut:#555;--line:#ccc;--acc:#0b5}}@media (prefers-color-scheme:dark){{:root{{--bg:#111;--fg:#eee;--mut:#aaa;--line:#444}}}}
body{{font:16px system-ui,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:16px}}main{{max-width:420px;margin:8vh auto}}
label{{display:block;margin:12px 0 4px}}input,textarea{{width:100%;box-sizing:border-box;padding:10px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg)}}
textarea{{font:14px ui-monospace,monospace;min-height:10em;resize:vertical}}
button{{margin-top:20px;width:100%;padding:12px;border:0;border-radius:6px;background:var(--acc);color:#fff;font-weight:600}}
.err{{color:#c22;margin-top:12px}}details{{margin-top:16px;color:var(--mut)}}p{{color:var(--mut)}}</style></head>
<body><main><h1>Connect your mailbox</h1><p>{client} (name supplied by the app) is asking to use your email hosted by {operator}. Sign in with the same address and password you use in your mail app.</p>
<p>When you connect, you will return to <strong>{target}</strong>. Only continue if you started this from your own AI app just now.</p>
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


def routes(p: Pages) -> list[Route]:
    """GET and POST of the sign-in page, at <service_path>/login."""
    settings, provider, limits, limiter = p.settings, p.provider, p.limits, p.limiter

    def page(req, client, redirect_uri, email="", more_open=False, error: str | list[str] = "", status=200):
        body = PAGE.format(req=html.escape(req), client=html.escape(client), email=html.escape(email),
                           target=html.escape(return_target(redirect_uri)),
                           product=html.escape(settings.product_name), operator=html.escape(settings.operator_name),
                           support=p.support, open=" open" if more_open else "", limit=p.limit_text,
                           error=error_box(error))
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

    async def get(request: Request) -> Response:
        req = request.query_params.get("req", "")
        found = provider.store.peek_pending(req)
        if not found:
            return p.expired()
        return page(req, await p.client_name(found[0]), str(found[1].redirect_uri))

    async def post(request: Request) -> Response:
        if (refused := p.cross_site(request)) is not None:
            return refused
        try:
            form = await read_form(request)
        except FormTooLarge:
            return p.too_large()
        req = str(form.get("req", ""))
        found = provider.store.peek_pending(req)
        if not found:
            return p.expired()
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
            return p.too_many(redirect_uri, "Too many wrong passwords on this page. Start again from your AI app.")
        # The client's attempt is reserved before the slow DNS and mail-server checks, so parallel requests
        # cannot all pass the limit. Malformed input and wrong credentials keep it; a mail-server outage or
        # a success gives it back.
        ip_key = f"ip:{p.ip(request)}"
        if not limiter.try_acquire([ip_key]):
            return p.too_many(redirect_uri)

        async def again(error: str | list[str], status: int = 200) -> Response:
            # The list is never sent back (it holds passwords); the main address is.
            errors = [error] if isinstance(error, str) else list(error)
            if more.strip():
                errors.append(PASTE_AGAIN)
            return page(req, await p.client_name(client_id), redirect_uri, email, bool(more.strip()), errors, status)

        if problem:
            return await again(problem)
        checked = await p.verify(request, entries, normalised, req, ip_key, again, redirect_uri)
        if isinstance(checked, Response):
            return checked
        entries, normalised, servers = checked
        try:
            redirect = provider.complete_login(
                req, [(address, entry.password, server) for address, entry, server in zip(normalised, entries, servers)])
        except LookupError:
            return p.expired()
        return done(redirect, redirect_uri, await p.client_name(client_id), normalised[0], len(entries))

    base = settings.service_path
    return [Route(f"{base}/login", get, methods=["GET"]), Route(f"{base}/login", post, methods=["POST"])]
