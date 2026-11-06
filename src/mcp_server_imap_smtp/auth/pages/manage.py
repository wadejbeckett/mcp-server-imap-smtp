# SPDX-License-Identifier: AGPL-3.0-or-later
"""The manage page: the main mailbox of a connection, checked over IMAP under the sign-in limits, opens a
short session in which that connection's mailboxes can be listed, added, given a new password or removed,
and the connection ended. New passwords are sealed to the connection's public key, so the page never
needs (or could use) the key in the AI app's tokens, and nothing it does can read mail."""
from __future__ import annotations

import html
import time

from starlette.requests import Request
from starlette.responses import HTMLResponse, Response
from starlette.routing import Route

from ...mail.hosts import HostNotAllowed
from ...mail.resolve import normalise_address
from .common import (ERROR, MAX_EMAIL, MAX_PASSWORD, PASTE_AGAIN, Entry, FormTooLarge, Pages, error_box, log,
                     parse_more, read_form, security_headers)

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


def routes(p: Pages) -> list[Route]:
    """GET and POST of the manage page, at <service_path>/manage."""
    settings, provider, limits, limiter, cap = p.settings, p.provider, p.limits, p.limiter, p.cap

    def manage_signin_page(email: str = "", error: str | list[str] = "", status: int = 200) -> Response:
        body = MANAGE_SIGNIN.format(product=html.escape(settings.product_name), email=html.escape(email),
                                    support=p.support, error=error_box(error))
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
                client=html.escape(await p.client_name(g["client_id"])), grant=html.escape(g["id"]),
                created=html.escape(time.strftime("%d %b %Y", time.gmtime(g["created"]))),
                count=f"{n} mailbox" + ("" if n == 1 else "es"), rows="".join(rows), session=html.escape(session)))
        if not parts:
            parts.append("<p>No AI app is connected with this mailbox as its main mailbox any more.</p>")
        messages = "".join(f'<p class="err" role="alert">{html.escape(e)}</p>' for e in errors)
        if notice:
            messages += f'<p class="ok" role="status">{html.escape(notice)}</p>'
        body = MANAGE_PAGE.format(product=html.escape(settings.product_name), subject=html.escape(subject),
                                  session=html.escape(session), notice=messages, connections="".join(parts),
                                  support=p.support)
        return HTMLResponse(body, status_code=status, headers=security_headers())

    async def manage_get(request: Request) -> Response:
        return manage_signin_page()

    async def manage_post(request: Request) -> Response:
        if (refused := p.cross_site(request)) is not None:
            return refused
        try:
            form = await read_form(request)
        except FormTooLarge:
            return p.too_large()
        action = str(form.get("action", ""))
        ip_key = f"ip:{p.ip(request)}"
        if action == "signin":
            email = str(form.get("email", "")).strip().lower()
            entry = Entry(None, email, str(form.get("password", "")))
            if limits.request.blocked(f"req:manage:{p.ip(request)}"):
                return p.page_locked(f"req:manage:{p.ip(request)}", "Too many attempts. Try again in {wait}.")
            if not limiter.try_acquire([ip_key]):
                return p.too_many(None)
            try:
                address = normalise_address(entry.address)[0]
            except HostNotAllowed:
                return manage_signin_page(email, ERROR)
            if not entry.password or len(entry.address) > MAX_EMAIL or len(entry.password) > MAX_PASSWORD:
                return manage_signin_page(email, ERROR)

            async def signin_again(error, status: int = 200) -> Response:
                return manage_signin_page(email, error, status)
            checked = await p.verify(request, [entry], [address], f"manage:{p.ip(request)}", ip_key, signin_again, None)
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
            return p.page_locked(f"req:{page_key}", "Too many wrong passwords. Sign in again in {wait}.")
        if not limiter.try_acquire([ip_key]):
            return p.too_many(None)
        checked = await p.verify(request, entries, normalised, page_key, ip_key, again, None)
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
    return [Route(f"{base}/manage", manage_get, methods=["GET"]), Route(f"{base}/manage", manage_post, methods=["POST"])]
