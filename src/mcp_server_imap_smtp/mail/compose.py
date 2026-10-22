# SPDX-License-Identifier: AGPL-3.0-or-later
"""Build outgoing messages: new, reply (threaded), forward (original attached). Images in an HTML body travel
inside the message as cid: parts (mail/inline.py)."""
from __future__ import annotations

import re
from email import policy
from email.message import EmailMessage
from email.parser import BytesHeaderParser, BytesParser
from email.utils import formataddr, formatdate, getaddresses, make_msgid, parseaddr

from . import inline, render
from .imap import MailError

_CTRL = re.compile(r"[\r\n\0]")
_BARE = re.compile(r"[^\s<>,;\"]+@[^\s<>,;\"@]+")


def _clean(value: str, what: str) -> str:
    if _CTRL.search(value):
        raise MailError(f"CR, LF and NUL are not allowed in the {what}")
    return value


def _address(value: str, what: str) -> str:
    """Validate one mailbox (bare or 'Name <addr>') and return its address part."""
    _clean(value, what)
    parsed = getaddresses([value])
    addr = parseaddr(value)[1]
    if len(parsed) != 1 or not addr or addr.count("@") != 1 or not _BARE.fullmatch(addr):
        raise MailError(f"{what} is not a single valid email address")
    return addr


def _set(m: EmailMessage, name: str, value: str) -> None:
    _clean(value, f"{name} header")
    try:
        m[name] = value
    except ValueError as exc:  # the email package refuses what it cannot fold safely
        raise MailError(f"invalid {name} header") from exc


def _base(from_addr: str, subject: str, text: str, html: str | None, fetch=inline.fetch_https) -> EmailMessage:
    sender = _address(from_addr, "From address")
    domain = sender.rpartition("@")[2]
    images = []
    if html:
        html, images = inline.embed(html, domain, fetch)
    m = EmailMessage()
    _set(m, "From", from_addr)
    _set(m, "Subject", subject)
    m["Date"] = formatdate(localtime=True)
    m["Message-ID"] = make_msgid(domain=domain)
    m.set_content(text)
    if html:
        m.add_alternative(html, subtype="html")
        # multipart/alternative: text/plain, then multipart/related holding the HTML and its images
        body = m.get_payload()[-1]
        for img in images:
            body.add_related(img.data, "image", img.subtype, cid=f"<{img.cid}>", disposition="inline",
                             filename=img.filename)
    return m


def _mailboxes(values, what: str) -> str:
    values = list(values)
    for v in values:
        _address(v, what)
    return ", ".join(values)


def new(from_addr, to, subject, text, html=None, cc=(), bcc=(), fetch=inline.fetch_https) -> EmailMessage:
    to_h, cc_h = _mailboxes(to, "recipient"), _mailboxes(cc, "Cc recipient")
    _mailboxes(bcc, "Bcc recipient")  # not a header, but it is sent to the server as an envelope recipient
    m = _base(from_addr, subject, text, html, fetch)
    _set(m, "To", to_h)
    if cc_h:
        _set(m, "Cc", cc_h)
    return m


def envelope_recipients(m: EmailMessage, bcc=()) -> list[str]:
    """Addresses for RCPT TO: To, Cc, then bcc, each address once (case-insensitive, first spelling kept)."""
    found = [_address(a, "recipient") for _, a in getaddresses([m.get("To", ""), m.get("Cc", "")]) if a]
    found += [_address(b, "Bcc recipient") for b in bcc]
    seen, out = set(), []
    for addr in found:
        if addr.lower() not in seen:
            seen.add(addr.lower())
            out.append(addr)
    return out


def _prefixed(prefix: str, subject: str) -> str:
    return subject if subject.lower().startswith(prefix.lower()) else f"{prefix} {subject}"


def _pairs(header: str) -> list[tuple[str, str]]:
    return [(n, a) for n, a in getaddresses([header]) if a]


def _join(pairs) -> str:
    # formataddr quotes display names such as "Lee, Ann", so each stays one mailbox.
    return ", ".join(formataddr(p) for p in pairs)


def reply(original_raw: bytes, from_addr, text, html=None, reply_all=False, fetch=inline.fetch_https) -> EmailMessage:
    o = render.summarise(original_raw)
    reply_to = BytesHeaderParser(policy=policy.default).parsebytes(original_raw).get("Reply-To")
    targets = _pairs(str(reply_to)) if reply_to else []
    sender = _pairs(o["from"])
    if not targets:
        targets = sender
    if not targets:
        raise MailError("the original message has no sender address to reply to")
    quoted = "\n".join("> " + line for line in o["text"].splitlines())
    body = f"{text}\n\nOn {o['date']}, {o['from']} wrote:\n{quoted}\n"
    m = _base(from_addr, _prefixed("Re:", o["subject"]), body, html, fetch)
    _set(m, "To", _join(targets))
    if reply_all:
        skip = {parseaddr(from_addr)[1].lower()} | {a.lower() for _, a in targets}
        others = []
        for n, a in sender + _pairs(o["to"]) + _pairs(o["cc"]):
            if a.lower() not in skip:
                skip.add(a.lower())
                others.append((n, a))
        if others:
            _set(m, "Cc", _join(others))
    if o["message_id"]:
        _set(m, "In-Reply-To", o["message_id"])
    refs = (o["references"] + " " + o["message_id"]).strip()
    if refs:
        _set(m, "References", refs)
    return m


def forward(original_raw: bytes, from_addr, to, text) -> EmailMessage:
    o = render.summarise(original_raw)
    to_h = _mailboxes(to, "recipient")
    m = _base(from_addr, _prefixed("Fwd:", o["subject"]), text, None)
    _set(m, "To", to_h)
    # Attach the parsed message: message/rfc822 must not be base64 encoded (RFC 2046 5.2.1).
    m.add_attachment(BytesParser(policy=policy.default).parsebytes(original_raw), filename="forwarded.eml")
    return m
