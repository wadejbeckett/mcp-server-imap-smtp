# SPDX-License-Identifier: AGPL-3.0-or-later
"""Build outgoing messages: new, reply (threaded, original quoted), forward (original attached or inline), with
files attached. Images in an HTML body travel inside the message as cid: parts (mail/inline.py).

The tree is mixed( alternative( text, related( html, images ) ), files ): each layer only when it has more than
one part, and multipart/related always names its root's type (RFC 2387 s3.1, defect D11)."""
from __future__ import annotations

import html as html_lib
import re
from dataclasses import dataclass
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
    if "@" in parseaddr(value)[0]:
        # '"x@evil.com" <y@good.com>' goes to y@good.com while a person checking the call reads x@evil.com
        # (security review 2026-10-20, A7).
        raise MailError(f"{what}: a display name may not contain an email address; give the address alone")
    return addr


def _set(m: EmailMessage, name: str, value: str) -> None:
    _clean(value, f"{name} header")
    try:
        m[name] = value
    except ValueError as exc:  # the email package refuses what it cannot fold safely
        raise MailError(f"invalid {name} header") from exc


@dataclass
class File:
    """One file to attach. disposition "inline" with a content_id puts an image beside the HTML body, for an
    <img src="cid:..."> the caller wrote; anything else is an ordinary attachment."""
    filename: str
    content_type: str
    data: bytes
    disposition: str = "attachment"
    content_id: str | None = None
    charset: str | None = None


_TOKEN = r"[a-z0-9][a-z0-9!#$&^_.+-]{0,126}"
_CTYPE = re.compile(f"{_TOKEN}/{_TOKEN}")
_CID = re.compile(r"[\x21-\x3b\x3d\x3f-\x7e]{1,250}")      # printable ASCII without < > and space
_CHARSET = re.compile(r"[A-Za-z0-9!#$%&'+^_`{}~.-]{1,64}")    # an RFC 2978 charset name
MAX_FILENAME = 255


def file(filename: str | None, content_type: str | None, data: bytes, disposition: str | None = None,
         content_id: str | None = None, charset: str | None = None) -> File:
    """A validated File. The filename loses any directory part; the content type must be type/subtype and
    not multipart; disposition is "attachment" (default) or "inline"."""
    name = (filename or "").replace("\\", "/").rsplit("/", 1)[-1].strip()
    if not name:
        raise MailError("an attachment needs a filename")
    _clean(name, "attachment filename")
    if len(name) > MAX_FILENAME:
        raise MailError(f"an attachment filename may be at most {MAX_FILENAME} characters")
    ctype = (content_type or "application/octet-stream").strip().lower()
    if not _CTYPE.fullmatch(ctype):
        raise MailError(f"attachment {name!r}: content_type must look like type/subtype, e.g. application/pdf")
    if ctype.startswith("multipart/"):
        raise MailError(f"attachment {name!r}: a multipart content type cannot be attached; "
                        "use application/octet-stream")
    disp = (disposition or "attachment").strip().lower()
    if disp not in ("attachment", "inline"):
        raise MailError(f"attachment {name!r}: disposition must be \"attachment\" or \"inline\"")
    cid = None
    if content_id is not None:
        cid = content_id.strip().strip("<>").strip()
        if not _CID.fullmatch(cid):
            raise MailError(f"attachment {name!r}: content_id must be printable ASCII without spaces or <>")
    if charset is not None and not _CHARSET.fullmatch(charset):
        charset = None           # a charset taken from stored mail that cannot be a parameter: leave it out
    return File(name, ctype, data, disp, cid, charset)


class Stored(EmailMessage):
    """A message kept as the octets it was stored as, to carry inside message/rfc822. The generator writes
    no header block for it (the _write_headers hook) and writes its payload line by line, 8-bit octets as
    they are (BytesGenerator._handle_text with surrogateescape), so only the line ends follow the
    generator's: CRLF on the wire, which stored mail already has."""

    def __init__(self, data: bytes):
        super().__init__()
        self.octets = data
        self.set_payload(data.decode("ascii", "surrogateescape"))

    def _write_headers(self, generator) -> None:
        pass


_LINE_END = re.compile(rb"\r?\n")


def _message_encoding(data: bytes) -> str | None:
    """The transfer encoding that carries a stored message unchanged inside message/rfc822: "7bit" or
    "8bit" (RFC 2046 s5.2.1 allows no other on the way through SMTP), or None when it needs "binary" (a NUL,
    a bare CR or a line over 998 octets, RFC 5322 s2.1.1), which SMTP without BINARYMIME cannot carry. A bare
    LF counts as a line end: it goes out as CRLF, as every mail server would send it."""
    if b"\0" in data:
        return None
    if any(b"\r" in line or len(line) > 998 for line in _LINE_END.split(data)):
        return None
    return "7bit" if data.isascii() else "8bit"


def _message_part(f: File) -> EmailMessage:
    """A message/* file. message/rfc822 and message/global carry the stored octets as they are, never parsed
    and re-serialised: refolding a long header or encoding a long token would change what was received and
    break its DKIM signature (review after merge, item 3). One that only binary could carry goes as an
    application/octet-stream file instead, base64 encoded, which decodes to the same octets (message/rfc822
    may not be base64 encoded, RFC 2046 s5.2.1). Any other message/* type (delivery-status and the like) is a
    plain text body."""
    if f.content_type in ("message/rfc822", "message/global"):
        cte = _message_encoding(f.data)
        if cte is None:
            return _octet_part(f)
        part = EmailMessage()
        part["Content-Type"] = f.content_type
        part["Content-Transfer-Encoding"] = cte
        part.add_header("Content-Disposition", f.disposition, filename=f.filename)
        part.set_payload([Stored(f.data)])
    else:
        # Parsed, so the generator finds the header blocks a delivery-status or disposition-notification
        # body is made of.
        cte = b"7bit" if f.data.isascii() else b"8bit"
        part = BytesParser(policy=policy.default).parsebytes(
            b"Content-Type: " + f.content_type.encode("ascii") + b"\r\nContent-Transfer-Encoding: " + cte
            + b"\r\n\r\n" + f.data)
        part.add_header("Content-Disposition", f.disposition, filename=f.filename)
    if f.content_id:
        part["Content-ID"] = f"<{f.content_id}>"
    return part


def _octet_part(f: File) -> EmailMessage:
    part = EmailMessage()
    part.set_content(f.data, "application", "octet-stream", disposition=f.disposition, filename=f.filename,
                     cid=f"<{f.content_id}>" if f.content_id else None)
    part.set_param("name", f.filename)
    return part


def _add_file(m: EmailMessage, f: File) -> None:
    if f.content_type.startswith("message/"):
        if m.get_content_type() != "multipart/mixed":
            m.make_mixed()
        m.attach(_message_part(f))
        return
    maintype, subtype = f.content_type.split("/", 1)
    m.add_attachment(f.data, maintype, subtype, filename=f.filename, disposition=f.disposition,
                     cid=f"<{f.content_id}>" if f.content_id else None)
    part = m.get_payload()[-1]
    part.set_param("name", f.filename)           # older clients read the name from Content-Type
    if f.charset and maintype == "text":
        part.set_param("charset", f.charset)


def _typed_related(m: EmailMessage) -> None:
    """D11: every multipart/related names the type of its root (the first part), RFC 2387 s3.1."""
    # Not m.walk(): it descends into an attached message/rfc822, whose bytes must stay as received.
    if m.get_content_maintype() != "multipart":
        return
    parts = list(m.iter_parts())
    if m.get_content_type() == "multipart/related" and parts:
        m.set_param("type", parts[0].get_content_type())
    for part in parts:
        _typed_related(part)


def _append_html(html: str, tail: str) -> str:
    """tail added at the end of the caller's HTML: inside </body> when the HTML is a whole document."""
    if not tail:
        return html
    at = html.lower().rfind("</body>")
    return html[:at] + tail + html[at:] if at >= 0 else html + tail


def _base(from_addr: str, subject: str, text: str, html: str | None, fetch=inline.fetch_https,
          files=(), html_tail: str = "") -> EmailMessage:
    """The message without recipients. html_tail is safe HTML (a quoted original) put after the caller's
    HTML once its images are embedded, so nothing in it is fetched."""
    sender = _address(from_addr, "From address")
    domain = sender.rpartition("@")[2]
    images = []
    if html:
        html, images = inline.embed(html, domain, fetch)
        html = _append_html(html, html_tail)
    m = EmailMessage()
    _set(m, "From", from_addr)
    _set(m, "Subject", subject)
    m["Date"] = formatdate(localtime=True)
    m["Message-ID"] = make_msgid(domain=domain)
    m.set_content(text)
    files = list(files)
    if html:
        m.add_alternative(html, subtype="html")
        # multipart/alternative: text/plain, then multipart/related holding the HTML, its images and the
        # caller's inline images
        body = m.get_payload()[-1]
        for img in images:
            body.add_related(img.data, "image", img.subtype, cid=f"<{img.cid}>", disposition="inline",
                             filename=img.filename)
        for f in [f for f in files if f.disposition == "inline" and f.content_id
                  and f.content_type.startswith("image/")]:
            files.remove(f)
            maintype, subtype = f.content_type.split("/", 1)
            body.add_related(f.data, maintype, subtype, cid=f"<{f.content_id}>", disposition="inline",
                             filename=f.filename)
    for f in files:
        _add_file(m, f)
    _typed_related(m)
    return m


def _mailboxes(values, what: str) -> str:
    values = list(values)
    for v in values:
        _address(v, what)
    return ", ".join(values)


def new(from_addr, to, subject, text, html=None, cc=(), bcc=(), fetch=inline.fetch_https, files=()) -> EmailMessage:
    to_h, cc_h = _mailboxes(to, "recipient"), _mailboxes(cc, "Cc recipient")
    _mailboxes(bcc, "Bcc recipient")  # not a header, but it is sent to the server as an envelope recipient
    m = _base(from_addr, subject, text, html, fetch, files)
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


def _attribution(o: dict) -> str:
    return f"On {o['date']}, {o['from']} wrote:"


def _references(o: dict) -> str:
    """The reply's References (RFC 5322 s3.6.4): the parent's References, or when it has none its In-Reply-To
    if that holds a single id (D7), then the parent's Message-ID."""
    parent = o["references"].strip()
    if not parent:
        ids = o["in_reply_to"].split()
        if len(ids) == 1 and ids[0].startswith("<") and ids[0].endswith(">"):
            parent = ids[0]
    return (parent + " " + o["message_id"]).strip()


def _mb(n: int) -> str:
    return f"{n / 1_048_576:.1f} MB" if n >= 1_048_576 else f"{n / 1024:.0f} KB"


def too_large(size: int, limit: int, where: str) -> str:
    """The refusal for a message over a server's advertised limit, naming the limit."""
    return (f"The message is {_mb(size)} ({size} bytes); {where} accepts at most {_mb(limit)} ({limit} bytes). "
            "Attachments grow by about a third when encoded for mail: attach fewer or smaller files.")


def wire_size(m: EmailMessage) -> int:
    """The message's size as it goes over SMTP or IMAP APPEND, with CRLF line ends."""
    return len(m.as_bytes(policy=m.policy.clone(linesep="\r\n")))


QUOTES = ("full", "none")
FORWARD_MODES = ("attachment", "inline")


def reply(original_raw: bytes, from_addr, text, html=None, reply_all=False, fetch=inline.fetch_https,
          quote: str = "full", files=()) -> EmailMessage:
    if quote not in QUOTES:
        raise MailError('quote must be "full" or "none"')
    o = render.summarise(original_raw)
    reply_to = BytesHeaderParser(policy=policy.default).parsebytes(original_raw).get("Reply-To")
    targets = _pairs(str(reply_to)) if reply_to else []
    sender = _pairs(o["from"])
    if not targets:
        targets = sender
    if not targets:
        raise MailError("the original message has no sender address to reply to")
    body, tail = text, ""
    if quote == "full":
        quoted = "\n".join("> " + line for line in o["text"].splitlines())
        body = f"{text}\n\n{_attribution(o)}\n{quoted}\n"
        if html:      # D9: the HTML part quotes the original too, as a cite blockquote of its safe HTML
            tail = (f'<br><div class="moz-cite-prefix">{html_lib.escape(_attribution(o), quote=False)}<br></div>'
                    f'<blockquote type="cite">{render.quotable_html(original_raw)}</blockquote>')
    m = _base(from_addr, _prefixed("Re:", o["subject"]), body, html, fetch, files, tail)
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
    refs = _references(o)
    if refs:
        _set(m, "References", refs)
    return m


def _forward_block(o: dict) -> list[tuple[str, str]]:
    rows = [("From", o["from"]), ("Date", o["date"]), ("Subject", o["subject"]), ("To", o["to"])]
    if o["cc"]:
        rows.append(("Cc", o["cc"]))
    return rows


def original_files(original_raw: bytes) -> list[File]:
    """Every attachment and inline part of a message (render's list), as files to carry in an inline forward."""
    return [file(p.filename, p.content_type, p.data(), "attachment", charset=p.charset)
            for p in render.attachment_parts(original_raw)]


def forward(original_raw: bytes, from_addr, to, text, html=None, mode: str = "attachment", files=(),
            fetch=inline.fetch_https) -> EmailMessage:
    """mode "attachment": the covering note, then the original as a message/rfc822 part. mode "inline": the
    original's header block and text below the note (and its safe HTML below an HTML note), with the
    original's attachments carried as files."""
    if mode not in FORWARD_MODES:
        raise MailError('forward_mode must be "attachment" or "inline"')
    o = render.summarise(original_raw)
    to_h = _mailboxes(to, "recipient")
    subject = _prefixed("Fwd:", o["subject"])
    if mode == "attachment":
        if html:
            raise MailError('html is not supported with forward_mode="attachment"; use forward_mode="inline"')
        m = _base(from_addr, subject, text, None, fetch,
                  [File("forwarded.eml", "message/rfc822", original_raw), *files])
    else:
        head = "---------- Forwarded message ----------"
        block = "\n".join(f"{n}: {v}" for n, v in _forward_block(o))
        body = f"{text}\n\n{head}\n{block}\n\n{o['text']}\n"
        tail = ""
        if html:
            rows = "".join(f"{html_lib.escape(n)}: {html_lib.escape(v, quote=False)}<br>" for n, v in _forward_block(o))
            tail = (f'<br><div class="moz-forward-container">{html_lib.escape(head)}<br>{rows}<br>'
                    f"{render.quotable_html(original_raw)}</div>")
        m = _base(from_addr, subject, body, html, fetch, [*original_files(original_raw), *files], tail)
    _set(m, "To", to_h)
    return m
