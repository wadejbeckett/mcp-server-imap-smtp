# SPDX-License-Identifier: AGPL-3.0-or-later
"""MIME parsing into a compact, model-friendly summary."""
from __future__ import annotations

import base64
import binascii
import html as html_lib
import quopri
import re
from email import errors, policy
from email.message import EmailMessage
from email.parser import BytesParser

import html2text
from html.parser import HTMLParser


def _parse(raw: bytes) -> EmailMessage:
    return BytesParser(policy=policy.default).parsebytes(raw)


_VOID = frozenset("area base br col embed hr img input link meta param source track wbr".split())
_ALWAYS_HIDDEN = frozenset({"template"})
_ZERO = re.compile(r"^-?0*\.?0*(px|pt|em|rem|%|)?$")
MAX_LINKS = 100


def _declarations(style: str) -> dict[str, str]:
    out = {}
    for part in style.lower().split(";"):
        name, sep, value = part.partition(":")
        if sep:
            out[name.strip()] = value.replace("!important", "").strip()
    return out


def _hidden(tag: str, attrs: dict[str, str | None]) -> bool:
    """True for an element a mail client would not show: the hidden attribute, display:none,
    visibility:hidden, font-size 0, opacity 0, or text coloured the same as its own background."""
    if tag in _ALWAYS_HIDDEN or "hidden" in attrs:
        return True
    d = _declarations(attrs.get("style") or "")
    if d.get("display") == "none" or d.get("visibility") in ("hidden", "collapse"):
        return True
    if _ZERO.match(d.get("font-size", "x")) or _ZERO.match(d.get("opacity", "x")):
        return True
    background = d.get("background-color") or (d.get("background") or "").split(" ")[0]
    return bool(d.get("color") and background and _colour(d["color"]) == _colour(background))


_NAMED = {"white": "#ffffff", "black": "#000000"}


def _colour(value: str) -> str:
    v = _NAMED.get(value.replace(" ", ""), value.replace(" ", ""))
    if re.fullmatch(r"#[0-9a-f]{3}", v):
        v = "#" + "".join(c * 2 for c in v[1:])
    return v


class _Visible(HTMLParser):
    """Re-emits the HTML without hidden elements, comments and link targets; link targets are collected."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self.links: list[str] = []
        self.hiding: list[str] = []     # open tags inside the outermost hidden element
        self.open: list[str] = []       # visible elements still open
        self.hidden_at = 0              # len(self.open) when the hidden element started

    def handle_starttag(self, tag, attrs):
        if self.hiding:
            if tag not in _VOID:
                self.hiding.append(tag)
            return
        named = {k.lower(): v for k, v in attrs}
        if _hidden(tag, named):
            if tag not in _VOID:
                self.hiding.append(tag)
                self.hidden_at = len(self.open)
            return
        if tag not in _VOID:
            self.open.append(tag)
        kept = []
        for k, v in attrs:
            if tag == "a" and k == "href":
                target = (v or "").strip()
                if target.lower().startswith(("http://", "https://", "mailto:")) and target not in self.links \
                        and len(self.links) < MAX_LINKS:
                    self.links.append(target)
                continue
            kept.append(f' {k}="{html_lib.escape(v or "")}"')
        self.out.append(f"<{tag}{''.join(kept)}>")

    def handle_startendtag(self, tag, attrs):
        # HTML ignores the slash on a non-void tag: <div style="display:none"/> stays open and hides what
        # follows until an enclosing element closes, so it is treated as a start tag here too.
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if self.hiding:
            if tag in self.hiding:
                while self.hiding.pop() != tag:
                    pass
                return
            if tag not in self.open[:self.hidden_at]:
                return
            # Closes an element opened before the hidden one: the hidden element was never closed (malformed
            # markup), so hiding stops here rather than swallowing the rest of the message.
            self.hiding.clear()
        if tag in self.open:
            while self.open.pop() != tag:
                pass
        self.out.append(f"</{tag}>")

    def handle_data(self, data):
        if not self.hiding:
            self.out.append(html_lib.escape(data, quote=False))


def _visible_html(html: str) -> tuple[str, list[str]]:
    parser = _Visible()
    parser.feed(html)
    parser.close()
    return "".join(parser.out), parser.links


def _html_to_text(html: str, links: list[str] | None = None) -> str:
    """Text of what a reader would see: hidden elements are left out (finding 9 of the 2026-10-20 review:
    hidden text is a prompt-injection channel) and link targets go to `links`, not into the text."""
    visible, found = _visible_html(html)
    if links is not None:
        links.extend(u for u in found if u not in links)
    h = html2text.HTML2Text()
    h.ignore_images = True
    h.ignore_links = True
    h.body_width = 0
    return h.handle(visible)


def _get_body_text(body: EmailMessage | None, links: list[str] | None = None) -> str:
    """Extract text content from a body part, handling encoding errors."""
    if body is None:
        return ""

    content_type = body.get_content_type()

    def _fallback_decode(body: EmailMessage) -> str:
        """Fall back to payload decoding with charset handling."""
        try:
            charset = body.get_content_charset() or "utf-8"
            data = body.get_payload(decode=True)
        except LookupError:
            data = body.get_payload(decode=True)
            charset = "utf-8"

        if data:
            try:
                return data.decode(charset, errors="replace")
            except LookupError:
                return data.decode("utf-8", errors="replace")
        return ""

    if content_type == "text/html":
        try:
            content = body.get_content()
            return _html_to_text(content, links)
        except (LookupError, UnicodeDecodeError):
            html_text = _fallback_decode(body)
            return _html_to_text(html_text, links) if html_text else ""
    else:  # text/plain
        try:
            return body.get_content()
        except (LookupError, UnicodeDecodeError):
            return _fallback_decode(body)


def _part_body(part: EmailMessage) -> bytes:
    """The body of a part as it is serialised, without its own header block."""
    whole = part.as_bytes()
    for sep in (b"\r\n\r\n", b"\n\n"):
        head, found, body = whole.partition(sep)
        if found:
            return body
    return b""


_UTF8 = policy.default.clone(utf8=True, refold_source="none")    # long UTF-8 header fields stay as sent


def _source(m) -> bytes:
    """The lines a parsed message (or header block) was made from, without re-serialising: its header fields
    as received, the blank line only if there was one, then its body. Used to undo a transfer encoding the
    parser read as if it were a message: a soft line break inside the header block ends that block early,
    and the generator would add a blank line there that is not in the encoded text."""
    head = "".join(f"{name}: {value}\n" for name, value in m.raw_items())
    missing = any(isinstance(d, errors.MissingHeaderBodySeparatorDefect) for d in m.defects)
    payload = m.get_payload()
    if isinstance(payload, list):
        body = b"".join(_source(sub) for sub in payload)
    else:
        body = (payload or "").encode("utf-8", "surrogateescape")
    return (head + ("" if missing else "\n")).encode("utf-8", "surrogateescape") + body


def _get_attachment_data(part: EmailMessage) -> bytes:
    """The bytes of one attachment. message/rfc822 (and message/global) is the serialised inner message;
    any other message/* part (delivery-status, disposition-notification, global-delivery-status,
    global-headers) is the body of the part as it was sent, not the empty result of decoding a parsed
    header block (D3 of the 2026-11-04 content research). A message/* part sent base64 or
    quoted-printable (RFC 6532 s3.5 allows it for the global types) is decoded first."""
    if part.get_content_maintype() == "message":
        cte = str(part.get("Content-Transfer-Encoding", "")).strip().lower()
        if cte in ("base64", "quoted-printable"):
            payload = part.get_payload()
            body = (b"".join(_source(sub) for sub in payload) if isinstance(payload, list)
                    else _part_body(part))
            try:
                return base64.b64decode(body) if cte == "base64" else quopri.decodestring(body)
            except (ValueError, binascii.Error):
                return body
        if part.get_content_type() in ("message/rfc822", "message/global") and isinstance(part.get_payload(), list):
            inner_msg = part.get_payload(0)
            if inner_msg is None:
                return b""
            # message/global carries UTF-8 header fields (RFC 6532): keep them as UTF-8, not encoded words
            return inner_msg.as_bytes(policy=_UTF8 if part.get_content_subtype() == "global" else inner_msg.policy)
        return _part_body(part)
    return part.get_payload(decode=True) or b""


def _size(part: EmailMessage) -> int:
    """The decoded size of an attachment, worked out from its encoded form so a large message's attachments
    are not all decoded just to list them (security review 2026-10-20, A9)."""
    if part.get_content_maintype() == "message" or part.is_multipart():
        return len(_get_attachment_data(part))
    payload = part.get_payload(decode=False)
    if not isinstance(payload, str):
        return len(_get_attachment_data(part))
    cte = str(part.get("Content-Transfer-Encoding", "")).strip().lower()
    if cte == "base64":
        b64 = "".join(payload.split())
        return max(len(b64) * 3 // 4 - (len(b64) - len(b64.rstrip("="))), 0)
    if cte == "quoted-printable":
        return len(_get_attachment_data(part))
    return len(payload.encode("utf-8", "surrogateescape"))


def _bodies(msg: EmailMessage) -> tuple[EmailMessage | None, EmailMessage | None]:
    return msg.get_body(preferencelist=("plain",)), msg.get_body(preferencelist=("html",))


def _attachments(msg: EmailMessage) -> list[EmailMessage]:
    """Every leaf of the MIME tree except the message's text: the body part get_body chooses and the other
    text versions of it in the same multipart/alternative (with the HTML root of a multipart/related
    there). Unlike the stdlib's iter_attachments this descends into nested multiparts, so a PDF inside a
    signed or list-relayed message is listed (D10), a text/calendar beside the body in an alternative is
    listed (D2), and a single-part message that is not text (an S/MIME application/pkcs7-mime) lists
    itself (D1). A message/* part is one leaf and is not descended."""
    plain, html, plain_text = _choose(msg)
    body = plain if plain_text else html if html is not None else plain
    hidden = {id(body)} | ({id(plain)} if plain is not None and not plain_text else set())  # a blank plain part
    leaves: list[tuple[EmailMessage, tuple[EmailMessage, ...]]] = []

    def visit(part: EmailMessage, path: tuple[EmailMessage, ...]) -> None:
        if part.get_content_maintype() == "multipart":
            for sub in part.iter_parts():
                visit(sub, path + (part,))
            return
        leaves.append((part, path))

    visit(msg, ())
    body_path = next((path for part, path in leaves if part is body), ())
    alternatives = {id(p) for p in body_path if p.get_content_subtype() == "alternative"}

    def is_text_version(part: EmailMessage, path: tuple[EmailMessage, ...]) -> bool:
        if part.get_content_type() not in ("text/plain", "text/html") or part.get_filename():
            return False
        for i, ancestor in enumerate(path):
            if id(ancestor) in alternatives:
                below = path[i + 1:]       # nothing but a related wrapper whose root this part is
                return all(r.get_content_subtype() == "related" and _related_root(r) is
                           (below[j + 1] if j + 1 < len(below) else part) for j, r in enumerate(below))
        return False

    return [part for part, path in leaves if id(part) not in hidden and not is_text_version(part, path)]


def _related_root(related: EmailMessage) -> EmailMessage | None:
    """The root of a multipart/related as get_body finds it: the part named by `start`, else the first."""
    parts = list(related.iter_parts())
    start = related.get_param("start")
    if start and isinstance(start, str):
        for part in parts:
            if str(part.get("Content-ID", "")).strip() == start.strip():
                return part
    return parts[0] if parts else None


def _plain_text(plain: EmailMessage | None) -> str:
    """The plain body as returned to the AI (format=flowed unwrapped, stripped); "" when there is none."""
    if plain is None:
        return ""
    text = _get_body_text(plain)
    if _param(plain, "format") == "flowed":
        text = _unflow(text, _param(plain, "delsp") == "yes")
    return text.strip()


def _choose(msg: EmailMessage) -> tuple[EmailMessage | None, EmailMessage | None, str]:
    """The plain and HTML body candidates and the plain text; the plain part is the body only when it has text,
    so summarise() and _attachments() agree on which part is shown."""
    plain, html = _bodies(msg)
    return plain, html, _plain_text(plain)


def _param(part: EmailMessage, name: str) -> str:
    """A Content-Type parameter, lower case; "" when absent or unreadable (an RFC 2231 tuple is collapsed)."""
    value = part.get_param(name, "")
    if isinstance(value, tuple):
        value = value[2] if len(value) == 3 else ""
    return str(value or "").strip().lower()


_FLOWED_QUOTE = re.compile(r"^>+")


def _unflow(text: str, delsp: bool) -> str:
    """Join the soft line breaks of a format=flowed body (RFC 3676 section 4.1): a line ending in a space
    continues on the next line of the same quote depth. The "-- " signature separator is never joined to the
    line before or after it, and space-stuffing is removed."""
    out: list[str] = []
    pending: str | None = None
    pending_depth = -1
    for line in text.splitlines():
        m = _FLOWED_QUOTE.match(line)
        depth = len(m.group(0)) if m else 0
        content = line[depth:]
        if content.startswith(" "):
            content = content[1:]
        separator = content == "-- "      # RFC 3676 s4.3: the signature separator starts a new line
        soft = content.endswith(" ") and not separator
        if pending is not None and (depth != pending_depth or separator):
            out.append(pending)
            pending = None
        if pending is None:
            pending, pending_depth = (">" * depth + (" " if depth else "")), depth
        if soft and delsp:
            content = content[:-1]
        pending += content
        if not soft:
            out.append(pending)
            pending = None
    if pending is not None:
        out.append(pending)
    return "\n".join(out)


def summarise(raw: bytes, body_cap: int = 50_000) -> dict:
    msg = _parse(raw)

    # Try plain text first, then HTML
    text = ""
    links: list[str] = []
    _, html_body, text = _choose(msg)

    # If plain text is empty/blank, try HTML
    if not text:
        if html_body is not None:
            text = _get_body_text(html_body, links)

    truncated = len(text) > body_cap
    atts = []
    ids = _section_ids(msg)
    for i, part in enumerate(_attachments(msg)):
        row = {"index": i, "part_id": ids.get(id(part)), "filename": part.get_filename() or f"attachment-{i}",
               "content_type": part.get_content_type(), "size": _size(part)}
        disposition = part.get_content_disposition()
        if disposition:
            row["disposition"] = disposition
        cid = _content_id(part)
        if cid:
            row["content_id"] = cid
        atts.append(row)
    return {
        "message_id": str(msg.get("Message-ID", "")), "date": str(msg.get("Date", "")), "from": str(msg.get("From", "")),
        "to": str(msg.get("To", "")), "cc": str(msg.get("Cc", "")), "subject": str(msg.get("Subject", "")),
        "in_reply_to": str(msg.get("In-Reply-To", "")), "references": str(msg.get("References", "")),
        "text": text[:body_cap], "truncated": truncated, "links": links, "attachments": atts,
    }


def attachment(raw: bytes, index: int) -> tuple[str, str, bytes, str | None]:
    """(filename, content type, decoded bytes, declared charset or None)."""
    parts = _attachments(_parse(raw))
    part = parts[index]
    data = _get_attachment_data(part)
    return part.get_filename() or f"attachment-{index}", part.get_content_type(), data, part.get_content_charset()


def _section_ids(msg: EmailMessage) -> dict[int, str]:
    """IMAP section numbers (RFC 3501 s6.4.5 BODY[section]) of every part, keyed by id(part): a single-part
    message's body is "1"; the parts of a multipart are numbered 1, 2, ... and nested multiparts add a level
    ("2.1"). A message/* part is one part here: its inside is not numbered, as it is never descended."""
    ids: dict[int, str] = {}

    def visit(part: EmailMessage, prefix: str) -> None:
        for i, sub in enumerate(part.iter_parts(), 1):
            sid = f"{prefix}.{i}" if prefix else str(i)
            ids[id(sub)] = sid
            if sub.get_content_maintype() == "multipart":
                visit(sub, sid)

    if msg.get_content_maintype() == "multipart":
        visit(msg, "")
    else:
        ids[id(msg)] = "1"
    return ids


def _content_id(part: EmailMessage) -> str:
    """The part's Content-ID without its angle brackets; "" when it has none."""
    return str(part.get("Content-ID", "") or "").strip().strip("<>").strip()


class Part:
    """One part of a stored message, as found by find_part: what an outgoing message needs to carry it."""

    def __init__(self, part: EmailMessage, name: str, part_id: str | None):
        self.part, self.part_id = part, part_id
        self.filename = part.get_filename() or name
        self.content_type = part.get_content_type()
        self.content_id = _content_id(part)
        self.disposition = part.get_content_disposition()
        self.charset = part.get_content_charset()

    def data(self) -> bytes:
        return _get_attachment_data(self.part)


def attachment_parts(raw: bytes) -> list[Part]:
    """Every part summarise() lists as an attachment, from one parse of the message."""
    msg = _parse(raw)
    ids = _section_ids(msg)
    return [Part(p, f"attachment-{i}", ids.get(id(p))) for i, p in enumerate(_attachments(msg))]


_PART_ID = re.compile(r"[1-9]\d{0,3}(\.[1-9]\d{0,3}){0,19}")


def find_part(raw: bytes, index: int | None = None, part: str | None = None,
              content_id: str | None = None) -> Part:
    """One part of a message by exactly one of: its position in summarise()["attachments"], its IMAP section
    number (any part that is not a multipart, the body included) or its Content-ID. Raises LookupError with
    a message for the AI when there is no such part."""
    msg = _parse(raw)
    if index is not None:
        parts = _attachments(msg)
        if not 0 <= index < len(parts):
            raise LookupError(f"no attachment at index {index}")
        return Part(parts[index], f"attachment-{index}", _section_ids(msg).get(id(parts[index])))
    ids = _section_ids(msg)
    if part is not None:
        wanted = part.strip()
        if not _PART_ID.fullmatch(wanted):
            raise LookupError(f"part {part!r} is not a part id like \"2\" or \"1.2\" (see mail_read attachments)")
        for p in msg.walk():
            if ids.get(id(p)) == wanted:
                if p.get_content_maintype() == "multipart":
                    raise LookupError(f"part {wanted} is a multipart container; name one of the parts inside it")
                return Part(p, f"part-{wanted}", wanted)
        raise LookupError(f"no part {wanted} in this message")
    wanted = (content_id or "").strip().strip("<>").strip()
    if not wanted:
        raise LookupError("content_id is empty")
    for p in msg.walk():
        if id(p) in ids and p.get_content_maintype() != "multipart" and _content_id(p) == wanted:
            return Part(p, f"part-{ids[id(p)]}", ids[id(p)])
    raise LookupError(f"no part with Content-ID {wanted!r} in this message")


# Quoting an original in an outgoing reply or inline forward (D9). Only plain formatting survives: no scripts,
# styles, forms, images (a remote image would be fetched by every reader, a cid: image would point at nothing)
# or attributes other than a link's http, https or mailto target. Hidden elements are left out, as they are
# from what the AI reads, so the quote shows the reader what the AI saw.
_QUOTE_TAGS = frozenset("a b blockquote br code div em h1 h2 h3 h4 h5 h6 hr i li ol p pre s small span strong "
                        "sub sup table tbody td tfoot th thead tr u ul".split())
_QUOTE_DROP = frozenset("script style head title template object embed iframe svg math noscript select "
                        "textarea button form".split())


class _Quotable(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self.dropping: list[str] = []     # open tags inside an element whose content is left out
        self.open: list[str] = []
        self.dropped_at = 0               # len(self.open) when the dropped element started

    def handle_starttag(self, tag, attrs):
        if self.dropping:
            if tag not in _VOID:
                self.dropping.append(tag)
            return
        named = {k.lower(): v for k, v in attrs}
        if tag in _QUOTE_DROP or _hidden(tag, named):
            if tag not in _VOID:
                self.dropping.append(tag)
                self.dropped_at = len(self.open)
            return
        if tag == "img":
            alt = (named.get("alt") or "").strip()
            if alt:
                self.out.append(html_lib.escape(f"[{alt}]", quote=False))
            return
        if tag not in _QUOTE_TAGS:
            return
        kept = ""
        if tag == "a":
            href = (named.get("href") or "").strip()
            if href.lower().startswith(("http://", "https://", "mailto:")):
                kept = f' href="{html_lib.escape(href)}"'
        if tag in _VOID:
            self.out.append(f"<{tag}>")
            return
        self.open.append(tag)
        self.out.append(f"<{tag}{kept}>")

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if self.dropping:
            if tag in self.dropping:
                while self.dropping.pop() != tag:
                    pass
                return
            if tag not in self.open[:self.dropped_at]:
                return
            # Closes an element opened before the dropped one, which was never closed: stop dropping here, as
            # _Visible does, so the quote keeps what the AI was shown.
            self.dropping.clear()
        if tag in self.open:
            while True:
                t = self.open.pop()
                self.out.append(f"</{t}>")
                if t == tag:
                    break

    def handle_data(self, data):
        if not self.dropping:
            self.out.append(html_lib.escape(data, quote=False))

    def result(self) -> str:
        return "".join(self.out) + "".join(f"</{t}>" for t in reversed(self.open))


def quotable_html(raw: bytes) -> str:
    """The original message's body as safe HTML to quote, from the same part summarise() reads: the plain text
    (escaped, line breaks kept) when it has any, else the HTML part through the allowlist above. An HTML
    alternative that says something else than the plain part is never quoted, since the AI never saw it."""
    _, html, text = _choose(_parse(raw))
    if html is not None and not text:      # the HTML only when it is what summarise() showed the AI
        try:
            source = html.get_content()
        except (LookupError, UnicodeDecodeError):
            source = (html.get_payload(decode=True) or b"").decode("utf-8", "replace")
        q = _Quotable()
        q.feed(source)
        q.close()
        quoted = q.result()
        if quoted.strip():
            return quoted
    return html_lib.escape(text, quote=False).replace("\n", "<br>\n")
