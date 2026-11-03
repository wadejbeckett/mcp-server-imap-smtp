# SPDX-License-Identifier: AGPL-3.0-or-later
"""MIME parsing into a compact, model-friendly summary."""
from __future__ import annotations

import base64
import html as html_lib
import re
from email import policy
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


def _get_attachment_data(part: EmailMessage) -> bytes:
    """Extract attachment data, handling message/rfc822 parts."""
    if part.get_content_type() == "message/rfc822":
        # For forwarded messages, get the serialized inner message
        inner_msg = part.get_payload(0)
        return inner_msg.as_bytes() if inner_msg else b""
    else:
        return part.get_payload(decode=True) or b""


def _size(part: EmailMessage) -> int:
    """The decoded size of an attachment, worked out from its encoded form so a large message's attachments
    are not all decoded just to list them (security review 2026-10-20, A9)."""
    if part.get_content_type() == "message/rfc822" or part.is_multipart():
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


def _attachments(msg: EmailMessage) -> list[EmailMessage]:
    return list(msg.iter_attachments())


def summarise(raw: bytes, body_cap: int = 50_000) -> dict:
    msg = _parse(raw)

    # Try plain text first, then HTML
    text = ""
    links: list[str] = []
    plain_body = msg.get_body(preferencelist=("plain",))
    if plain_body is not None:
        plain_text = _get_body_text(plain_body).strip()
        if plain_text:
            text = plain_text

    # If plain text is empty/blank, try HTML
    if not text:
        html_body = msg.get_body(preferencelist=("html",))
        if html_body is not None:
            text = _get_body_text(html_body, links)

    truncated = len(text) > body_cap
    atts = []
    for i, part in enumerate(_attachments(msg)):
        atts.append({"index": i, "filename": part.get_filename() or f"attachment-{i}",
                     "content_type": part.get_content_type(), "size": _size(part)})
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
