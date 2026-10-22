# SPDX-License-Identifier: AGPL-3.0-or-later
"""MIME parsing into a compact, model-friendly summary."""
from __future__ import annotations

import base64
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser

import html2text


def _parse(raw: bytes) -> EmailMessage:
    return BytesParser(policy=policy.default).parsebytes(raw)


def _html_to_text(html: str) -> str:
    h = html2text.HTML2Text()
    h.ignore_images = True
    h.body_width = 0
    return h.handle(html)


def _get_body_text(body: EmailMessage | None) -> str:
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
            return _html_to_text(content)
        except (LookupError, UnicodeDecodeError):
            html_text = _fallback_decode(body)
            return _html_to_text(html_text) if html_text else ""
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


def _attachments(msg: EmailMessage) -> list[EmailMessage]:
    return list(msg.iter_attachments())


def summarise(raw: bytes, body_cap: int = 50_000) -> dict:
    msg = _parse(raw)

    # Try plain text first, then HTML
    text = ""
    plain_body = msg.get_body(preferencelist=("plain",))
    if plain_body is not None:
        plain_text = _get_body_text(plain_body).strip()
        if plain_text:
            text = plain_text

    # If plain text is empty/blank, try HTML
    if not text:
        html_body = msg.get_body(preferencelist=("html",))
        if html_body is not None:
            text = _get_body_text(html_body)

    truncated = len(text) > body_cap
    atts = []
    for i, part in enumerate(_attachments(msg)):
        data = _get_attachment_data(part)
        atts.append({"index": i, "filename": part.get_filename() or f"attachment-{i}",
                     "content_type": part.get_content_type(), "size": len(data)})
    return {
        "message_id": str(msg.get("Message-ID", "")), "date": str(msg.get("Date", "")), "from": str(msg.get("From", "")),
        "to": str(msg.get("To", "")), "cc": str(msg.get("Cc", "")), "subject": str(msg.get("Subject", "")),
        "in_reply_to": str(msg.get("In-Reply-To", "")), "references": str(msg.get("References", "")),
        "text": text[:body_cap], "truncated": truncated, "attachments": atts,
    }


def attachment(raw: bytes, index: int) -> tuple[str, str, bytes, str | None]:
    """(filename, content type, decoded bytes, declared charset or None)."""
    parts = _attachments(_parse(raw))
    part = parts[index]
    data = _get_attachment_data(part)
    return part.get_filename() or f"attachment-{index}", part.get_content_type(), data, part.get_content_charset()
