# SPDX-License-Identifier: AGPL-3.0-or-later
from email.message import EmailMessage
from mcp_server_imap_smtp.mail import render

def eml(html=None, text=None, attach=None):
    m = EmailMessage(); m["From"] = "A <a@x.co.za>"; m["To"] = "b@y.co.za"; m["Subject"] = "Hi"
    m["Message-ID"] = "<1@x>"; m["Date"] = "Mon, 05 Oct 2026 10:00:00 +0200"
    if text: m.set_content(text)
    if html: (m.add_alternative(html, subtype="html") if text else m.set_content(html, subtype="html"))
    if attach: m.add_attachment(attach, maintype="application", subtype="pdf", filename="inv.pdf")
    return m.as_bytes()

def test_plain():
    s = render.summarise(eml(text="hello"))
    assert s["subject"] == "Hi" and s["text"].strip() == "hello" and not s["truncated"]

def test_html_only():
    s = render.summarise(eml(html="<p>Invoice <b>R100</b></p><script>x()</script>"))
    assert "Invoice" in s["text"] and "R100" in s["text"] and "x()" not in s["text"]

def test_truncation():
    s = render.summarise(eml(text="a" * 60_000), body_cap=50_000)
    assert len(s["text"]) == 50_000 and s["truncated"]

def test_attachments():
    raw = eml(text="see attached", attach=b"%PDF-1.4 data")
    s = render.summarise(raw)
    assert s["attachments"] == [{"index": 0, "filename": "inv.pdf", "content_type": "application/pdf", "size": 13}]
    assert render.attachment(raw, 0) == ("inv.pdf", "application/pdf", b"%PDF-1.4 data", None)

def test_unknown_charset():
    # Create message with unknown charset - should not crash
    m = EmailMessage(); m["From"] = "A <a@x.co.za>"; m["Subject"] = "Test"
    m["Message-ID"] = "<1@x>"; m["Date"] = "Mon, 05 Oct 2026 10:00:00 +0200"
    m.set_content("Hello", subtype="plain")
    # Manually modify the charset to an unknown one
    raw = m.as_bytes().replace(b"charset=\"utf-8\"", b"charset=\"x-unknown\"")
    s = render.summarise(raw)
    assert "Hello" in s["text"]

def test_message_rfc822_attachment():
    # Create an inner message (plain text)
    inner = EmailMessage(); inner["From"] = "inner@x.co.za"; inner["Subject"] = "Fwd inner"
    inner.set_content("forwarded content")

    # Create outer message with inner message attached as EmailMessage object
    m = EmailMessage(); m["From"] = "A <a@x.co.za>"; m["Subject"] = "Wrapper"
    m["Message-ID"] = "<1@x>"; m["Date"] = "Mon, 05 Oct 2026 10:00:00 +0200"
    m.set_content("see attached")
    m.add_attachment(inner)  # Attach EmailMessage object directly
    raw = m.as_bytes()

    s = render.summarise(raw)
    assert s["attachments"][0]["size"] > 0
    data = render.attachment(raw, 0)[2]
    assert b"Subject: Fwd inner" in data

def test_message_rfc822_multipart_attachment():
    # Create an inner message with multipart content (text + html)
    inner = EmailMessage(); inner["From"] = "inner@x.co.za"; inner["Subject"] = "Fwd multi"
    inner.set_content("plain text content")
    inner.add_alternative("<p>html content</p>", subtype="html")

    # Create outer message with multipart inner message attached
    m = EmailMessage(); m["From"] = "A <a@x.co.za>"; m["Subject"] = "Wrapper"
    m["Message-ID"] = "<1@x>"; m["Date"] = "Mon, 05 Oct 2026 10:00:00 +0200"
    m.set_content("see attached")
    m.add_attachment(inner)  # Attach EmailMessage object directly
    raw = m.as_bytes()

    s = render.summarise(raw)
    assert s["attachments"][0]["size"] > 0
    data = render.attachment(raw, 0)[2]
    assert b"Subject: Fwd multi" in data
    assert b"plain text content" in data or b"html content" in data

def test_blank_plain_text_uses_html():
    # Create message with blank plain text but HTML content
    m = EmailMessage(); m["From"] = "A <a@x.co.za>"; m["Subject"] = "Test"
    m["Message-ID"] = "<1@x>"; m["Date"] = "Mon, 05 Oct 2026 10:00:00 +0200"
    m.set_content("   \n  ")  # Blank plain text
    m.add_alternative("<p>HTML Content</p>", subtype="html")
    raw = m.as_bytes()

    s = render.summarise(raw)
    assert "HTML Content" in s["text"]
