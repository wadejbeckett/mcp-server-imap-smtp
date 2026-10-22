# SPDX-License-Identifier: AGPL-3.0-or-later
import pytest
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses
from mcp_server_imap_smtp.mail import compose
from mcp_server_imap_smtp.mail.imap import MailError


def original():
    m = EmailMessage(); m["From"] = "Client <c@client.co.za>"; m["To"] = "me@x.co.za"; m["Cc"] = "ops@x.co.za, other@z.com"
    m["Subject"] = "Quote"; m["Message-ID"] = "<abc@client>"; m["References"] = "<root@client>"; m.set_content("need a quote")
    return m.as_bytes()


def test_new_has_bcc_out_of_headers():
    m = compose.new("me@x.co.za", ["a@b.co"], "Hi", "body", bcc=["hidden@b.co"])
    assert m["From"] == "me@x.co.za" and m["Bcc"] is None and m["Message-ID"]
    assert compose.envelope_recipients(m, bcc=["hidden@b.co"]) == ["a@b.co", "hidden@b.co"]


def test_new_includes_cc_in_envelope_and_html_alternative():
    m = compose.new("me@x.co.za", ["a@b.co"], "Hi", "body", html="<p>body</p>", cc=["c@b.co"])
    assert m["Cc"] == "c@b.co"
    assert compose.envelope_recipients(m) == ["a@b.co", "c@b.co"]
    assert m.get_body(("html",)).get_content().strip() == "<p>body</p>"


def test_envelope_takes_address_part_of_bcc_display_form():
    m = compose.new("me@x.co.za", ["a@b.co"], "Hi", "body")
    assert compose.envelope_recipients(m, bcc=["Hidden <hidden@b.co>"]) == ["a@b.co", "hidden@b.co"]


def test_reply_threads():
    m = compose.reply(original(), "me@x.co.za", "R5000")
    assert m["Subject"] == "Re: Quote" and m["In-Reply-To"] == "<abc@client>"
    assert m["References"] == "<root@client> <abc@client>" and m["To"] == "Client <c@client.co.za>"
    assert "> need a quote" in m.get_body().get_content()


def test_reply_all_excludes_self():
    m = compose.reply(original(), "me@x.co.za", "ok", reply_all=True)
    assert "other@z.com" in m["Cc"] and "me@x.co.za" not in (m["Cc"] or "")


def test_forward_attaches_original():
    m = compose.forward(original(), "me@x.co.za", ["boss@x.co.za"], "FYI")
    assert m["Subject"] == "Fwd: Quote"
    assert any(p.get_content_type() == "message/rfc822" for p in m.iter_attachments())


# Header injection: CR/LF in any header value we set is refused, not folded into a new header.
INJECT = "x\r\nBcc: evil@x.com"


@pytest.mark.parametrize("kwargs", [
    dict(subject=INJECT),
    dict(to=["a@b.co" + INJECT]),
    dict(to=[INJECT + "@b.co"]),
    dict(cc=["c@b.co" + INJECT]),
    dict(bcc=["d@b.co" + INJECT]),
    dict(from_addr="me@x.co.za" + INJECT),
    dict(subject="a\nb"),
    dict(subject="a\rb"),
])
def test_new_refuses_header_injection(kwargs):
    args = dict(from_addr="me@x.co.za", to=["a@b.co"], subject="Hi", text="body")
    args.update(kwargs)
    with pytest.raises(MailError):
        compose.new(**args)


def test_forward_refuses_injection_in_recipient():
    with pytest.raises(MailError):
        compose.forward(original(), "me@x.co.za", ["boss@x.co.za" + INJECT], "FYI")


def test_envelope_refuses_injection_in_bcc():
    m = compose.new("me@x.co.za", ["a@b.co"], "Hi", "body")
    with pytest.raises(MailError):
        compose.envelope_recipients(m, bcc=["d@b.co>\r\nRCPT TO:<evil@x.com"])


@pytest.mark.parametrize("bad", ["", "   ", "plain", "a@@b.co", "a@b@c.co", "Name <>", "<@b.co>", "a b@c.co", "a@b.co, c@d.co"])
def test_recipient_validation(bad):
    with pytest.raises(MailError):
        compose.new("me@x.co.za", [bad], "Hi", "body")
    with pytest.raises(MailError):
        compose.forward(original(), "me@x.co.za", [bad], "FYI")


def test_recipient_with_display_name_is_accepted():
    m = compose.new("me@x.co.za", ["Ann Lee <ann@b.co>"], "Hi", "body")
    assert compose.envelope_recipients(m) == ["ann@b.co"]


def test_reply_to_message_with_long_folded_headers():
    raw = (b"From: Client <c@client.co.za>\r\nTo: me@x.co.za\r\n"
           b"Subject: " + b"A very long subject line " * 6 + b"\r\n"
           b"Message-ID: <abc@client>\r\nReferences: " + b" ".join(b"<r%d@client.example.com>" % i for i in range(8)) + b"\r\n"
           b"\r\nbody\r\n")
    m = compose.reply(raw, "me@x.co.za", "ok")
    assert m["In-Reply-To"] == "<abc@client>" and m["References"].endswith("<r7@client.example.com> <abc@client>")
    assert m["Subject"].startswith("Re: A very long subject line")


def test_reply_to_message_without_ids_has_no_empty_threading_headers():
    m = compose.reply(b"From: c@client.co.za\r\nSubject: hi\r\n\r\nbody\r\n", "me@x.co.za", "ok")
    assert m["In-Reply-To"] is None and m["References"] is None


def comma_original(**extra):
    m = EmailMessage(); m["From"] = '"Lee, Ann" <ann@z.com>'; m["To"] = '"Doe, Jo" <me@x.co.za>, "Roe, Max" <max@z.com>'
    m["Cc"] = '"Poe, Ed" <ed@z.com>, plain@z.com'; m["Subject"] = "Quote"; m["Message-ID"] = "<abc@client>"
    for k, v in extra.items():
        m[k] = v
    m.set_content("need a quote")
    return m.as_bytes()


def test_reply_all_keeps_comma_display_names_as_single_mailboxes():
    m = compose.reply(comma_original(), "me@x.co.za", "ok", reply_all=True)
    assert [a for _, a in getaddresses([m["To"]])] == ["ann@z.com"]
    assert [a for _, a in getaddresses([m["Cc"]])] == ["max@z.com", "ed@z.com", "plain@z.com"]
    assert getaddresses([m["To"]])[0][0] == "Lee, Ann" and getaddresses([m["Cc"]])[0][0] == "Roe, Max"
    assert compose.envelope_recipients(m) == ["ann@z.com", "max@z.com", "ed@z.com", "plain@z.com"]


def test_reply_prefers_reply_to_over_from():
    m = compose.reply(comma_original(**{"Reply-To": '"Sales, Team" <sales@z.com>'}), "me@x.co.za", "ok")
    assert compose.envelope_recipients(m) == ["sales@z.com"] and m["Cc"] is None


def test_reply_all_with_reply_to_still_copies_the_sender():
    m = compose.reply(comma_original(**{"Reply-To": "sales@z.com"}), "me@x.co.za", "ok", reply_all=True)
    assert [a for _, a in getaddresses([m["To"]])] == ["sales@z.com"]
    assert [a for _, a in getaddresses([m["Cc"]])] == ["ann@z.com", "max@z.com", "ed@z.com", "plain@z.com"]


def test_reply_all_does_not_repeat_the_reply_target_or_self():
    raw = comma_original(**{"Reply-To": "MAX@z.com"})
    m = compose.reply(raw, "me@x.co.za", "ok", reply_all=True)
    assert [a.lower() for _, a in getaddresses([m["Cc"]])] == ["ann@z.com", "ed@z.com", "plain@z.com"]


def test_forward_attaches_parsed_message_not_base64():
    m = compose.forward(comma_original(), "me@x.co.za", ["boss@x.co.za"], "FYI")
    wire = BytesParser(policy=policy.default).parsebytes(m.as_bytes())
    part = next(p for p in wire.iter_attachments() if p.get_content_type() == "message/rfc822")
    assert (part.get("Content-Transfer-Encoding") or "7bit").lower() in ("7bit", "8bit", "binary")
    assert b"base64" not in m.as_bytes().lower().split(b"message/rfc822", 1)[1].split(b"\n\n", 1)[0]
    assert part.get_content()["Subject"] == "Quote" and part.get_content()["From"] == '"Lee, Ann" <ann@z.com>'


def test_envelope_recipients_are_deduplicated_case_insensitively():
    m = compose.new("me@x.co.za", ["A@b.co", "Ann <a@b.co>"], "Hi", "body", cc=["a@B.co", "c@b.co"])
    assert compose.envelope_recipients(m, bcc=["C@b.co", "hidden@b.co", "HIDDEN@b.co"]) == ["A@b.co", "c@b.co", "hidden@b.co"]
