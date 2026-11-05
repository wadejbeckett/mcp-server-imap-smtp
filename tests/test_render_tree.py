# SPDX-License-Identifier: AGPL-3.0-or-later
"""MIME read fixes from the 2026-11-04 content research (D1, D2, D3, D4, D10)."""
from mcp_server_imap_smtp.mail import render

HEAD = b"From: a@x.co.za\r\nTo: b@y.co.za\r\nSubject: s\r\nMessage-ID: <1@x>\r\nMIME-Version: 1.0\r\n"


def names(raw):
    return [(a["filename"], a["content_type"]) for a in render.summarise(raw)["attachments"]]


SIGNED_WITH_PDF = HEAD + (
    b'Content-Type: multipart/signed; boundary=S; protocol="application/pgp-signature"\r\n\r\n'
    b"--S\r\nContent-Type: multipart/mixed; boundary=M\r\n\r\n"
    b"--M\r\nContent-Type: text/plain\r\n\r\nHello body\r\n"
    b"--M\r\nContent-Type: application/pdf; name=inv.pdf\r\nContent-Disposition: attachment; filename=inv.pdf\r\n"
    b"Content-Transfer-Encoding: base64\r\n\r\nJVBERi0xLjQ=\r\n--M--\r\n"
    b"--S\r\nContent-Type: application/pgp-signature; name=signature.asc\r\n\r\nSIG\r\n--S--\r\n")


def test_d10_pdf_inside_signed_message_is_listed_and_fetched():
    s = render.summarise(SIGNED_WITH_PDF)
    assert s["text"] == "Hello body"
    assert names(SIGNED_WITH_PDF) == [("inv.pdf", "application/pdf"), ("signature.asc", "application/pgp-signature")]
    assert s["attachments"][0]["size"] == 8
    assert render.attachment(SIGNED_WITH_PDF, 0)[2] == b"%PDF-1.4"


def test_d10_list_relayed_message_lists_the_inner_pdf():
    raw = HEAD + (b"Content-Type: multipart/mixed; boundary=O\r\n\r\n"
                  b"--O\r\nContent-Type: multipart/mixed; boundary=I\r\n\r\n"
                  b"--I\r\nContent-Type: text/plain\r\n\r\nInvoice attached\r\n"
                  b"--I\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=a.pdf\r\n\r\nPDF\r\n"
                  b"--I--\r\n--O\r\nContent-Type: text/plain\r\nContent-Disposition: inline\r\n\r\nList footer\r\n--O--\r\n")
    got = names(raw)
    assert ("a.pdf", "application/pdf") in got
    assert not any(t.startswith("multipart/") for _, t in got)
    assert render.summarise(raw)["text"] == "Invoice attached"


def test_d2_calendar_beside_the_body_in_an_alternative_is_listed():
    raw = HEAD + (b"Content-Type: multipart/alternative; boundary=A\r\n\r\n"
                  b"--A\r\nContent-Type: text/plain\r\n\r\nInvite\r\n"
                  b"--A\r\nContent-Type: text/html\r\n\r\n<p>Invite</p>\r\n"
                  b"--A\r\nContent-Type: text/calendar; method=REQUEST\r\n\r\nBEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n--A--\r\n")
    assert names(raw) == [("attachment-0", "text/calendar")]


def test_html_alternative_and_inline_image_root_are_not_attachments():
    raw = HEAD + (b"Content-Type: multipart/alternative; boundary=A\r\n\r\n"
                  b"--A\r\nContent-Type: text/plain\r\n\r\nHi\r\n"
                  b"--A\r\nContent-Type: multipart/related; boundary=R\r\n\r\n"
                  b"--R\r\nContent-Type: text/html\r\n\r\n<p>Hi<img src=cid:i1></p>\r\n"
                  b"--R\r\nContent-Type: image/png\r\nContent-ID: <i1>\r\n\r\nPNG\r\n--R--\r\n--A--\r\n")
    assert names(raw) == [("attachment-0", "image/png")]


def test_d1_single_part_smime_lists_itself():
    raw = HEAD + (b'Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name=smime.p7m\r\n'
                  b"Content-Disposition: attachment; filename=smime.p7m\r\nContent-Transfer-Encoding: base64\r\n\r\n"
                  b"AAEC\r\n")
    s = render.summarise(raw)
    assert s["text"] == ""
    assert names(raw) == [("smime.p7m", "application/pkcs7-mime")]
    assert render.attachment(raw, 0)[2] == b"\x00\x01\x02"


DSN = HEAD + (b"Content-Type: multipart/report; report-type=delivery-status; boundary=R\r\n\r\n"
              b"--R\r\nContent-Type: text/plain\r\n\r\nIt failed\r\n"
              b"--R\r\nContent-Type: message/delivery-status\r\n\r\n"
              b"Reporting-MTA: dns; mx.example\r\n\r\nFinal-Recipient: rfc822; z@y.example\r\nAction: failed\r\n"
              b"Status: 5.1.1\r\n\r\n"
              b"--R\r\nContent-Type: message/global-delivery-status\r\n\r\n"
              b"Reporting-MTA: dns; mx.example\r\n\r\nFinal-Recipient: utf-8; z@y.example\r\nAction: failed\r\n\r\n"
              b"--R\r\nContent-Type: message/global-headers\r\n\r\nFrom: z@y.example\r\nSubject: hi\r\n\r\n--R--\r\n")


def test_d3_report_parts_keep_their_content():
    s = render.summarise(DSN)
    assert s["text"] == "It failed"
    types = [a["content_type"] for a in s["attachments"]]
    assert types == ["message/delivery-status", "message/global-delivery-status", "message/global-headers"]
    assert all(a["size"] > 0 for a in s["attachments"])
    status = render.attachment(DSN, 0)[2]
    assert b"Final-Recipient: rfc822; z@y.example" in status and b"Status: 5.1.1" in status
    assert b"Action: failed" in render.attachment(DSN, 1)[2]
    assert b"Subject: hi" in render.attachment(DSN, 2)[2]


def test_d4_format_flowed_is_unwrapped():
    raw = HEAD + (b"Content-Type: text/plain; charset=utf-8; format=flowed\r\n\r\n"
                  b"This is one long \r\nparagraph that was \r\nwrapped.\r\n"
                  b"> quoted soft \r\n> line\r\n"
                  b" >not a quote\r\n"
                  b"-- \r\nsig line\r\n")
    assert render.summarise(raw)["text"] == ("This is one long paragraph that was wrapped.\n"
                                             "> quoted soft line\n>not a quote\n-- \nsig line")


def test_d4_flowed_delsp_removes_the_soft_space():
    raw = HEAD + b"Content-Type: text/plain; format=flowed; delsp=yes\r\n\r\nver \r\nbinding\r\n"
    assert render.summarise(raw)["text"] == "verbinding"


def test_fixed_text_is_not_unwrapped():
    raw = HEAD + b"Content-Type: text/plain\r\n\r\nline one \r\nline two\r\n"
    assert render.summarise(raw)["text"] == "line one \r\nline two"


def test_related_root_named_by_start_is_not_an_attachment():
    raw = HEAD + (b"Content-Type: multipart/alternative; boundary=A\r\n\r\n"
                  b"--A\r\nContent-Type: text/plain\r\n\r\nHi\r\n"
                  b'--A\r\nContent-Type: multipart/related; boundary=R; start="<h@x>"\r\n\r\n'
                  b"--R\r\nContent-Type: image/png\r\nContent-ID: <i1>\r\n\r\nPNG\r\n"
                  b"--R\r\nContent-Type: text/html\r\nContent-ID: <h@x>\r\n\r\n<p>Hi</p>\r\n--R--\r\n--A--\r\n")
    assert names(raw) == [("attachment-0", "image/png")]


def test_html_shown_because_the_plain_part_is_blank_is_not_also_an_attachment():
    raw = HEAD + (b"Content-Type: multipart/mixed; boundary=M\r\n\r\n"
                  b"--M\r\nContent-Type: text/plain\r\n\r\n   \r\n"
                  b"--M\r\nContent-Type: text/html\r\n\r\n<p>Real body</p>\r\n"
                  b"--M\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=a.pdf\r\n\r\nPDF\r\n--M--\r\n")
    s = render.summarise(raw)
    assert "Real body" in s["text"]
    assert names(raw) == [("a.pdf", "application/pdf")]
    assert render.attachment(raw, 0)[0] == "a.pdf"


def test_html_beside_a_plain_body_in_mixed_is_still_listed():
    raw = HEAD + (b"Content-Type: multipart/mixed; boundary=M\r\n\r\n"
                  b"--M\r\nContent-Type: text/plain\r\n\r\nSee the page\r\n"
                  b"--M\r\nContent-Type: text/html\r\n\r\n<p>page</p>\r\n--M--\r\n")
    assert names(raw) == [("attachment-0", "text/html")]
