# SPDX-License-Identifier: AGPL-3.0-or-later
import base64
import random
import re
import socket
import struct
import time
import zlib
from email import policy
from email.parser import BytesParser

import httpx
import pytest

from mcp_server_imap_smtp.mail import compose, inline
from mcp_server_imap_smtp.mail.imap import MailError


def png() -> bytes:
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    ihdr = struct.pack(">IIBBBBB", 2, 2, 8, 6, 0, 0, 0)
    raw = b"".join(b"\x00" + b"\xff\xff\xff\xff" * 2 for _ in range(2))
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")


def animated_gif() -> bytes:
    """A 1x1 GIF89a with two frames, a NETSCAPE loop and 530 ms delays: a blinking cursor."""
    head = b"GIF89a" + struct.pack("<HHBBB", 1, 1, 0x80, 0, 0) + b"\xff\xa3\x01\x00\x00\x00"
    loop = b"\x21\xff\x0bNETSCAPE2.0\x03\x01\x00\x00\x00"
    frame = lambda index: (b"\x21\xf9\x04\x00" + struct.pack("<H", 53) + bytes([index]) + b"\x00"
                           + b"\x2c" + struct.pack("<HHHHB", 0, 0, 1, 1, 0) + b"\x02\x02\x44\x01\x00")
    return head + loop + frame(0) + frame(1) + b"\x3b"


def gif_frames(data: bytes) -> int:
    return data.count(b"\x21\xf9\x04")


WORDMARK = "https://brand.example.org/logo/wordmark-white.png"
CURSOR = "https://brand.example.org/email/cursor-amber.gif"
SIGNATURE = (
    '<p>Hello,</p><table><tr><td><a href="https://www.example.org"><img moz-do-not-send="false" '
    f'src="{WORDMARK}" width="122" height="40" alt="Example"></a></td></tr>'
    '<tr><td>[example] | signal<img moz-do-not-send="false" '
    f'src="{CURSOR}" width="8" height="15" alt=""></td></tr></table>')
ASSETS = {WORDMARK: png(), CURSOR: animated_gif()}


def fake_fetch(url):
    return ASSETS[url]


def parts(m):
    raw = BytesParser(policy=policy.default).parsebytes(m.as_bytes())
    return raw, [p for p in raw.walk() if p.get_content_maintype() == "image"]


def test_signature_images_become_cid_parts_of_a_related_body():
    m = compose.new("me@x.example", ["c@y.example"], "Hi", "Hello,", html=SIGNATURE, fetch=fake_fetch)
    raw, images = parts(m)
    assert raw.get_content_type() == "multipart/alternative"
    plain, related = raw.get_payload()
    assert plain.get_content_type() == "text/plain" and plain.get_content().strip() == "Hello,"
    assert related.get_content_type() == "multipart/related"
    html = related.get_payload()[0]
    assert html.get_content_type() == "text/html"
    body = html.get_content()
    assert WORDMARK not in body and CURSOR not in body and "data:" not in body
    assert [p.get_content_type() for p in images] == ["image/png", "image/gif"]
    for p in images:
        cid = p["Content-ID"].strip("<>")
        assert f'src="cid:{cid}"' in body
        assert cid.endswith("@x.example")
        assert p.get_content_disposition() == "inline"
    assert images[0].get_content() == ASSETS[WORDMARK]
    assert images[1].get_content() == ASSETS[CURSOR]          # byte for byte: the animation is kept
    assert gif_frames(images[1].get_content()) == 2
    assert [p.get_filename() for p in images] == ["wordmark-white.png", "cursor-amber.gif"]


def test_reply_embeds_images_too():
    original = b"From: Cust <c@y.example>\r\nTo: me@x.example\r\nSubject: Q\r\nMessage-ID: <1@y>\r\n\r\nhello\r\n"
    m = compose.reply(original, "me@x.example", "answer", html=SIGNATURE, fetch=fake_fetch)
    _, images = parts(m)
    assert len(images) == 2


def test_data_uri_is_decoded_and_embedded():
    uri = "data:image/png;base64," + base64.b64encode(png()).decode()
    out, images = inline.embed(f'<img alt="x" src="{uri}">', "x.example", fetch=pytest.fail)
    assert images[0].data == png() and images[0].subtype == "png"
    assert out == f'<img alt="x" src="cid:{images[0].cid}">'


def test_same_source_twice_is_one_part_and_cid_is_left_alone():
    html = f"<img src='{CURSOR}'><img src={CURSOR}><img src=\"cid:keep@x\"><img data-src=\"{WORDMARK}\" src=\"{CURSOR}\">"
    calls = []
    out, images = inline.embed(html, "x.example", fetch=lambda u: calls.append(u) or ASSETS[u])
    assert calls == [CURSOR] and len(images) == 1
    assert out.count(f'"cid:{images[0].cid}"') == 3 and 'src="cid:keep@x"' in out
    assert f'data-src="{WORDMARK}"' in out


def test_entity_in_src_is_unescaped_before_fetching():
    out, images = inline.embed('<img src="https://h.example/a.png?x=1&amp;y=2">', "x.example",
                               fetch=lambda u: png() if u == "https://h.example/a.png?x=1&y=2" else pytest.fail(u))
    assert len(images) == 1


def test_gt_inside_an_attribute_does_not_end_the_tag():
    out, images = inline.embed(f'<img alt="a > b" src="{CURSOR}">', "x.example", fetch=fake_fetch)
    assert out == f'<img alt="a > b" src="cid:{images[0].cid}">'


@pytest.mark.parametrize("src", ["http://h.example/a.png", "a.png", "file:///etc/passwd", "//h.example/a.png"])
def test_other_sources_are_refused(src):
    with pytest.raises(MailError, match="cannot be embedded"):
        inline.embed(f'<img src="{src}">', "x.example", fetch=pytest.fail)


def test_non_image_bytes_are_refused():
    with pytest.raises(MailError, match="not a PNG"):
        inline.embed(f'<img src="{CURSOR}">', "x.example", fetch=lambda u: b"<html>hi</html>")


def test_caps(monkeypatch):
    monkeypatch.setattr(inline, "MAX_IMAGES", 1)
    with pytest.raises(MailError, match="too many images"):
        inline.embed(SIGNATURE, "x.example", fetch=fake_fetch)
    monkeypatch.setattr(inline, "MAX_IMAGES", 30)
    monkeypatch.setattr(inline, "MAX_TOTAL_BYTES", len(png()) + 1)
    with pytest.raises(MailError, match="together are larger"):
        inline.embed(SIGNATURE, "x.example", fetch=fake_fetch)


def test_no_new_fetch_after_the_embed_deadline():
    ticks = iter([0.0, 0.0, inline.EMBED_DEADLINE + 1])
    with pytest.raises(MailError, match="took too long"):
        inline.embed(SIGNATURE, "x.example", fetch=fake_fetch, clock=lambda: next(ticks))


@pytest.mark.parametrize("html", ["<img " * 40_000, '<img "x" ' * 25_000, "<img alt='" + "<img " * 40_000,
                                  "<img " + "a" * 200_000])
def test_unclosed_img_tags_take_linear_time(html):
    started = time.perf_counter()
    assert inline.embed(html, "x.example", fetch=pytest.fail) == (html, [])
    assert time.perf_counter() - started < 0.5


def test_img_spans_match_the_tags_the_pattern_finds():
    pattern = re.compile(r"""<img\b(?:[^>"']|"[^"]*"|'[^']*')*>""", re.I)
    rng = random.Random(20261103)
    for _ in range(3000):
        html = "".join(rng.choice(["<img", "<IMG", "<imgx", " ", "a", ">", '"', "'", "<", "src=x"])
                       for _ in range(rng.randint(0, 25)))
        assert list(inline._img_spans(html)) == [m.span() for m in pattern.finditer(html)], html


def test_html_without_images_is_unchanged_and_needs_no_fetch():
    m = compose.new("me@x.example", ["c@y.example"], "Hi", "body", html="<p>body</p>", fetch=pytest.fail)
    assert m.get_body(("html",)).get_content().strip() == "<p>body</p>"
    assert not parts(m)[1]


# --- fetching ------------------------------------------------------------------------------

def resolver(*addresses):
    return lambda host, port, type=0: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port)) for a in addresses]


PUBLIC = resolver("93.184.215.14")


def client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_fetch_returns_bytes_from_a_public_host():
    http = client(lambda r: httpx.Response(200, content=png()))
    assert inline.fetch_https("https://h.example/a.png", http=http, resolve=PUBLIC) == png()


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.5", "169.254.169.254", "::1", "fd00::1",
                                     "::ffff:127.0.0.1", "100.64.0.1"])
def test_fetch_refuses_names_that_resolve_to_private_addresses(address):
    http = client(lambda r: pytest.fail("must not connect"))
    with pytest.raises(MailError, match="not on the public internet"):
        inline.fetch_https("https://h.example/a.png", http=http, resolve=resolver("93.184.215.14", address))


@pytest.mark.parametrize("url", ["http://h.example/a.png", "https://127.0.0.1/a.png", "https://[::1]/a.png",
                                 "https://u:p@h.example/a.png", "https://h.example:8443/a.png"])
def test_fetch_refuses_unsafe_urls(url):
    with pytest.raises(MailError):
        inline.fetch_https(url, http=client(lambda r: pytest.fail("must not connect")), resolve=PUBLIC)


def test_fetch_follows_a_few_checked_redirects():
    def handler(r):
        if r.url.path == "/old.png":
            return httpx.Response(301, headers={"location": "/new.png"})
        return httpx.Response(200, content=png())
    assert inline.fetch_https("https://h.example/old.png", http=client(handler), resolve=PUBLIC) == png()


def test_fetch_refuses_a_redirect_to_http_or_a_loop():
    with pytest.raises(MailError, match="only https"):
        inline.fetch_https("https://h.example/a.png", resolve=PUBLIC,
                           http=client(lambda r: httpx.Response(302, headers={"location": "http://h.example/a.png"})))
    with pytest.raises(MailError, match="redirects too many"):
        inline.fetch_https("https://h.example/a.png", resolve=PUBLIC,
                           http=client(lambda r: httpx.Response(302, headers={"location": "/a.png"})))


def test_fetch_caps_size_and_reports_http_errors(monkeypatch):
    monkeypatch.setattr(inline, "MAX_IMAGE_BYTES", 10)
    with pytest.raises(MailError, match="larger than 10"):
        inline.fetch_https("https://h.example/a.png", resolve=PUBLIC,
                           http=client(lambda r: httpx.Response(200, content=b"x" * 11)))
    with pytest.raises(MailError, match="HTTP 404"):
        inline.fetch_https("https://h.example/a.png", resolve=PUBLIC, http=client(lambda r: httpx.Response(404)))


def test_fetch_refuses_when_the_connected_address_is_private():
    class Stream:
        def get_extra_info(self, key):
            return ("10.0.0.5", 443) if key == "server_addr" else None
    http = client(lambda r: httpx.Response(200, content=png(), extensions={"network_stream": Stream()}))
    with pytest.raises(MailError, match="not on the public internet"):
        inline.fetch_https("https://h.example/a.png", http=http, resolve=PUBLIC)
