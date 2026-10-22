# SPDX-License-Identifier: AGPL-3.0-or-later
"""Embed the images of an HTML body in the message itself.

Mail clients block remote images and Gmail drops data: URIs, so each <img src> that is an https URL or a data:
URI becomes an inline part of a multipart/related HTML body, referenced by cid: (RFC 2392), the way desktop
mail clients send them. Any other src (http, relative, file) is refused rather than sent broken; cid: is kept.

Fetching a URL the AI chose is an SSRF vector, so a fetch is confined: https on port 443 only, no userinfo or
IP literals, every address the name resolves to must be public and so must the address actually connected to,
at most MAX_REDIRECTS redirects (each checked again), a deadline and a size cap enforced while streaming, and
the body must be a PNG, GIF, JPEG or WebP by its first bytes. Image bytes are never altered, so an animated GIF
stays animated.
"""
from __future__ import annotations

import base64
import binascii
import html as htmllib
import ipaddress
import re
import secrets
import socket
import time
from dataclasses import dataclass
from typing import Callable
from urllib.parse import unquote_to_bytes

import httpx

from .imap import MailError

MAX_IMAGES = 30
MAX_IMAGE_BYTES = 2_000_000
MAX_TOTAL_BYTES = 8_000_000
MAX_REDIRECTS = 3
TIMEOUT = 10.0       # per network step
DEADLINE = 20.0      # whole fetch of one image, redirects included
EMBED_DEADLINE = 30.0   # no new fetch starts after this: a message's images are fetched while a mail session is held

_IMG = re.compile(r"""<img\b(?:[^>"']|"[^"]*"|'[^']*')*>""", re.I)
_SRC = re.compile(r"""(\ssrc\s*=\s*)(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))""", re.I)
_HOSTNAME = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")
_DATA = re.compile(r"^data:([^,]*),(.*)$", re.I | re.S)
_NAME = re.compile(r"[^A-Za-z0-9._-]")


@dataclass(frozen=True)
class Image:
    cid: str          # without the angle brackets
    data: bytes
    subtype: str      # image/<subtype>
    filename: str


def sniff(data: bytes) -> str | None:
    """The image subtype by magic number, or None: only formats every mail client shows."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return None


def _public(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def _checked(url: str, resolve: Callable) -> httpx.URL:
    try:
        u = httpx.URL(url)
        host, port = u.host, u.port
    except (httpx.InvalidURL, ValueError):
        raise MailError(f"image URL is not valid: {url}") from None
    if u.scheme != "https":
        raise MailError(f"only https images can be embedded: {url}")
    if u.userinfo or port not in (None, 443) or not host or not _HOSTNAME.fullmatch(host):
        raise MailError(f"image URL must be https on the standard port, with a host name: {url}")
    try:
        ipaddress.ip_address(host)
        raise MailError(f"image URL must use a host name, not an IP address: {url}")
    except ValueError:
        pass
    try:
        addresses = {info[4][0] for info in resolve(host, 443, type=socket.SOCK_STREAM)}
    except (OSError, UnicodeError):
        raise MailError(f"could not resolve the image host: {url}") from None
    if not addresses or not all(_public(a) for a in addresses):
        raise MailError(f"image host is not on the public internet: {url}")
    return u


def fetch_https(url: str, *, http: httpx.Client | None = None, resolve: Callable = socket.getaddrinfo,
                clock: Callable[[], float] = time.monotonic) -> bytes:
    """The bytes at an https image URL, within the limits in the module docstring; MailError otherwise."""
    owned = http is None
    http = http or httpx.Client(timeout=TIMEOUT, follow_redirects=False)
    end = clock() + DEADLINE
    asked = url
    try:
        for _ in range(MAX_REDIRECTS + 1):
            u = _checked(url, resolve)
            with http.stream("GET", u, headers={"accept": "image/*"}, timeout=TIMEOUT, follow_redirects=False) as r:
                if r.is_redirect and "location" in r.headers:
                    url = str(u.join(r.headers["location"]))
                    continue
                if r.status_code != 200:
                    raise MailError(f"image {asked} could not be fetched (HTTP {r.status_code})")
                # The name was checked before connecting; the address connected to is checked too, so a
                # name that resolves differently the second time (DNS rebinding) cannot reach a private host.
                stream = r.extensions.get("network_stream")
                peer = stream.get_extra_info("server_addr") if stream is not None else None
                if peer and not _public(peer[0]):
                    raise MailError(f"image host is not on the public internet: {asked}")
                body = bytearray()
                for chunk in r.iter_bytes():
                    body += chunk
                    if len(body) > MAX_IMAGE_BYTES:
                        raise MailError(f"image {asked} is larger than {MAX_IMAGE_BYTES} bytes")
                    if clock() > end:
                        raise MailError(f"image {asked} took too long to fetch")
                return bytes(body)
        raise MailError(f"image {asked} redirects too many times")
    except httpx.HTTPError as exc:
        raise MailError(f"image {asked} could not be fetched ({exc.__class__.__name__})") from None
    finally:
        if owned:
            http.close()


def decode_data_uri(uri: str) -> bytes:
    m = _DATA.match(uri)
    if not m:
        raise MailError("a data: image is not a valid data URI")
    meta, payload = m.group(1).split(";"), m.group(2)
    if len(payload) > MAX_IMAGE_BYTES * 4 // 3 + 4 + payload.count("%") * 2:
        raise MailError(f"a data: image is larger than {MAX_IMAGE_BYTES} bytes")
    try:
        if any(p.strip().lower() == "base64" for p in meta[1:]):
            return base64.b64decode(re.sub(r"\s+", "", unquote_to_bytes(payload).decode("ascii")), validate=True)
        return unquote_to_bytes(payload)
    except (binascii.Error, UnicodeDecodeError, ValueError):
        raise MailError("a data: image is not valid base64") from None


def _filename(url: str, subtype: str, n: int) -> str:
    if url.lower().startswith("https://"):
        name = _NAME.sub("", httpx.URL(url).path.rsplit("/", 1)[-1])[:80]
        if name.strip("."):
            return name
    return f"image{n}.{'jpg' if subtype == 'jpeg' else subtype}"


def embed(html: str, domain: str, fetch: Callable[[str], bytes] = fetch_https, *,
          clock: Callable[[], float] = time.monotonic) -> tuple[str, list[Image]]:
    """(html with each https/data: <img src> rewritten to cid:, the images in order). The same source used
    twice becomes one part. Raises MailError, naming the image, when one cannot be embedded."""
    found: dict[str, Image] = {}
    total = 0
    end = clock() + EMBED_DEADLINE

    def src(s: re.Match) -> str:
        nonlocal total
        raw = next(g for g in s.groups()[1:] if g is not None)
        url = htmllib.unescape(raw).strip()
        low = url.lower()
        if low.startswith("cid:"):
            return s.group(0)
        if url not in found:
            if len(found) >= MAX_IMAGES:
                raise MailError(f"too many images; at most {MAX_IMAGES} per message")
            if low.startswith("data:"):
                data = decode_data_uri(url)
            elif low.startswith("https://"):
                if clock() > end:
                    raise MailError("the images took too long to fetch; use fewer or smaller images")
                data = fetch(url)
            else:
                shown = url if len(url) <= 200 else url[:200] + "..."
                raise MailError(f"image {shown!r} cannot be embedded: use an https URL or a data: URI")
            subtype = sniff(data)
            label = "a data: image" if low.startswith("data:") else f"image {url}"
            if subtype is None:
                raise MailError(f"{label} is not a PNG, GIF, JPEG or WebP image")
            if len(data) > MAX_IMAGE_BYTES:
                raise MailError(f"{label} is larger than {MAX_IMAGE_BYTES} bytes")
            total += len(data)
            if total > MAX_TOTAL_BYTES:
                raise MailError(f"the images together are larger than {MAX_TOTAL_BYTES} bytes")
            cid = f"img{len(found) + 1}.{secrets.token_hex(8)}@{domain}"
            found[url] = Image(cid, data, subtype, _filename(url, subtype, len(found) + 1))
        return f'{s.group(1)}"cid:{found[url].cid}"'

    out = _IMG.sub(lambda m: _SRC.sub(src, m.group(0), count=1), html)
    return out, list(found.values())
