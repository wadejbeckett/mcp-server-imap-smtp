# SPDX-License-Identifier: AGPL-3.0-or-later
"""Pure IMAP wire helpers: quoting arguments, checking flags and UID sets, parsing response data and the
patterns for response codes. Nothing here touches a connection, so the imap_ext mixins can use it without
importing the client; imap.py re-exports every name."""
from __future__ import annotations

import re
from datetime import date

from . import utf7
from .imap_types import MailError

_LIST = re.compile(rb'\((?P<flags>[^)]*)\) (?P<delim>"[^"]*"|NIL) (?P<name>.+)$')
_CTRL = re.compile(r"[\r\n\0]")
_FLAG = re.compile(r"\\?[A-Za-z0-9$_.-]+")
_UNSELECTABLE = {"\\noselect", "\\nonexistent"}

_TRANSIENT_LOGIN = re.compile(r"\[(UNAVAILABLE|SERVERBUG|INUSE|LIMIT)\]", re.IGNORECASE)
_BUSY_LOGIN = re.compile(r"\[(INUSE|LIMIT)\]", re.IGNORECASE)   # may be sent after the password was accepted


def _quote(s: str) -> str:
    if _CTRL.search(s):
        raise MailError("CR, LF and NUL are not allowed in IMAP arguments")
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _mbox(name: str) -> str:
    if _CTRL.search(name):
        raise MailError("CR, LF and NUL are not allowed in folder names")
    return _quote(utf7.encode(name))


def _check_flags(flags) -> None:
    for f in flags:
        if not _FLAG.fullmatch(f):
            raise MailError(f"invalid flag {f!r}")


def _uid_seq(uids) -> str:
    if not uids:
        raise MailError("no messages given")
    for u in uids:
        if type(u) is not int or u <= 0:
            raise MailError("message ids must be positive integers")
    return ",".join(map(str, uids))


def _parse_sexp(data: bytes) -> list:
    """Parse the parenthesised lists, quoted strings and NIL atoms of an IMAP response into
    nested Python lists, bytes and None. Raises ValueError on malformed input."""
    pos = 0

    def skip_space():
        nonlocal pos
        while data[pos:pos + 1] == b" ":
            pos += 1

    def item():
        nonlocal pos
        skip_space()
        ch = data[pos:pos + 1]
        if ch == b"(":
            pos += 1
            out = []
            while True:
                skip_space()
                if data[pos:pos + 1] == b")":
                    pos += 1
                    return out
                out.append(item())
        if ch == b'"':
            pos += 1
            buf = bytearray()
            while True:
                c = data[pos:pos + 1]
                if not c:
                    raise ValueError("unterminated string")
                if c == b"\\":
                    buf += data[pos + 1:pos + 2]
                    pos += 2
                elif c == b'"':
                    pos += 1
                    return bytes(buf)
                else:
                    buf += c
                    pos += 1
        m = re.compile(rb'[^\s()"]+').match(data, pos)
        if not m:
            raise ValueError("unexpected input")
        pos = m.end()
        return None if m.group().upper() == b"NIL" else m.group()

    items = []
    while True:
        skip_space()
        if pos >= len(data):
            return items
        items.append(item())


def _imap_date(d: date) -> str:
    return d.strftime("%d-%b-%Y")


def _login_kind(caps, password: str) -> str | None:
    """How to sign in, from the capabilities read over TLS: AUTHENTICATE PLAIN in one line when the server
    offers it with SASL-IR (RFC 4959); else LOGIN, unless LOGINDISABLED or the password is not ASCII (LOGIN
    is ASCII-only); else AUTHENTICATE PLAIN with a continuation. None: the server allows none of these."""
    if "AUTH=PLAIN" in caps and "SASL-IR" in caps:
        return "sasl-ir"
    if password.isascii() and "LOGINDISABLED" not in caps:
        return "login"
    if "AUTH=PLAIN" in caps or "LOGINDISABLED" not in caps:
        return "plain"
    return None


_RESP_CODE = re.compile(r"\s*\[([A-Za-z-]+)")
_APPENDUID = re.compile(rb"\[APPENDUID (\d+) (\d+)\]", re.IGNORECASE)


_DIGITS = re.compile(r"[0-9]{1,15}")


def limit_value(text: str) -> int | None:
    """A size limit a server announced (SMTP SIZE, IMAP APPENDLIMIT) as bytes; None for anything but ASCII
    digits, and for 0, which both define as no fixed limit."""
    text = (text or "").strip()
    return int(text) if _DIGITS.fullmatch(text) and int(text) > 0 else None
