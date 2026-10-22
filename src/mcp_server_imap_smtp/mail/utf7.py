# SPDX-License-Identifier: AGPL-3.0-or-later
"""IMAP modified UTF-7 (RFC 3501 §5.1.3) for mailbox names."""
from __future__ import annotations

import base64


def _b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-16-be")).decode().rstrip("=").replace("/", ",")


def encode(name: str) -> str:
    out, buf = [], []
    for ch in name:
        if 0x20 <= ord(ch) <= 0x7E:
            if buf:
                out.append("&" + _b64("".join(buf)) + "-"); buf = []
            out.append("&-" if ch == "&" else ch)
        else:
            buf.append(ch)
    if buf:
        out.append("&" + _b64("".join(buf)) + "-")
    return "".join(out)


def decode(name: str) -> str:
    try:
        out, i = [], 0
        while i < len(name):
            ch = name[i]
            if ch != "&":
                out.append(ch); i += 1; continue
            end = name.index("-", i)
            chunk = name[i + 1:end]
            if not chunk:
                out.append("&")
            else:
                b = chunk.replace(",", "/")
                out.append(base64.b64decode(b + "=" * (-len(b) % 4), validate=True).decode("utf-16-be"))
            i = end + 1
        return "".join(out)
    except ValueError:
        # Any malformed segment: return raw input unchanged
        return name
