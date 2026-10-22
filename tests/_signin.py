# SPDX-License-Identifier: AGPL-3.0-or-later
"""A successful sign-in answers with a "connected" page whose Continue link carries the code."""
import html
import re

_LINK = re.compile(r'<a class="b" href="([^"]+)"')


def connected(r) -> bool:
    return r.status_code == 200 and " connected</h1>" in r.text


def location(r) -> str:
    """The redirect (with code and state) that a successful sign-in hands to the AI app."""
    assert connected(r), (r.status_code, r.text[:300])
    return html.unescape(_LINK.search(r.text)[1])
