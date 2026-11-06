# SPDX-License-Identifier: AGPL-3.0-or-later
"""Self-hosted sign-in page: one mailbox address and password, and/or any number of mailboxes pasted
one per line, each checked on its own server before anything is connected.

The pages live in auth/pages/ (ticket 81); this module is their import surface and keeps every name it
had. The tunables below are defined here and nowhere else: tests patch them on this module, so the pages
read them through it at call time (pages/common.py _surface()), never by importing them by name.
tests/test_auth_package.py enforces both."""
from __future__ import annotations

import logging

from ..mail.imap import ImapClient
from .pages import login_routes
# Private names too (_BUSY, _LINE_BREAK, _UNAVAILABLE, _STYLE): they were module globals here before the split.
from .pages.common import (
    _BUSY, _LINE_BREAK, _UNAVAILABLE, DAY, DUPLICATE, ERROR, MAX_EMAIL, MAX_PASSWORD, MAX_SHOWN_NAME, NOT_HOSTED,
    PASTE_AGAIN, TOO_SLOW, UNAVAILABLE, Entry, FormTooLarge, LoginLimits, MailboxBusy, MailUnavailable, Verifier,
    bounded, imap_verifier, moved, parse_more, read_form, return_target, security_headers, shown_name, wait_text)
from .pages.login import DONE_PAGE, PAGE
from .pages.manage import _STYLE, CONNECTION, MANAGE_PAGE, MANAGE_SIGNIN, MANAGE_TTL, REMOVE, ROW

log = logging.getLogger(__name__)

# Tunables, read through this module at call time by auth/pages/ (see the module docstring).
MAX_FORM_BYTES = 2 * 1024 * 1024   # the whole sign-in form, the same as nginx's client_max_body_size
DNS_WORKERS = 8           # sign-in DNS resolution threads at once, so slow DNS cannot take every worker thread
DNS_PER_SIGN_IN = 4       # domains one sign-in resolves at once
VERIFY_WORKERS = 8        # passwords one sign-in checks at once (after its main mailbox, which is checked alone)
VERIFY_THREADS = 32       # password-check threads for all sign-ins together, outside the shared thread pool
VERIFY_BUDGET_BASE = 60.0           # seconds a sign-in may spend on DNS and password checks ...
VERIFY_BUDGET_PER_MAILBOX = 2.0     # ... plus this much for each mailbox on the form
TUNABLES = ("MAX_FORM_BYTES", "DNS_WORKERS", "DNS_PER_SIGN_IN", "VERIFY_WORKERS", "VERIFY_THREADS",
            "VERIFY_BUDGET_BASE", "VERIFY_BUDGET_PER_MAILBOX", "ImapClient")

__all__ = [
    # the tunables
    *TUNABLES, "TUNABLES",
    # what app.py, cli.py and the tests use
    "login_routes", "LoginLimits", "Verifier", "imap_verifier", "MailUnavailable", "MailboxBusy", "parse_more",
    "wait_text", "log",
    # the rest of what this module had before the split
    "DAY", "DUPLICATE", "ERROR", "MAX_EMAIL", "MAX_PASSWORD", "MAX_SHOWN_NAME", "NOT_HOSTED", "PASTE_AGAIN",
    "TOO_SLOW", "UNAVAILABLE", "Entry", "FormTooLarge", "bounded", "moved", "read_form", "return_target",
    "security_headers", "shown_name", "PAGE", "DONE_PAGE", "MANAGE_TTL", "MANAGE_SIGNIN", "MANAGE_PAGE",
    "CONNECTION", "ROW", "REMOVE",
]
