# SPDX-License-Identifier: AGPL-3.0-or-later
"""The errors and value types of the IMAP client. Kept apart from imap.py so the imap_ext mixins and other
modules can use them without importing the client; imap.py re-exports every name."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date


class MailError(Exception):
    pass


class MailAuthError(MailError):
    pass


class MailBusy(MailError):
    """[INUSE] or [LIMIT] at login: not a wrong password, but possibly sent only after a right one."""


@dataclass(frozen=True)
class Folder:
    name: str
    delimiter: str
    flags: tuple[str, ...]
    special: str | None


@dataclass(frozen=True)
class SearchQuery:
    text: str | None = None
    from_: str | None = None
    to: str | None = None
    subject: str | None = None
    since: date | None = None
    before: date | None = None
    unread: bool | None = None
    flagged: bool | None = None
