# SPDX-License-Identifier: AGPL-3.0-or-later
"""Lab checks for ticket 33: the UID of an appended message, and no folder created by a move. Dovecot sends
APPENDUID even where UIDPLUS is hidden (stripped profile), so the Message-ID fallback is covered by unit tests."""
import time
from email.message import EmailMessage

import pytest

from mcp_server_imap_smtp.mail.imap import ImapClient, MailError, SearchQuery
from tests._lab import PROFILES, record_commands, require_lab, users
from tests.test_lab import lab_ca  # noqa: F401  (fixture)

pytestmark = pytest.mark.lab
ALICE = "alice@example.test"


@pytest.fixture(scope="module", autouse=True)
def _lab_up():
    require_lab()


def message(subject: str, mid: str) -> bytes:
    m = EmailMessage(); m["From"] = ALICE; m["To"] = ALICE; m["Subject"] = subject; m["Message-ID"] = mid
    m.set_content("draft body")
    return m.as_bytes()


@pytest.mark.parametrize("profile", PROFILES, ids=lambda p: p.name)
def test_append_returns_the_uid_the_folder_shows(lab_ca, profile):
    with ImapClient.open(profile.server(), ALICE, users()[ALICE]) as c:
        drafts = c.special("drafts")
        tag, mid = f"t33-{time.time_ns()}", f"<{time.time_ns()}@lab>"
        uid = c.append(drafts, message(tag, mid), ("\\Draft",), message_id=mid)
        assert [r["uid"] for r in c.search(drafts, SearchQuery(subject=tag))[1]] == [uid]


@pytest.mark.parametrize("profile", PROFILES, ids=lambda p: p.name)
def test_move_to_a_missing_folder_sends_no_create(lab_ca, profile):
    with ImapClient.open(profile.server(), ALICE, users()[ALICE]) as c:
        tag, mid = f"t33-{time.time_ns()}", f"<{time.time_ns()}@lab>"
        uid = c.append("INBOX", message(tag, mid), (), message_id=mid)
        with record_commands(c.c) as sent:
            with pytest.raises(MailError, match="does not exist"):
                c.move("INBOX", [uid], f"missing-{time.time_ns()}")
        assert "CREATE" not in [name for name, _ in sent]
