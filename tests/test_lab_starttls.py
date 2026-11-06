# SPDX-License-Identifier: AGPL-3.0-or-later
"""Lab tests for ticket 09: the connector over implicit TLS (465, 993) and STARTTLS (587, 143) against the lab's
Postfix and Dovecot, with every byte written before TLS recorded (tests/_lab.py record_plaintext): only EHLO and
STARTTLS, or CAPABILITY and STARTTLS, may go out in cleartext."""
import base64
import imaplib
import smtplib
import time
from email.message import EmailMessage

import pytest

from mcp_server_imap_smtp.auth.login import imap_verifier
from mcp_server_imap_smtp.mail import smtp as smtp_mod
from mcp_server_imap_smtp.mail.imap import ImapClient, MailError
from tests._lab import CA_FILE, FLAT, HOST, PREFIXED, STRIPPED, context, record_plaintext, require_lab, users

pytestmark = pytest.mark.lab

ALICE, BOB = "alice@example.test", "bob@example.test"


@pytest.fixture(scope="module", autouse=True)
def _lab_up():
    require_lab()


@pytest.fixture
def lab_ca(monkeypatch):
    """Make ssl.create_default_context (which the connector uses) trust the lab CA, and only it."""
    monkeypatch.setenv("SSL_CERT_FILE", str(CA_FILE))
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)


def cleartext_lines(recorded: list[bytes]) -> list[str]:
    """The recorded lines, with each SMTP verb upper-cased (smtplib writes "ehlo" and "quit")."""
    lines = [line for line in b"".join(recorded).decode("ascii").split("\r\n") if line]
    return [line.split(" ", 1)[0].upper() + line[len(line.split(" ", 1)[0]):] for line in lines]


def assert_no_credentials(recorded: list[bytes], address: str):
    wire = b"".join(recorded)
    password = users()[address].encode()
    for secret in (password, base64.b64encode(password), base64.b64encode(f"\0{address}\0".encode() + password)):
        assert secret not in wire
    assert b"AUTH" not in wire.upper().replace(b"STARTTLS", b"") and b"LOGIN" not in wire.upper()


def message(subject: str) -> EmailMessage:
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = ALICE, BOB, subject
    msg.set_content("Lab STARTTLS test.")
    return msg


def wait_for(subject: str) -> None:
    c = imaplib.IMAP4_SSL(HOST, FLAT.imaps, ssl_context=context())
    try:
        c.login(BOB, users()[BOB])
        for _ in range(20):                    # Postfix hands over to Dovecot LMTP within a moment
            c.select("INBOX", readonly=True)
            typ, data = c.search(None, "SUBJECT", f'"{subject}"')
            if typ == "OK" and data[0]:
                return
            time.sleep(0.5)
        pytest.fail("message did not arrive in bob's INBOX")
    finally:
        c.logout()


# --- SMTP ------------------------------------------------------------------------------------------

def test_send_over_465_writes_nothing_in_cleartext(lab_ca, monkeypatch):
    subject = f"lab 465 {time.time_ns()}"
    with record_plaintext(monkeypatch) as recorded:
        assert smtp_mod.send(FLAT.server(), ALICE, users()[ALICE], message(subject)) == [BOB]
    assert recorded == []
    wait_for(subject)


def test_send_over_587_with_starttls(lab_ca, monkeypatch):
    subject = f"lab 587 {time.time_ns()}"
    with record_plaintext(monkeypatch) as recorded:
        assert smtp_mod.send(FLAT.server(smtp="starttls"), ALICE, users()[ALICE], message(subject)) == [BOB]
    assert cleartext_lines(recorded) == ["EHLO lab-client.example.test", "STARTTLS"]
    assert_no_credentials(recorded, ALICE)
    wait_for(subject)


def test_submission_without_starttls_is_refused(lab_ca, monkeypatch):
    """The stripped profile's submission offers no STARTTLS: the connector says so and only says QUIT."""
    with record_plaintext(monkeypatch) as recorded:
        with pytest.raises(MailError, match="does not offer STARTTLS"):
            smtp_mod.send(STRIPPED.server(smtp="starttls"), ALICE, users()[ALICE], message("never sent"))
    assert cleartext_lines(recorded) == ["EHLO lab-client.example.test", "QUIT"]


def test_stripped_submission_really_lacks_starttls():
    with smtplib.SMTP(HOST, STRIPPED.submission, timeout=10) as s:
        s.ehlo("lab-check.example.test")
        assert not s.has_extn("starttls") and not s.has_extn("auth")


# --- IMAP ------------------------------------------------------------------------------------------

def test_imap_143_requires_starttls_before_login():
    c = imaplib.IMAP4(HOST, FLAT.imap, timeout=10)
    try:
        assert "STARTTLS" in c.capabilities and "LOGINDISABLED" in c.capabilities
    finally:
        c.shutdown()


@pytest.mark.parametrize("profile", [FLAT, PREFIXED])
def test_imap_over_143_with_starttls(lab_ca, monkeypatch, profile):
    with record_plaintext(monkeypatch) as recorded:
        with ImapClient.open(profile.server(imap="starttls"), ALICE, users()[ALICE]) as c:
            assert "INBOX" in [f.name for f in c.folders()]
    # imaplib asks CAPABILITY itself on Python 3.14; before that it takes the list from Dovecot's greeting.
    # Either way STARTTLS is the last thing said in cleartext and nothing but these two is ever sent.
    sent = [line.split(" ", 1)[1] for line in cleartext_lines(recorded)]
    assert sent in (["STARTTLS"], ["CAPABILITY", "STARTTLS"])
    assert_no_credentials(recorded, ALICE)


def test_imap_over_993_writes_nothing_in_cleartext(lab_ca, monkeypatch):
    with record_plaintext(monkeypatch) as recorded:
        with ImapClient.open(FLAT.server(), ALICE, users()[ALICE]) as c:
            c.folders()
    assert recorded == []


def test_sign_in_check_against_a_starttls_server(lab_ca, monkeypatch):
    with record_plaintext(monkeypatch) as recorded:
        assert imap_verifier(ALICE, users()[ALICE], FLAT.server(imap="starttls", smtp="starttls")) is True
    assert_no_credentials(recorded, ALICE)
