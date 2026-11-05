# SPDX-License-Identifier: AGPL-3.0-or-later
"""Lab tests: the container mail servers from scripts/lab.sh, reached through TLS that trusts only the lab CA.
These check that the lab is what later tickets' tests rely on, and that the connector signs in to it."""
import base64
import imaplib
import smtplib
import socket
import ssl
import time
from email.message import EmailMessage

import pytest

from mcp_server_imap_smtp.mail import smtp as smtp_mod
from mcp_server_imap_smtp.mail.imap import ImapClient, MailAuthError
from tests._lab import CA_FILE, FLAT, HOST, PREFIXED, PROFILES, STRIPPED, context, require_lab, users

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


def imap_caps(profile, address=ALICE) -> set[str]:
    c = imaplib.IMAP4_SSL(HOST, profile.imaps, ssl_context=context())
    try:
        c.login(address, users()[address])
        typ, data = c.capability()
        assert typ == "OK"
        return set(data[0].decode().upper().split())
    finally:
        c.logout()


# IMAP on 993

@pytest.mark.parametrize("profile", PROFILES, ids=lambda p: p.name)
def test_connector_signs_in_over_imaps_with_lab_ca(lab_ca, profile):
    with ImapClient.open(profile.server(), ALICE, users()[ALICE]) as client:
        names = {f.name for f in client.folders()}
    assert "INBOX" in names


def test_imaps_certificate_is_verified():
    """Without the lab CA the connector's default context must refuse the lab certificate."""
    with pytest.raises(ssl.SSLCertVerificationError):
        ImapClient.open(FLAT.server(), ALICE, users()[ALICE])


def test_wrong_password_is_refused(lab_ca):
    with pytest.raises(MailAuthError):
        ImapClient.open(FLAT.server(), ALICE, "not-the-password")


def test_full_profile_advertises_the_extensions_tests_need():
    caps = imap_caps(FLAT)
    assert {"MOVE", "UIDPLUS", "ESEARCH", "SPECIAL-USE", "CONDSTORE", "QRESYNC",
            "QUOTA", "ACL", "METADATA", "NAMESPACE", "IDLE"} <= caps


def test_stripped_profile_lacks_move_uidplus_esearch():
    caps = imap_caps(STRIPPED)
    assert not {"MOVE", "UIDPLUS", "ESEARCH"} & caps
    assert {"IMAP4REV1", "SPECIAL-USE", "QUOTA"} <= caps   # everything else is still there


@pytest.mark.parametrize("profile,prefix", [(FLAT, ""), (PREFIXED, "INBOX."), (STRIPPED, "")],
                         ids=["flat", "prefixed", "stripped"])
def test_namespace_and_special_use_folders(lab_ca, profile, prefix):
    with ImapClient.open(profile.server(), ALICE, users()[ALICE]) as client:
        assert client.namespaces()["personal"] == [[prefix, "."]]
        assert client.special("sent") == f"{prefix}Sent"
        assert client.special("trash") == f"{prefix}Trash"
        assert client.special("drafts") == f"{prefix}Drafts"


def test_quota_and_acl_answer():
    c = imaplib.IMAP4_SSL(HOST, FLAT.imaps, ssl_context=context())
    try:
        c.login(ALICE, users()[ALICE])
        typ, data = c.getquotaroot("INBOX")
        assert typ == "OK" and b"STORAGE" in data[1][0]
        typ, data = c.myrights("INBOX")
        assert typ == "OK" and b"lrws" in data[0]
    finally:
        c.logout()


# SMTP submission on 465 (implicit TLS) and 587 (STARTTLS required)

SUBMISSION_EXTENSIONS = ("size", "dsn", "chunking", "smtputf8", "8bitmime", "auth")


def test_smtps_465_verified_and_advertises_extensions():
    with smtplib.SMTP_SSL(HOST, FLAT.smtps, context=context(), timeout=10) as s:
        s.ehlo()
        for ext in SUBMISSION_EXTENSIONS:
            assert s.has_extn(ext), ext
        s.login(ALICE, users()[ALICE])


def test_smtps_465_refuses_untrusted_certificate():
    with pytest.raises(ssl.SSLCertVerificationError):
        smtplib.SMTP_SSL(HOST, FLAT.smtps, context=ssl.create_default_context(), timeout=10)


def test_submission_587_requires_starttls():
    with smtplib.SMTP(HOST, FLAT.submission, timeout=10) as s:
        s.ehlo()
        assert s.has_extn("starttls")
        assert not s.has_extn("auth")          # no AUTH offered in the clear
        code, _ = s.docmd("MAIL FROM:<alice@example.test>")
        assert code == 530                     # 5.7.0 Must issue a STARTTLS command first
        s.starttls(context=context())          # verifies the certificate and the name
        s.ehlo()
        for ext in SUBMISSION_EXTENSIONS:
            assert s.has_extn(ext), ext
        s.login(ALICE, users()[ALICE])


def test_submission_refuses_a_sender_the_login_does_not_own():
    with smtplib.SMTP_SSL(HOST, FLAT.smtps, context=context(), timeout=10) as s:
        s.login(ALICE, users()[ALICE])
        s.mail(BOB)
        code, msg = s.rcpt(BOB)
        assert code == 553 and b"not owned by user" in msg
        s.rset()
        s.mail("sales@example.test")           # an identity alice is allowed to send as
        assert s.rcpt(BOB)[0] == 250


def test_connector_sends_and_mail_is_delivered(lab_ca):
    subject = f"lab delivery {time.time_ns()}"
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = ALICE, BOB, subject
    msg.set_content("Lab delivery test.")
    assert smtp_mod.send(FLAT.server(), ALICE, users()[ALICE], msg, local_hostname="lab-client") == [BOB]
    c = imaplib.IMAP4_SSL(HOST, FLAT.imaps, ssl_context=context())
    try:
        c.login(BOB, users()[BOB])
        for _ in range(20):                    # Postfix hands over to Dovecot LMTP within a moment
            c.select("INBOX", readonly=True)
            typ, data = c.search(None, "SUBJECT", f'"{subject}"')
            if typ == "OK" and data[0]:
                break
            time.sleep(0.5)
        assert data[0], "message did not arrive in bob's INBOX"
    finally:
        c.logout()


# ManageSieve on 4190

def _sieve_lines(f) -> list[str]:
    lines = []
    while True:
        line = f.readline().decode().rstrip("\r\n")
        lines.append(line)
        if line.startswith(("OK", "NO", "BYE")):
            return lines


def test_managesieve_greeting_and_starttls_login():
    raw = socket.create_connection((HOST, FLAT.sieve), timeout=10)
    try:
        greeting = _sieve_lines(raw.makefile("rb"))
        caps = {line.split(" ", 1)[0].strip('"'): line.split(" ", 1)[1].strip('"') if " " in line else ""
                for line in greeting[:-1]}
        assert greeting[-1].startswith("OK")
        assert "STARTTLS" in caps and caps.get("SASL") == ""   # no login before TLS
        assert {"vacation", "fileinto", "imap4flags", "variables"} <= set(caps["SIEVE"].split())
        raw.sendall(b"STARTTLS\r\n")
        assert _sieve_lines(raw.makefile("rb"))[-1].startswith("OK")
        tls = context().wrap_socket(raw, server_hostname=HOST)
        raw = tls
        f = tls.makefile("rb")
        after = _sieve_lines(f)                 # RFC 5804: capabilities are sent again after STARTTLS
        assert any(line.startswith('"SASL"') and "PLAIN" in line for line in after)
        token = base64.b64encode(f"\0{ALICE}\0{users()[ALICE]}".encode()).decode()
        tls.sendall(f'AUTHENTICATE "PLAIN" "{token}"\r\n'.encode())
        assert _sieve_lines(f)[-1].startswith("OK")
        tls.sendall(b"LOGOUT\r\n")
    finally:
        raw.close()
