# SPDX-License-Identifier: AGPL-3.0-or-later
"""SMTPS submission with the mailbox's own credentials, over a Connector-verified socket."""
from __future__ import annotations

import base64
import re
import smtplib
from email.message import EmailMessage
from email.utils import parseaddr

from .compose import envelope_recipients
from .hosts import Connector, MailServer
from .imap import MailAuthError, MailError
from .resolve import normalise_address

_CTRL = re.compile(r"[\r\n\0]")


class _SMTP(smtplib.SMTP):
    """smtplib.SMTP over a socket Connector has already opened and verified. Only the socket
    factory is replaced, so connect() and the greeting handling stay smtplib's own on every
    Python version (3.11 to 3.14)."""

    def __init__(self, sock, local_hostname: str | None = None):
        self._presock = sock
        super().__init__(local_hostname=local_hostname)

    def _get_socket(self, host, port, timeout):
        return self._presock


def _auth_failure(code: int, resp) -> MailError:
    """Only a "credentials invalid" reply (535, or enhanced status 5.7.8) means the password is wrong;
    that revokes the grant. Any other refusal (504 mechanism, 530 STARTTLS, 454 temporary, 534 5.7.9
    "mechanism too weak" per RFC 4954...) is a plain MailError, so a server quirk never throws away a
    password IMAP has just accepted."""
    text = resp.decode("utf-8", "replace") if isinstance(resp, bytes) else str(resp or "")
    enhanced = text.split(None, 1)[0] if text.strip() else ""
    if code == 535 or (500 <= code < 600 and enhanced == "5.7.8"):
        return MailAuthError("mail server rejected the address or password")
    return MailError(f"SMTP AUTH failed with {code}")


def _login(s: _SMTP, user: str, password: str) -> None:
    # smtplib's AUTH PLAIN/LOGIN helpers encode credentials as ASCII, so a non-ASCII password
    # would fail inside smtplib. PLAIN is sent explicitly instead, carrying UTF-8 (RFC 4616).
    if "PLAIN" in s.esmtp_features.get("auth", "").upper().split():
        secret = b"\0" + user.encode() + b"\0" + password.encode("utf-8")
        code, resp = s.docmd("AUTH", "PLAIN " + base64.b64encode(secret).decode("ascii"))
        if code == 235:
            return
        raise _auth_failure(code, resp)
    if not password.isascii():
        raise MailError("mail server does not offer AUTH PLAIN, which this password needs")
    try:
        s.login(user, password)
    except smtplib.SMTPAuthenticationError as exc:
        raise _auth_failure(exc.smtp_code, exc.smtp_error) from exc


def _shutdown(s: _SMTP | None, sock) -> None:
    try:
        if s is not None:
            s.quit()
    except Exception:
        pass
    finally:
        sock.close()


_ENHANCED = re.compile(r"\s*([245]\.\d{1,3}\.\d{1,3})\b")


def refusal(code: int, text: bytes | str) -> str:
    """What the AI is told about an SMTP refusal: the reply code, the enhanced status code when there is one
    and whether it is temporary, never the server's free text (security review 2026-10-20, A8)."""
    text = text.decode("utf-8", "replace") if isinstance(text, bytes) else str(text)
    m = _ENHANCED.match(text)
    kind = "temporary; try again later" if 400 <= code < 500 else "permanent" if 500 <= code < 600 else "unexpected"
    return f"SMTP refused: {code}" + (f" {m.group(1)}" if m else "") + f" ({kind})"


def _body_options(s: smtplib.SMTP, msg: EmailMessage, envelope: list[str]) -> list[str]:
    """MAIL FROM parameters for the body: 8-bit content is declared with BODY=8BITMIME when the server offers
    it (RFC 6152; RFC 5321 section 2.4: without it the content must be 7-bit ASCII). A non-ASCII envelope
    address makes smtplib add SMTPUTF8 and BODY=8BITMIME itself, so it is not added twice."""
    if not "".join(envelope).isascii():
        return []
    if s.has_extn("8bitmime") and not msg.as_bytes().isascii():
        return ["BODY=8BITMIME"]
    return []


def send(server: MailServer, address: str, password: str, msg: EmailMessage, bcc=(),
         local_hostname: str | None = None) -> list[str]:
    """Send msg as the mailbox through server (port server.smtp_port); returns the recipients the
    server accepted (To, Cc and bcc).

    local_hostname is the EHLO name; None lets smtplib work it out with getfqdn()."""
    rcpts = envelope_recipients(msg, bcc)  # validated before any connection is made
    # Decided outside any except block, so no exception that mentions the password can end up
    # as __context__ of the error we raise.
    unusable = bool(_CTRL.search(password))
    if not unusable:
        try:
            password.encode("utf-8")
        except UnicodeEncodeError:
            unusable = True
    if unusable:
        raise MailAuthError("password contains characters the mail server login cannot accept")
    address, _ = normalise_address(address)
    if parseaddr(str(msg.get("From", "")))[1].lower() != address:
        raise MailError("From must be the signed-in mailbox")
    sock = Connector(server).tls_connect(server.smtp_port)
    s = None
    try:
        sock.settimeout(30)
        s = _SMTP(sock, local_hostname)
        code, _ = s.connect(server.host, server.smtp_port)
        if code != 220:
            raise MailError(f"SMTP greeting {code}")
        s.ehlo()
        _login(s, address, password)
        refused = s.send_message(msg, from_addr=address, to_addrs=rcpts, mail_options=_body_options(s, msg, [address, *rcpts]))
        return [r for r in rcpts if r not in refused]
    except smtplib.SMTPRecipientsRefused as exc:
        raise MailError("mail server refused every recipient") from exc
    except smtplib.SMTPResponseException as exc:
        raise MailError(refusal(exc.smtp_code, exc.smtp_error)) from exc
    except smtplib.SMTPException as exc:
        raise MailError(f"SMTP failed ({exc.__class__.__name__})") from exc
    except OSError as exc:
        raise MailError("mail server connection failed") from exc
    finally:
        _shutdown(s, sock)
