# SPDX-License-Identifier: AGPL-3.0-or-later
"""SMTP submission with the mailbox's own credentials, over a Connector-verified socket: implicit TLS (SMTPS,
465) or STARTTLS (submission, 587), per the server's smtp_security."""
from __future__ import annotations

import base64
import copy
import re
import smtplib
import ssl
from email import encoders, policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr

from .compose import Stored, envelope_recipients, too_large, wire_size
from .hosts import Connector, MailServer, StartTLSRefused, address_literal, reader_buffered
from .imap import MailAuthError, MailError, limit_value
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
        if s is not None and s.sock is not None:
            s.sock.close()        # the TLS socket after STARTTLS; quit() leaves it open when QUIT fails
        sock.close()


def _ehlo_name(server: MailServer, sock) -> str:
    """The configured EHLO name, else the address literal of this end of the connection: never
    socket.getfqdn(), which would leak this machine's own name or make one up."""
    if server.ehlo_name:
        return server.ehlo_name
    try:
        return address_literal(sock.getsockname()[0])
    except (OSError, ValueError, IndexError):
        return "[127.0.0.1]"


class _Cleartext(Exception):
    """A STARTTLS refusal on which a cleartext QUIT is still safe (the server simply does not offer it)."""


def _starttls(s: _SMTP, connector: Connector, port: int) -> None:
    """RFC 3207 on a plain connection whose greeting has been read: EHLO, require STARTTLS, upgrade with the
    verified context, forget everything learnt before TLS and EHLO again. Nothing but EHLO, STARTTLS and
    (on a refusal) QUIT is ever sent in cleartext."""
    code, _ = s.ehlo()
    if code != 250 or not s.has_extn("starttls"):
        raise _Cleartext(f"the mail server does not offer STARTTLS on port {port}; set smtp_security = \"tls\" "
                         "if it speaks TLS from the start (usually port 465)")
    code, _ = s.docmd("STARTTLS")
    if code != 220:
        raise _Cleartext(f"the mail server refused STARTTLS ({code})")
    s.sock = connector.starttls(s.sock, buffered=reader_buffered(s.file))
    # As smtplib's own starttls(): the old reader and every EHLO answer from before TLS are discarded.
    s.file = None
    s.helo_resp = s.ehlo_resp = None
    s.esmtp_features = {}
    s.does_esmtp = False
    s.ehlo()


_ENHANCED = re.compile(r"\s*([245]\.\d{1,3}\.\d{1,3})\b")


def refusal(code: int, text: bytes | str) -> str:
    """What the AI is told about an SMTP refusal: the reply code, the enhanced status code when there is one
    and whether it is temporary, never the server's free text (security review 2026-10-20, A8)."""
    text = text.decode("utf-8", "replace") if isinstance(text, bytes) else str(text)
    m = _ENHANCED.match(text)
    kind = "temporary; try again later" if 400 <= code < 500 else "permanent" if 500 <= code < 600 else "unexpected"
    return f"SMTP refused: {code}" + (f" {m.group(1)}" if m else "") + f" ({kind})"


def _seven_bit(msg: EmailMessage) -> EmailMessage:
    """A copy of msg for a server that does not offer 8BITMIME: every leaf part whose content is not 7-bit
    ASCII, whatever its Content-Transfer-Encoding label says, is re-encoded as quoted-printable (text) or
    base64 (anything else), and a message/* wrapper labelled 8bit or binary is relabelled 7bit."""
    out = copy.deepcopy(msg)
    for part in list(out.walk()):
        payload = part.get_payload()
        if isinstance(payload, list) and payload and isinstance(payload[0], Stored) and not payload[0].octets.isascii():
            # An attached original carries its stored octets (compose.Stored); 8-bit ones cannot travel to
            # this server as they are, so they are parsed and their 8-bit parts re-encoded below, as a mail
            # client would.
            part.set_payload([BytesParser(policy=policy.default).parsebytes(payload[0].octets)])
    for part in out.walk():
        if part.is_multipart():
            continue
        payload = part.get_payload()
        if isinstance(payload, (str, bytes)) and payload.isascii():
            continue
        data = part.get_payload(decode=True) or b""
        del part["Content-Transfer-Encoding"]
        part.set_payload(data)
        (encoders.encode_quopri if part.get_content_maintype() == "text" else encoders.encode_base64)(part)
    for part in out.walk():
        if (part.get_content_maintype() == "message"
                and str(part.get("Content-Transfer-Encoding", "")).strip().lower() in ("8bit", "binary")):
            part.replace_header("Content-Transfer-Encoding", "7bit")
    return out


def _for_server(s: smtplib.SMTP, msg: EmailMessage, envelope: list[str]) -> tuple[EmailMessage, list[str]]:
    """The message as it goes on the wire and the MAIL FROM body parameters (RFC 5321 section 2.4: 8-bit
    content needs BODY=8BITMIME, RFC 6152). A non-ASCII envelope address makes smtplib add SMTPUTF8 and
    BODY=8BITMIME itself, so it is not added twice. When the server does not offer 8BITMIME the 8-bit parts
    are re-encoded to 7 bits; what still is not 7-bit (raw 8-bit header fields in a forwarded original) is
    refused before anything is sent."""
    if not "".join(envelope).isascii() or msg.as_bytes().isascii():
        return msg, []
    if s.has_extn("8bitmime"):
        return msg, ["BODY=8BITMIME"]
    wire = _seven_bit(msg)
    if not wire.as_bytes().isascii():
        raise MailError("the mail server does not accept 8-bit mail (no 8BITMIME) and this message cannot be "
                        "made 7-bit; send it without the forwarded original")
    return wire, []


def size_limit(s: smtplib.SMTP) -> int | None:
    """The SIZE the server announced in EHLO (RFC 1870), or None: no SIZE, SIZE without a number, or 0 (which
    RFC 1870 s4 defines as no fixed limit)."""
    return limit_value(s.esmtp_features.get("size") or "") if s.has_extn("size") else None


def nothing_sent(exc: BaseException) -> bool:
    """True for a send() failure that came before MAIL FROM (a SIZE refusal, the sign-in, the connection):
    no message can have left, so a send budget may be given back."""
    return getattr(exc, "nothing_sent", False)


def send(server: MailServer, address: str, password: str, msg: EmailMessage, bcc=(),
         local_hostname: str | None = None) -> list[str]:
    """Send msg as the mailbox through server (port server.smtp_port, implicit TLS or STARTTLS per
    server.smtp_security); returns the recipients the server accepted (To, Cc and bcc). A failure
    before MAIL FROM is marked (nothing_sent).

    local_hostname is the EHLO name; None takes server.ehlo_name (see _ehlo_name)."""
    started = []          # holds True once MAIL FROM may have gone out
    try:
        return _send(server, address, password, msg, bcc, local_hostname, started)
    except Exception as exc:
        if not started:
            exc.nothing_sent = True
        raise


def _send(server: MailServer, address: str, password: str, msg: EmailMessage, bcc, local_hostname: str | None,
          started: list) -> list[str]:
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
    connector = Connector(server)
    starttls = server.smtp_security == "starttls"
    sock = (connector.plain_connect if starttls else connector.tls_connect)(server.smtp_port)
    s = None
    try:
        sock.settimeout(30)
        s = _SMTP(sock, local_hostname or _ehlo_name(server, sock))
        code, _ = s.connect(server.host, server.smtp_port)
        if code != 220:
            raise MailError(f"SMTP greeting {code}")
        if starttls:
            _starttls(s, connector, server.smtp_port)
        else:
            s.ehlo()
        wire, options = _for_server(s, msg, [address, *rcpts])
        limit = size_limit(s)
        size = wire_size(wire) if limit is not None else 0
        if limit is not None and size > limit:      # refused before AUTH and before MAIL FROM
            raise MailError(too_large(size, limit, "the mail server (SMTP SIZE)"))
        _login(s, address, password)
        started.append(True)        # send_message starts with MAIL FROM
        refused = s.send_message(wire, from_addr=address, to_addrs=rcpts, mail_options=options)
        return [r for r in rcpts if r not in refused]
    except _Cleartext as exc:
        raise MailError(str(exc)) from None
    except StartTLSRefused as exc:
        s = None                  # nothing more is said on a connection someone may be tampering with
        raise MailError(f"STARTTLS refused: {exc}") from None
    except smtplib.SMTPRecipientsRefused as exc:
        raise MailError("mail server refused every recipient") from exc
    except smtplib.SMTPResponseException as exc:
        raise MailError(refusal(exc.smtp_code, exc.smtp_error)) from exc
    except smtplib.SMTPException as exc:
        raise MailError(f"SMTP failed ({exc.__class__.__name__})") from exc
    except ssl.SSLCertVerificationError:
        s = None
        raise                     # as from tls_connect: the caller tells the operator the certificate is not trusted
    except OSError as exc:
        raise MailError("mail server connection failed") from exc
    finally:
        _shutdown(s, sock)
