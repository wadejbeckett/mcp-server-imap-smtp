# SPDX-License-Identifier: AGPL-3.0-or-later
"""Drive the real smtp.send over a socketpair against a scripted SMTP server thread.

No network and no credentials: Connector.tls_connect is patched to hand back the client end.
This is what exercises the _SMTP subclass on every supported Python version."""
import base64
import socket
import threading

import pytest

from mcp_server_imap_smtp.mail import compose, smtp
from mcp_server_imap_smtp.mail.hosts import Connector, MailServer
from mcp_server_imap_smtp.mail.imap import MailAuthError, MailError

ADDR = "me@x.co.za"
SECRET = "s3cret-pässwörd-✓"


class ScriptedServer(threading.Thread):
    """A minimal SMTP server: 220, EHLO, AUTH PLAIN/LOGIN, MAIL, RCPT, DATA, QUIT."""

    def __init__(self, sock, *, password=SECRET, auth_code=None, mechs="PLAIN LOGIN", greeting="220 mail.test ESMTP",
                 mail_code="250 OK", refuse=(), data_code="250 queued", hang_up_after=None, extensions="8BITMIME"):
        super().__init__(daemon=True)
        self.sock, self.password, self.auth_code, self.mechs = sock, password, auth_code, mechs
        self.greeting, self.mail_code, self.refuse, self.data_code = greeting, mail_code, set(refuse), data_code
        self.hang_up_after, self.extensions = hang_up_after, extensions
        self.commands, self.rcpts, self.data, self.credentials = [], [], b"", None
        self.quit_seen = False
        self.sock.settimeout(10)

    def _send(self, line):
        self.sock.sendall(line.encode() + b"\r\n")

    def _plain(self, b64):
        _, user, pw = base64.b64decode(b64).decode("utf-8").split("\0")
        self.credentials = (user, pw)

    def _auth_result(self):
        if self.auth_code:  # scripted reply, whatever the credentials were
            self._send(self.auth_code)
        elif self.credentials == (ADDR, self.password):
            self._send("235 2.7.0 Authentication successful")
        else:
            self._send("535 5.7.8 Authentication failed")

    def run(self):
        f = self.sock.makefile("rb")
        try:
            self._send(self.greeting)
            if not self.greeting.startswith("220"):
                return
            while True:
                line = f.readline().rstrip(b"\r\n").decode("utf-8", "replace")
                if not line:
                    return
                self.commands.append(line.split(" ")[0].upper())
                if self.hang_up_after and self.commands.count(self.hang_up_after):
                    return
                verb = line.upper()
                if verb.startswith("EHLO"):
                    self.ehlo_name = line.split(" ", 1)[1]
                    ext = "".join(f"250-{e}\r\n" for e in self.extensions.split())
                    self.sock.sendall(f"250-mail.test\r\n{ext}250 AUTH {self.mechs}\r\n".encode())
                elif verb.startswith("AUTH PLAIN"):
                    self._plain(line.split(" ", 2)[2])
                    self._auth_result()
                elif verb.startswith("AUTH LOGIN"):
                    parts = line.split(" ", 2)
                    user = base64.b64decode(parts[2]).decode() if len(parts) > 2 else None
                    if user is None:
                        self._send("334 " + base64.b64encode(b"Username:").decode())
                        user = base64.b64decode(f.readline().strip()).decode()
                    self._send("334 " + base64.b64encode(b"Password:").decode())
                    pw = base64.b64decode(f.readline().strip()).decode("utf-8")
                    self.credentials = (user, pw)
                    self._auth_result()
                elif verb.startswith("MAIL FROM"):
                    self.mail_from = line
                    self._send(self.mail_code)
                elif verb.startswith("RCPT TO"):
                    addr = line.split("<", 1)[1].split(">", 1)[0]
                    if addr in self.refuse:
                        self._send("550 5.1.1 no such user")
                    else:
                        self.rcpts.append(addr)
                        self._send("250 OK")
                elif verb.startswith("DATA"):
                    self._send("354 go ahead")
                    buf = b""
                    while not buf.endswith(b"\r\n.\r\n"):
                        buf += f.readline()
                    self.data = buf
                    self._send(self.data_code)
                elif verb.startswith("QUIT"):
                    self.quit_seen = True
                    self._send("221 bye")
                    return
                elif verb.startswith("RSET"):
                    self._send("250 OK")
                else:
                    self._send("502 not implemented")
        except OSError:
            pass
        finally:
            f.close()
            self.sock.close()


@pytest.fixture
def wire(monkeypatch):
    """wire(**server_options) -> (client_sock, server, mail_server); patches tls_connect to return client_sock."""
    started = []

    def make(**options):
        client, server_end = socket.socketpair()
        server = ScriptedServer(server_end, **options)
        monkeypatch.setattr(Connector, "tls_connect", lambda self, port, timeout=10.0: client)
        server.start()
        started.append((client, server))
        return client, server, MailServer("mail1.hosting.example")

    yield make
    for client, server in started:
        client.close()
        server.join(timeout=5)
        assert not server.is_alive()


def msg(**kw):
    args = dict(from_addr=ADDR, to=["a@b.co"], subject="Hi", text="body")
    args.update(kw)
    return compose.new(**args)


def chain(exc):
    seen = []
    while exc is not None and exc not in seen:
        seen.append(exc)
        exc = exc.__cause__ or exc.__context__
    return seen


def test_send_returns_accepted_recipients_and_keeps_bcc_out_of_headers(wire):
    client, server, mail_server = wire()
    m = msg(to=["a@b.co"], cc=["c@b.co"], bcc=["hidden@b.co"])
    accepted = smtp.send(mail_server, ADDR, SECRET, m, bcc=["hidden@b.co"])
    assert accepted == ["a@b.co", "c@b.co", "hidden@b.co"]
    server.join(timeout=5)
    assert server.rcpts == ["a@b.co", "c@b.co", "hidden@b.co"]
    assert server.mail_from.lower().startswith(f"mail from:<{ADDR}>")
    assert b"hidden@b.co" not in server.data and b"Bcc" not in server.data
    assert b"To: a@b.co" in server.data and b"Cc: c@b.co" in server.data
    assert server.credentials == (ADDR, SECRET)  # non-ASCII password went across intact (PLAIN, UTF-8)
    assert server.quit_seen and client.fileno() == -1


def test_ascii_password_over_login_only_server(wire):
    client, server, mail_server = wire(mechs="LOGIN", password="plain-secret")
    assert smtp.send(mail_server, ADDR, "plain-secret", msg()) == ["a@b.co"]
    assert client.fileno() == -1


def test_non_ascii_password_needs_plain(wire):
    client, server, mail_server = wire(mechs="LOGIN")
    with pytest.raises(MailError) as info:
        smtp.send(mail_server, ADDR, SECRET, msg())
    assert SECRET not in "".join(str(e) + repr(e) for e in chain(info.value))
    assert client.fileno() == -1


def test_auth_failure_is_mailautherror_without_password(wire):
    client, server, mail_server = wire()
    with pytest.raises(MailAuthError) as info:
        smtp.send(mail_server, ADDR, "wrong-" + SECRET, msg())
    for e in chain(info.value):
        assert "wrong-" + SECRET not in str(e) + repr(e) and SECRET not in str(e) + repr(e)
    assert "MAIL" not in server.commands
    assert client.fileno() == -1


def test_temporary_auth_failure_is_mailerror_not_auth(wire):
    client, server, mail_server = wire(auth_code="454 4.7.0 Temporary authentication failure")
    with pytest.raises(MailError) as info:
        smtp.send(mail_server, ADDR, SECRET, msg())
    assert not isinstance(info.value, MailAuthError) and "454" in str(info.value)
    assert "MAIL" not in server.commands and client.fileno() == -1


def test_password_with_nul_is_refused_before_connecting(wire):
    client, server, mail_server = wire()
    with pytest.raises(MailAuthError):
        smtp.send(mail_server, ADDR, "bad\0pass", msg())
    client.close()
    server.join(timeout=5)
    assert server.commands == []  # nothing was ever sent


def test_refused_recipient_is_excluded(wire):
    client, server, mail_server = wire(refuse=["c@b.co"])
    accepted = smtp.send(mail_server, ADDR, SECRET, msg(cc=["c@b.co"]))
    assert accepted == ["a@b.co"]
    assert client.fileno() == -1


def test_all_recipients_refused_is_mailerror(wire):
    client, server, mail_server = wire(refuse=["a@b.co"])
    with pytest.raises(MailError):
        smtp.send(mail_server, ADDR, SECRET, msg())
    assert client.fileno() == -1


def test_mail_from_rejected_is_mailerror_not_auth(wire):
    client, server, mail_server = wire(mail_code="553 5.7.1 sender not allowed")
    with pytest.raises(MailError) as info:
        smtp.send(mail_server, ADDR, SECRET, msg())
    assert not isinstance(info.value, MailAuthError)
    assert "553" in str(info.value)
    assert client.fileno() == -1


def test_data_rejected_is_mailerror(wire):
    client, server, mail_server = wire(data_code="554 5.7.1 rejected as spam")
    with pytest.raises(MailError):
        smtp.send(mail_server, ADDR, SECRET, msg())
    assert client.fileno() == -1


def test_bad_greeting_is_mailerror(wire):
    client, server, mail_server = wire(greeting="554 no service")
    with pytest.raises(MailError):
        smtp.send(mail_server, ADDR, SECRET, msg())
    assert client.fileno() == -1


def test_connection_dropped_mid_session_is_mailerror(wire):
    client, server, mail_server = wire(hang_up_after="MAIL")
    with pytest.raises(MailError):
        smtp.send(mail_server, ADDR, SECRET, msg())
    assert client.fileno() == -1


def test_bcc_injection_is_refused_before_connecting(wire):
    client, server, mail_server = wire()
    with pytest.raises(MailError):
        smtp.send(mail_server, ADDR, SECRET, msg(), bcc=["d@b.co>\r\nRCPT TO:<evil@x.com"])
    client.close()
    server.join(timeout=5)
    assert server.commands == []


@pytest.mark.parametrize("from_header", ["Mallory <ceo@bank.com>", "other@x.co.za", "ceo@bank.com"])
def test_from_header_must_be_the_signed_in_mailbox(wire, monkeypatch, from_header):
    client, server, mail_server = wire()
    calls = []
    monkeypatch.setattr(Connector, "tls_connect", lambda self, port, timeout=10.0: calls.append(1))
    with pytest.raises(MailError, match="From must be the signed-in mailbox"):
        smtp.send(mail_server, ADDR, SECRET, msg(from_addr=from_header))
    assert calls == []  # no connection attempted
    client.close()
    server.join(timeout=5)
    assert server.commands == []


def test_from_with_display_name_and_different_case_is_allowed(wire):
    client, server, mail_server = wire()
    assert smtp.send(mail_server, "ME@X.co.za", SECRET, msg(from_addr="Me Myself <Me@x.co.za>")) == ["a@b.co"]
    server.join(timeout=5)
    assert server.mail_from.lower().startswith("mail from:<me@x.co.za>")


def test_missing_from_header_is_refused(wire):
    client, server, mail_server = wire()
    m = msg()
    del m["From"]
    with pytest.raises(MailError, match="From must be the signed-in mailbox"):
        smtp.send(mail_server, ADDR, SECRET, m)
    client.close()
    server.join(timeout=5)
    assert server.commands == []


def test_overlapping_recipients_get_one_rcpt_and_are_returned_once(wire):
    client, server, mail_server = wire()
    m = msg(to=["a@b.co"], cc=["A@B.co"])
    assert smtp.send(mail_server, ADDR, SECRET, m, bcc=["a@b.co", "z@b.co"]) == ["a@b.co", "z@b.co"]
    server.join(timeout=5)
    assert server.rcpts == ["a@b.co", "z@b.co"]


def test_local_hostname_is_used_for_ehlo(wire):
    client, server, mail_server = wire()
    smtp.send(mail_server, ADDR, SECRET, msg(), local_hostname="hosted.mcp.test")
    server.join(timeout=5)
    assert server.ehlo_name == "hosted.mcp.test"


@pytest.mark.parametrize("mechs", ["PLAIN LOGIN", "LOGIN"])
@pytest.mark.parametrize("reply", ["504 5.5.4 Unrecognized authentication type",
                                   "530 5.7.0 Must issue a STARTTLS command first",
                                   "454 4.7.0 Temporary authentication failure",
                                   "534 5.7.9 Authentication mechanism is too weak"])
def test_auth_failures_other_than_bad_credentials_are_not_autherror(wire, mechs, reply):
    client, server, mail_server = wire(auth_code=reply, mechs=mechs, password="plain-secret")
    with pytest.raises(MailError) as info:
        smtp.send(mail_server, ADDR, "plain-secret", msg())
    code = reply.split()[0]
    assert not isinstance(info.value, MailAuthError) and str(info.value) == f"SMTP AUTH failed with {code}"
    assert "MAIL" not in server.commands and client.fileno() == -1


@pytest.mark.parametrize("mechs", ["PLAIN LOGIN", "LOGIN"])
@pytest.mark.parametrize("reply", ["535 5.7.8 Authentication credentials invalid", "535 Authentication failed",
                                   "554 5.7.8 Error: authentication failed"])
def test_bad_credentials_replies_are_autherror(wire, mechs, reply):
    client, server, mail_server = wire(auth_code=reply, mechs=mechs, password="plain-secret")
    with pytest.raises(MailAuthError):
        smtp.send(mail_server, ADDR, "plain-secret", msg())
    assert client.fileno() == -1


def test_eight_bit_body_declares_8bitmime(wire):
    client, server, mail_server = wire()
    smtp.send(mail_server, ADDR, SECRET, msg(text="Héllo wörld"))
    server.join(timeout=5)
    assert server.mail_from.upper().endswith(" BODY=8BITMIME")


def test_ascii_body_sends_no_body_parameter(wire):
    client, server, mail_server = wire()
    smtp.send(mail_server, ADDR, SECRET, msg(text="plain ascii"))
    server.join(timeout=5)
    assert "BODY=" not in server.mail_from.upper()


def test_no_8bitmime_parameter_when_the_server_does_not_offer_it(wire):
    client, server, mail_server = wire(extensions="")
    smtp.send(mail_server, ADDR, SECRET, msg(text="Héllo wörld"))
    server.join(timeout=5)
    assert "BODY=" not in server.mail_from.upper()
