# SPDX-License-Identifier: AGPL-3.0-or-later
"""STARTTLS for SMTP submission (587) and IMAP (143), ticket 09: the attack cases against small in-process
servers on 127.0.0.1, each with a certificate from a CA made for the test run.

Every fake server records what it read before TLS was up (`plain`) and after (`secure`), so each test can
say exactly what the connector put on the wire in cleartext: never a password, AUTH, LOGIN or mail."""
import base64
import datetime
import ipaddress
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from mcp_server_imap_smtp.auth.login import MailUnavailable, imap_verifier
from mcp_server_imap_smtp.mail import compose, hosts, smtp
from mcp_server_imap_smtp.mail.hosts import MailServer, StartTLSRefused, verified_starttls
from mcp_server_imap_smtp.mail.imap import ImapClient, MailAuthError, MailError

HOST = "localhost"
ADDR = "me@example.test"
SECRET = "s3cret-pw"


# --- certificates --------------------------------------------------------------------------------

def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _key():
    return ec.generate_private_key(ec.SECP256R1())


def _ca(cn):
    key, now = _key(), datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(cn)).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    return key, cert


def _leaf(ca, name, tmp):
    ca_key, ca_cert = ca
    key, now = _key(), datetime.datetime.now(datetime.timezone.utc)
    sans = [x509.DNSName(name)] + ([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))] if name == HOST else [])
    cert = (x509.CertificateBuilder().subject_name(_name(name)).issuer_name(ca_cert.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    path = tmp / f"{name}-{ca_cert.subject.rfc4514_string()}.pem".replace("=", "_").replace(" ", "_")
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM) + key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(path)
    return ctx


@pytest.fixture(scope="module")
def certs(tmp_path_factory):
    """Server contexts: `good` (localhost, trusted CA), `wrong_name` (trusted CA, another name), `untrusted`
    (localhost from a CA the client does not trust). The trusted CA's file is `ca_file`."""
    tmp = tmp_path_factory.mktemp("starttls-certs")
    trusted, stranger = _ca("starttls test CA"), _ca("stranger CA")
    ca_file = tmp / "ca.pem"
    ca_file.write_bytes(trusted[1].public_bytes(serialization.Encoding.PEM))
    return {"ca_file": ca_file, "good": _leaf(trusted, HOST, tmp),
            "wrong_name": _leaf(trusted, "other.example.test", tmp), "untrusted": _leaf(stranger, HOST, tmp)}


@pytest.fixture(autouse=True)
def trust_test_ca(monkeypatch, certs):
    """ssl.create_default_context(), which the connector uses, trusts the test CA and only it."""
    monkeypatch.setenv("SSL_CERT_FILE", str(certs["ca_file"]))
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)


# --- fake servers --------------------------------------------------------------------------------

class FakeServer(threading.Thread):
    """Listens on 127.0.0.1, serves one connection with self.serve(), records each line it reads."""

    def __init__(self, tls_context, **options):
        super().__init__(daemon=True)
        self.tls_context, self.options = tls_context, options
        self.plain, self.secure, self.tls_up, self.error = [], [], False, None
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.start()

    def run(self):
        try:
            conn, _ = self.listener.accept()
            conn.settimeout(10)
            self.sock, self.file = conn, conn.makefile("rb")
            try:
                self.serve()
            finally:
                self.sock.close()
        except Exception as exc:    # a client that walks away mid-script is part of several tests
            self.error = exc
        finally:
            self.listener.close()

    def send(self, data: str):
        self.sock.sendall(data.encode())

    def line(self) -> str:
        raw = self.file.readline()
        if not raw:
            raise EOFError
        verb, sep, rest = raw.decode("utf-8", "replace").rstrip("\r\n").partition(" ")
        text = verb.upper() + sep + rest if isinstance(self, FakeSMTP) else verb + sep + rest
        (self.secure if self.tls_up else self.plain).append(text)
        return text

    def upgrade(self):
        self.sock = self.tls_context.wrap_socket(self.sock, server_side=True)
        self.file, self.tls_up = self.sock.makefile("rb"), True

    def finish(self):
        self.join(timeout=10)
        assert not self.is_alive()


class FakeSMTP(FakeServer):
    """Submission with STARTTLS. Options: starttls (advertise it), starttls_reply (the line(s) sent to STARTTLS,
    in one write), plain_auth (AUTH mechanisms offered before TLS), auth (mechanisms after TLS)."""

    def serve(self):
        o = self.options
        self.send("220 mail.example ESMTP\r\n")
        while True:
            verb = self.line().upper()
            if verb.startswith("EHLO"):
                self.ehlo_name = verb.split(" ", 1)[1].lower()
                if self.tls_up:
                    self.send(f"250-mail.example\r\n250-8BITMIME\r\n250 AUTH {o.get('auth', 'PLAIN LOGIN')}\r\n")
                else:
                    ext = "250-STARTTLS\r\n" if o.get("starttls", True) else ""
                    self.send(f"250-mail.example\r\n{ext}250 AUTH {o.get('plain_auth', 'PLAIN')}\r\n")
            elif verb == "STARTTLS" and not self.tls_up:
                reply = o.get("starttls_reply", "220 2.0.0 go ahead\r\n")
                self.send(reply)
                if reply.startswith("220"):
                    self.upgrade()
            elif verb.startswith("AUTH PLAIN "):
                _, user, password = base64.b64decode(verb.split(" ", 2)[2]).split(b"\0")
                self.send("235 2.7.0 ok\r\n")
            elif verb.startswith("AUTH LOGIN"):
                self.send("334 VXNlcm5hbWU6\r\n"); self.line()
                self.send("334 UGFzc3dvcmQ6\r\n"); self.line()
                self.send("235 2.7.0 ok\r\n")
            elif verb.startswith(("MAIL FROM", "RCPT TO")):
                self.send("250 ok\r\n")
            elif verb == "DATA":
                self.send("354 go ahead\r\n")
                while self.line() != ".":
                    pass
                self.send("250 queued\r\n")
            elif verb == "QUIT":
                self.send("221 bye\r\n")
                return
            else:
                self.send("502 no\r\n")


class FakeIMAP(FakeServer):
    """IMAP with STARTTLS. Options: greeting, caps (before TLS), starttls_reply (sent to STARTTLS in one write;
    {tag} is filled in), tls_caps (after TLS)."""

    def serve(self):
        o = self.options
        self.send(o.get("greeting", "* OK ready\r\n"))
        while True:
            tag, _, rest = self.line().partition(" ")
            verb = rest.split(" ", 1)[0].upper()
            if verb == "CAPABILITY":
                caps = o.get("tls_caps", "IMAP4rev1 AUTH=PLAIN SASL-IR") if self.tls_up else \
                    o.get("caps", "IMAP4rev1 STARTTLS LOGINDISABLED")
                self.send(f"* CAPABILITY {caps}\r\n{tag} OK done\r\n")
            elif verb == "STARTTLS" and not self.tls_up:
                reply = o.get("starttls_reply", "{tag} OK begin TLS\r\n").format(tag=tag)
                self.send(reply)
                if " OK " in reply.split("\r\n")[0]:
                    self.upgrade()
            elif verb in ("LOGIN", "AUTHENTICATE"):
                self.send(f"{tag} OK logged in\r\n")
            elif verb == "LOGOUT":
                self.send(f"* BYE bye\r\n{tag} OK done\r\n")
                return
            else:
                self.send(f"{tag} BAD unknown\r\n")


def smtp_server(fake, **kw):
    return MailServer(HOST, smtp_security="starttls", smtp_port=fake.port, ehlo_name="mcp.example.test", **kw)


def imap_server(fake):
    return MailServer(HOST, imap_security="starttls", imap_port=fake.port)


def message():
    return compose.new(from_addr=ADDR, to=["you@example.test"], subject="Hi", text="body")


SENSITIVE = ("AUTH", "LOGIN", "AUTHENTICATE", "MAIL", "RCPT", "DATA", SECRET.upper())


def assert_nothing_secret(lines):
    for line in lines:
        assert not line.upper().startswith(SENSITIVE[:-1]), line
        assert SECRET.upper() not in line.upper() and base64.b64encode(SECRET.encode()).decode() not in line


# --- SMTP --------------------------------------------------------------------------------------------

def test_smtp_starttls_sends_only_after_a_verified_upgrade(certs):
    fake = FakeSMTP(certs["good"])
    assert smtp.send(smtp_server(fake), ADDR, SECRET, message()) == ["you@example.test"]
    fake.finish()
    assert fake.plain == ["EHLO mcp.example.test", "STARTTLS"]
    assert fake.secure[0] == "EHLO mcp.example.test"           # asked again after TLS
    assert any(line.startswith("AUTH PLAIN ") for line in fake.secure) and "QUIT" in fake.secure


def test_smtp_capabilities_from_before_tls_are_forgotten(certs):
    """Before TLS the server (or someone on the path) offers PLAIN; after TLS only LOGIN: LOGIN is used."""
    fake = FakeSMTP(certs["good"], plain_auth="PLAIN", auth="LOGIN")
    smtp.send(smtp_server(fake), ADDR, SECRET, message())
    fake.finish()
    assert any(line.startswith("AUTH LOGIN") for line in fake.secure)
    assert not any(line.startswith("AUTH PLAIN") for line in fake.secure)


def test_smtp_server_without_starttls_is_refused_with_only_quit(certs):
    fake = FakeSMTP(certs["good"], starttls=False)
    with pytest.raises(MailError, match="does not offer STARTTLS"):
        smtp.send(smtp_server(fake), ADDR, SECRET, message())
    fake.finish()
    assert fake.plain == ["EHLO mcp.example.test", "QUIT"] and fake.secure == []


def test_smtp_starttls_error_reply_is_refused(certs):
    fake = FakeSMTP(certs["good"], starttls_reply="454 4.7.0 TLS not available\r\n")
    with pytest.raises(MailError, match="STARTTLS"):
        smtp.send(smtp_server(fake), ADDR, SECRET, message())
    fake.finish()
    assert fake.plain == ["EHLO mcp.example.test", "STARTTLS", "QUIT"] and fake.secure == []


@pytest.mark.parametrize("cert", ["wrong_name", "untrusted"])
def test_smtp_certificate_that_does_not_verify_is_refused(certs, cert):
    fake = FakeSMTP(certs[cert])
    with pytest.raises(ssl.SSLCertVerificationError):
        smtp.send(smtp_server(fake), ADDR, SECRET, message())
    fake.finish()
    assert fake.plain == ["EHLO mcp.example.test", "STARTTLS"] and fake.secure == []


def test_smtp_data_sent_with_the_starttls_reply_is_refused(certs):
    """A reply that arrives in the same packet as "220 go ahead" would be read after the handshake as if
    the server had said it over TLS."""
    fake = FakeSMTP(certs["good"], starttls_reply="220 go ahead\r\n250-mail.example\r\n250 AUTH PLAIN\r\n")
    with pytest.raises(MailError, match="before the TLS handshake"):
        smtp.send(smtp_server(fake), ADDR, SECRET, message())
    fake.finish()
    assert fake.plain == ["EHLO mcp.example.test", "STARTTLS"] and fake.secure == []


def test_smtp_ehlo_name_comes_from_configuration_never_getfqdn(certs, monkeypatch):
    def no_getfqdn(*a):
        raise AssertionError("getfqdn must not be used")
    monkeypatch.setattr(socket, "getfqdn", no_getfqdn)
    fake = FakeSMTP(certs["good"])
    smtp.send(smtp_server(fake), ADDR, SECRET, message())
    fake.finish()
    assert fake.ehlo_name == "mcp.example.test"


def test_smtp_without_any_ehlo_name_uses_the_local_address_literal(certs, monkeypatch):
    monkeypatch.setattr(socket, "getfqdn", lambda *a: pytest.fail("getfqdn must not be used"))
    fake = FakeSMTP(certs["good"])
    smtp.send(MailServer(HOST, smtp_security="starttls", smtp_port=fake.port), ADDR, SECRET, message())
    fake.finish()
    assert fake.ehlo_name == "[127.0.0.1]"


# --- IMAP --------------------------------------------------------------------------------------------

def test_imap_starttls_logs_in_only_after_a_verified_upgrade(certs):
    fake = FakeIMAP(certs["good"])
    with ImapClient.open(imap_server(fake), ADDR, SECRET):
        pass
    fake.finish()
    assert [line.split(" ", 1)[1] for line in fake.plain] == ["CAPABILITY", "STARTTLS"]
    verbs = [line.split(" ")[1] for line in fake.secure]
    assert verbs[0] == "CAPABILITY"                     # asked again after TLS
    secret = base64.b64encode(f"\0{ADDR}\0{SECRET}".encode()).decode()
    assert any(line.endswith(f"AUTHENTICATE PLAIN {secret}") for line in fake.secure)   # SASL-IR, one line


def test_imap_without_sasl_ir_after_tls_uses_login(certs):
    """Before TLS the capabilities said AUTH=PLAIN SASL-IR; after TLS they do not: they are forgotten."""
    fake = FakeIMAP(certs["good"], caps="IMAP4rev1 STARTTLS AUTH=PLAIN SASL-IR", tls_caps="IMAP4rev1")
    with ImapClient.open(imap_server(fake), ADDR, SECRET):
        pass
    fake.finish()
    assert any(line.split(" ")[1] == "LOGIN" for line in fake.secure)
    assert not any(line.split(" ")[1] == "AUTHENTICATE" for line in fake.secure)


def test_imap_logindisabled_without_plain_is_refused_without_login(certs):
    fake = FakeIMAP(certs["good"], tls_caps="IMAP4rev1 LOGINDISABLED")
    with pytest.raises(MailError, match="LOGINDISABLED") as info:
        ImapClient.open(imap_server(fake), ADDR, SECRET)
    assert not isinstance(info.value, MailAuthError)
    fake.finish()
    assert [line.split(" ")[1] for line in fake.secure] == ["CAPABILITY", "LOGOUT"]


def test_imap_server_without_starttls_is_refused_with_only_logout(certs):
    fake = FakeIMAP(certs["good"], caps="IMAP4rev1 AUTH=PLAIN")
    with pytest.raises(MailError, match="does not offer STARTTLS"):
        ImapClient.open(imap_server(fake), ADDR, SECRET)
    fake.finish()
    assert [line.split(" ", 1)[1] for line in fake.plain] == ["CAPABILITY", "LOGOUT"] and fake.secure == []


def test_imap_starttls_error_reply_is_refused(certs):
    fake = FakeIMAP(certs["good"], starttls_reply="{tag} NO TLS not available\r\n")
    with pytest.raises(MailError, match="STARTTLS"):
        ImapClient.open(imap_server(fake), ADDR, SECRET)
    fake.finish()
    assert_nothing_secret(fake.plain)
    assert fake.secure == []


@pytest.mark.parametrize("cert", ["wrong_name", "untrusted"])
def test_imap_certificate_that_does_not_verify_is_refused(certs, cert):
    fake = FakeIMAP(certs[cert])
    with pytest.raises(ssl.SSLCertVerificationError):
        ImapClient.open(imap_server(fake), ADDR, SECRET)
    fake.finish()
    assert [line.split(" ", 1)[1] for line in fake.plain] == ["CAPABILITY", "STARTTLS"] and fake.secure == []


def test_imap_data_sent_with_the_starttls_reply_is_refused(certs):
    fake = FakeIMAP(certs["good"], starttls_reply="{tag} OK begin TLS\r\n* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\n")
    with pytest.raises(MailError, match="before the TLS handshake"):
        ImapClient.open(imap_server(fake), ADDR, SECRET)
    fake.finish()
    assert [line.split(" ", 1)[1] for line in fake.plain] == ["CAPABILITY", "STARTTLS"] and fake.secure == []


def test_imap_preauth_in_cleartext_is_refused(certs):
    fake = FakeIMAP(certs["good"], greeting="* PREAUTH welcome\r\n")
    with pytest.raises(MailError, match="PREAUTH"):
        ImapClient.open(imap_server(fake), ADDR, SECRET)
    fake.finish()
    assert_nothing_secret(fake.plain)
    assert "STARTTLS" not in " ".join(fake.plain) and fake.secure == []


def test_sign_in_check_uses_starttls(certs):
    fake = FakeIMAP(certs["good"])
    assert imap_verifier(ADDR, SECRET, imap_server(fake)) is True
    fake.finish()
    assert_nothing_secret(fake.plain)


def test_sign_in_check_reports_a_server_without_starttls_as_unavailable_not_a_wrong_password(certs):
    fake = FakeIMAP(certs["good"], caps="IMAP4rev1")
    with pytest.raises(MailUnavailable):
        imap_verifier(ADDR, SECRET, imap_server(fake))
    fake.finish()


# --- the shared helper (also for ManageSieve later) ------------------------------------------------

def test_helper_refuses_bytes_the_caller_already_buffered(certs):
    a, b = socket.socketpair()
    try:
        with pytest.raises(StartTLSRefused):
            verified_starttls(a, HOST, ssl.create_default_context(), buffered=b"* OK injected\r\n")
    finally:
        a.close(); b.close()


def test_helper_refuses_bytes_already_queued_on_the_socket(certs):
    a, b = socket.socketpair()
    try:
        b.sendall(b"250 injected\r\n")
        with pytest.raises(StartTLSRefused):
            verified_starttls(a, HOST, ssl.create_default_context())
        assert a.recv(100) == b"250 injected\r\n"     # only peeked at, and the timeout is unchanged
        assert a.gettimeout() is None
    finally:
        a.close(); b.close()


def test_helper_refuses_a_context_that_does_not_verify(certs):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    a, b = socket.socketpair()
    try:
        with pytest.raises(StartTLSRefused):
            verified_starttls(a, HOST, ctx)
    finally:
        a.close(); b.close()

