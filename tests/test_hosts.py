# SPDX-License-Identifier: AGPL-3.0-or-later
import ssl

import pytest

from mcp_server_imap_smtp.mail import hosts
from mcp_server_imap_smtp.mail.hosts import Connector, MailServer


def test_mail_server_defaults():
    s = MailServer("mail1.hosting.example")
    assert (s.imap_port, s.smtp_port, s.domains, s.match_mx) == (993, 465, (), True)


def test_mail_server_domains_list_becomes_tuple_and_is_hashable():
    s = MailServer("mail1.hosting.example", domains=["a.co.za", "*.b.co.za", "*"])
    assert s.domains == ("a.co.za", "*.b.co.za", "*") and hash(s)


@pytest.mark.parametrize("host", ["", "Mail1.hosting.example", "https://mail1.hosting.example", "mail1.hosting.example:993", "mail1.hosting.example.",
                                  "127.0.0.1", "[::1]", "-mail1.co.za", "mail1..co.za", "mail1 hosting.example", "nëo.co.za"])
def test_mail_server_host_must_be_a_lowercase_dns_name(host):
    with pytest.raises(ValueError):
        MailServer(host)


@pytest.mark.parametrize("kw", [{"imap_port": 0}, {"smtp_port": 70000}, {"imap_port": "993"}, {"smtp_port": True},
                                {"domains": ("UPPER.co.za",)}, {"domains": ("*.",)}, {"domains": ("a.*.co.za",)},
                                {"domains": ("**",)}, {"match_mx": "yes"}])
def test_mail_server_rejects_bad_fields(kw):
    with pytest.raises(ValueError):
        MailServer("mail1.hosting.example", **kw)


class FakeContext:
    def __init__(self, calls):
        self.calls = calls

    def wrap_socket(self, raw, server_hostname):
        self.calls.append(("wrap", server_hostname))
        return "tls-socket"


def test_tls_connect_verifies_the_configured_host_only(monkeypatch):
    calls = []
    monkeypatch.setattr(hosts.socket, "create_connection", lambda addr, timeout: calls.append(("tcp", addr)) or object())
    sock = Connector(MailServer("mail1.hosting.example"), lambda: FakeContext(calls)).tls_connect(993)
    assert sock == "tls-socket"
    assert calls == [("tcp", ("mail1.hosting.example", 993)), ("wrap", "mail1.hosting.example")]


def test_tls_failure_closes_the_raw_socket_and_is_not_retried(monkeypatch):
    class Raw:
        closed = False

        def close(self):
            self.closed = True
    raw, attempts = Raw(), []

    class Failing:
        def wrap_socket(self, sock, server_hostname):
            attempts.append(server_hostname)
            err = ssl.SSLCertVerificationError("hostname mismatch")
            err.verify_code = 62
            raise err
    monkeypatch.setattr(hosts.socket, "create_connection", lambda addr, timeout: raw)
    with pytest.raises(ssl.SSLCertVerificationError):
        Connector(MailServer("mail1.hosting.example"), Failing).tls_connect(465)
    assert raw.closed and attempts == ["mail1.hosting.example"]


def test_connect_error_propagates(monkeypatch):
    def refuse(addr, timeout):
        raise OSError("timeout")
    monkeypatch.setattr(hosts.socket, "create_connection", refuse)
    with pytest.raises(OSError):
        Connector(MailServer("mail1.hosting.example")).tls_connect(993)


def test_default_context_factory_requires_verification():
    ctx = ssl.create_default_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
