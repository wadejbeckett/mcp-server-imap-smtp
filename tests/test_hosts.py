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


# STARTTLS (ticket 09): the security mode per service, and the ports that follow from it

def test_security_defaults_to_implicit_tls_on_the_usual_ports():
    s = MailServer("mail1.hosting.example")
    assert (s.imap_security, s.smtp_security, s.imap_port, s.smtp_port) == ("tls", "tls", 993, 465)


def test_starttls_ports_follow_the_mode_when_no_port_is_set():
    s = MailServer("mail1.hosting.example", imap_security="starttls", smtp_security="starttls")
    assert (s.imap_port, s.smtp_port) == (143, 587)
    assert MailServer("mail1.hosting.example", smtp_security="starttls", smtp_port=2587).smtp_port == 2587


@pytest.mark.parametrize("kw", [{"smtp_security": "none"}, {"smtp_security": "plain"}, {"imap_security": "ssl"},
                                {"imap_security": "STARTTLS"}, {"smtp_security": ""}, {"imap_security": True},
                                {"smtp_security": "opportunistic"}])
def test_security_accepts_only_tls_or_starttls(kw):
    with pytest.raises(ValueError, match="no cleartext"):
        MailServer("mail1.hosting.example", **kw)


def test_ehlo_name_is_not_part_of_the_servers_identity():
    assert MailServer("mail1.hosting.example", ehlo_name="mcp.example.test") == MailServer("mail1.hosting.example")


@pytest.mark.parametrize("name", ["Bad Name", "a..b", "-x.example", "x.example."])
def test_ehlo_name_must_be_a_dns_name_or_address_literal(name):
    with pytest.raises(ValueError, match="ehlo_name"):
        MailServer("mail1.hosting.example", ehlo_name=name)


@pytest.mark.parametrize("name", ["mcp.example.test", "[192.0.2.1]", "[IPv6:2001:db8::1]"])
def test_ehlo_name_accepts_names_and_address_literals(name):
    assert MailServer("mail1.hosting.example", ehlo_name=name).ehlo_name == name
