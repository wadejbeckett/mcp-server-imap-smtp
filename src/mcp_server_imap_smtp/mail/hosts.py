# SPDX-License-Identifier: AGPL-3.0-or-later
"""Which mail servers exist, and how to reach one. The service only ever opens sockets to a
configured MailServer, so the sign-in page cannot be aimed anywhere else (see resolve.py for how
an address is mapped to a server)."""
from __future__ import annotations

import ipaddress
import re
import socket
import ssl
from dataclasses import dataclass, field
from typing import Callable

_LABEL = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)")


class HostNotAllowed(Exception):
    """The address is malformed or its domain is not served by any configured mail server."""


def is_dns_name(name: str, *, min_labels: int = 1) -> bool:
    """A lowercase ASCII (IDNA A-label) DNS name: no scheme, port, trailing dot or IP literal."""
    if not isinstance(name, str) or not name or len(name) > 253:
        return False
    labels = name.split(".")
    return (len(labels) >= min_labels and all(_LABEL.fullmatch(label) for label in labels)
            and not labels[-1].isdigit())


def _valid_domain_pattern(pattern: str) -> bool:
    """`*` (any domain), `*.suffix` (any domain under suffix, not suffix itself) or an exact domain."""
    if pattern == "*":
        return True
    if pattern.startswith("*."):
        return is_dns_name(pattern[2:])
    return is_dns_name(pattern)


def _valid_port(port) -> bool:
    return type(port) is int and 0 < port < 65536


# How a service's connection is secured. "tls": TLS from the first byte (IMAPS 993, SMTPS 465). "starttls": a
# plain connection that must be upgraded with STARTTLS, and verified, before anything else is said (IMAP 143,
# submission 587). There is deliberately no cleartext and no opportunistic mode (RFC 8314).
SECURITY_MODES = ("tls", "starttls")
DEFAULT_PORTS = {"imap": {"tls": 993, "starttls": 143}, "smtp": {"tls": 465, "starttls": 587}}


def address_literal(ip: str) -> str:
    """An SMTP address literal (RFC 5321 s4.1.3) for an IP address: [192.0.2.1] or [IPv6:2001:db8::1]."""
    addr = ipaddress.ip_address(ip)
    return f"[IPv6:{addr.compressed}]" if addr.version == 6 else f"[{addr}]"


def is_ehlo_name(name: str) -> bool:
    """A DNS name or an address literal, the two forms RFC 5321 s4.1.1.1 allows after EHLO."""
    if is_dns_name(name):
        return True
    if isinstance(name, str) and name.startswith("[") and name.endswith("]"):
        try:
            return address_literal(name[1:-1].removeprefix("IPv6:")) == name
        except ValueError:
            return False
    return False


@dataclass(frozen=True)
class MailServer:
    """One IMAP/SMTP server. TLS verifies the certificate chain and the hostname against `host`.

    domains: addresses whose domain matches one of these patterns are served here without any DNS
    lookup (exact domain, `*.suffix`, or `*` for every domain). match_mx: also serve any domain whose
    MX host is `host` or a name under it. max_sessions: IMAP and SMTP sessions the connector holds open
    on this server at once, for all users together (mail/sessions.py); at least 2, since mail_send holds
    one of each.

    imap_security, smtp_security: "tls" (implicit TLS) or "starttls" (see SECURITY_MODES); a port left
    unset follows its mode (IMAP 993 or 143, SMTP 465 or 587). ehlo_name: the name the connector gives in
    SMTP EHLO; config.Settings fills it from the connector's public host name. It is how the connector
    introduces itself, not part of which server this is, so it is left out of equality."""
    host: str
    imap_port: int | None = None
    smtp_port: int | None = None
    domains: tuple[str, ...] = ()
    match_mx: bool = True
    max_sessions: int = 8
    imap_security: str = "tls"
    smtp_security: str = "tls"
    ehlo_name: str = field(default="", compare=False)

    def __post_init__(self):
        if isinstance(self.domains, (list, str)):
            object.__setattr__(self, "domains", tuple([self.domains] if isinstance(self.domains, str) else self.domains))
        if not is_dns_name(self.host):
            raise ValueError(f"mail server host {self.host!r} must be a lowercase DNS name (no scheme, no port)")
        for service in ("imap", "smtp"):
            mode = getattr(self, f"{service}_security")
            if not isinstance(mode, str) or mode not in SECURITY_MODES:
                raise ValueError(f'mail server {self.host}: {service}_security must be "tls" or "starttls" '
                                 "(there is no cleartext mode)")
            if getattr(self, f"{service}_port") is None:
                object.__setattr__(self, f"{service}_port", DEFAULT_PORTS[service][mode])
        if self.ehlo_name and not is_ehlo_name(self.ehlo_name):
            raise ValueError(f"mail server {self.host}: ehlo_name must be a DNS name or an address literal "
                             "such as [192.0.2.1]")
        for name in ("imap_port", "smtp_port"):
            if not _valid_port(getattr(self, name)):
                raise ValueError(f"mail server {self.host}: {name} must be an integer from 1 to 65535")
        bad = [d for d in self.domains if not isinstance(d, str) or not _valid_domain_pattern(d)]
        if bad:
            raise ValueError(f"mail server {self.host}: invalid domain pattern(s) {bad!r} "
                             "(use lowercase ASCII names, `*.suffix` or `*`)")
        if type(self.match_mx) is not bool:
            raise ValueError(f"mail server {self.host}: match_mx must be true or false")
        if type(self.max_sessions) is not int or self.max_sessions < 2:
            raise ValueError(f"mail server {self.host}: max_sessions must be a whole number, 2 or more "
                             "(mail_send holds an IMAP and an SMTP session at once)")


class StartTLSRefused(Exception):
    """The STARTTLS upgrade cannot be trusted (data already waiting before the handshake, or a context that
    would not verify). The connection must be dropped; nothing more may be said on it."""


def _waiting(sock: socket.socket) -> bool:
    """True if bytes (or the end of the stream) are already queued on sock, without waiting or consuming them."""
    previous = sock.gettimeout()
    sock.settimeout(0)
    try:
        sock.recv(1, socket.MSG_PEEK)
        return True                   # data, or b"" for a closed stream: either way not a clean handshake
    except (BlockingIOError, InterruptedError):
        return False
    finally:
        sock.settimeout(previous)


def reader_buffered(reader) -> bytes:
    """What a buffered socket reader (sock.makefile("rb"), as smtplib and imaplib before Python 3.14 use)
    already holds past the last line it returned, without waiting for more: pass it to verified_starttls."""
    if reader is None:
        return b""
    sock = getattr(getattr(reader, "raw", None), "_sock", None)
    previous = sock.gettimeout() if sock is not None else None
    if sock is not None:
        sock.settimeout(0)        # an empty buffer must not wait for the network
    try:
        return reader.peek(1) or b""
    except (BlockingIOError, InterruptedError):
        return b""
    finally:
        if sock is not None:
            sock.settimeout(previous)


def verified_starttls(sock: socket.socket, host: str, context: ssl.SSLContext,
                      buffered: bytes = b"") -> ssl.SSLSocket:
    """Upgrade a plain connection on which the server has just answered STARTTLS with "go ahead" (SMTP 220,
    IMAP OK, ManageSieve OK) to TLS, verifying the certificate chain and the name against `host`, the
    configured server name. Returns the TLS socket; the caller then forgets everything the server said
    before TLS (RFC 3207 s4.2, RFC 9051 s6.2.1, RFC 5804 s2.2) and asks again.

    buffered: whatever the caller's reader already holds past the go-ahead reply. Anything there, or already
    queued on the socket, was sent before the handshake by someone who could be anyone on the path; read
    after the handshake it would pass for the server's answer (STARTTLS response injection, the client-side
    twin of CVE-2011-0411). That is refused, as is a context that would not verify the server."""
    if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
        raise StartTLSRefused("the TLS context does not verify the server")
    if buffered or _waiting(sock):
        raise StartTLSRefused("the mail server sent data before the TLS handshake")
    return context.wrap_socket(sock, server_hostname=host)


class Connector:
    """Opens verified TLS sockets to one MailServer. There is no fallback name: the server the user
    is told about is the one whose certificate is checked."""

    def __init__(self, server: MailServer, context_factory: Callable[[], ssl.SSLContext] = ssl.create_default_context):
        self.server = server
        self._context_factory = context_factory

    def tls_connect(self, port: int, timeout: float = 10.0) -> ssl.SSLSocket:
        raw = socket.create_connection((self.server.host, port), timeout=timeout)
        try:
            return self._context_factory().wrap_socket(raw, server_hostname=self.server.host)
        except BaseException:
            raw.close()
            raise

    def plain_connect(self, port: int, timeout: float = 10.0) -> socket.socket:
        """A plain TCP connection, for a protocol that must upgrade it with starttls() before anything else."""
        return socket.create_connection((self.server.host, port), timeout=timeout)

    def starttls(self, sock: socket.socket, buffered: bytes = b"") -> ssl.SSLSocket:
        """verified_starttls() with the same verifying context and the same name check as tls_connect()."""
        return verified_starttls(sock, self.server.host, self._context_factory(), buffered)
