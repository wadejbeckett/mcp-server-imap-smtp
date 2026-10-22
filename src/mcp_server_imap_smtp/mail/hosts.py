# SPDX-License-Identifier: AGPL-3.0-or-later
"""Which mail servers exist, and how to reach one. The service only ever opens sockets to a
configured MailServer, so the sign-in page cannot be aimed anywhere else (see resolve.py for how
an address is mapped to a server)."""
from __future__ import annotations

import re
import socket
import ssl
from dataclasses import dataclass
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


@dataclass(frozen=True)
class MailServer:
    """One IMAP/SMTP server. TLS verifies the certificate chain and the hostname against `host`.

    domains: addresses whose domain matches one of these patterns are served here without any DNS
    lookup (exact domain, `*.suffix`, or `*` for every domain). match_mx: also serve any domain whose
    MX host is `host` or a name under it. max_sessions: IMAP and SMTP sessions the connector holds open
    on this server at once, for all users together (mail/sessions.py); at least 2, since mail_send holds
    one of each."""
    host: str
    imap_port: int = 993
    smtp_port: int = 465
    domains: tuple[str, ...] = ()
    match_mx: bool = True
    max_sessions: int = 8

    def __post_init__(self):
        if isinstance(self.domains, (list, str)):
            object.__setattr__(self, "domains", tuple([self.domains] if isinstance(self.domains, str) else self.domains))
        if not is_dns_name(self.host):
            raise ValueError(f"mail server host {self.host!r} must be a lowercase DNS name (no scheme, no port)")
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
