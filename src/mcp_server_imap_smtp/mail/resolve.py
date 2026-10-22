# SPDX-License-Identifier: AGPL-3.0-or-later
"""Map a mailbox address to the configured MailServer that hosts it.

Order: (1) validate and normalise the address; (2) explicit `domains` patterns (exact beats
`*.suffix`, longer suffix beats shorter, `*` last; config order breaks ties); (3) when any server
has match_mx, the domain's MX hosts: (a) by name, a server matches when an MX host equals its
`host` or ends with "." + host; (b) failing that, by address, a server matches when the A/AAAA
addresses of one of the first MX_HOSTS MX hosts intersect the A/AAAA addresses of its `host`
(Plesk publishes `MX mail.<domain>` with an A record pointing at the server); config order
breaks ties in both; (4) otherwise HostNotAllowed.

DNS decides eligibility only. The result is always one of the configured servers, so DNS can
choose between them but never add a destination: the connection still goes to `server.host`, and
TLS verifies the certificate against that name, whatever the MX or its addresses say.

Answers are cached by name for CACHE_TTL (MX by domain, addresses by host name); a DNS outage
(ResolveUnavailable) is cached for FAIL_TTL so repeated sign-in attempts fail fast.
"""
from __future__ import annotations

import ipaddress
import re
import threading
import time
from typing import Callable, Iterable

from .hosts import HostNotAllowed, MailServer, is_dns_name

_LOCAL = re.compile(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}")
MX_LIFETIME = 5.0          # seconds, whole MX query including retries
ADDR_LIFETIME = 5.0        # seconds, per A or AAAA query including retries
CACHE_TTL = 600.0          # seconds, positive and negative answers alike
FAIL_TTL = 30.0            # seconds a DNS failure (ResolveUnavailable) is remembered per name
CACHE_MAX = 10_000         # names per cache
MX_HOSTS = 5               # MX hosts whose addresses are looked up, in the order DNS returned them


class ResolveUnavailable(OSError):
    """DNS could not answer (timeout, SERVFAIL, no nameservers). An outage, not a verdict on the
    address: the sign-in page treats it like an unreachable mail server. Subclasses OSError, as
    socket.gaierror does, so existing network-error handling also covers it. Cached for FAIL_TTL only."""


def normalise_address(address: str) -> tuple[str, str]:
    """Return (address, domain), lowercased with the domain in IDNA ASCII form, or raise HostNotAllowed.
    Unicode dot variants (U+3002, U+FF0E, U+FF61), fullwidth letters, case and one trailing dot on the
    domain all collapse to the same result."""
    address = address.strip().lower()
    local, at, domain = address.rpartition("@")
    if not at or not _LOCAL.fullmatch(local or "x y"):
        raise HostNotAllowed(address)
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise HostNotAllowed(address) from exc
    if domain.endswith("."):
        domain = domain[:-1]
    if not is_dns_name(domain, min_labels=2):
        raise HostNotAllowed(address)
    return f"{local}@{domain}", domain


def default_mx_lookup(domain: str) -> list[str]:
    """MX exchange hosts for domain via dnspython. [] when the domain has no MX (NXDOMAIN, no
    answer); ResolveUnavailable when DNS cannot answer."""
    import dns.exception
    import dns.resolver

    try:
        answer = dns.resolver.resolve(domain + ".", "MX", lifetime=MX_LIFETIME, search=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException as exc:   # Timeout / LifetimeTimeout, NoNameservers, ...
        raise ResolveUnavailable(f"MX lookup for {domain} failed ({exc.__class__.__name__})") from None
    return [r.exchange.to_text() for r in answer]


def default_addr_lookup(name: str) -> list[str]:
    """A and AAAA addresses of name via dnspython. [] for NXDOMAIN; a type with no answer adds
    nothing; ResolveUnavailable when DNS cannot answer."""
    import dns.exception
    import dns.resolver

    out: list[str] = []
    for rdtype in ("A", "AAAA"):
        try:
            answer = dns.resolver.resolve(name + ".", rdtype, lifetime=ADDR_LIFETIME, search=False)
        except dns.resolver.NXDOMAIN:
            return []
        except dns.resolver.NoAnswer:
            continue
        except dns.exception.DNSException as exc:
            raise ResolveUnavailable(f"{rdtype} lookup for {name} failed ({exc.__class__.__name__})") from None
        out.extend(r.to_text() for r in answer)
    return out


def _mx_host(name: str) -> str:
    return name.strip().lower().rstrip(".")


def _ip(text: str) -> str | None:
    """Canonical text form of an IP address, so equal addresses compare equal; None if not an address."""
    try:
        return str(ipaddress.ip_address(text.strip()))
    except ValueError:
        return None


def _pattern_rank(pattern: str, domain: str) -> int | None:
    """Higher is more specific; None when the pattern does not match."""
    if pattern == "*":
        return 0
    if pattern.startswith("*."):
        return len(pattern) if domain.endswith(pattern[1:]) else None
    return 10_000 if domain == pattern else None


class _Failed:
    """Cache marker: the lookup raised ResolveUnavailable."""
    def __init__(self, exc: ResolveUnavailable):
        self.exc = exc


class _TTLCache:
    """Bounded name -> (expiry, value) map. Expired entries go first when full, then the oldest."""

    def __init__(self, clock: Callable[[], float], max_entries: int):
        self._clock, self._max = clock, max_entries
        self._data: dict[str, tuple[float, object]] = {}
        self._lock = threading.Lock()

    def __len__(self) -> int:
        return len(self._data)

    def get(self, name: str):
        now = self._clock()
        with self._lock:
            hit = self._data.get(name)
            return hit[1] if hit and hit[0] > now else None

    def put(self, name: str, value, ttl: float) -> None:
        now = self._clock()
        with self._lock:
            self._data.pop(name, None)
            if len(self._data) >= self._max:
                for key in [k for k, (exp, _) in self._data.items() if exp <= now]:
                    del self._data[key]
                while len(self._data) >= self._max:          # still full: drop the oldest entries
                    del self._data[next(iter(self._data))]
            self._data[name] = (now + ttl, value)

    def lookup(self, name: str, fetch: Callable[[str], tuple], ttl: float, fail_ttl: float) -> tuple:
        hit = self.get(name)
        if isinstance(hit, _Failed):
            raise ResolveUnavailable(*hit.exc.args)
        if hit is not None:
            return hit
        try:
            value = fetch(name)
        except ResolveUnavailable as exc:
            self.put(name, _Failed(exc), fail_ttl)
            raise
        self.put(name, value, ttl)
        return value


class Resolver:
    def __init__(self, servers: Iterable[MailServer], mx_lookup: Callable[[str], list[str]] = default_mx_lookup,
                 clock: Callable[[], float] = time.monotonic, ttl: float = CACHE_TTL, max_entries: int = CACHE_MAX,
                 addr_lookup: Callable[[str], list[str]] = default_addr_lookup, fail_ttl: float = FAIL_TTL):
        self.servers = tuple(servers)
        if not self.servers:
            raise ValueError("at least one mail server is required")
        self._mx_lookup, self._addr_lookup = mx_lookup, addr_lookup
        self._ttl, self._fail_ttl = ttl, fail_ttl
        self._cache = _TTLCache(clock, max_entries)        # MX hosts by domain
        self._addr_cache = _TTLCache(clock, max_entries)   # addresses by host name

    def resolve(self, address: str) -> tuple[str, MailServer]:
        """(normalised address, server). HostNotAllowed: malformed or not served here.
        ResolveUnavailable: DNS failed, try again later."""
        address, domain = normalise_address(address)
        best: tuple[int, MailServer] | None = None
        for server in self.servers:
            for pattern in server.domains:
                rank = _pattern_rank(pattern, domain)
                if rank is not None and (best is None or rank > best[0]):
                    best = (rank, server)
        if best:
            return address, best[1]
        mx_servers = [s for s in self.servers if s.match_mx]
        if not mx_servers:
            raise HostNotAllowed(address)
        hosts = self._mx(domain)
        for server in mx_servers:
            if any(h == server.host or h.endswith("." + server.host) for h in hosts):
                return address, server
        server = self._match_by_address(hosts, mx_servers)
        if server is None:
            raise HostNotAllowed(address)
        return address, server

    def _match_by_address(self, hosts: tuple[str, ...], mx_servers: list[MailServer]) -> MailServer | None:
        """The first match_mx server whose host shares an address with one of the first MX_HOSTS MX
        hosts. A lookup that fails is skipped; if nothing matched and one failed, ResolveUnavailable."""
        failure: ResolveUnavailable | None = None
        mx_addrs: set[str] = set()
        for host in [h for h in hosts if is_dns_name(h)][:MX_HOSTS]:
            try:
                mx_addrs.update(self._addrs(host))
            except ResolveUnavailable as exc:
                failure = failure or exc
        if mx_addrs:
            for server in mx_servers:
                try:
                    if mx_addrs & self._addrs(server.host):
                        return server
                except ResolveUnavailable as exc:
                    failure = failure or exc
        if failure is not None:
            raise failure
        return None

    def _mx(self, domain: str) -> tuple[str, ...]:
        return self._cache.lookup(domain, lambda d: tuple(_mx_host(h) for h in self._mx_lookup(d)),
                                  self._ttl, self._fail_ttl)

    def _addrs(self, name: str) -> frozenset[str]:
        return self._addr_cache.lookup(
            name, lambda n: frozenset(a for a in map(_ip, self._addr_lookup(n)) if a), self._ttl, self._fail_ttl)
