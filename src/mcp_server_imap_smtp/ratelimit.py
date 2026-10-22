# SPDX-License-Identifier: AGPL-3.0-or-later
"""In-memory sliding-window attempt counter. One process, so memory is enough.

Sign-in reserves its attempt up front (`try_acquire`), then gives it back (`refund`) when the
attempt turns out not to be the person's fault, so parallel requests cannot outrun the limit."""
from __future__ import annotations

import ipaddress
import threading
import time
from collections import deque
from typing import Iterable


def client_key(host: str | None) -> str:
    """The rate-limit identity of a client address. An IPv6 client is one /64: a single host or VPS is
    normally given a whole /64 and can rotate through it, so counting each address apart would hand it a
    fresh budget per request. An IPv4-mapped IPv6 address counts as its IPv4 address."""
    if not host:
        return "?"
    try:
        ip = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return host
    if ip.version == 6:
        if ip.ipv4_mapped:
            return str(ip.ipv4_mapped)
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    return str(ip)


def client_network(host: str | None) -> str:
    """A wider client network for long-lived counters: IPv4 /24, IPv6 /48."""
    if not host:
        return "?"
    try:
        ip = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return host
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ipaddress.ip_network(f"{ip}/{24 if ip.version == 4 else 48}", strict=False))


class RateLimiter:
    SWEEP_EVERY = 256        # every N recording calls, drop keys whose window has emptied

    def __init__(self, max_failures: int, window: int):
        self.max, self.window = max_failures, window
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()
        self._ops = 0

    def _trim(self, key: str) -> deque[float] | None:
        """Drop expired entries; forget the key when none are left so idle keys cost nothing."""
        q = self._hits.get(key)
        if q is None:
            return None
        cutoff = time.monotonic() - self.window
        while q and q[0] < cutoff:
            q.popleft()
        if not q:
            del self._hits[key]
            return None
        return q

    def _record(self, key: str) -> None:
        q = self._trim(key)
        if q is None:
            q = self._hits[key] = deque()
        q.append(time.monotonic())
        self._ops += 1
        if self._ops % self.SWEEP_EVERY == 0:
            for k in list(self._hits):          # keys nobody asks about again would otherwise stay forever
                self._trim(k)

    def _blocked(self, key: str) -> bool:
        q = self._trim(key)
        return q is not None and len(q) >= self.max

    def blocked(self, key: str) -> bool:
        with self._lock:
            return self._blocked(key)

    def count(self, key: str) -> int:
        with self._lock:
            q = self._trim(key)
            return 0 if q is None else len(q)

    def __len__(self) -> int:
        """Number of keys currently tracked."""
        with self._lock:
            return len(self._hits)

    def hit(self, key: str) -> None:
        with self._lock:
            self._record(key)

    fail = hit

    def try_acquire(self, keys: Iterable[str]) -> bool:
        """Atomically: if none of the keys is blocked, record an attempt on all of them and return True."""
        keys = list(keys)
        with self._lock:
            if any(self._blocked(k) for k in keys):
                return False
            for k in keys:
                self._record(k)
            return True

    def refund(self, key: str) -> None:
        """Remove the most recent attempt on the key (no-op if there is none)."""
        with self._lock:
            q = self._trim(key)
            if q is not None:
                q.pop()
                if not q:
                    del self._hits[key]

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)
