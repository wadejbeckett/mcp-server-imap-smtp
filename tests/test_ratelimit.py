# SPDX-License-Identifier: AGPL-3.0-or-later
import threading

from mcp_server_imap_smtp.ratelimit import RateLimiter


def clock(monkeypatch, start=1000.0):
    now = [start]
    monkeypatch.setattr("mcp_server_imap_smtp.ratelimit.time.monotonic", lambda: now[0])
    return now


def test_blocks_after_n_failures_in_window(monkeypatch):
    now = clock(monkeypatch)
    r = RateLimiter(3, 60)
    for _ in range(3):
        assert not r.blocked("ip:1"); r.fail("ip:1")
    assert r.blocked("ip:1") and not r.blocked("ip:2")
    now[0] += 61
    assert not r.blocked("ip:1")


def test_reset_clears_one_key():
    r = RateLimiter(1, 60)
    r.fail("a"); r.fail("b")
    r.reset("a")
    assert not r.blocked("a") and r.blocked("b")


def test_count_and_hit_and_refund(monkeypatch):
    now = clock(monkeypatch)
    r = RateLimiter(5, 60)
    assert r.count("a") == 0
    r.hit("a"); now[0] += 1; r.hit("a")
    assert r.count("a") == 2
    r.refund("a")
    assert r.count("a") == 1
    r.refund("a"); r.refund("a")                  # refunding an empty key is harmless
    assert r.count("a") == 0 and len(r) == 0
    now[0] += 61
    r.hit("a")
    assert r.count("a") == 1


def test_refund_removes_the_most_recent_hit(monkeypatch):
    now = clock(monkeypatch)
    r = RateLimiter(2, 60)
    r.hit("a"); now[0] += 50; r.hit("a")
    r.refund("a")
    now[0] += 20                                   # the first hit is now 70s old, the refunded one is gone
    assert r.count("a") == 0


def test_try_acquire_is_all_or_nothing(monkeypatch):
    r = RateLimiter(2, 60)
    r.hit("a"); r.hit("a")                         # "a" is at its limit
    assert not r.try_acquire(["ip", "a"])
    assert r.count("ip") == 0 and r.count("a") == 2    # nothing was recorded for the refused attempt
    assert r.try_acquire(["ip", "b"]) and r.count("ip") == 1 and r.count("b") == 1


def test_try_acquire_concurrent_never_exceeds_limit():
    r = RateLimiter(5, 60)
    barrier, wins = threading.Barrier(20), []
    def go():
        barrier.wait(); wins.append(r.try_acquire(["ip:1", "addr:a"]))
    ts = [threading.Thread(target=go) for _ in range(20)]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert wins.count(True) == 5 and r.count("ip:1") == 5


def test_checking_a_key_does_not_create_it(monkeypatch):
    r = RateLimiter(3, 60)
    r.blocked("never-failed"); r.count("never-failed")
    assert len(r) == 0


def test_expired_key_is_dropped_on_read(monkeypatch):
    now = clock(monkeypatch)
    r = RateLimiter(3, 60)
    r.fail("a")
    now[0] += 61
    assert not r.blocked("a") and len(r) == 0


def test_unqueried_idle_keys_are_swept(monkeypatch):
    now = clock(monkeypatch)
    monkeypatch.setattr(RateLimiter, "SWEEP_EVERY", 10)
    r = RateLimiter(3, 60)
    for i in range(50):
        r.fail(f"addr:junk{i}")                    # never queried again
    now[0] += 61
    for _ in range(10):                            # ordinary traffic on another key triggers the sweep
        r.try_acquire(["ip:real"]); r.refund("ip:real")
    assert len(r) == 0
