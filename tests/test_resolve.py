# SPDX-License-Identifier: AGPL-3.0-or-later
"""Address -> MailServer resolution. The MX lookup is always a fake: no DNS traffic."""
import sys
import types

import pytest

from mcp_server_imap_smtp.mail import resolve
from mcp_server_imap_smtp.mail.hosts import HostNotAllowed, MailServer
from mcp_server_imap_smtp.mail.resolve import ResolveUnavailable, Resolver, normalise_address

MAIL1 = MailServer("mail1.hosting.example")                                                   # match_mx
ISP = MailServer("mail.client.example", domains=("client.example",), match_mx=False)
WILD = MailServer("mail.group.example", domains=("*.group.example",), match_mx=False)


class FakeMX:
    def __init__(self, table=None, fail=()):
        self.table, self.fail, self.calls = table or {}, set(fail), []

    def __call__(self, domain):
        self.calls.append(domain)
        if domain in self.fail:
            raise ResolveUnavailable("timeout")
        return list(self.table.get(domain, []))


class FakeAddr(FakeMX):
    """A/AAAA lookup by name: same shape as FakeMX, so no test ever touches DNS."""


def make(*servers, table=None, fail=(), addrs=None, addr_fail=(), **kw):
    mx = FakeMX(table, fail)
    kw.setdefault("addr_lookup", FakeAddr(addrs, addr_fail))
    return Resolver(servers or (MAIL1, ISP, WILD), mx_lookup=mx, **kw), mx


def test_explicit_domain_wins_without_dns():
    r, mx = make(table={"client.example": ["mail1.hosting.example."]})
    assert r.resolve("me@client.example") == ("me@client.example", ISP)
    assert mx.calls == []


def test_wildcard_suffix_matches_subdomains_not_the_suffix_itself():
    r, mx = make()
    assert r.resolve("me@a.group.example") == ("me@a.group.example", WILD)
    assert r.resolve("me@x.y.group.example")[1] is WILD
    with pytest.raises(HostNotAllowed):
        r.resolve("me@group.example")
    with pytest.raises(HostNotAllowed):
        r.resolve("me@evilgroup.example")


def test_star_serves_every_domain_without_dns():
    legacy = MailServer("mail1.hosting.example", domains=("*",), match_mx=False)
    r, mx = make(legacy)
    assert r.resolve("anyone@gmail.com") == ("anyone@gmail.com", legacy)
    assert mx.calls == []


def test_most_specific_pattern_wins():
    catch_all = MailServer("a.example", domains=("*",), match_mx=False)
    suffix = MailServer("b.example", domains=("*.co.za",), match_mx=False)
    exact = MailServer("c.example", domains=("x.co.za",), match_mx=False)
    r, _ = make(catch_all, suffix, exact)
    assert r.resolve("me@x.co.za")[1] is exact
    assert r.resolve("me@y.co.za")[1] is suffix
    assert r.resolve("me@y.com")[1] is catch_all


def test_mx_exact_host():
    r, mx = make(table={"client.co.za": ["mail1.hosting.example."]})
    assert r.resolve("me@client.co.za") == ("me@client.co.za", MAIL1)
    assert mx.calls == ["client.co.za"]


def test_mx_under_the_server_host():
    r, _ = make(table={"client.co.za": ["mx1.mail1.hosting.example."]})
    assert r.resolve("me@client.co.za")[1] is MAIL1


def test_mx_case_and_trailing_dot_ignored():
    r, _ = make(table={"client.co.za": ["MAIL1.hosting.example."]})
    assert r.resolve("me@client.co.za")[1] is MAIL1


def test_any_of_several_mx_hosts_matches():
    r, _ = make(table={"client.co.za": ["mx.backup.example.", "mail1.hosting.example."]})
    assert r.resolve("me@client.co.za")[1] is MAIL1


@pytest.mark.parametrize("mx_hosts", [["aspmx.l.google.com."], ["evilmail1.hosting.example."], ["mail1.hosting.example.evil.com."],
                                      ["hosting.example."], ["."]])
def test_mx_elsewhere_refused(mx_hosts):
    r, _ = make(table={"client.co.za": mx_hosts})
    with pytest.raises(HostNotAllowed):
        r.resolve("me@client.co.za")


def test_no_mx_refused():
    r, _ = make()
    with pytest.raises(HostNotAllowed):
        r.resolve("me@nomx.co.za")


def test_mx_only_consulted_for_match_mx_servers():
    r, mx = make(ISP, WILD, table={"client.co.za": ["mail.client.example."]})
    with pytest.raises(HostNotAllowed):
        r.resolve("me@client.co.za")
    assert mx.calls == []


def test_dns_failure_is_unavailable_not_refusal_and_cached_for_30s():
    now = [1000.0]
    r, mx = make(fail={"client.co.za"}, clock=lambda: now[0])
    for _ in range(3):
        with pytest.raises(ResolveUnavailable) as ei:
            r.resolve("me@client.co.za")
        assert not isinstance(ei.value, HostNotAllowed)
    assert mx.calls == ["client.co.za"]                      # repeated attempts fail fast from the cache
    now[0] += resolve.FAIL_TTL + 1
    mx.fail.clear(); mx.table["client.co.za"] = ["mail1.hosting.example."]
    assert r.resolve("me@client.co.za")[1] is MAIL1
    assert mx.calls == ["client.co.za", "client.co.za"]


def test_positive_cache_hit_and_expiry():
    now = [1000.0]
    r, mx = make(table={"client.co.za": ["mail1.hosting.example."]}, clock=lambda: now[0])
    for _ in range(3):
        assert r.resolve("me@client.co.za")[1] is MAIL1
    assert r.resolve("other@client.co.za")[1] is MAIL1
    assert mx.calls == ["client.co.za"]
    now[0] += resolve.CACHE_TTL + 1
    r.resolve("me@client.co.za")
    assert mx.calls == ["client.co.za", "client.co.za"]


def test_negative_cache():
    r, mx = make()
    for _ in range(3):
        with pytest.raises(HostNotAllowed):
            r.resolve("me@gmail.com")
    assert mx.calls == ["gmail.com"]


def test_cache_is_bounded():
    r, mx = make(max_entries=3)
    for i in range(10):
        with pytest.raises(HostNotAllowed):
            r.resolve(f"me@d{i}.co.za")
    assert len(r._cache) == 3
    with pytest.raises(HostNotAllowed):
        r.resolve("me@d9.co.za")          # newest kept
    assert mx.calls.count("d9.co.za") == 1


def test_idna_domain():
    r, mx = make(MailServer("mail1.hosting.example", domains=("xn--bcher-kva.co.za",), match_mx=False), MAIL1,
                 table={"xn--mller-kva.co.za": ["mail1.hosting.example"]})
    assert r.resolve("me@Bücher.co.za") == ("me@xn--bcher-kva.co.za", r.servers[0])
    assert r.resolve("me@müller.co.za") == ("me@xn--mller-kva.co.za", MAIL1)
    assert mx.calls == ["xn--mller-kva.co.za"]


def test_uppercase_and_whitespace_normalised():
    r, mx = make(table={"client.co.za": ["mail1.hosting.example."]})
    assert r.resolve("  Me@Client.CO.ZA ") == ("me@client.co.za", MAIL1)
    assert mx.calls == ["client.co.za"]


@pytest.mark.parametrize("bad", ["nobody", "a@", "@b.co", "a@b", "a@-b.co", "a@b..co", "a@127.0.0.1", "a@[::1]",
                                 "a b@c.co", "a\n@b.co", "a@b\n.co", "a\r@b.co", "a@b.co..", "x@" + "a" * 250 + ".co",
                                 "a" * 65 + "@b.co", "a@" + "b" * 64 + ".co"])
def test_malformed_addresses_refused_before_dns(bad):
    r, mx = make()
    with pytest.raises(HostNotAllowed):
        r.resolve(bad)
    assert mx.calls == []


def test_normalise_address():
    assert normalise_address(" A.B+tag@Example.CO.ZA") == ("a.b+tag@example.co.za", "example.co.za")


@pytest.mark.parametrize("variant", ["bob@hosting。example", "bob@ｈｏｓｔｉｎｇ.example", "BOB@hosting.example",
                                     "bob@hosting.example.", "bob@hosting．example", "bob@hosting｡example",
                                     "bob@ＨＯＳＴＩＮＧ.example。"])
def test_unicode_dot_fullwidth_case_and_trailing_dot_collapse(variant):
    assert normalise_address(variant) == ("bob@hosting.example", "hosting.example")


# MX by address: Plesk publishes MX mail.<domain>, whose A/AAAA is the server's address.

HOST_IPS = ["160.119.0.10", "2c0f:0:0:0::10"]


def test_mx_matches_by_address_when_the_name_does_not():
    r, mx = make(table={"shop.example": ["mail.shop.example."]},
                 addrs={"mail.shop.example": ["160.119.0.10"], "mail1.hosting.example": HOST_IPS})
    assert r.resolve("me@shop.example") == ("me@shop.example", MAIL1)
    assert r._addr_lookup.calls == ["mail.shop.example", "mail1.hosting.example"]


def test_mx_address_match_on_ipv6_in_any_spelling():
    r, _ = make(table={"c.co.za": ["mail.c.co.za."]},
                addrs={"mail.c.co.za": ["2c0f::10"], "mail1.hosting.example": HOST_IPS})
    assert r.resolve("me@c.co.za")[1] is MAIL1


def test_name_match_is_tried_before_any_address_lookup():
    r, _ = make(table={"c.co.za": ["mail.c.co.za.", "mail1.hosting.example."]}, addrs={"mail.c.co.za": HOST_IPS})
    assert r.resolve("me@c.co.za")[1] is MAIL1
    assert r._addr_lookup.calls == []


def test_mx_address_elsewhere_refused():
    r, _ = make(table={"c.co.za": ["mail.c.co.za."]},
                addrs={"mail.c.co.za": ["192.0.2.1"], "mail1.hosting.example": HOST_IPS})
    with pytest.raises(HostNotAllowed):
        r.resolve("me@c.co.za")


def test_mx_address_match_only_for_match_mx_servers_and_config_order_breaks_ties():
    other = MailServer("mail.other.example")
    off = MailServer("off.example", match_mx=False)
    addrs = {"mail.c.co.za": ["192.0.2.7"], "off.example": ["192.0.2.7"], "mail.other.example": ["192.0.2.7"],
             "mail1.hosting.example": ["192.0.2.7"]}
    r, _ = make(off, other, MAIL1, table={"c.co.za": ["mail.c.co.za."]}, addrs=addrs)
    assert r.resolve("me@c.co.za")[1] is other
    assert "off.example" not in r._addr_lookup.calls


def test_at_most_five_mx_hosts_are_looked_up():
    hosts = [f"mx{i}.c.co.za." for i in range(8)]
    r, _ = make(table={"c.co.za": hosts}, addrs={"mx6.c.co.za": HOST_IPS, "mail1.hosting.example": HOST_IPS})
    with pytest.raises(HostNotAllowed):
        r.resolve("me@c.co.za")
    assert r._addr_lookup.calls == [f"mx{i}.c.co.za" for i in range(5)]


def test_no_server_lookup_when_mx_hosts_have_no_address():
    r, _ = make(table={"c.co.za": ["mail.c.co.za.", "."]})
    with pytest.raises(HostNotAllowed):
        r.resolve("me@c.co.za")
    assert r._addr_lookup.calls == ["mail.c.co.za"]


def test_address_lookup_failure_is_unavailable_unless_another_host_matches():
    r, _ = make(table={"c.co.za": ["mx1.c.co.za.", "mx2.c.co.za."]}, addrs={"mx2.c.co.za": HOST_IPS,
                "mail1.hosting.example": HOST_IPS}, addr_fail={"mx1.c.co.za"})
    assert r.resolve("me@c.co.za")[1] is MAIL1
    r, _ = make(table={"c.co.za": ["mx1.c.co.za."]}, addr_fail={"mx1.c.co.za"})
    with pytest.raises(ResolveUnavailable):
        r.resolve("me@c.co.za")
    r, _ = make(table={"c.co.za": ["mail.c.co.za."]}, addrs={"mail.c.co.za": HOST_IPS}, addr_fail={"mail1.hosting.example"})
    with pytest.raises(ResolveUnavailable):
        r.resolve("me@c.co.za")


def test_address_answers_are_cached_by_name_and_failures_for_30s():
    now = [0.0]
    r, _ = make(table={"a.co.za": ["mail.a.co.za."], "b.co.za": ["mail.b.co.za."]},
                addrs={"mail.a.co.za": HOST_IPS, "mail.b.co.za": HOST_IPS, "mail1.hosting.example": HOST_IPS},
                clock=lambda: now[0])
    assert r.resolve("x@a.co.za")[1] is MAIL1 and r.resolve("y@b.co.za")[1] is MAIL1 and r.resolve("z@a.co.za")[1] is MAIL1
    assert r._addr_lookup.calls == ["mail.a.co.za", "mail1.hosting.example", "mail.b.co.za"]   # mail1 looked up once
    r2, _ = make(table={"c.co.za": ["mail.c.co.za."]}, addr_fail={"mail.c.co.za"}, clock=lambda: now[0])
    for _ in range(3):
        with pytest.raises(ResolveUnavailable):
            r2.resolve("me@c.co.za")
    assert r2._addr_lookup.calls == ["mail.c.co.za"]
    now[0] += resolve.FAIL_TTL + 1
    with pytest.raises(ResolveUnavailable):
        r2.resolve("me@c.co.za")
    assert r2._addr_lookup.calls == ["mail.c.co.za"] * 2


def test_address_cache_is_bounded():
    r, _ = make(max_entries=3, table={f"d{i}.co.za": [f"mail.d{i}.co.za."] for i in range(10)})
    for i in range(10):
        with pytest.raises(HostNotAllowed):
            r.resolve(f"me@d{i}.co.za")
    assert len(r._addr_cache) == 3


def test_resolver_needs_a_server():
    with pytest.raises(ValueError):
        Resolver(())



def fake_dns(monkeypatch, outcome):
    exc_mod = types.ModuleType("dns.exception")

    class DNSException(Exception): pass
    class Timeout(DNSException): pass
    exc_mod.DNSException, exc_mod.Timeout = DNSException, Timeout
    res_mod = types.ModuleType("dns.resolver")

    class NXDOMAIN(DNSException): pass
    class NoAnswer(DNSException): pass
    class NoNameservers(DNSException): pass
    res_mod.NXDOMAIN, res_mod.NoAnswer, res_mod.NoNameservers = NXDOMAIN, NoAnswer, NoNameservers
    seen = {}

    def resolve_(qname, rdtype, lifetime, search):
        seen.update(qname=qname, rdtype=rdtype, lifetime=lifetime, search=search)
        result = outcome(res_mod, exc_mod)
        if isinstance(result, Exception):
            raise result
        return result
    res_mod.resolve = resolve_
    pkg = types.ModuleType("dns")
    pkg.resolver, pkg.exception = res_mod, exc_mod
    monkeypatch.setitem(sys.modules, "dns", pkg)
    monkeypatch.setitem(sys.modules, "dns.resolver", res_mod)
    monkeypatch.setitem(sys.modules, "dns.exception", exc_mod)
    return seen


class _Name:
    def __init__(self, text): self.text = text
    def to_text(self): return self.text


class _MX:
    def __init__(self, text): self.exchange = _Name(text)


def test_default_lookup_returns_exchanges_with_lifetime_5s(monkeypatch):
    seen = fake_dns(monkeypatch, lambda r, e: [_MX("mail1.hosting.example."), _MX("mx2.mail1.hosting.example.")])
    assert resolve.default_mx_lookup("client.co.za") == ["mail1.hosting.example.", "mx2.mail1.hosting.example."]
    assert seen == {"qname": "client.co.za.", "rdtype": "MX", "lifetime": 5.0, "search": False}


@pytest.mark.parametrize("name", ["NXDOMAIN", "NoAnswer"])
def test_default_lookup_no_mx_is_empty(monkeypatch, name):
    fake_dns(monkeypatch, lambda r, e: getattr(r, name)())
    assert resolve.default_mx_lookup("client.co.za") == []


@pytest.mark.parametrize("which", ["timeout", "nonameservers"])
def test_default_lookup_failure_is_unavailable(monkeypatch, which):
    fake_dns(monkeypatch, lambda r, e: e.Timeout() if which == "timeout" else r.NoNameservers())
    with pytest.raises(ResolveUnavailable):
        resolve.default_mx_lookup("client.co.za")


class _Rdata:
    def __init__(self, text): self.text = text
    def to_text(self): return self.text


def test_default_addr_lookup_queries_a_and_aaaa_with_lifetime_5s(monkeypatch):
    seen = []
    def outcome(r, e):
        return None
    fake_dns(monkeypatch, outcome)
    import dns.resolver as res_mod

    def resolve_(qname, rdtype, lifetime, search):
        seen.append((qname, rdtype, lifetime, search))
        return [_Rdata("192.0.2.1")] if rdtype == "A" else [_Rdata("2001:db8::1")]
    res_mod.resolve = resolve_
    assert resolve.default_addr_lookup("mail.c.co.za") == ["192.0.2.1", "2001:db8::1"]
    assert seen == [("mail.c.co.za.", "A", 5.0, False), ("mail.c.co.za.", "AAAA", 5.0, False)]


def test_default_addr_lookup_nxdomain_and_noanswer(monkeypatch):
    fake_dns(monkeypatch, lambda r, e: r.NXDOMAIN())
    assert resolve.default_addr_lookup("gone.c.co.za") == []
    fake_dns(monkeypatch, lambda r, e: r.NoAnswer())
    assert resolve.default_addr_lookup("none.c.co.za") == []
    import dns.resolver as res_mod
    res_mod.resolve = lambda q, t, lifetime, search: (_ for _ in ()).throw(res_mod.NoAnswer()) if t == "A" \
        else [_Rdata("2001:db8::1")]
    assert resolve.default_addr_lookup("v6.c.co.za") == ["2001:db8::1"]


@pytest.mark.parametrize("which", ["timeout", "nonameservers"])
def test_default_addr_lookup_failure_is_unavailable(monkeypatch, which):
    fake_dns(monkeypatch, lambda r, e: e.Timeout() if which == "timeout" else r.NoNameservers())
    with pytest.raises(ResolveUnavailable):
        resolve.default_addr_lookup("mail.c.co.za")


def test_resolve_unavailable_is_an_oserror():
    assert issubclass(ResolveUnavailable, OSError) and not issubclass(ResolveUnavailable, HostNotAllowed)
