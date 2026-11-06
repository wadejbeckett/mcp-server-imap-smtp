# SPDX-License-Identifier: AGPL-3.0-or-later
import pytest

from mcp_server_imap_smtp.config import Settings, load_settings, redirect_allowed
from mcp_server_imap_smtp.mail.hosts import MailServer


def write(tmp_path, body):
    p = tmp_path / "c.toml"; p.write_text(body); return p

HEAD = '''
issuer_url = "http://127.0.0.1:8765"
mail_resource_url = "http://127.0.0.1:8765/mail"
db_path = "{db}"
'''
BASE = HEAD + 'mail_host = "mail1.hosting.example"\n'

SERVERS = '''
[[mail_servers]]
host = "mail1.hosting.example"

[[mail_servers]]
host = "mail.client.example"
domains = ["client.example", "*.client.example"]
match_mx = false
imap_port = 1993
'''


def load(tmp_path, body):
    return load_settings(write(tmp_path, body.replace("{db}", str(tmp_path / "x.sqlite"))))


def test_load_defaults(tmp_path):
    s = load(tmp_path, BASE)
    assert s.mail_path == "/mail"
    assert s.public_host == "127.0.0.1:8765"
    assert s.access_ttl == 3600 and s.refresh_ttl == 30 * 86400


def test_legacy_mail_host_is_one_server_for_every_domain_without_dns(tmp_path):
    s = load(tmp_path, BASE)
    assert s.mail_servers == (MailServer("mail1.hosting.example", 993, 465, ("*",), False),)


def test_legacy_top_level_ports_apply(tmp_path):
    s = load(tmp_path, "imap_port = 143\nsmtp_port = 587\n" + BASE)
    assert (s.mail_servers[0].imap_port, s.mail_servers[0].smtp_port) == (143, 587)


def test_mail_servers_tables(tmp_path):
    s = load(tmp_path, HEAD + SERVERS)
    mail1, isp = s.mail_servers
    assert mail1 == MailServer("mail1.hosting.example")
    assert isp == MailServer("mail.client.example", 1993, 465, ("client.example", "*.client.example"), False)


def test_top_level_ports_are_defaults_for_tables(tmp_path):
    s = load(tmp_path, "smtp_port = 587\n" + HEAD + SERVERS)
    assert [m.smtp_port for m in s.mail_servers] == [587, 587]
    assert [m.imap_port for m in s.mail_servers] == [993, 1993]


@pytest.mark.parametrize("body,match", [
    (HEAD, "no mail server"),
    (BASE + SERVERS, "not both"),
    (HEAD + "mail_servers = []\n", "no mail server"),
    (HEAD + '[[mail_servers]]\nimap_port = 993\n', "host is required"),
    (HEAD + '[[mail_servers]]\nhost = "mail1.hosting.example"\nsni = "x"\n', "unknown key"),
    (HEAD + '[[mail_servers]]\nhost = "mail1.hosting.example"\ndomains = "x.co.za"\n', "domains must be a list"),
    (HEAD + '[[mail_servers]]\nhost = "a.co.za"\n[[mail_servers]]\nhost = "a.co.za"\n', "only once"),
    (HEAD + '[[mail_servers]]\nhost = "Mail1.hosting.example"\n', "lowercase DNS name"),
    (HEAD + '[[mail_servers]]\nhost = "imaps://mail1.hosting.example"\n', "lowercase DNS name"),
    (HEAD + '[[mail_servers]]\nhost = "mail1.hosting.example:993"\n', "lowercase DNS name"),
    (HEAD + 'mail_host = "mail1.hosting.example:993"\n', "lowercase DNS name"),
    (HEAD + '[[mail_servers]]\nhost = "mail1.hosting.example"\ndomains = ["Bad Domain"]\n', "invalid domain"),
    (HEAD + '[[mail_servers]]\nhost = "mail1.hosting.example"\nimap_port = 0\n', "imap_port"),
])
def test_refused_configs(tmp_path, body, match):
    with pytest.raises(ValueError, match=match):
        load(tmp_path, body)


def test_settings_requires_a_mail_server(tmp_path):
    with pytest.raises(ValueError):
        Settings(issuer_url="https://i", mail_resource_url="https://i/mail", mail_servers=(), db_path=tmp_path)


def test_redirect_allowlist(tmp_path):
    s = load(tmp_path, BASE)
    assert redirect_allowed("https://claude.ai/api/mcp/auth_callback", s)
    assert redirect_allowed("https://chatgpt.com/connector/oauth/abc123", s)
    assert redirect_allowed("http://127.0.0.1:53280/callback", s)
    assert redirect_allowed("http://localhost:6274/oauth/callback", s)
    assert not redirect_allowed("https://claude.ai.evil.com/api/mcp/auth_callback", s)
    assert not redirect_allowed("https://evil.com/cb", s)
    assert not redirect_allowed("http://127.0.0.1.evil.com/cb", s)


def test_cimd_allowed_hosts_default_and_toml_override(tmp_path):
    base = 'issuer_url="https://i"\nmail_resource_url="https://i/mail"\nmail_host="m.example"\ndb_path="/tmp/x"\n'
    f = tmp_path / "c.toml"
    f.write_text(base)
    assert "chatgpt.com" in load_settings(f).cimd_allowed_hosts
    f.write_text(base + 'cimd_allowed_hosts=["example.org"]\n')
    assert load_settings(f).cimd_allowed_hosts == ("example.org",)


def test_ipv6_loopback_redirect_is_accepted(tmp_path):
    s = load(tmp_path, BASE)
    assert redirect_allowed("http://[::1]:53280/callback", s)          # RFC 8252 section 7.3
    assert redirect_allowed("http://[::1]/callback", s)
    assert not redirect_allowed("https://[::1]:53280/callback", s)     # loopback is http only, as for 127.0.0.1
    assert not redirect_allowed("http://[::2]:53280/callback", s)
    assert not redirect_allowed("http://[::ffff:127.0.0.1]:53280/callback", s)


def test_ipv6_loopback_follows_the_loopback_switch(tmp_path):
    s = load(tmp_path, BASE + "allow_loopback_redirects = false\n")
    assert not redirect_allowed("http://[::1]:53280/callback", s)


def test_operator_values_default_to_neutral_text(tmp_path):
    s = load(tmp_path, BASE)
    assert (s.operator_name, s.product_name, s.support_url, s.support_email) == \
        ("the operator", "Mail Connector", "", "")


def test_operator_values_load_from_toml(tmp_path):
    s = load(tmp_path, HEAD + 'operator_name = "Acme"\nproduct_name = "Acme Mail"\n'
             'support_url = "https://acme.example/help"\nsupport_email = "help@acme.example"\nmail_host = "m.acme.example"\n')
    assert (s.operator_name, s.product_name, s.support_url, s.support_email) == \
        ("Acme", "Acme Mail", "https://acme.example/help", "help@acme.example")


@pytest.mark.parametrize("line,message", [
    ('operator_name = ""', "operator_name"),
    ('product_name = "  "', "product_name"),
    ('support_url = "javascript:alert(1)"', "support_url"),
    ('support_email = "a b@x"', "support_email"),
    ('support_email = "nobody"', "support_email"),
])
def test_operator_values_are_checked(tmp_path, line, message):
    with pytest.raises(ValueError, match=message):
        load(tmp_path, BASE + line + "\n")


def test_grok_callback_is_allowed_exactly_and_by_prefix(tmp_path):
    s = load(tmp_path, BASE)
    assert redirect_allowed("https://grok.com/connectors-oauth-exchange-code/", s)
    assert not redirect_allowed("https://grok.com/connectors-oauth-exchange-code/abc", s)   # exact (review L2)
    assert not redirect_allowed("https://grok.com/connectors-oauth-exchange-code", s)
    assert not redirect_allowed("https://grok.com.evil.com/connectors-oauth-exchange-code/", s)
    assert redirect_allowed("https://chatgpt.com/connector/oauth/", s)       # a trailing-slash entry matches itself


# legacy_mail_host (review fix 4)

def test_legacy_server_is_the_named_host(tmp_path):
    s = load(tmp_path, HEAD + 'legacy_mail_host = "mail.client.example"\n' + SERVERS)
    assert s.legacy_server.host == "mail.client.example" and s.legacy_server.imap_port == 1993


def test_legacy_server_defaults_to_the_only_server(tmp_path):
    assert load(tmp_path, BASE).legacy_server.host == "mail1.hosting.example"


def test_legacy_server_is_none_with_several_servers_and_no_setting(tmp_path):
    assert load(tmp_path, HEAD + SERVERS).legacy_server is None


def test_legacy_mail_host_must_be_a_configured_server(tmp_path):
    with pytest.raises(ValueError, match="legacy_mail_host"):
        load(tmp_path, HEAD + 'legacy_mail_host = "elsewhere.example"\n' + SERVERS)


# redirect prefix entries (review fix 6)

GROK = "https://grok.com/connectors-oauth-exchange-code/"


def _s(tmp_path):
    return Settings(issuer_url="http://i", mail_resource_url="http://i/mail", mail_servers=(MailServer("a.example"),),
                    db_path=tmp_path, allow_loopback_redirects=False)


@pytest.mark.parametrize("uri", [GROK, "https://chatgpt.com/connector/oauth/xyz",
                                 "https://chatgpt.com/connector/oauth/abc/def?x=1"])
def test_prefix_entries_allow_paths_under_them(tmp_path, uri):
    assert redirect_allowed(uri, _s(tmp_path))


@pytest.mark.parametrize("tail", ["../../x", "a/../../x", "..", "a\\..\\x", "\\evil", "%2e%2e/x", "%2E%2E/x",
                                  "a/%2e./x", "%2E", "abc#frag", "#", "x?y=..%2f"])
def test_prefix_entries_refuse_traversal_backslashes_encoded_dots_and_fragments(tmp_path, tail):
    assert not redirect_allowed(GROK + tail, _s(tmp_path))
    assert not redirect_allowed("https://chatgpt.com/connector/oauth/" + tail, _s(tmp_path))


def test_exact_entries_are_unchanged(tmp_path):
    assert redirect_allowed("https://claude.ai/api/mcp/auth_callback", _s(tmp_path))
    assert not redirect_allowed("https://claude.ai/api/mcp/auth_callback/../x", _s(tmp_path))


def test_mailbox_and_sending_defaults_are_unlimited(tmp_path):
    """Defaults: as many mailboxes as the client has, and sending with no connector cap."""
    s = load(tmp_path, BASE)
    assert (s.max_mailboxes, s.search_max_mailboxes) == (0, 0)
    assert (s.send_mode, s.send_hourly_limit, s.send_daily_limit, s.send_max_recipients, s.send_allow_bcc) == \
        ("send", 0, 0, 0, True)


def test_mailbox_and_sending_limits_load_from_toml(tmp_path):
    s = load(tmp_path, HEAD + 'max_mailboxes = 300\nsearch_max_mailboxes = 50\nsend_mode = "draft_only"\n'
                              'send_hourly_limit = 20\nsend_daily_limit = 100\nsend_max_recipients = 10\n'
                              'send_allow_bcc = false\nmail_host = "mail1.hosting.example"\n')
    assert (s.max_mailboxes, s.search_max_mailboxes, s.send_mode) == (300, 50, "draft_only")
    assert (s.send_hourly_limit, s.send_daily_limit, s.send_max_recipients, s.send_allow_bcc) == (20, 100, 10, False)


@pytest.mark.parametrize("line", ["max_mailboxes = -1", 'max_mailboxes = "200"', "search_max_mailboxes = 1.5",
                                  "send_daily_limit = true"])
def test_mailbox_and_sending_limits_must_be_whole_numbers(tmp_path, line):
    with pytest.raises(ValueError, match="whole number"):
        load(tmp_path, HEAD + line + '\nmail_host = "mail1.hosting.example"\n')


# STARTTLS and the EHLO name (ticket 09)

def test_security_modes_per_server_and_their_default_ports(tmp_path):
    s = load(tmp_path, HEAD + '[[mail_servers]]\nhost = "mail1.hosting.example"\n'
             '[[mail_servers]]\nhost = "mail.client.example"\nimap_security = "starttls"\nsmtp_security = "starttls"\n')
    mail1, isp = s.mail_servers
    assert (mail1.imap_security, mail1.smtp_security, mail1.imap_port, mail1.smtp_port) == ("tls", "tls", 993, 465)
    assert (isp.imap_security, isp.smtp_security, isp.imap_port, isp.smtp_port) == ("starttls", "starttls", 143, 587)


def test_legacy_mail_host_takes_top_level_security(tmp_path):
    s = load(tmp_path, 'smtp_security = "starttls"\n' + BASE)
    assert (s.mail_servers[0].smtp_security, s.mail_servers[0].smtp_port) == ("starttls", 587)


@pytest.mark.parametrize("line", ['smtp_security = "none"', 'imap_security = "plain"', 'smtp_security = "STARTTLS"'])
def test_unknown_security_mode_stops_start_up(tmp_path, line):
    with pytest.raises(ValueError, match='"tls" or "starttls"'):
        load(tmp_path, HEAD + f'[[mail_servers]]\nhost = "mail1.hosting.example"\n{line}\n')


def test_ehlo_name_defaults_to_the_public_host_name(tmp_path):
    s = load(tmp_path, BASE.replace("http://127.0.0.1:8765", "https://mcp.example.test"))
    assert s.mail_servers[0].ehlo_name == "mcp.example.test"


def test_ehlo_name_from_an_ip_issuer_is_an_address_literal(tmp_path):
    assert load(tmp_path, BASE).mail_servers[0].ehlo_name == "[127.0.0.1]"


def test_ehlo_name_setting_wins_and_a_server_may_override_it(tmp_path):
    s = load(tmp_path, 'ehlo_name = "relay.example.test"\n' + HEAD + SERVERS.replace(
        "imap_port = 1993", 'imap_port = 1993\nehlo_name = "client-side.example.test"'))
    assert [m.ehlo_name for m in s.mail_servers] == ["relay.example.test", "client-side.example.test"]


def test_ehlo_name_setting_may_use_capitals(tmp_path):
    """Domain names are case-insensitive (RFC 5321 s2.4); the name is given as written."""
    assert load(tmp_path, 'ehlo_name = "Mcp.Example.test"\n' + BASE).mail_servers[0].ehlo_name == "Mcp.Example.test"


def test_bad_ehlo_name_stops_start_up(tmp_path):
    with pytest.raises(ValueError, match="ehlo_name"):
        load(tmp_path, 'ehlo_name = "not a name"\n' + BASE)
