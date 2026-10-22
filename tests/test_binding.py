# SPDX-License-Identifier: AGPL-3.0-or-later
"""The connector only ever signs in to the mail servers it is bound to ([[mail_servers]])."""
from pathlib import Path

import pytest

from mcp_server_imap_smtp.config import load_settings
from mcp_server_imap_smtp.mail.hosts import HostNotAllowed
from mcp_server_imap_smtp.mail.resolve import Resolver

ROOT = Path(__file__).resolve().parents[1]
BASE = 'issuer_url = "https://mcp.example.net"\nmail_resource_url = "https://mcp.example.net/mail"\ndb_path = "{db}"\n'


def write(tmp_path, text: str) -> Path:
    p = tmp_path / "c.toml"
    p.write_text(text.replace("{db}", str(tmp_path / "s.sqlite")))
    return p


def test_no_mail_servers_means_no_service(tmp_path):
    with pytest.raises(ValueError, match="no mail server configured"):
        load_settings(write(tmp_path, BASE))
    with pytest.raises(ValueError):
        load_settings(write(tmp_path, BASE + "mail_servers = []\n"))


def test_an_address_on_no_bound_server_is_refused_before_any_password(tmp_path):
    s = load_settings(write(tmp_path, BASE + '[[mail_servers]]\nhost = "mail.client.example"\n'
                                              'domains = ["client.example", "*.client.example"]\nmatch_mx = false\n'))
    r = Resolver(s.mail_servers)
    assert r.resolve("ann@client.example")[1].host == "mail.client.example"
    assert r.resolve("ann@eu.client.example")[1].host == "mail.client.example"
    for address in ("ann@gmail.com", "ann@client.example.evil.com", "ann@notclient.example"):
        with pytest.raises(HostNotAllowed):
            r.resolve(address)


@pytest.mark.parametrize("path", ["config.example.toml", "deploy/config.prod.toml.template"])
def test_shipped_configs_listen_on_loopback_and_bind_named_servers_only(tmp_path, path):
    text = (ROOT / path).read_text().replace("@MCP_HOSTNAME@", "mcp.example.net").replace("@NAME@", "x")
    text = text.replace('"./mcp-server-imap-smtp.sqlite"', '"{db}"').replace('"/var/lib/x/mcp-server-imap-smtp.sqlite"', '"{db}"')
    s = load_settings(write(tmp_path, text))
    assert s.listen_host == "127.0.0.1"                                   # never on a public interface
    assert all("*" not in m.domains for m in s.mail_servers)              # no catch-all server
    assert {m.host for m in s.mail_servers} <= {"mail.example.com", "mail.client.example"}   # reserved names only
