# SPDX-License-Identifier: AGPL-3.0-or-later
"""Security review 2026-10-20, finding 19 (mail sub-report A6-A9, S1)."""
import tomllib
from email.message import EmailMessage
from pathlib import Path

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from mcp_server_imap_smtp.mail import compose, render, smtp
from mcp_server_imap_smtp.mail.hosts import HostNotAllowed
from mcp_server_imap_smtp.mail.imap import ImapClient, MailError
from mcp_server_imap_smtp.mail.resolve import normalise_address
from mcp_server_imap_smtp.mail import tools as tools_mod
from tests.test_tools import FakeImap, anyio_backend, build, env, payload  # noqa: F401

ROOT = Path(__file__).resolve().parent.parent


# A6: IDNA 2008 / UTS 46 non-transitional: ß stays ß.
def test_sharp_s_domain_is_not_folded_to_ss():
    assert normalise_address("u@faß.de") == ("u@xn--fa-hia.de", "xn--fa-hia.de")
    assert normalise_address("u@xn--fa-hia.de")[1] == "xn--fa-hia.de"


@pytest.mark.parametrize("bad", ["u@-bad-.de", "u@a..de", "u@​.de"])
def test_invalid_idna_is_refused(bad):
    with pytest.raises(HostNotAllowed):
        normalise_address(bad)


# A7: a display name may not look like an address.
@pytest.mark.parametrize("value", ['"x@evil.com" <y@good.com>', "x@evil.com <y@good.com>",
                                   '"Pay x@evil.com" <y@good.com>'])
def test_display_name_holding_an_address_is_refused(value):
    with pytest.raises(MailError):
        compose.new("me@x.co.za", [value], "s", "t")


def test_plain_display_names_still_work():
    m = compose.new("me@x.co.za", ['"Jane Doe" <jane@good.com>', "bob@good.com"], "s", "t")
    assert "jane@good.com" in m["To"]


# A8: server reply text is not passed back; only a code and a short category.
class _Conn:
    def __init__(self, typ, data):
        self.r = (typ, data)

    def list(self, *a):
        return self.r


def test_imap_refusal_keeps_the_response_code_only():
    c = ImapClient.__new__(ImapClient)
    with pytest.raises(MailError) as e:
        c._ok("NO", [b"[NONEXISTENT] Folder secret-hr-folder on internal-host-7 does not exist"], "SELECT")
    assert "secret-hr" not in str(e.value) and "internal-host" not in str(e.value)
    assert "NONEXISTENT" in str(e.value) and "does not exist" in str(e.value)
    with pytest.raises(MailError) as e:
        c._ok("NO", [b"backend 10.0.0.5 said no"], "STORE")
    assert "10.0.0.5" not in str(e.value) and "STORE failed" in str(e.value)


def test_smtp_refusal_keeps_codes_only():
    msg = smtp.refusal(550, b"5.1.1 <victim@y.co.za>: Recipient address rejected: relay.internal 10.1.2.3")
    assert "victim" not in msg and "10.1.2.3" not in msg and "550" in msg and "5.1.1" in msg
    assert "permanent" in msg
    assert "temporary" in smtp.refusal(451, b"try later")


# A9: uid lists are capped; attachment sizes need no decoding.
@pytest.mark.anyio
async def test_uid_lists_are_capped(env):
    srv, _ = build(env)
    with pytest.raises(ToolError, match="at most 500"):
        await srv.call_tool("mail_flag", {"folder": "INBOX", "uids": list(range(1, 502)), "seen": True})
    out = payload(await srv.call_tool("mail_flag", {"folder": "INBOX", "uids": list(range(1, 501)), "seen": True}))
    assert len(out["updated"]) == 500


def test_attachment_size_is_counted_without_decoding(monkeypatch):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = "a@x.co.za", "b@y.co.za", "s"
    m.set_content("body")
    m.add_attachment(b"x" * 1000, maintype="application", subtype="octet-stream", filename="a.bin")
    m.add_attachment(b"y" * 13, maintype="application", subtype="pdf", filename="b.pdf")
    raw = m.as_bytes()
    monkeypatch.setattr(render, "_get_attachment_data", lambda part: pytest.fail("decoded"))
    assert [a["size"] for a in render.summarise(raw)["attachments"]] == [1000, 13]


# S1: the build backend is pinned to one version.
def test_build_backend_is_pinned():
    requires = tomllib.loads((ROOT / "pyproject.toml").read_text())["build-system"]["requires"]
    assert len(requires) == 1 and requires[0].startswith("setuptools==")
