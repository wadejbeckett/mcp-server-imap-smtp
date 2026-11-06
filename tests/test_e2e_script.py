# SPDX-License-Identifier: AGPL-3.0-or-later
"""deploy/e2e.py: its pure parts (PKCE, page parsing, the env-file check, redaction), and a walk through the
real ASGI app in process, where the mail layer always fails, to show no secret is printed even then."""
import base64
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from mcp_server_imap_smtp.app import build_app
from tests.test_e2e import BASE, make_settings, no_network

SCRIPT = Path(__file__).resolve().parent.parent / "deploy" / "e2e.py"
_spec = importlib.util.spec_from_file_location("e2e_script", SCRIPT)
e2e = importlib.util.module_from_spec(_spec)
sys.modules["e2e_script"] = e2e          # dataclasses look their module up while the file runs
_spec.loader.exec_module(e2e)

ADDRESS, PASSWORD = "me@x.co.za", "pw-Secret+/=&é"


# PKCE

def test_s256_matches_rfc_7636_appendix_b():
    assert e2e.s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_pkce_pair_is_fresh_and_well_formed():
    v1, c1 = e2e.pkce_pair()
    v2, _ = e2e.pkce_pair()
    assert v1 != v2 and 43 <= len(v1) <= 128 and set(v1) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
    assert c1 == e2e.s256(v1) and len(c1) == 43


# base URL and metadata location

@pytest.mark.parametrize("url, expected", [("https://mcp.example.com/", "https://mcp.example.com"),
                                           ("http://127.0.0.1:8765", "http://127.0.0.1:8765"),
                                           ("http://localhost:9000", "http://localhost:9000"),
                                           ("http://[::1]:9000", "http://[::1]:9000")])
def test_check_base_accepts(url, expected):
    assert e2e.check_base(url) == expected


@pytest.mark.parametrize("url", ["http://mcp.example.com", "https://mcp.example.com/mail", "ftp://x.example",
                                 "https://user:pw@mcp.example.com", "mcp.example.com", "https://mcp.example.com?x=1"])
def test_check_base_refuses(url):
    with pytest.raises(e2e.UsageError):
        e2e.check_base(url)


def test_as_metadata_url_puts_the_well_known_segment_before_the_path():
    assert e2e.as_metadata_url("https://a.example") == "https://a.example/.well-known/oauth-authorization-server"
    assert e2e.as_metadata_url("https://a.example/") == "https://a.example/.well-known/oauth-authorization-server"
    assert e2e.as_metadata_url("https://a.example/t1") == "https://a.example/.well-known/oauth-authorization-server/t1"


# env file

def env_file(tmp_path, text, mode):
    p = tmp_path / "e2e.env"
    p.write_text(text)
    p.chmod(mode)
    return str(p)


def test_env_file_is_read_when_only_the_owner_can_read_it(tmp_path):
    path = env_file(tmp_path, "# test mailbox\nexport MCP_E2E_ADDRESS=me@x.co.za\nMCP_E2E_PASSWORD='a b=c'\n\n", 0o600)
    assert e2e.credentials(path, {}) == ("me@x.co.za", "a b=c")


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o660, 0o644, 0o602])
def test_env_file_readable_by_others_is_refused(tmp_path, mode):
    path = env_file(tmp_path, f"MCP_E2E_ADDRESS={ADDRESS}\nMCP_E2E_PASSWORD={PASSWORD}\n", mode)
    with pytest.raises(e2e.UsageError) as err:
        e2e.credentials(path, {})
    assert "chmod 600" in str(err.value) and PASSWORD not in str(err.value)


def test_credentials_come_from_the_environment_without_a_file():
    assert e2e.credentials(None, {"MCP_E2E_ADDRESS": ADDRESS, "MCP_E2E_PASSWORD": PASSWORD}) == (ADDRESS, PASSWORD)
    with pytest.raises(e2e.UsageError):
        e2e.credentials(None, {"MCP_E2E_ADDRESS": ADDRESS})


def test_missing_credentials_exit_2_before_anything_is_sent(capsys):
    class Refuse(e2e.Http):
        def __init__(self): pass
        def send(self, *a): raise AssertionError("nothing may be sent")
    assert e2e.main(["https://mcp.example.com"], environ={}, http=Refuse()) == 2
    assert "MCP_E2E_PASSWORD" in capsys.readouterr().err


def test_there_is_no_password_option():
    with pytest.raises(SystemExit):
        e2e.parse_args(["https://mcp.example.com", "--password", "x"])


# pages

def test_sign_in_form_and_fields_as_a_browser_sends_them():
    page = e2e.parse_page('<form method="post" action="login"><input type="hidden" name="req" value="a&amp;b">'
                          '<input name="email" type="email" value=""><input name="password" type="password">'
                          '<textarea name="more"></textarea></form><form action="x"><input name="q"></form>')
    form = e2e.sign_in_form(page)
    assert form["action"] == "login"
    assert e2e.form_fields(form, ADDRESS, PASSWORD) == {"req": "a&b", "email": ADDRESS, "password": PASSWORD,
                                                        "more": ""}


def test_connected_page_link_and_error_text_are_found():
    page = e2e.parse_page('<p class="err" role="alert">Address or password incorrect.</p>'
                          '<a class="b" href="http://127.0.0.1:5/cb?code=c&amp;state=s">Continue</a>')
    assert page.links == ["http://127.0.0.1:5/cb?code=c&state=s"]
    assert page.errors == ["Address or password incorrect."]


def test_security_header_problems():
    good = e2e.Headers({"x-frame-options": "DENY", "cache-control": "no-store", "referrer-policy": "same-origin",
                        "content-security-policy": "default-src 'none'; frame-ancestors 'none'"})
    assert e2e.security_header_problems(good, https=False) == []
    assert e2e.security_header_problems(good, https=True) == ["Strict-Transport-Security missing"]
    assert len(e2e.security_header_problems(e2e.Headers(), https=False)) == 4


# tools/list

def tool(**hints):
    return {"inputSchema": {"type": "object"}, "annotations": {
        "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False, **hints}}


def test_tool_problems_accepts_any_extra_tool_with_complete_hints():
    tools = {n: tool() for n in (*e2e.CORE_TOOLS, "mail_future_tool")}
    assert e2e.tool_problems(tools) == []


def test_tool_problems_names_missing_core_tools_hints_and_schemas():
    tools = {n: tool() for n in e2e.CORE_TOOLS if n != "mail_read"}
    tools["mail_search"] = tool(openWorldHint=None)
    tools["mail_folders"] = {**tool(), "inputSchema": None}
    assert e2e.tool_problems(tools) == ["core tools missing: mail_read", "mail_folders has no object input schema",
                                        "mail_search lacks openWorldHint"]


# redaction

def test_redactor_hides_plain_and_url_encoded_secrets():
    r = e2e.Redactor()
    r.add(PASSWORD, "tok_abcdef", None, "")
    text = f"x {PASSWORD} y tok_abcdef z {e2e.urllib.parse.quote(PASSWORD, safe='')} " \
           f"{e2e.urllib.parse.quote_plus(PASSWORD)}"
    out = r(text)
    assert PASSWORD not in out and "tok_abcdef" not in out and out.count("[redacted]") == 4


def test_report_redacts_failure_details(capsys):
    redact = e2e.Redactor()
    redact.add(PASSWORD)
    report = e2e.Report(redact, sys.stdout)
    report.add("FAIL", "sign-in", f"server said: {PASSWORD}")
    out = capsys.readouterr().out
    assert PASSWORD not in out and out.startswith("FAIL  sign-in: server said: [redacted]")
    assert PASSWORD not in json.dumps(report.summary(BASE, [], None, 1.0))


# the walk through the real app, in process

class AppHttp(e2e.Http):
    """The script's HTTP layer on a Starlette TestClient; keeps every answer to look for secrets in."""

    def __init__(self, client):
        self.client, self.answers = client, []

    def send(self, method, url, headers, body):
        r = self.client.request(method, url, headers=headers, content=body)
        self.answers.append(r.content)
        return e2e.Response(r.status_code, e2e.Headers({k.lower(): v for k, v in r.headers.items()}), r.content)


def secrets_seen(answers) -> set[str]:
    """Every token, code and sign-in request id the app handed out."""
    found = set()
    for body in answers:
        text = body.decode("utf-8", "replace")
        try:
            doc = json.loads(text)
        except ValueError:
            doc = None
        if isinstance(doc, dict):
            found.update(str(doc[k]) for k in ("access_token", "refresh_token") if doc.get(k))
        found.update(e2e.re.findall(r'name="req" value="([^"]+)"', text))
        found.update(e2e.re.findall(r"code=([A-Za-z0-9_\-]+)", text))
    return found


@pytest.fixture
def app_http(tmp_path):
    app = build_app(make_settings(tmp_path), opener=no_network, sender=no_network,
                    verifier=lambda a, p, server: (a, p) == (ADDRESS, PASSWORD))
    with TestClient(app, base_url=BASE, follow_redirects=False) as c:
        yield AppHttp(c)


def run(app_http, capsys, *args):
    code = e2e.main([BASE, "--json", *args], environ={"MCP_E2E_ADDRESS": ADDRESS, "MCP_E2E_PASSWORD": PASSWORD},
                    http=app_http)
    out = capsys.readouterr()
    return code, out.out, out.err


def test_walk_with_a_failing_mail_layer_reports_and_never_prints_a_secret(app_http, capsys):
    code, out, err = run(app_http, capsys, "--write", "--send")
    assert code == 1
    summary = json.loads(out)
    steps = {s["name"]: s["outcome"] for s in summary["steps"]}
    for name in ("401 without a token", "protected-resource metadata", "authorization-server metadata",
                 "client registration", "authorization request", "sign-in page", "sign-in",
                 "cross-site sign-in refused", "token exchange", "token refresh", "MCP initialize",
                 "MCP initialized notification", "tools/list", "mail_accounts", "revocation", "revoked token refused"):
        assert steps[name] == "PASS", (name, summary)
    assert steps["TLS"] == "SKIP"
    assert steps["mail_folders"] == "FAIL" and steps["draft saved"] == "FAIL"
    assert summary["ok"] is False and "mail_search" in summary["tools"]
    seen = secrets_seen(app_http.answers)
    assert len(seen) >= 4                      # tokens of the exchange and the refresh, the code, the req id
    for secret in {PASSWORD, ADDRESS, *seen}:
        for variant in (secret, e2e.urllib.parse.quote(secret, safe=""), base64.b64encode(secret.encode()).decode()):
            assert variant not in out and variant not in err, secret


def test_walk_with_keep_leaves_the_connection(app_http, capsys):
    code, out, _ = run(app_http, capsys, "--keep")
    steps = {s["name"]: s for s in json.loads(out)["steps"]}
    assert steps["revocation"]["outcome"] == "SKIP" and "--keep" in steps["revocation"]["detail"]
    assert "revoked token refused" not in steps


def test_env_file_permissions_are_checked_by_main(tmp_path, capsys):
    path = env_file(tmp_path, f"MCP_E2E_ADDRESS={ADDRESS}\nMCP_E2E_PASSWORD={PASSWORD}\n", 0o644)
    assert e2e.main(["https://mcp.example.com", "--env-file", path], environ={}) == 2
    out = capsys.readouterr()
    assert PASSWORD not in out.out + out.err and "chmod 600" in out.err


def test_script_is_executable_and_standard_library_only():
    assert os.access(SCRIPT, os.X_OK)
    imports = e2e.re.findall(r"^(?:from|import) ([a-z0-9_.]+)", SCRIPT.read_text(), e2e.re.MULTILINE)
    assert all(i.split(".")[0] in sys.stdlib_module_names or i == "__future__" for i in imports), imports


def test_unreachable_or_untrusted_instance_fails_at_the_first_check(capsys):
    class Untrusted(e2e.Http):
        def __init__(self): self.calls = 0
        def send(self, method, url, headers, body):
            self.calls += 1
            raise e2e.StepFailed(f"cannot reach {e2e.origin(url)}: [SSL: CERTIFICATE_VERIFY_FAILED]")
    http = Untrusted()
    code = e2e.main(["https://mcp.example.com", "--json"], environ={"MCP_E2E_ADDRESS": ADDRESS,
                                                                    "MCP_E2E_PASSWORD": PASSWORD}, http=http)
    out = capsys.readouterr()
    steps = [(s["name"], s["outcome"]) for s in json.loads(out.out)["steps"]]
    assert code == 1 and http.calls == 1
    assert steps == [("401 without a token", "FAIL"), ("revocation", "SKIP")]
    assert "CERTIFICATE_VERIFY_FAILED" in out.err and PASSWORD not in out.err + out.out
