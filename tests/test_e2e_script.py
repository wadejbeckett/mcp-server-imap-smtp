# SPDX-License-Identifier: AGPL-3.0-or-later
"""deploy/e2e.py: its pure parts (PKCE, page parsing, the env-file check, redaction), and a walk through the
real ASGI app in process, where the mail layer always fails, to show no secret is printed even then."""
import base64
import importlib.util
import json
import os
import re
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


def strings(value):
    """Every string in a parsed JSON value, keys included: what a reader of the --json output sees."""
    if isinstance(value, dict):
        for k, v in value.items():
            yield k
            yield from strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from strings(v)
    elif isinstance(value, str):
        yield value


def test_report_redacts_failure_details(capsys):
    redact = e2e.Redactor()
    redact.add(PASSWORD)
    report = e2e.Report(redact, sys.stdout)
    report.add("FAIL", "sign-in", f"server said: {PASSWORD}")
    out = capsys.readouterr().out
    assert PASSWORD not in out and out.startswith("FAIL  sign-in: server said: [redacted]")
    parsed = json.loads(report.json(report.summary(BASE, [], None, 1.0)))
    assert not any(PASSWORD in s for s in strings(parsed))


def test_json_output_is_redacted_before_it_is_escaped():
    # json.dumps escapes the non-ASCII character of the password, so redacting the serialised text misses it.
    redact = e2e.Redactor()
    redact.add(PASSWORD)
    report = e2e.Report(redact, sys.stdout)
    text = report.json({"base": BASE, "steps": [{"detail": f"said {PASSWORD}"}], PASSWORD: [PASSWORD]})
    assert not any(PASSWORD in s for s in strings(json.loads(text)))
    assert json.dumps(PASSWORD)[1:-1] not in text


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
    assert_no_secret(out, err, {PASSWORD, ADDRESS, *seen})


def assert_no_secret(out, err, secrets):
    """No secret in the check lines or the --json object, as printed (JSON-escaped too) or once parsed."""
    parsed = list(strings(json.loads(out))) if out.strip() else []
    for secret in secrets:
        for variant in (secret, e2e.urllib.parse.quote(secret, safe=""), base64.b64encode(secret.encode()).decode(),
                        json.dumps(secret)[1:-1]):
            assert variant not in out and variant not in err, secret
            assert not any(variant in s for s in parsed), secret


# registration on an instance that refuses loopback redirects

@pytest.fixture
def app_http_with(tmp_path):
    """An AppHttp on the real app built with the given settings."""
    clients = []

    def make(**settings):
        app = build_app(make_settings(tmp_path, **settings), opener=no_network, sender=no_network,
                        verifier=lambda a, p, server: (a, p) == (ADDRESS, PASSWORD))
        c = TestClient(app, base_url=BASE, follow_redirects=False)
        clients.append(c.__enter__())
        return AppHttp(c)
    yield make
    for c in clients:
        c.__exit__(None, None, None)


def test_instance_without_loopback_redirects_is_named_as_the_cause(app_http_with, capsys):
    code, out, err = run(app_http_with(allow_loopback_redirects=False), capsys)
    assert code == 1
    steps = {s["name"]: s for s in json.loads(out)["steps"]}
    detail = steps["client registration"]["detail"]
    assert steps["client registration"]["outcome"] == "FAIL"
    assert "allow_loopback_redirects" in detail and "--redirect-uri" in detail, detail


def test_redirect_uri_on_the_allowlist_walks_a_hardened_instance(app_http_with, capsys):
    allowed = "https://app.example.org/callback"
    http = app_http_with(allow_loopback_redirects=False, redirect_allowlist=(allowed,))
    code, out, err = run(http, capsys, "--redirect-uri", allowed)
    steps = {s["name"]: s["outcome"] for s in json.loads(out)["steps"]}
    for name in ("client registration", "authorization request", "sign-in page", "sign-in",
                 "cross-site sign-in refused", "token exchange", "token refresh", "MCP initialize", "revocation",
                 "revoked token refused"):
        assert steps[name] == "PASS", (name, steps)


@pytest.mark.parametrize("uri", ["app.example.org/cb", "ftp://app.example.org/cb", "https://app.example.org/cb#x"])
def test_redirect_uri_must_be_an_absolute_http_url(uri, capsys):
    env = {"MCP_E2E_ADDRESS": ADDRESS, "MCP_E2E_PASSWORD": PASSWORD}
    assert e2e.main(["https://mcp.example.com", "--redirect-uri", uri], environ=env, http=NoSend()) == 2
    assert "--redirect-uri" in capsys.readouterr().err


class NoSend(e2e.Http):
    def __init__(self): pass
    def send(self, *a): raise AssertionError("nothing may be sent")


# the walk never sends a secret off the instance's origin

class Rewriting(AppHttp):
    """Rewrites the app's answers the way a misconfigured proxy or a hostile instance could, and records the
    origin and body of every request instead of sending one off the instance."""

    def __init__(self, inner: AppHttp, rewrite):
        super().__init__(inner.client)
        self.rewrite, self.sent = rewrite, []

    def send(self, method, url, headers, body):
        self.sent.append((e2e.origin(url), body or b""))
        if e2e.origin(url) != BASE:
            return e2e.Response(200, e2e.Headers(), b"{}")
        r = super().send(method, url, headers, body)
        return e2e.Response(r.status, r.headers, self.rewrite(url, r.body))


def foreign_sends(http):
    return [body for where, body in http.sent if where != BASE]


@pytest.mark.parametrize("action", ["http://127.0.0.1:9999/login", "https://other.example.org/login"])
def test_password_is_not_posted_to_a_form_action_on_another_origin(app_http, capsys, action):
    def rewrite(url, body):
        return re.sub(rb'<form([^>]*?) action="[^"]*"', b'<form\\1 action="' + action.encode() + b'"', body) \
            if b'type="password"' in body else body
    http = Rewriting(app_http, rewrite)
    code, out, err = run(http, capsys)
    steps = {s["name"]: s for s in json.loads(out)["steps"]}
    assert code == 1 and steps["sign-in"]["outcome"] == "FAIL"
    assert "password not sent" in steps["sign-in"]["detail"]
    assert not any(e2e.urllib.parse.quote_plus(PASSWORD).encode() in b for b in foreign_sends(http))
    assert foreign_sends(http) == []


def test_cross_site_post_is_not_sent_to_a_form_action_on_another_origin(app_http, capsys):
    pages = []

    def rewrite(url, body):
        if b'type="password"' in body:
            pages.append(url)
            if len(pages) == 2:      # the second sign-in page is the cross-site attempt's
                return re.sub(rb' action="[^"]*"', b' action="https://other.example.org/login"', body, count=1)
        return body
    http = Rewriting(app_http, rewrite)
    run(http, capsys)
    assert foreign_sends(http) == []


@pytest.mark.parametrize("endpoint", ["http://127.0.0.1:9999/revoke", "https://other.example.org/revoke"])
def test_revocation_endpoint_on_another_origin_fails_discovery(app_http, capsys, endpoint):
    def rewrite(url, body):
        if "/.well-known/oauth-authorization-server" in url:
            doc = json.loads(body)
            doc["revocation_endpoint"] = endpoint
            return json.dumps(doc).encode()
        return body
    http = Rewriting(app_http, rewrite)
    code, out, _ = run(http, capsys)
    steps = {s["name"]: s for s in json.loads(out)["steps"]}
    assert code == 1 and steps["authorization-server metadata"]["outcome"] == "FAIL"
    assert "revocation_endpoint" in steps["authorization-server metadata"]["detail"]
    assert foreign_sends(http) == []


def test_cleanup_never_posts_the_refresh_token_to_another_origin():
    class Record(e2e.Http):
        def __init__(self): self.sent = []
        def send(self, method, url, headers, body):
            self.sent.append(url)
            return e2e.Response(200, e2e.Headers(), b"{}")
    http, report = Record(), e2e.Report(e2e.Redactor(), sys.stderr)
    walk = e2e.Walk("https://mcp.example.com", "/mail", ADDRESS, PASSWORD, http, report)
    walk.s.asm = {"revocation_endpoint": "https://other.example.org/revoke"}
    walk.s.refresh, walk.s.access, walk.s.client_id = "refresh-token-value", "access-token-value", "client"
    walk.cleanup()
    steps = {s.name: s for s in report.steps}
    assert steps["revocation"].outcome == "FAIL" and "another origin" in steps["revocation"].detail
    assert not any(e2e.origin(u) != "https://mcp.example.com" for u in http.sent)


# structured results

class Answer(e2e.Http):
    """Answers every MCP post with one tools/call result."""

    def __init__(self, result): self.result = result
    def send(self, method, url, headers, body):
        message = {"jsonrpc": "2.0", "id": json.loads(body)["id"], "result": self.result}
        return e2e.Response(200, e2e.Headers({"content-type": "application/json"}), json.dumps(message).encode())


def test_a_tool_result_without_structured_content_fails_where_structure_is_checked():
    text_only = {"content": [{"type": "text", "text": json.dumps({"mailboxes": [ADDRESS]})}]}
    mcp = e2e.Mcp(Answer(text_only), BASE + "/mail", "token")
    assert mcp.call("mail_accounts", {}) == {"mailboxes": [ADDRESS]}      # reading a value: the text will do
    with pytest.raises(e2e.StepFailed, match="structuredContent"):
        mcp.call("mail_accounts", {}, require_structured=True)
    structured = {**text_only, "structuredContent": {"mailboxes": [ADDRESS]}}
    assert e2e.Mcp(Answer(structured), BASE + "/mail", "t").call("mail_accounts", {}, require_structured=True) \
        == {"mailboxes": [ADDRESS]}


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
