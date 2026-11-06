# SPDX-License-Identifier: AGPL-3.0-or-later
"""auth/login.py is the import surface of the auth/pages/ package (ticket 81).

Three guards: every name the surface promises exists on it and is the object the pages use; no page module
binds a tunable by name (tests patch them on auth.login, so the pages must read them through it at call
time); and the pages answer a fixed set of requests byte for byte as they did before the split. The
'before' responses are in tests/fixtures/auth_pages_before.json, recorded from the module as it was; ids,
codes, sessions and dates are replaced by placeholders in both, never skipped."""
import ast
import json
import re
import tempfile
from pathlib import Path

import pytest
from pydantic import AnyUrl
from starlette.applications import Starlette
from starlette.testclient import TestClient
from mcp.server.auth.provider import AuthorizationParams
from mcp.shared.auth import OAuthClientInformationFull

import mcp_server_imap_smtp.auth.login as login_mod
from mcp_server_imap_smtp.auth.provider import GatewayProvider
from mcp_server_imap_smtp.config import Settings
from mcp_server_imap_smtp.mail.hosts import MailServer
from mcp_server_imap_smtp.mail.resolve import Resolver
from mcp_server_imap_smtp.ratelimit import RateLimiter
from mcp_server_imap_smtp.store import Store

FIXTURE = Path(__file__).parent / "fixtures" / "auth_pages_before.json"

# Every public name auth/login.py had before the split (ticket 81), all of which stay importable from it.
BEFORE_PUBLIC = (
    "CONNECTION", "DAY", "DNS_PER_SIGN_IN", "DNS_WORKERS", "DONE_PAGE", "DUPLICATE", "ERROR", "Entry",
    "FormTooLarge", "ImapClient", "LoginLimits", "MANAGE_PAGE", "MANAGE_SIGNIN", "MANAGE_TTL", "MAX_EMAIL",
    "MAX_FORM_BYTES", "MAX_PASSWORD", "MAX_SHOWN_NAME", "MailUnavailable", "MailboxBusy", "NOT_HOSTED", "PAGE",
    "PASTE_AGAIN", "REMOVE", "ROW", "TOO_SLOW", "UNAVAILABLE", "VERIFY_BUDGET_BASE", "VERIFY_BUDGET_PER_MAILBOX",
    "VERIFY_THREADS", "VERIFY_WORKERS", "Verifier", "bounded", "imap_verifier", "log", "login_routes", "moved",
    "parse_more", "read_form", "return_target", "security_headers", "shown_name", "wait_text",
)
# The private module globals it had, kept as attributes for anyone who reached for them.
BEFORE_PRIVATE = ("_BUSY", "_LINE_BREAK", "_STYLE", "_UNAVAILABLE")
# The module globals existing tests patch with monkeypatch.setattr(login_mod, ...) or on login_mod.ImapClient.
PATCHED_BY_TESTS = ("DNS_WORKERS", "ImapClient", "MAX_FORM_BYTES", "VERIFY_BUDGET_BASE",
                    "VERIFY_BUDGET_PER_MAILBOX", "VERIFY_WORKERS")


# --- the surface -----------------------------------------------------------------------------------------

def test_every_name_in_all_exists_on_the_surface():
    assert login_mod.__all__, "auth.login must declare __all__"
    assert len(set(login_mod.__all__)) == len(login_mod.__all__)
    for name in login_mod.__all__:
        assert hasattr(login_mod, name), name


def test_the_surface_keeps_every_name_it_had():
    assert set(BEFORE_PUBLIC) <= set(login_mod.__all__)
    for name in BEFORE_PRIVATE:
        assert hasattr(login_mod, name), name


def test_the_surface_names_are_the_objects_the_pages_use():
    from mcp_server_imap_smtp.auth import pages
    from mcp_server_imap_smtp.auth.pages import common, login, manage
    tunables = set(login_mod.TUNABLES)
    for name in (*login_mod.__all__, *BEFORE_PRIVATE):
        if name in tunables or name in ("TUNABLES", "log"):
            continue
        homes = [m for m in (pages, common, login, manage) if name in vars(m)]
        assert homes, f"{name} is defined on auth.login itself, not in auth/pages/"
        assert all(getattr(m, name) is getattr(login_mod, name) for m in homes), name


def test_the_pages_log_under_the_old_logger_name():
    from mcp_server_imap_smtp.auth.pages import common
    assert common.log is login_mod.log and login_mod.log.name == "mcp_server_imap_smtp.auth.login"


def test_the_patched_names_are_tunables_defined_on_the_surface():
    assert set(PATCHED_BY_TESTS) <= set(login_mod.TUNABLES)
    for name in login_mod.TUNABLES:
        assert name in login_mod.__all__ and hasattr(login_mod, name), name


def test_the_section_stubs_exist_and_add_nothing():
    from mcp_server_imap_smtp.auth.pages import identities, keys, totp
    for module, ticket in ((totp, "88"), (identities, "70"), (keys, "68")):
        assert ticket in (module.__doc__ or "")
        assert not [n for n in vars(module) if not n.startswith("__")], module.__name__


# --- the package-attribute rule ----------------------------------------------------------------------------

def tunable_bindings(source: str, tunables: set[str]) -> list[str]:
    """Places where a module binds a tunable by name, so a monkeypatch on auth.login would not reach it:
    importing it (`from ..login import VERIFY_WORKERS`, `from ...mail.imap import ImapClient`), assigning it at
    module level, copying it into another module-level name, or freezing it in a function default."""
    found = []
    tree = ast.parse(source)

    def names_in(node) -> set[str]:
        out = set()
        for n in ast.walk(node):
            if isinstance(n, ast.Name) and n.id in tunables:
                out.add(n.id)
            elif isinstance(n, ast.Attribute) and n.attr in tunables:
                out.add(n.attr)
        return out

    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".")[0]
                if alias.name.rpartition(".")[2] in tunables or bound in tunables:
                    found.append(f"line {node.lineno}: imports {alias.name}")
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            for default in (*node.args.defaults, *node.args.kw_defaults):
                if default is not None and names_in(default):
                    found.append(f"line {default.lineno}: default argument {sorted(names_in(default))}")
    for node in tree.body:
        stmts = [node]
        if isinstance(node, ast.ClassDef):
            stmts = node.body
        for stmt in stmts:
            if isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                hit = set().union(*(names_in(t) for t in targets))
                if stmt.value is not None:
                    hit |= names_in(stmt.value)
                if hit:
                    found.append(f"line {stmt.lineno}: module-level binding of {sorted(hit)}")
    return found


def test_the_scan_catches_every_way_of_binding_a_tunable():
    tunables = {"VERIFY_WORKERS", "ImapClient"}
    for bad in ("from ..login import VERIFY_WORKERS",
                "from mcp_server_imap_smtp.auth.login import VERIFY_WORKERS as W",
                "from ...mail.imap import ImapClient",
                "VERIFY_WORKERS = 8",
                "W = _surface().VERIFY_WORKERS",
                "class C:\n    open = ImapClient.open",
                "def f(n=_surface().VERIFY_WORKERS):\n    return n"):
        assert tunable_bindings(bad, tunables), bad
    for good in ("from ..login import TOO_SLOW",
                 "def f():\n    return _surface().VERIFY_WORKERS",
                 "async def g():\n    with _surface().ImapClient.open(1, 2, 3):\n        pass"):
        assert not tunable_bindings(good, tunables), good


def test_no_page_module_binds_a_tunable_by_name():
    pages_dir = Path(login_mod.__file__).parent / "pages"
    files = sorted(pages_dir.glob("*.py"))
    assert {f.name for f in files} >= {"__init__.py", "common.py", "login.py", "manage.py",
                                       "totp.py", "identities.py", "keys.py"}
    problems = {f.name: found for f in files
                if (found := tunable_bindings(f.read_text(), set(login_mod.TUNABLES)))}
    assert not problems, problems


def test_a_patched_tunable_reaches_the_pages(monkeypatch):
    from mcp_server_imap_smtp.auth.pages import common
    monkeypatch.setattr(login_mod, "MAX_FORM_BYTES", 7)
    monkeypatch.setattr(login_mod, "VERIFY_BUDGET_BASE", 1.5)
    assert common._surface().MAX_FORM_BYTES == 7 and common._surface().VERIFY_BUDGET_BASE == 1.5


# --- byte for byte ------------------------------------------------------------------------------------------

MAIL1 = MailServer("mail1.hosting.example", domains=("example.test",), match_mx=False)
PASSWORDS = {"me@example.test": "pw", "a@example.test": "pa", "b@example.test": "pb"}
OWN = "http://127.0.0.1:8765"
_MONTHS = "Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec"
_DATE = re.compile(rf"\b\d{{2}} (?:{_MONTHS}) \d{{4}}( \d{{2}}:\d{{2}} UTC)?")
_SESSION = re.compile(r'name="s" value="([^"]+)"')
_CODE = re.compile(r"[?&;]code=([^&\"\s]+)")


def verifier(address, password, server):
    if address == "down@example.test":
        raise login_mod.MailUnavailable("mail server unavailable")
    return PASSWORDS.get(address) == password


class Normaliser:
    """Replaces what differs between two runs (the pending request id, grant id, manage sessions, codes and
    dates) with numbered placeholders, so the same token in two responses keeps one placeholder."""

    def __init__(self):
        self.names: dict[str, str] = {}

    def name(self, kind: str, value: str) -> None:
        if value and value not in self.names:
            self.names[value] = f"<{kind}{sum(1 for v in self.names.values() if v.startswith('<' + kind)) + 1}>"

    def text(self, value: str) -> str:
        for pattern, kind in ((_SESSION, "SESSION"), (_CODE, "CODE")):
            for found in pattern.findall(value):
                self.name(kind, found)
        for literal in sorted(self.names, key=len, reverse=True):
            value = value.replace(literal, self.names[literal])
        return _DATE.sub(lambda m: "<DATE>" + (" <TIME>" if m[1] else ""), value)

    def response(self, r) -> dict:
        return {"status": r.status_code,
                "headers": [[k.lower(), self.text(v)] for k, v in r.headers.multi_items() if k.lower() != "content-length"],
                "body": self.text(r.content.decode())}


class Env:
    def __init__(self, folder: Path, max_mailboxes: int = 3):
        s = Settings(issuer_url=OWN, mail_resource_url=f"{OWN}/mail", mail_servers=(MAIL1,),
                     db_path=folder / "s.sqlite", login_failures=3, operator_name="Example Hosting",
                     product_name="Example Connector", support_url="https://help.example.org/",
                     support_email="help@example.org", max_mailboxes=max_mailboxes,
                     redirect_allowlist=("https://app.example.org/callback",))
        self.store = Store(s.db_path)
        provider = GatewayProvider(s, self.store)
        self.req = self.store.create_pending("c1", AuthorizationParams(
            state="st", scopes=None, code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            redirect_uri=AnyUrl("https://app.example.org/callback"), redirect_uri_provided_explicitly=True,
            resource=s.mail_resource_url), ttl=600)
        self.store.save_client(OAuthClientInformationFull(
            client_id="c1", client_name="Example <AI> App", redirect_uris=[AnyUrl("https://app.example.org/callback")],
            token_endpoint_auth_method="none"))
        self.gid, key = self.store.create_grant("c1", s.mail_resource_url, [("me@example.test", "pw", MAIL1),
                                                                            ("a@example.test", "pa", MAIL1)])
        self.store.issue_tokens(self.gid, key, "c1", [], s.mail_resource_url, 3600, 86400)
        self.store.mark_mailbox(self.gid, "a@example.test", True)
        app = Starlette(routes=login_mod.login_routes(provider, Resolver((MAIL1,)), verifier,
                                                      RateLimiter(3, 900), s))
        self.client = TestClient(app, follow_redirects=False)
        self.norm = Normaliser()
        self.norm.name("REQ", self.req)
        self.norm.name("GRANT", self.gid)

    def login(self, **data):
        return self.client.post("/mail/login", data={"req": self.req, **data})

    def manage(self, **data):
        return self.client.post("/mail/manage", data=data)

    def signin(self, email="me@example.test", password="pw"):
        return self.manage(action="signin", email=email, password=password)

    def act(self, signed_in, action, **fields):
        session = _SESSION.search(signed_in.text)[1]
        return self.manage(s=session, action=action, grant=self.gid, **fields)


def _signed_in(e, action, **fields):
    r = e.signin()
    return [r, e.act(r, action, **fields)]


SCENARIOS = {
    "sign-in page with a pending request": lambda e: [e.client.get(f"/mail/login?req={e.req}")],
    "sign-in page, expired request": lambda e: [e.client.get("/mail/login?req=nope")],
    "sign-in, wrong password with a list": lambda e: [e.login(email="me@example.test", password="bad",
                                                              more="a@example.test SeCrEt")],
    "sign-in, wrong password in the list": lambda e: [e.login(email="me@example.test", password="pw",
                                                              more="a@example.test bad\nb@example.test pb")],
    "sign-in, success": lambda e: [e.login(email="Me@Example.test", password="pw", more="a@example.test pa")],
    "sign-in, malformed list line": lambda e: [e.login(email="me@example.test", password="pw", more="a@example.test")],
    "sign-in, not hosted": lambda e: [e.login(email="me@example.test", password="pw", more="x@example.org px")],
    "sign-in, duplicate with another password": lambda e: [e.login(email="me@example.test", password="pw",
                                                                   more="me@example.test other")],
    "sign-in, too many mailboxes": lambda e: [e.login(email="me@example.test", password="pw",
                                                      more="a@example.test pa\nb@example.test pb\nc@example.test pc")],
    "sign-in, mail server down": lambda e: [e.login(email="down@example.test", password="pw")],
    "sign-in, cross-origin post": lambda e: [e.client.post("/mail/login", data={"req": e.req},
                                                           headers={"Origin": "https://attacker.example"})],
    "sign-in, null-origin post": lambda e: [e.client.post("/mail/login", data={"req": e.req},
                                                          headers={"Origin": "null"})],
    "sign-in, own-origin post": lambda e: [e.client.post("/mail/login", data={"req": e.req, "email": "me@example.test",
                                                                              "password": "bad"},
                                                         headers={"Origin": OWN})],
    "sign-in, form too large": lambda e: [e.login(email="me@example.test", password="pw",
                                                  more="x" * (2 * 1024 * 1024 + 1))],
    "sign-in, lockout": lambda e: [e.login(email="me@example.test", password="bad") for _ in range(4)],
    "old sign-in address": lambda e: [e.client.get("/login?req=abc&x=1"), e.client.post("/manage")],
    "manage page signed out": lambda e: [e.client.get("/mail/manage")],
    "manage, wrong password": lambda e: [e.signin(password="bad")],
    "manage, not a main mailbox": lambda e: [e.signin("a@example.test", "pa")],
    "manage, signed in": lambda e: [e.signin()],
    "manage, cross-origin post": lambda e: [e.client.post("/mail/manage", data={"action": "signin"},
                                                          headers={"Origin": "https://attacker.example"})],
    "manage, session ended": lambda e: [e.manage(s="mg.nope.nope", action="add")],
    "manage, add and update": lambda e: _signed_in(e, "add", more="a@example.test pa\nb@example.test pb"),
    "manage, add with a wrong password": lambda e: _signed_in(e, "add", more="b@example.test bad"),
    "manage, add an empty list": lambda e: _signed_in(e, "add", more=""),
    "manage, remove": lambda e: _signed_in(e, "remove", address="a@example.test"),
    "manage, remove the main mailbox": lambda e: _signed_in(e, "remove", address="me@example.test"),
    "manage, disconnect": lambda e: _signed_in(e, "disconnect"),
    "manage, unknown connection": lambda e: [e.manage(s=_SESSION.search(e.signin().text)[1], action="add",
                                                      grant="nope")],
    "manage, sign out": lambda e: _signed_in(e, "signout"),
}


def record() -> dict:
    """Every scenario's responses, normalised, each in a fresh store."""
    out = {}
    for title, run in SCENARIOS.items():
        with tempfile.TemporaryDirectory() as folder:
            e = Env(Path(folder))
            out[title] = [e.norm.response(r) for r in run(e)]
    return out


def test_the_normaliser_replaces_rather_than_drops():
    n = Normaliser()
    n.name("REQ", "abc123")
    text = n.text('<input name="s" value="mg.x.y">abc123 on 06 Nov 2026 14:05 UTC, from 01 Jan 2026; ?code=c.1.2&amp;s')
    assert text == '<input name="s" value="<SESSION1>"><REQ1> on <DATE> <TIME>, from <DATE>; ?code=<CODE1>&amp;s'


@pytest.mark.parametrize("title", list(SCENARIOS))
def test_the_pages_answer_byte_for_byte_as_before(title, tmp_path):
    before = json.loads(FIXTURE.read_text())
    assert set(before) == set(SCENARIOS)
    e = Env(tmp_path)
    after = [e.norm.response(r) for r in SCENARIOS[title](e)]
    assert after == before[title]


@pytest.mark.parametrize("first", ["mcp_server_imap_smtp.auth.pages", "mcp_server_imap_smtp.auth.pages.common",
                                   "mcp_server_imap_smtp.auth.pages.login", "mcp_server_imap_smtp.auth.pages.manage"])
def test_the_pages_import_in_any_order(first):
    # A page module that imported auth.login at the top would break when it is imported first (circular).
    import subprocess
    import sys
    code = (f"import {first}; import mcp_server_imap_smtp.auth.login as m; "
            "import mcp_server_imap_smtp.auth.pages.common as c; assert c._surface() is m and m.login_routes")
    subprocess.run([sys.executable, "-c", code], check=True)
