#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""End-to-end check of a running mcp-server-imap-smtp instance, the way an AI app uses it.

    MCP_E2E_ADDRESS=user@example.com MCP_E2E_PASSWORD=... deploy/e2e.py https://mcp.example.com
    deploy/e2e.py https://mcp.example.com --env-file ~/e2e.env --write --send

Walks discovery (401 without a token, both metadata documents), dynamic client registration as a public
client, authorisation with PKCE S256 through the sign-in page, a refused cross-site sign-in post, token
exchange and refresh, MCP initialize and tools/list, and a read-only tool sweep. --write also saves a draft
with attachments, reads it back, flags it and removes it; --send also sends a message to the mailbox itself
and removes it once it arrives. At the end the connection is revoked (unless --keep) and the revoked token
is shown to be refused. Every check prints PASS, FAIL or SKIP; the exit code is 1 when any check failed.

Credentials come only from the environment (MCP_E2E_ADDRESS, MCP_E2E_PASSWORD) or from --env-file, a
KEY=value file that only its owner may read. They are never printed, and neither are tokens or mail content.
Only messages this script created are changed or removed. An http:// base URL is allowed for a loopback
address only (local testing); the TLS and HSTS checks are then skipped.
The client is registered with a loopback redirect URI (nothing listens there: the code is read from the
connected page); for an instance with allow_loopback_redirects = false, pass --redirect-uri with a URI
that its redirect_allowlist accepts.

Python 3.11 or later, standard library only: copy this one file to any machine.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import os
import re
import secrets
import ssl
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from html.parser import HTMLParser

PROTOCOL_VERSION = "2025-06-18"
CORE_TOOLS = ("mail_accounts", "mail_folders", "mail_search", "mail_read")
HINTS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")
LOOPBACK = ("127.0.0.1", "localhost", "::1")
ARRIVAL_WAIT = 60        # seconds to wait for the message sent to the mailbox itself
ARRIVAL_POLL = 3
CROSS_SITE_ORIGIN = "https://cross-site.example"
# A 1x1 transparent PNG: the inline image of the test draft.
PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR4nGNgAAIAAAUAAXpeqz8AAAAASUVORK5CYII=")


class UsageError(Exception):
    """A problem with the command line, the base URL or the credentials: exit code 2, nothing was sent."""


class StepFailed(Exception):
    """The check failed for the reason given."""


class Skip(Exception):
    """The check cannot be made here, for the reason given."""


class Abort(Exception):
    """A check later checks depend on failed: stop the walk and clean up."""


# PKCE (RFC 7636)

def s256(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).decode("ascii").rstrip("=")


def pkce_pair() -> tuple[str, str]:
    """(code_verifier, S256 code_challenge). 64 URL-safe characters, inside the 43-128 RFC 7636 allows."""
    verifier = secrets.token_urlsafe(48)
    return verifier, s256(verifier)


# Credentials

def read_env_file(path: str) -> dict[str, str]:
    """KEY=value lines; blank lines and # comments ignored; one pair of surrounding quotes removed. A file
    that group or others can read (or write) is refused: it holds a mailbox password."""
    try:
        info = os.stat(path)
    except OSError as exc:
        raise UsageError(f"cannot read {path}: {exc.strerror}") from None
    if not stat.S_ISREG(info.st_mode):
        raise UsageError(f"{path} is not a regular file")
    if info.st_mode & 0o077:
        raise UsageError(f"{path} can be read by group or others (mode {stat.S_IMODE(info.st_mode):04o}); "
                         f"run: chmod 600 {path}")
    values = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key, value = key.strip().removeprefix("export ").strip(), value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                value = value[1:-1]
            values[key] = value
    return values


def credentials(env_file: str | None, environ) -> tuple[str, str]:
    """(address, password): from --env-file when given, else from the environment."""
    source = read_env_file(env_file) if env_file else environ
    address, password = source.get("MCP_E2E_ADDRESS", "").strip(), source.get("MCP_E2E_PASSWORD", "")
    if not address or not password:
        where = env_file or "the environment"
        raise UsageError(f"set MCP_E2E_ADDRESS and MCP_E2E_PASSWORD in {where}")
    return address, password


def check_base(url: str) -> str:
    """The base URL without a trailing slash: scheme://host[:port], https, or http on a loopback address."""
    url = url.rstrip("/")
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.path or parts.query or parts.fragment \
            or parts.username or parts.password:
        raise UsageError("the base URL must be scheme://host[:port] with no path, e.g. https://mcp.example.com")
    try:
        parts.port
    except ValueError:
        raise UsageError("the base URL has an invalid port") from None
    if parts.scheme == "http" and parts.hostname not in LOOPBACK:
        raise UsageError("http:// is allowed only for a loopback address (127.0.0.1, localhost, [::1]): "
                         "a password must not cross the network unencrypted")
    return url


def check_redirect_uri(uri: str) -> str:
    """--redirect-uri: an absolute http(s) URL without a fragment (RFC 6749 section 3.1.2)."""
    parts = urllib.parse.urlsplit(uri)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.fragment or "#" in uri:
        raise UsageError("--redirect-uri must be an absolute http(s) URL without a fragment, "
                         "e.g. https://app.example.org/callback")
    return uri


def origin(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def as_metadata_url(issuer: str) -> str:
    """RFC 8414 section 3.1: the well-known segment goes between the host and any path of the issuer."""
    parts = urllib.parse.urlsplit(issuer)
    path = parts.path.rstrip("/")
    return f"{parts.scheme}://{parts.netloc}/.well-known/oauth-authorization-server{path}"


# Pages

class PageParser(HTMLParser):
    """The forms (action, method, inputs) and link targets of an HTML page. Attribute values arrive with
    character references already decoded."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms: list[dict] = []
        self.links: list[str] = []
        self.errors: list[str] = []
        self._form: dict | None = None
        self._in_error = False

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag == "form":
            self._form = {"action": a.get("action", ""), "method": a.get("method", "get").lower(), "inputs": {},
                          "types": {}}
            self.forms.append(self._form)
        elif tag in ("input", "textarea") and self._form is not None and a.get("name"):
            self._form["inputs"][a["name"]] = a.get("value", "")
            self._form["types"][a["name"]] = a.get("type", "text" if tag == "input" else "textarea").lower()
        elif tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "p" and "err" in a.get("class", "").split():
            self._in_error = True
            self.errors.append("")

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None
        elif tag == "p":
            self._in_error = False

    def handle_data(self, data):
        if self._in_error:
            self.errors[-1] += data


def parse_page(text: str) -> PageParser:
    p = PageParser()
    p.feed(text)
    p.close()
    return p


def sign_in_form(page: PageParser) -> dict | None:
    """The form with a password field."""
    return next((f for f in page.forms if "password" in f["types"].values()), None)


def form_fields(form: dict, address: str, password: str) -> dict[str, str]:
    """What a browser sends: the form's hidden fields, the address and password typed into their fields, and
    every other field empty."""
    out = {}
    for name, kind in form["types"].items():
        if kind == "hidden":
            out[name] = form["inputs"][name]
        elif kind == "password":
            out[name] = password
        elif kind == "email" or name == "email":
            out[name] = address
        else:
            out[name] = ""
    return out


def security_header_problems(headers: Headers, https: bool) -> list[str]:
    """The headers the sign-in page promises (see deploy/smoke.sh)."""
    problems = []
    if headers.get("x-frame-options", "").upper() != "DENY":
        problems.append("X-Frame-Options not DENY")
    csp = headers.get("content-security-policy", "")
    if "default-src 'none'" not in csp or "frame-ancestors 'none'" not in csp:
        problems.append("Content-Security-Policy missing or weak")
    if "no-store" not in headers.get("cache-control", ""):
        problems.append("Cache-Control lacks no-store")
    if headers.get("referrer-policy", "") != "same-origin":
        problems.append("Referrer-Policy not same-origin")
    if https and "max-age=" not in headers.get("strict-transport-security", ""):
        problems.append("Strict-Transport-Security missing")
    return problems


def tool_problems(tools: dict[str, dict]) -> list[str]:
    """What tools/list gets wrong: a core tool missing, a tool without all four annotation hints (clients
    decide from them when to ask the user) or without an object input schema. Other tools may come and go."""
    missing = [t for t in CORE_TOOLS if t not in tools]
    problems = [f"core tools missing: {', '.join(missing)}"] if missing else []
    for name in sorted(tools):
        hints = tools[name].get("annotations") or {}
        lacking = [h for h in HINTS if not isinstance(hints.get(h), bool)]
        if lacking:
            problems.append(f"{name} lacks {', '.join(lacking)}")
        schema = tools[name].get("inputSchema")
        if not isinstance(schema, dict) or schema.get("type") != "object":
            problems.append(f"{name} has no object input schema")
    return problems


# Output

class Redactor:
    """Replaces every secret (password, address, tokens, codes, sign-in request ids) in text before it is
    printed, in plain and URL-encoded form."""

    def __init__(self):
        self.secrets: set[str] = set()

    def add(self, *values) -> None:
        for v in values:
            if isinstance(v, str) and len(v) >= 4:
                self.secrets.update({v, urllib.parse.quote(v, safe=""), urllib.parse.quote_plus(v)})

    def __call__(self, text: str) -> str:
        for s in sorted(self.secrets, key=len, reverse=True):
            text = text.replace(s, "[redacted]")
        return text


@dataclass
class Step:
    name: str
    outcome: str        # PASS, FAIL or SKIP
    detail: str
    seconds: float


class Report:
    def __init__(self, redact: Redactor, out):
        self.redact, self.out = redact, out
        self.steps: list[Step] = []

    def add(self, outcome: str, name: str, detail: str = "", seconds: float = 0.0) -> None:
        detail = self.redact(" ".join(str(detail).split()))[:400]
        self.steps.append(Step(name, outcome, detail, round(seconds, 2)))
        print(f"{outcome:<5} {name}" + (f": {detail}" if detail else ""), file=self.out, flush=True)

    @property
    def failed(self) -> int:
        return sum(s.outcome == "FAIL" for s in self.steps)

    def json(self, summary: dict) -> str:
        """The summary as JSON, every string redacted before it is serialised: json.dumps escapes non-ASCII
        characters, quotes and backslashes, so the escaped text no longer holds a secret as it was added."""
        def clean(value):
            if isinstance(value, dict):
                return {clean(k): clean(v) for k, v in value.items()}
            if isinstance(value, list):
                return [clean(v) for v in value]
            return self.redact(value) if isinstance(value, str) else value
        return json.dumps(clean(summary))

    def summary(self, base: str, tools: list[str], removal: str | None, seconds: float) -> dict:
        count = {o: sum(s.outcome == o for s in self.steps) for o in ("PASS", "FAIL", "SKIP")}
        return {"base": base, "ok": not count["FAIL"], "passed": count["PASS"], "failed": count["FAIL"],
                "skipped": count["SKIP"], "seconds": round(seconds, 2), "tools": tools, "removal": removal,
                "steps": [s.__dict__ for s in self.steps]}


# HTTP

class Headers(dict):
    """Lower-case header names; a repeated header keeps its last value."""


@dataclass
class Response:
    status: int
    headers: Headers
    body: bytes

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self):
        try:
            return json.loads(self.body)
        except ValueError:
            raise StepFailed(f"HTTP {self.status}: the answer is not JSON") from None


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None          # a redirect is answered as it is, so the walk can check where it points


class Http:
    def __init__(self, timeout: float, context: ssl.SSLContext | None):
        self.timeout = timeout
        self.opener = urllib.request.build_opener(_NoRedirects, urllib.request.HTTPSHandler(context=context))

    def send(self, method: str, url: str, headers: dict[str, str], body: bytes | None) -> Response:
        req = urllib.request.Request(url, data=body, method=method,
                                     headers={"User-Agent": "mcp-server-imap-smtp-e2e", **headers})
        try:
            with self.opener.open(req, timeout=self.timeout) as r:
                return Response(r.status, _headers(r.headers), r.read())
        except urllib.error.HTTPError as e:
            with e:
                return Response(e.code, _headers(e.headers), e.read())
        except (urllib.error.URLError, OSError) as e:
            reason = getattr(e, "reason", e)
            raise StepFailed(f"cannot reach {origin(url)}: {reason}") from None

    def get(self, url: str, headers: dict | None = None) -> Response:
        return self.send("GET", url, headers or {}, None)

    def post_form(self, url: str, data: dict, headers: dict | None = None) -> Response:
        body = urllib.parse.urlencode(data).encode()
        return self.send("POST", url, {"Content-Type": "application/x-www-form-urlencoded", **(headers or {})}, body)

    def post_json(self, url: str, data, headers: dict | None = None) -> Response:
        return self.send("POST", url, {"Content-Type": "application/json", **(headers or {})}, json.dumps(data).encode())


def _headers(message) -> Headers:
    out = Headers()
    for k, v in message.items():
        out[k.lower()] = v
    return out


# MCP over streamable HTTP

class ToolFailed(StepFailed):
    pass


class Mcp:
    def __init__(self, http: Http, url: str, token: str):
        self.http, self.url, self.token = http, url, token
        self.protocol: str | None = None
        self.session: str | None = None
        self._id = 0

    def post(self, body: dict, token: str | None = None) -> Response:
        headers = {"Accept": "application/json, text/event-stream", "Authorization": f"Bearer {token or self.token}"}
        if self.protocol:
            headers["MCP-Protocol-Version"] = self.protocol
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        return self.http.post_json(self.url, body, headers)

    def request(self, method: str, params: dict) -> dict:
        self._id += 1
        r = self.post({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params})
        if r.status != 200:
            raise StepFailed(f"{method}: HTTP {r.status}")
        message = _rpc_message(r, self._id)
        if "error" in message:
            raise StepFailed(f"{method}: JSON-RPC error {message['error'].get('code')}: "
                             f"{str(message['error'].get('message', ''))[:200]}")
        if r.headers.get("mcp-session-id"):
            self.session = r.headers["mcp-session-id"]
        return message.get("result") or {}

    def notify(self, method: str) -> int:
        return self.post({"jsonrpc": "2.0", "method": method}).status

    def call(self, name: str, arguments: dict, require_structured: bool = False) -> dict:
        """The tool's result object. require_structured fails a result that has no structuredContent (every
        tool must return one); without it the JSON of a text block will do, for reading a value."""
        result = self.request("tools/call", {"name": name, "arguments": arguments})
        if result.get("isError"):
            text = " ".join(c.get("text", "") for c in result.get("content", []) if c.get("type") == "text")
            raise ToolFailed(f"{name} returned an error: {text[:300]}")
        structured = result.get("structuredContent")
        if isinstance(structured, dict):
            return structured
        if require_structured:
            raise StepFailed(f"{name}: no structuredContent in the result")
        for c in result.get("content", []):
            if c.get("type") == "text":
                with contextlib.suppress(ValueError):
                    value = json.loads(c["text"])
                    if isinstance(value, dict):
                        return value
        raise StepFailed(f"{name}: no structured result")


def _rpc_message(r: Response, wanted_id: int) -> dict:
    """The JSON-RPC response with the request's id, from a JSON body or an SSE stream."""
    if r.headers.get("content-type", "").startswith("text/event-stream"):
        for line in r.text.splitlines():
            if line.startswith("data:"):
                with contextlib.suppress(ValueError):
                    message = json.loads(line[5:])
                    if isinstance(message, dict) and message.get("id") == wanted_id:
                        return message
        raise StepFailed("no response in the event stream")
    message = r.json()
    if not isinstance(message, dict):
        raise StepFailed("the JSON-RPC answer is not an object")
    return message


# The walk

@dataclass
class Created:
    """A message this script made: where it is and the unique token in its subject."""
    folder: str
    uid: int
    token: str
    removed: bool = False


@dataclass
class State:
    prm: dict = field(default_factory=dict)
    asm: dict = field(default_factory=dict)
    client_id: str = ""
    redirect_uri: str = ""
    code: str = ""
    verifier: str = ""
    access: str = ""
    refresh: str = ""
    tools: dict[str, dict] = field(default_factory=dict)
    folders: dict[str, str] = field(default_factory=dict)     # role -> folder name
    created: list[Created] = field(default_factory=list)
    removal: str | None = None


class Walk:
    def __init__(self, base: str, mail_path: str, address: str, password: str, http: Http, report: Report,
                 *, write: bool = False, send: bool = False, keep: bool = False, redirect_uri: str | None = None):
        self.base, self.mail_url = base, base + "/" + mail_path.strip("/") if mail_path.strip("/") else base + "/"
        self.address, self.password = address, password
        self.http, self.report, self.redact = http, report, report.redact
        self.write, self.send, self.keep = write, send, keep
        self.https = base.startswith("https://")
        self.s = State()
        self.redirect_uri = redirect_uri
        self.mcp: Mcp | None = None
        self.redact.add(address, password)

    # running steps

    @contextlib.contextmanager
    def step(self, name: str, required: bool = False):
        """Run one check: PASS with the detail the block puts in the yielded list, SKIP on Skip, FAIL on any
        other exception. A failed required check stops the walk (Abort); cleanup still runs."""
        detail: list[str] = []
        start = time.monotonic()
        try:
            yield detail
        except Skip as e:
            self.report.add("SKIP", name, str(e), time.monotonic() - start)
        except Abort:
            raise
        except StepFailed as e:
            self.report.add("FAIL", name, str(e), time.monotonic() - start)
            if required:
                raise Abort() from None
        except Exception as e:     # an unexpected answer shape: report it, never crash past cleanup
            self.report.add("FAIL", name, f"{type(e).__name__}: {e}", time.monotonic() - start)
            if required:
                raise Abort() from None
        else:
            self.report.add("PASS", name, "; ".join(detail), time.monotonic() - start)

    def run(self) -> None:
        try:
            self.discovery()
            self.registration()
            self.authorisation()
            self.cross_site()
            self.tokens()
            self.session()
            self.read_sweep()
            self.write_sweep()
            self.send_sweep()
        except Abort:
            pass
        finally:
            self.cleanup()

    # a. discovery

    def discovery(self) -> None:
        with self.step("401 without a token", required=True) as d:
            r = self.http.post_json(self.mail_url, _initialize(), {"Accept": "application/json, text/event-stream"})
            if r.status != 401:
                raise StepFailed(f"HTTP {r.status}, expected 401")
            found = re.search(r'resource_metadata="([^"]+)"', r.headers.get("www-authenticate", ""))
            if not found:
                raise StepFailed("WWW-Authenticate does not name resource_metadata")
            prm_url = found[1]
            if origin(prm_url) != origin(self.base):
                raise StepFailed("resource_metadata points at another host")
            d.append("WWW-Authenticate names the protected-resource metadata")
        # The request above went through certificate verification (a failure there fails that check).
        if self.https:
            self.report.add("PASS", "TLS", "certificate chain and host name verified")
        else:
            self.report.add("SKIP", "TLS", "base URL is http (loopback)")
        with self.step("protected-resource metadata", required=True) as d:
            r = self.http.get(prm_url)
            if r.status != 200:
                raise StepFailed(f"HTTP {r.status}")
            prm = self.s.prm = r.json()
            if str(prm.get("resource", "")).rstrip("/") != self.mail_url.rstrip("/"):
                raise StepFailed(f"resource is {prm.get('resource')!r}, expected {self.mail_url!r}")
            if not any(str(a).rstrip("/") == self.base for a in prm.get("authorization_servers", [])):
                raise StepFailed(f"authorization_servers {prm.get('authorization_servers')!r} does not list {self.base}")
            d.append("resource and authorization server match")
        with self.step("authorization-server metadata", required=True) as d:
            r = self.http.get(as_metadata_url(self.base))
            if r.status != 200:
                raise StepFailed(f"HTTP {r.status}")
            asm = self.s.asm = r.json()
            problems = []
            if str(asm.get("issuer", "")).rstrip("/") != self.base:
                problems.append(f"issuer is {asm.get('issuer')!r}")
            for key in ("authorization_endpoint", "token_endpoint", "registration_endpoint", "revocation_endpoint"):
                if key == "revocation_endpoint" and not asm.get(key):
                    continue        # optional; reported below and again at the end
                if not str(asm.get(key, "")).startswith(self.base + "/"):
                    problems.append(f"{key} is {asm.get(key)!r}")
            if "S256" not in asm.get("code_challenge_methods_supported", []):
                problems.append("S256 missing from code_challenge_methods_supported")
            if "none" not in asm.get("token_endpoint_auth_methods_supported", []):
                problems.append("public clients (none) missing from token_endpoint_auth_methods_supported")
            if problems:
                raise StepFailed("; ".join(problems))
            d.append("issuer and endpoints match, S256, public clients")
            d.append("iss parameter advertised" if asm.get("authorization_response_iss_parameter_supported")
                     else "iss parameter not advertised")
            d.append("revocation endpoint listed" if asm.get("revocation_endpoint") else "no revocation endpoint")

    # b. registration

    def registration(self) -> None:
        with self.step("client registration", required=True) as d:
            # Nothing needs to listen at the redirect URI: the code is read from the connected page. By default a
            # loopback redirect on a random port; --redirect-uri for an instance that refuses loopback redirects.
            self.s.redirect_uri = self.redirect_uri or f"http://127.0.0.1:{secrets.randbelow(16000) + 49152}/callback"
            r = self.http.post_json(self.s.asm["registration_endpoint"], {
                "redirect_uris": [self.s.redirect_uri], "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
                "client_name": "mcp-server-imap-smtp e2e check"})
            if r.status != 201:
                raise StepFailed(f"HTTP {r.status}, expected 201{_oauth_error(r)}{self._redirect_hint(r)}")
            reg = r.json()
            if not reg.get("client_id"):
                raise StepFailed("no client_id")
            if reg.get("client_secret"):
                self.redact.add(reg["client_secret"])
                raise StepFailed("a client_secret was issued to a public client")
            self.s.client_id = reg["client_id"]
            d.append("public client with " + ("the given redirect URI" if self.redirect_uri else "a loopback redirect"))

    def _redirect_hint(self, r: Response) -> str:
        """Why a registration refused for its redirect URI most likely failed, and what to do."""
        if r.status != 400 or "redirect" not in r.text.lower():
            return ""
        if self.redirect_uri:
            return "; the instance refuses --redirect-uri: give one on its redirect_allowlist"
        return ("; the instance refuses loopback redirect URIs (allow_loopback_redirects = false): "
                "give --redirect-uri with a URI on its redirect_allowlist (nothing is sent there)")

    # c. authorisation and sign-in

    def _authorize(self, state: str, challenge: str) -> str:
        """The sign-in page URL the authorization endpoint redirects to."""
        query = urllib.parse.urlencode({
            "response_type": "code", "client_id": self.s.client_id, "redirect_uri": self.s.redirect_uri,
            "code_challenge": challenge, "code_challenge_method": "S256", "state": state,
            "resource": self.s.prm["resource"], "scope": "offline_access"})
        r = self.http.get(f"{self.s.asm['authorization_endpoint']}?{query}")
        location = r.headers.get("location", "")
        if r.status not in (302, 303) or not location:
            raise StepFailed(f"HTTP {r.status}, expected a redirect to the sign-in page")
        location = urllib.parse.urljoin(self.s.asm["authorization_endpoint"], location)
        if location.startswith(self.s.redirect_uri):
            error = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query).get("error", ["?"])[0]
            raise StepFailed(f"the authorization request was refused: {error}")
        if origin(location) != origin(self.base):
            raise StepFailed("the sign-in page is on another host")
        self.redact.add(*urllib.parse.parse_qs(urllib.parse.urlsplit(location).query).get("req", []))
        return location

    def _sign_in_page(self, url: str) -> tuple[Response, dict]:
        r = self.http.get(url)
        if r.status != 200:
            raise StepFailed(f"HTTP {r.status}")
        form = sign_in_form(parse_page(r.text))
        if form is None:
            raise StepFailed("no sign-in form on the page")
        self.redact.add(*form["inputs"].values())
        return r, form

    def _form_action(self, login_url: str, form: dict) -> str:
        """Where the sign-in form posts, refused when that is not the instance's own origin (another host, or
        http behind an https base): the password must go nowhere else."""
        action = urllib.parse.urljoin(login_url, form["action"] or login_url)
        if origin(action) != origin(self.base):
            raise StepFailed("the sign-in form posts to another origin; password not sent")
        return action

    def authorisation(self) -> None:
        state = secrets.token_urlsafe(16)
        self.s.verifier, challenge = pkce_pair()
        self.redact.add(self.s.verifier)
        with self.step("authorization request", required=True) as d:
            login_url = self._authorize(state, challenge)
            d.append("redirected to the sign-in page")
        with self.step("sign-in page", required=True) as d:
            r, form = self._sign_in_page(login_url)
            problems = security_header_problems(r.headers, self.https)
            if problems:
                raise StepFailed("; ".join(problems))
            d.append("form found; security headers present" + ("" if self.https else " (HSTS not checked over http)"))
        with self.step("sign-in", required=True) as d:
            action = self._form_action(login_url, form)
            r = self.http.post_form(action, form_fields(form, self.address, self.password),
                                    {"Origin": origin(login_url), "Referer": login_url})
            callback = self._callback(r)
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(callback).query)
            code = q.get("code", [""])[0]
            self.redact.add(code)
            if not code:
                raise StepFailed("the redirect carries no code")
            self.s.code = code
            if q.get("state") != [state]:
                raise StepFailed("state does not match")
            d.append("code received; state matches")
            if self.s.asm.get("authorization_response_iss_parameter_supported"):
                if q.get("iss") != [self.s.asm.get("issuer")]:
                    raise StepFailed("iss is missing or is not the issuer (RFC 9207)")
                d.append("iss is the issuer")

    def _callback(self, r: Response) -> str:
        """The redirect to the AI app after a sign-in: the connected page's Continue link, or a redirect."""
        if r.status in (302, 303) and r.headers.get("location", "").startswith(self.s.redirect_uri):
            return r.headers["location"]
        if r.status == 429:
            raise StepFailed("HTTP 429: too many attempts; wait for the login window and try again")
        if r.status != 200:
            raise StepFailed(f"HTTP {r.status}")
        page = parse_page(r.text)
        link = next((h for h in page.links if h.startswith(self.s.redirect_uri)), None)
        if link is None:
            shown = " ".join(e.strip() for e in page.errors if e.strip())
            raise StepFailed("the page did not connect" + (f": {shown}" if shown else ""))
        return link

    # d. cross-site refusal

    def cross_site(self) -> None:
        with self.step("cross-site sign-in refused") as d:
            _, challenge = pkce_pair()
            login_url = self._authorize(secrets.token_urlsafe(16), challenge)
            _, form = self._sign_in_page(login_url)
            # No password is sent: the refusal must come before the form is read, and a wrong password
            # must never reach a real mail server.
            fields = form_fields(form, "", "")
            r = self.http.post_form(self._form_action(login_url, form), fields,
                                    {"Origin": CROSS_SITE_ORIGIN})
            if r.status != 403:
                raise StepFailed(f"HTTP {r.status}, expected 403 for a post from another site")
            d.append("403 for a foreign Origin, no password sent")

    # e. tokens

    def tokens(self) -> None:
        with self.step("token exchange", required=True) as d:
            r = self.http.post_form(self.s.asm["token_endpoint"], {
                "grant_type": "authorization_code", "code": self.s.code, "redirect_uri": self.s.redirect_uri,
                "client_id": self.s.client_id, "code_verifier": self.s.verifier, "resource": self.s.prm["resource"]})
            tok = r.json() if r.status == 200 else {}
            self.redact.add(tok.get("access_token"), tok.get("refresh_token"))
            if r.status != 200:
                raise StepFailed(f"HTTP {r.status}{_oauth_error(r)}")
            if str(tok.get("token_type", "")).lower() != "bearer" or not tok.get("access_token"):
                raise StepFailed("no bearer access token")
            if not tok.get("refresh_token"):
                raise StepFailed("no refresh token")
            self.s.access, self.s.refresh = tok["access_token"], tok["refresh_token"]
            d.append(f"bearer access token (expires in {tok.get('expires_in', '?')} s) and refresh token")
        with self.step("token refresh", required=True) as d:
            r = self.http.post_form(self.s.asm["token_endpoint"], {
                "grant_type": "refresh_token", "refresh_token": self.s.refresh, "client_id": self.s.client_id})
            tok = r.json() if r.status == 200 else {}
            self.redact.add(tok.get("access_token"), tok.get("refresh_token"))
            if r.status != 200:
                raise StepFailed(f"HTTP {r.status}{_oauth_error(r)}")
            if not tok.get("access_token") or tok["access_token"] == self.s.access:
                raise StepFailed("no new access token")
            if not tok.get("refresh_token") or tok["refresh_token"] == self.s.refresh:
                raise StepFailed("the refresh token was not rotated")
            self.s.access, self.s.refresh = tok["access_token"], tok["refresh_token"]
            d.append("new access token; refresh token rotated")

    # f. MCP session

    def session(self) -> None:
        self.mcp = Mcp(self.http, self.mail_url, self.s.access)
        with self.step("MCP initialize", required=True) as d:
            result = self.mcp.request("initialize", _initialize()["params"])
            self.mcp.protocol = result.get("protocolVersion") or PROTOCOL_VERSION
            name = (result.get("serverInfo") or {}).get("name", "?")
            d.append(f"with the refreshed access token; server {name!r}, protocol {self.mcp.protocol}")
        with self.step("MCP initialized notification") as d:
            status = self.mcp.notify("notifications/initialized")
            if status not in (200, 202, 204):
                raise StepFailed(f"HTTP {status}")
            d.append(f"HTTP {status}")
        with self.step("tools/list", required=True) as d:
            tools, cursor = [], None
            for _ in range(20):
                result = self.mcp.request("tools/list", {"cursor": cursor} if cursor else {})
                tools += result.get("tools", [])
                cursor = result.get("nextCursor")
                if not cursor:
                    break
            self.s.tools = {t.get("name", "?"): t for t in tools}
            names = sorted(self.s.tools)
            d.append(f"{len(names)} tools: {', '.join(names)}")
            problems = tool_problems(self.s.tools)
            if problems:
                raise StepFailed("; ".join(problems))
            d.append("every tool states all four hints and an input schema")

    def _call(self, name: str, **arguments) -> dict:
        if name not in self.s.tools:
            raise Skip(f"{name} is not listed")
        return self.mcp.call(name, arguments, require_structured=True)

    # g. read sweep

    def read_sweep(self) -> None:
        first = None
        with self.step("mail_accounts") as d:
            out = self._call("mail_accounts")
            boxes = [str(b).lower() for b in out.get("mailboxes", [])]
            if self.address.lower() not in boxes:
                raise StepFailed("the signed-in mailbox is not listed")
            d.append(f"{len(boxes)} mailbox(es), the signed-in one listed")
        with self.step("mail_folders") as d:
            out = self._call("mail_folders")
            folders = out.get("folders", [])
            for f in folders:
                if f.get("role") and f["role"] not in self.s.folders:
                    self.s.folders[f["role"]] = f.get("name", "")
            if not any(f.get("name", "").upper() == "INBOX" or f.get("role") == "inbox" for f in folders):
                raise StepFailed("no INBOX listed")
            d.append(f"{len(folders)} folders; roles: {', '.join(sorted(self.s.folders)) or 'none'}")
        with self.step("mail_search INBOX") as d:
            out = self._call("mail_search", folder="INBOX", limit=3)
            _needs_notice(out, "mail_search")
            rows = out.get("messages")
            if not isinstance(rows, list):
                raise StepFailed("no messages list")
            first = rows[0] if rows else None
            d.append(f"{len(rows)} row(s) of {out.get('total', '?')}; content_notice present")
        with self.step("mail_read") as d:
            if first is None:
                raise Skip("INBOX is empty or could not be searched")
            out = self._call("mail_read", folder="INBOX", uid=first["uid"])
            _needs_notice(out, "mail_read")
            if not isinstance(out.get("attachments"), list) or "text" not in out:
                raise StepFailed("the result lacks text or attachments")
            d.append(f"newest INBOX message read; {len(out['attachments'])} attachment(s); content_notice present")
        with self.step("mail_thread") as d:
            if first is None:
                raise Skip("INBOX is empty or could not be searched")
            out = self._call("mail_thread", folder="INBOX", uid=first["uid"])
            _needs_notice(out, "mail_thread")
            if not isinstance(out.get("messages"), list):
                raise StepFailed("no messages list")
            d.append(f"{len(out['messages'])} message(s) in the conversation; content_notice present")

    # h. write sweep

    def _find_own(self, folder: str, token: str) -> list[dict]:
        out = self.mcp.call("mail_search", {"folder": folder, "subject": token, "limit": 10})
        return [r for r in out.get("messages", []) if token in str(r.get("subject", ""))]

    def _confirm_own(self, item: Created) -> dict:
        """The search row of a message this script created, checked again just before it is changed."""
        rows = [r for r in self._find_own(item.folder, item.token) if r.get("uid") == item.uid]
        if not rows:
            raise StepFailed(f"uid {item.uid} in {item.folder} is no longer the message this script created; "
                             "left untouched")
        return rows[0]

    def _remove(self, item: Created) -> str:
        """Remove a message this script created the safest way the instance offers: mail_delete (to Trash)
        when listed, else mail_move to Trash. Returns the tool used."""
        self._confirm_own(item)
        if "mail_delete" in self.s.tools:
            self.mcp.call("mail_delete", {"folder": item.folder, "uids": [item.uid]})
            used = "mail_delete"
        elif "mail_move" in self.s.tools:
            self.mcp.call("mail_move", {"folder": item.folder, "uids": [item.uid], "destination": "trash"})
            used = "mail_move to Trash"
        else:
            raise StepFailed("neither mail_delete nor mail_move is listed; the message was left in place")
        item.removed = True
        self.s.removal = used
        if any(r.get("uid") == item.uid for r in self._find_own(item.folder, item.token)):
            raise StepFailed(f"{used} answered, but the message is still in {item.folder}")
        return used

    def write_sweep(self) -> None:
        if not self.write:
            self.report.add("SKIP", "write sweep", "not asked for (--write)")
            return
        if "mail_draft" not in self.s.tools:
            self.report.add("SKIP", "write sweep", "mail_draft is not listed (sending is off on this instance)")
            return
        token = f"e2e-{secrets.token_hex(6)}"
        cid = f"{token}.dot@e2e.invalid"
        text_bytes = f"End-to-end check attachment {token}\n".encode()
        draft: Created | None = None
        text_att = image_att = None
        with self.step("draft saved") as d:
            out = self.mcp.call("mail_draft", {
                "to": [self.address], "subject": f"mcp-server-imap-smtp e2e check {token}",
                "text": f"End-to-end check {token}. This draft is removed again by the check.",
                "html": f'<p>End-to-end check {token}.</p><p><img src="cid:{cid}" alt=""></p>',
                "attachments": [
                    {"filename": "e2e-check.txt", "content_type": "text/plain",
                     "base64": base64.b64encode(text_bytes).decode()},
                    {"filename": "e2e-dot.png", "content_type": "image/png", "base64": base64.b64encode(PNG).decode(),
                     "disposition": "inline", "content_id": cid}]})
            folder, uid = out.get("saved_to"), out.get("uid")
            if not folder:
                raise StepFailed("the result does not say where the draft was saved")
            if uid is None:      # the server could not say (no UIDPLUS): find it by its token
                rows = self._find_own(folder, token)
                if len(rows) != 1:
                    raise StepFailed("the server returned no uid and the draft could not be found by its subject")
                uid = rows[0]["uid"]
            draft = Created(folder, int(uid), token)
            self.s.created.append(draft)
            d.append(f"saved to {folder} as uid {uid}")
        if draft is None:
            return          # nothing was saved, so there is nothing to check or remove
        with self.step("draft read back") as d:
            out = self.mcp.call("mail_read", {"folder": draft.folder, "uid": draft.uid})
            _needs_notice(out, "mail_read")
            if token not in str(out.get("subject", "")):
                raise StepFailed("the subject read back is not the draft's")
            atts = out.get("attachments", [])
            text_att = next((a for a in atts if a.get("filename") == "e2e-check.txt"), None)
            image_att = next((a for a in atts if str(a.get("content_id", "")).strip("<>") == cid), None)
            if text_att is None or image_att is None:
                raise StepFailed(f"attachments listed: {len(atts)}; the text file or the inline image is missing")
            d.append(f"subject matches; {len(atts)} attachments listed, the text file and the inline image among them")
        with self.step("attachments fetched") as d:
            if text_att is None:
                raise Skip("the attachments were not listed")
            out = self.mcp.call("mail_attachment", {"folder": draft.folder, "uid": draft.uid,
                                                    "index": text_att["index"]})
            _needs_notice(out, "mail_attachment")
            got = out["text"].encode() if "text" in out else base64.b64decode(out.get("base64", ""))
            if got != text_bytes:
                raise StepFailed("the text attachment differs from what was saved")
            out = self.mcp.call("mail_attachment", {"folder": draft.folder, "uid": draft.uid, "content_id": cid})
            if base64.b64decode(out.get("base64", "")) != PNG:
                raise StepFailed("the inline image differs from what was saved")
            d.append("text attachment and inline image match byte for byte")
        with self.step("flag set and cleared") as d:
            for flagged in (True, False):
                self._confirm_own(draft)
                self.mcp.call("mail_flag", {"folder": draft.folder, "uids": [draft.uid], "flagged": flagged})
                row = self._confirm_own(draft)
                if ("\\Flagged" in row.get("flags", [])) != flagged:
                    raise StepFailed(f"the flag was not {'set' if flagged else 'cleared'}")
            d.append("\\Flagged set, then cleared")
        with self.step("draft removed") as d:
            d.append(f"with {self._remove(draft)}")

    # i. send sweep

    def send_sweep(self) -> None:
        if not self.send:
            self.report.add("SKIP", "send sweep", "not asked for (--send)")
            return
        if "mail_send" not in self.s.tools:
            self.report.add("SKIP", "send sweep", "mail_send is not listed (sending is off or draft-only here)")
            return
        token = f"e2e-{secrets.token_hex(6)}"
        sent_copy = sent = False
        with self.step("message sent to the mailbox itself") as d:
            out = self.mcp.call("mail_send", {"to": [self.address], "subject": f"mcp-server-imap-smtp e2e send {token}",
                                              "text": f"End-to-end check {token}. Removed again by the check."})
            if not out.get("message_id"):
                raise StepFailed("no message_id in the result")
            sent, sent_copy = True, bool(out.get("saved_to_sent"))
            d.append("accepted" + ("; copy saved to Sent" if sent_copy else "; no copy in Sent"))
        if not sent:
            return
        received: Created | None = None
        with self.step("message arrived") as d:
            start = time.monotonic()
            while True:
                rows = self._find_own("INBOX", token)
                if rows:
                    received = Created("INBOX", int(rows[0]["uid"]), token)
                    self.s.created.append(received)
                    break
                if time.monotonic() - start > ARRIVAL_WAIT:
                    raise StepFailed(f"not in INBOX after {ARRIVAL_WAIT} s (a filter or the spam check may have "
                                     "moved it; the message is not removed)")
                time.sleep(ARRIVAL_POLL)
            d.append(f"in INBOX after {time.monotonic() - start:.0f} s")
        if sent_copy:
            folder = self.s.folders.get("sent", "sent")
            with contextlib.suppress(StepFailed):
                rows = self._find_own(folder, token)
                if len(rows) == 1:
                    self.s.created.append(Created(folder, int(rows[0]["uid"]), token))
        if received is not None:
            with self.step("received message read") as d:
                out = self.mcp.call("mail_read", {"folder": "INBOX", "uid": received.uid})
                _needs_notice(out, "mail_read")
                if token not in str(out.get("subject", "")):
                    raise StepFailed("the subject read back is not the one sent")
                d.append("subject matches; content_notice present")
        with self.step("sent messages removed") as d:
            items = [c for c in self.s.created if c.token == token and not c.removed]
            if not items:
                raise Skip("nothing arrived to remove")
            used = {self._remove(c) for c in items}
            d.append(f"{len(items)} removed with {', '.join(sorted(used))}")

    # j. cleanup

    def cleanup(self) -> None:
        left = [c for c in self.s.created if not c.removed]
        if left and self.mcp is not None:
            with self.step("cleanup: test messages") as d:
                problems = []
                for item in left:
                    try:
                        self._remove(item)
                    except StepFailed as e:
                        problems.append(str(e))
                if problems:
                    raise StepFailed("; ".join(problems))
                d.append(f"{len(left)} left over from a failed check removed")
        if self.keep:
            self.report.add("SKIP", "revocation", "--keep given: the connection stays until it expires or is "
                                                  "ended on the manage page")
            return
        if not self.s.refresh:
            self.report.add("SKIP", "revocation", "no connection was made")
            return
        with self.step("revocation") as d:
            endpoint = self.s.asm.get("revocation_endpoint")
            if not endpoint:
                raise StepFailed("no revocation_endpoint advertised: the connection stays until it expires")
            if origin(endpoint) != origin(self.base):
                raise StepFailed("the revocation endpoint is on another origin; refresh token not sent")
            r = self.http.post_form(endpoint, {"token": self.s.refresh, "token_type_hint": "refresh_token",
                                               "client_id": self.s.client_id})
            if r.status != 200:
                raise StepFailed(f"HTTP {r.status}{_oauth_error(r)}")
            d.append("refresh token revoked")
        with self.step("revoked token refused") as d:
            r = Mcp(self.http, self.mail_url, self.s.access).post(_initialize())
            if r.status != 401:
                raise StepFailed(f"HTTP {r.status}, expected 401: the access token still works")
            d.append("the access token now gets 401")


def _initialize() -> dict:
    return {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
        "protocolVersion": PROTOCOL_VERSION, "capabilities": {},
        "clientInfo": {"name": "mcp-server-imap-smtp-e2e", "version": "1"}}}


def _needs_notice(out: dict, tool: str) -> None:
    if not out.get("content_notice"):
        raise StepFailed(f"{tool} returned message content without content_notice")


def _oauth_error(r: Response) -> str:
    with contextlib.suppress(Exception):
        body = json.loads(r.body)
        if isinstance(body, dict) and body.get("error"):
            return f" ({str(body['error'])[:60]})"
    return ""


# Command line

def parse_args(argv: list[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(prog="e2e.py", description="End-to-end check of a running mcp-server-imap-smtp "
                                 "instance. Credentials: MCP_E2E_ADDRESS and MCP_E2E_PASSWORD in the environment "
                                 "or in --env-file.")
    ap.add_argument("base_url", help="the instance's base URL, e.g. https://mcp.example.com")
    ap.add_argument("--mail-path", default="/mail", help="path of the mail MCP endpoint (default /mail)")
    ap.add_argument("--write", action="store_true", help="also save, read, flag and remove a draft")
    ap.add_argument("--send", action="store_true", help="also send a message to the mailbox itself and remove it")
    ap.add_argument("--keep", action="store_true", help="keep the connection instead of revoking it at the end")
    ap.add_argument("--json", action="store_true", help="print a JSON summary on stdout (the check lines go to stderr)")
    ap.add_argument("--env-file", help="KEY=value file with MCP_E2E_ADDRESS and MCP_E2E_PASSWORD (mode 600)")
    ap.add_argument("--redirect-uri", help="register this redirect URI instead of a loopback one, for an instance "
                    "with allow_loopback_redirects = false: a URI on its redirect_allowlist (nothing is sent there)")
    ap.add_argument("--cafile", help="trust this CA bundle (PEM) instead of the system's")
    ap.add_argument("--timeout", type=float, default=60, help="seconds per HTTP request (default 60)")
    return ap.parse_args(argv)


def main(argv: list[str] | None = None, environ=None, http: Http | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    environ = os.environ if environ is None else environ
    out = sys.stderr if args.json else sys.stdout
    try:
        base = check_base(args.base_url)
        if args.redirect_uri is not None:
            check_redirect_uri(args.redirect_uri)
        address, password = credentials(args.env_file, environ)
        context = ssl.create_default_context(cafile=args.cafile) if args.cafile else ssl.create_default_context()
    except (UsageError, OSError, ssl.SSLError) as e:
        print(f"e2e: {e}", file=sys.stderr)
        return 2
    report = Report(Redactor(), out)
    walk = Walk(base, args.mail_path, address, password, http or Http(args.timeout, context), report,
                write=args.write, send=args.send, keep=args.keep, redirect_uri=args.redirect_uri)
    start = time.monotonic()
    try:
        walk.run()
    except KeyboardInterrupt:
        report.add("FAIL", "interrupted", "stopped before the end")
    summary = report.summary(base, sorted(walk.s.tools), walk.s.removal, time.monotonic() - start)
    if summary["ok"]:
        print(f"e2e: all checks passed for {base}", file=out)
    else:
        print(f"e2e: FAILED ({summary['failed']} of {len(report.steps)} checks)", file=out)
    if args.json:
        print(report.json(summary))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
