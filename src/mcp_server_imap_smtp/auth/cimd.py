# SPDX-License-Identifier: AGPL-3.0-or-later
"""OAuth Client ID Metadata Documents: a client_id that is an https URL to its own metadata.

Fetching a URL chosen by an unauthenticated caller is an SSRF vector, so the fetch is confined: the host
must be on settings.cimd_allowed_hosts (checked before any network request), https on port 443 only, no
IP literals, userinfo or fragment, a 5 s timeout, no redirects and a response cap enforced while streaming.
"""
from __future__ import annotations

import functools
import ipaddress
import json
import re
import time
from typing import Callable, Sequence

import httpx
from mcp.shared.auth import OAuthClientInformationFull
from starlette.types import ASGIApp, Receive, Scope, Send

from ..config import Settings, redirect_allowed

MAX_BYTES = 10_000
TIMEOUT = 5.0


def is_cimd(client_id: str) -> bool:
    return client_id.startswith("https://")


_HOSTNAME = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")


def _parse(client_id_url: str, settings: Settings) -> httpx.URL | None:
    """The one parser for both the gate and the request: the URL checked is the URL fetched."""
    try:
        u = httpx.URL(client_id_url)
        host, port = u.host, u.port
    except (httpx.InvalidURL, ValueError):
        return None
    if u.scheme != "https" or not host or u.fragment or u.userinfo or port not in (None, 443):
        return None
    if not _HOSTNAME.fullmatch(host):         # rejects IP literals' brackets, escapes, backslashes, spaces, trailing dots
        return None
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    if not any(host == h or host.endswith("." + h) for h in settings.cimd_allowed_hosts):
        return None
    return u


def cimd_fetchable(client_id_url: str, settings: Settings) -> bool:
    return _parse(client_id_url, settings) is not None


def _read_capped(http: httpx.Client, url: httpx.URL, deadline: float, clock: Callable[[], float]) -> bytes | None:
    """Per-step timeouts do not bound a slow drip, so the whole fetch also has a monotonic deadline."""
    end = clock() + deadline
    with http.stream("GET", url, headers={"accept": "application/json"}, timeout=TIMEOUT,
                     follow_redirects=False) as r:
        if r.status_code != 200:
            return None
        body = bytearray()
        for chunk in r.iter_bytes():
            body += chunk
            if len(body) > MAX_BYTES or clock() > end:
                return None
        return bytes(body)


def fetch_client_document(client_id_url: str, settings: Settings, http: httpx.Client | None = None, *,
                          deadline: float = TIMEOUT, clock: Callable[[], float] = time.monotonic) -> OAuthClientInformationFull | None:
    url = _parse(client_id_url, settings)
    if url is None:
        return None
    owned = http is None
    http = http or httpx.Client(timeout=TIMEOUT, follow_redirects=False)
    try:
        raw = _read_capped(http, url, deadline, clock)
        doc = json.loads(raw) if raw is not None else None
    except (httpx.HTTPError, httpx.InvalidURL, ValueError):
        return None
    finally:
        if owned:
            http.close()
    if not isinstance(doc, dict) or doc.get("client_id") != client_id_url:
        return None
    uris = doc.get("redirect_uris") or []
    if not isinstance(uris, list) or not uris or not all(isinstance(x, str) and redirect_allowed(x, settings) for x in uris):
        return None
    doc.setdefault("token_endpoint_auth_method", "none")
    if doc["token_endpoint_auth_method"] != "none":
        return None
    doc.pop("client_secret", None)          # a public client has no secret; never trust one from a document
    try:
        return OAuthClientInformationFull.model_validate(doc)
    except ValueError:
        return None


class MetadataPatch:
    """Fill in what the SDK-built discovery documents cannot say.

    Authorization-server metadata gains CIMD support, the "none" token auth method and scopes_supported
    (the SDK fills that only from ClientRegistrationOptions.valid_scopes, which would also refuse any
    registration naming another scope). Protected-resource metadata gains scopes_supported: the SDK only
    fills it from AuthSettings.required_scopes, which would also make every bearer token carry those
    scopes, and tokens issued without a scope must keep working.

    Only a 200 JSON response to a GET or HEAD is rewritten; a HEAD is passed on as a GET so that its
    headers (Content-Length above all) match the patched GET, and its body is dropped. Everything else
    (the CORS preflight the SDK answers with plain text, errors, other methods) streams through untouched,
    and so does a body that is not valid JSON."""
    PATH = "/.well-known/oauth-authorization-server"

    def __init__(self, app: ASGIApp, *, resource_metadata_path: str | None = None,
                 scopes: Sequence[str] = ()):
        self.app = app
        self.patches: dict[str, Callable[[dict], None]] = {
            self.PATH: functools.partial(self._authorization_server, list(scopes))}
        if resource_metadata_path and scopes:
            self.patches[resource_metadata_path] = functools.partial(self._protected_resource, list(scopes))

    @staticmethod
    def _authorization_server(scopes: list[str], meta: dict) -> None:
        meta["client_id_metadata_document_supported"] = True
        methods = meta.setdefault("token_endpoint_auth_methods_supported", [])
        if "none" not in methods:
            methods.append("none")
        if scopes:
            meta["scopes_supported"] = scopes

    @staticmethod
    def _protected_resource(scopes: list[str], meta: dict) -> None:
        meta["scopes_supported"] = scopes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        method = scope.get("method") if scope["type"] == "http" else None
        patch = self.patches.get(scope["path"]) if method in ("GET", "HEAD") else None
        if patch is None:
            return await self.app(scope, receive, send)
        head = method == "HEAD"
        if head:
            scope = {**scope, "method": "GET"}
        start: dict = {}
        chunks: list[bytes] = []
        patching = False

        async def capture(message):
            nonlocal patching
            if message["type"] == "http.response.start":
                ctype = next((v for k, v in message.get("headers", []) if k.lower() == b"content-type"), b"")
                patching = message["status"] == 200 and ctype.lower().startswith(b"application/json")
                if patching:
                    start.update(message)
                else:
                    await send(message)
            elif not patching:
                if not head:
                    await send(message)
                elif not message.get("more_body"):       # a HEAD gets the GET's headers and one empty body
                    await send({"type": "http.response.body", "body": b""})
            else:
                chunks.append(message.get("body", b""))
                if not message.get("more_body"):
                    original = b"".join(chunks)
                    try:
                        meta = json.loads(original)
                        patch(meta)
                        body = json.dumps(meta).encode()
                    except (ValueError, AttributeError, TypeError):
                        body = original
                    headers = [(k, v) for k, v in start["headers"] if k.lower() != b"content-length"]
                    headers.append((b"content-length", str(len(body)).encode()))
                    await send({**start, "headers": headers})
                    await send({"type": "http.response.body", "body": b"" if head else body})
        await self.app(scope, receive, capture)
