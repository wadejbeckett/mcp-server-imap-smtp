# SPDX-License-Identifier: AGPL-3.0-or-later
"""OAuth 2.1 authorization server for the gateway, on the MCP SDK's provider protocol."""
from __future__ import annotations

import json
import logging
import time
from typing import Callable
from urllib.parse import urlsplit

import anyio
import httpx
from mcp.server.auth.provider import (AccessToken, AuthorizationCode, AuthorizationParams, AuthorizeError,
                                      IdentityAssertionParams, RefreshToken, RegistrationError, TokenError,
                                      construct_redirect_uri)
from mcp.shared.auth import OAuthClientInformationFull, OAuthMetadata, OAuthToken
import re

from pydantic import AnyUrl

from ..config import Settings, redirect_allowed
from ..mail.hosts import MailServer
from ..store import Store
from .cimd import cimd_fetchable, fetch_client_document, is_cimd

log = logging.getLogger(__name__)

CIMD_TTL = 86400
CIMD_FAILURE_TTL = 60
CIMD_WORKERS = 4        # a private worker limit: anonymous /authorize traffic must not drain the shared pool
CIMD_CACHE_MAX = 1024

# Every scope the gateway knows. Scopes do not gate anything here (a grant is to the signed-in mailboxes,
# and a refresh token is issued either way); offline_access exists because ChatGPT drops a connection at
# access-token expiry unless the authorization server advertises it. Claude and Claude Code are expected
# to ask for it too, since it is advertised; clients that ask for no scope keep working.
SCOPES = ("offline_access",)


def known_scopes(requested: str | None) -> list[str]:
    """The gateway's scopes among those requested, in order and without duplicates. Anything else is
    ignored rather than refused (RFC 6749 section 3.3 lets the server grant less than was asked): scopes
    gate nothing here, so refusing an unknown one would only break a client that adds openid or similar."""
    return [s for s in dict.fromkeys((requested or "").split()) if s in SCOPES]


MAX_CLIENT_NAME = 100
MAX_REDIRECT_URIS = 10
MAX_URI = 512
_URI_FIELDS = ("client_uri", "logo_uri", "tos_uri", "policy_uri", "jwks_uri")


def registration_problem(info: OAuthClientInformationFull) -> str | None:
    """Size limits on dynamically registered client metadata, which is stored and shown on the sign-in
    page: what is wrong with it, or None."""
    if info.client_name and len(info.client_name) > MAX_CLIENT_NAME:
        return f"client_name longer than {MAX_CLIENT_NAME} characters"
    uris = info.redirect_uris or []
    if len(uris) > MAX_REDIRECT_URIS:
        return f"more than {MAX_REDIRECT_URIS} redirect_uris"
    if any(len(str(u)) > MAX_URI for u in uris):
        return f"a redirect_uri longer than {MAX_URI} characters"
    for name in _URI_FIELDS:
        value = getattr(info, name, None)
        if value is not None and len(str(value)) > MAX_URI:
            return f"{name} longer than {MAX_URI} characters"
    if len(info.model_dump_json()) > 8192:
        return "client metadata too large"
    return None


class GatewayClient(OAuthClientInformationFull):
    """A registered or CIMD client, whose allowed scopes are the gateway's, not the ones it registered.

    The SDK checks a requested scope against the client's own `scope` field, so a client registered before
    scopes existed, or a CIMD document with no scope (or with scopes we do not have), could never ask for
    offline_access. Here the server's list decides, for every client alike: known scopes are granted,
    unknown ones are dropped, whitespace is split on any run, and an empty result means no scope."""

    def validate_scope(self, requested_scope: str | None) -> list[str] | None:
        return known_scopes(requested_scope) or None

    def validate_redirect_uri(self, redirect_uri: AnyUrl | None) -> AnyUrl:
        """The SDK matches redirect URIs exactly. RFC 8252 section 7.3: for a loopback redirect (http to
        localhost, 127.0.0.1 or [::1]) the authorization server must allow any port, because native apps
        such as Claude Code pick a free port at run time while their registration or client metadata
        document lists the URI without one. So a loopback request matches a registered loopback URI with
        the same scheme, host, path and query and any port. Every other URI is still matched exactly."""
        if redirect_uri is not None and self.redirect_uris and redirect_uri not in self.redirect_uris:
            wanted = _loopback_key(str(redirect_uri))
            if wanted is not None and any(_loopback_key(str(u)) == wanted for u in self.redirect_uris):
                return redirect_uri
        return super().validate_redirect_uri(redirect_uri)


_LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "::1")


def _loopback_key(uri: str) -> tuple[str, str, str] | None:
    """(host, path, query) of an http loopback URI with no user info or fragment, else None."""
    parts = urlsplit(uri)
    if parts.scheme != "http" or parts.hostname not in _LOOPBACK_HOSTS or parts.username or parts.password \
            or parts.fragment:
        return None
    try:
        parts.port            # raises on a malformed port
    except ValueError:
        return None
    return parts.hostname, parts.path or "/", parts.query


_S256_CHALLENGE = re.compile(r"[A-Za-z0-9_-]{43}")


def _gateway_client(info: OAuthClientInformationFull | None) -> GatewayClient | None:
    return None if info is None else GatewayClient.model_validate(info.model_dump())


class GatewayProvider:
    def __init__(self, settings: Settings, store: Store, *, cimd_http: httpx.Client | None = None,
                 clock: Callable[[], float] = time.time):
        self.settings, self.store = settings, store
        self._cimd_http, self._clock = cimd_http, clock
        # Fetched metadata documents live only here, for 24 h, and are never written to the store: a
        # restart or expiry re-fetches, and a client whose document changes cannot linger in the database.
        self._cimd_cache: dict[str, tuple[OAuthClientInformationFull, float]] = {}
        self._cimd_failures: dict[str, float] = {}     # url -> retry-after time, so a bad URL is not refetched for 60 s
        self._cimd_limiter = anyio.CapacityLimiter(CIMD_WORKERS)
        # The issuer exactly as the SDK's metadata document writes it (OAuthMetadata keeps an empty path
        # empty), which is what a client compares the RFC 9207 iss parameter with.
        self.issuer = json.loads(OAuthMetadata(issuer=settings.issuer_url, authorization_endpoint=settings.issuer_url,
                                               token_endpoint=settings.issuer_url).model_dump_json())["issuer"]

    def _remember(self, table: dict, key: str, value) -> None:
        if len(table) >= CIMD_CACHE_MAX:
            now = self._clock()
            for k in [k for k, v in table.items() if (v[1] if isinstance(v, tuple) else v) <= now]:
                del table[k]
        if len(table) < CIMD_CACHE_MAX:
            table[key] = value

    def _allowed_only(self, info: OAuthClientInformationFull | None) -> OAuthClientInformationFull | None:
        """A stored client with only the redirect URIs the current allowlist accepts, or None when none is
        left, so the SDK never redirects (not even an error) to a URI the operator has since removed."""
        if info is None:
            return None
        uris = [u for u in info.redirect_uris or [] if redirect_allowed(str(u), self.settings)]
        if not uris:
            return None
        return info if len(uris) == len(info.redirect_uris or []) else info.model_copy(update={"redirect_uris": uris})

    def _resource_ok(self, resource: str) -> bool:
        return resource.rstrip("/") == self.settings.mail_resource_url.rstrip("/")

    # clients
    async def get_client(self, client_id: str) -> GatewayClient | None:
        return _gateway_client(await self._load_client(client_id))

    async def _load_client(self, client_id: str) -> OAuthClientInformationFull | None:
        if not is_cimd(client_id):
            return self._allowed_only(self.store.get_client(client_id))
        if not cimd_fetchable(client_id, self.settings):     # refused URLs cost no worker and no cache slot
            return None
        cached = self._cimd_cache.get(client_id)
        if cached and cached[1] > self._clock() and all(
                redirect_allowed(str(u), self.settings) for u in cached[0].redirect_uris or []):
            return cached[0]
        self._cimd_cache.pop(client_id, None)
        if self._cimd_failures.get(client_id, 0) > self._clock():
            return None
        self._cimd_failures.pop(client_id, None)
        info = await anyio.to_thread.run_sync(fetch_client_document, client_id, self.settings, self._cimd_http,
                                              limiter=self._cimd_limiter)
        if info:
            self._remember(self._cimd_cache, client_id, (info, self._clock() + CIMD_TTL))
        else:
            self._remember(self._cimd_failures, client_id, self._clock() + CIMD_FAILURE_TTL)
        return info

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        problem = registration_problem(client_info)
        if problem:
            log.warning("registration refused: %s", problem)
            raise RegistrationError(error="invalid_client_metadata", error_description=problem)
        for uri in client_info.redirect_uris or []:
            if not redirect_allowed(str(uri), self.settings):
                # Logged so the callback of an AI app not yet on the allowlist can be captured and added.
                # Registration carries no secrets; %r keeps control characters out of the log line.
                log.warning("registration refused: redirect_uri %r not allowed (client_name %r)",
                            str(uri)[:500], (client_info.client_name or "")[:200])
                raise RegistrationError(error="invalid_redirect_uri", error_description=f"redirect URI not allowed: {uri}")
        # Whatever scope was registered (none, offline_access, openid ...), the client may ask for exactly
        # the gateway's scopes, so that is what is recorded and echoed in the registration response.
        client_info.scope = " ".join(SCOPES)
        self.store.save_client(client_info)

    # authorization
    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        if not redirect_allowed(str(params.redirect_uri), self.settings):
            raise AuthorizeError(error="invalid_request", error_description="redirect URI not allowed")
        # The SDK requires S256 but not its form: an S256 challenge is 43 base64url characters (RFC 7636).
        if not _S256_CHALLENGE.fullmatch(params.code_challenge or ""):
            raise AuthorizeError(error="invalid_request", error_description="code_challenge must be an S256 value")
        resource = params.resource or self.settings.mail_resource_url
        if not self._resource_ok(resource):
            raise AuthorizeError(error="invalid_target", error_description="unknown resource")
        params = params.model_copy(update={"resource": self.settings.mail_resource_url})
        req = self.store.create_pending(client.client_id, params, self.settings.pending_ttl)
        return f"{self.settings.service_url}/login?req={req}"

    def complete_login(self, req: str, mailboxes: list[tuple[str, str, MailServer]]) -> str:
        """mailboxes: (address, password, server) for each verified mailbox, main first."""
        found = self.store.take_pending(req)
        if not found:
            raise LookupError("login request expired")
        client_id, params = found
        gid, key = self.store.create_grant(client_id, params.resource, mailboxes)
        code = self.store.issue_code(gid, key, client_id, params, self.settings.code_ttl)
        # RFC 9207: the issuer, exactly as the metadata states it, so a client talking to many authorization
        # servers can tell which one answered (mix-up protection).
        return construct_redirect_uri(str(params.redirect_uri), code=code, state=params.state,
                                      iss=self.issuer)

    async def load_authorization_code(self, client, authorization_code: str) -> AuthorizationCode | None:
        rec = self.store.load_code(authorization_code)
        if not rec:
            # A code presented again after it was used: someone else may hold it (RFC 6749 section 4.1.2),
            # so the grant it opened, and every token issued from it, ends.
            replayed = self.store.replayed_grant(authorization_code, "code", grace=0)
            if replayed:
                log.warning("authorization code reused: grant %s revoked", replayed)
            return None
        if rec.client_id != client.client_id:
            return None
        p = rec.params
        return AuthorizationCode(code=authorization_code, scopes=p.scopes or [], expires_at=rec.expires,
                                 client_id=rec.client_id, code_challenge=p.code_challenge, redirect_uri=p.redirect_uri,
                                 redirect_uri_provided_explicitly=p.redirect_uri_provided_explicitly,
                                 resource=p.resource, subject=self.store.grant_subject(rec.grant_id))

    def _tokens(self, grant_id, key, client_id, scopes, resource) -> OAuthToken:
        at, rt = self.store.issue_tokens(grant_id, key, client_id, scopes, resource,
                                         self.settings.access_ttl, self.settings.refresh_ttl)
        return self._oauth_token(at, rt, scopes)

    def _oauth_token(self, access: str, refresh: str, scopes: list[str]) -> OAuthToken:
        return OAuthToken(access_token=access, token_type="Bearer", expires_in=self.settings.access_ttl,
                          scope=" ".join(scopes) or None, refresh_token=refresh)

    async def exchange_authorization_code(self, client, authorization_code: AuthorizationCode) -> OAuthToken:
        # Read the record first (grant id, resource), then consume atomically: only one caller gets the key.
        rec = self.store.load_code(authorization_code.code)
        if not rec or rec.client_id != client.client_id:
            raise TokenError(error="invalid_grant", error_description="code already used or expired")
        key = self.store.consume_code(authorization_code.code)
        if key is None:
            raise TokenError(error="invalid_grant", error_description="code already used or expired")
        return self._tokens(rec.grant_id, key, client.client_id, authorization_code.scopes, rec.params.resource)

    # refresh
    async def load_refresh_token(self, client, refresh_token: str) -> RefreshToken | None:
        rec = self.store.load_token(refresh_token, "refresh")
        if not rec:
            # A rotated-out refresh token used again may mean two parties hold the grant (RFC 9700 section
            # 4.14.2), or a client whose sessions share one stored credential. Logged, not revoked, until
            # live traffic shows which: revoking would cut off legitimate multi-session clients.
            spent = self.store.spent_grant(refresh_token, "refresh")
            if spent:
                log.warning("rotated-out refresh token presented again (grant %s); refused, not revoked", spent)
            return None
        if rec.client_id != client.client_id:
            return None
        return RefreshToken(token=refresh_token, client_id=rec.client_id, scopes=rec.scopes,
                            expires_at=int(rec.expires), resource=rec.resource,
                            subject=self.store.grant_subject(rec.grant_id))

    async def exchange_refresh_token(self, client, refresh_token: RefreshToken, scopes: list[str]) -> OAuthToken:
        # The SDK has already refused any scope the refresh token lacks; a repeated one is collapsed here.
        scopes = list(dict.fromkeys(s for s in scopes if s))
        # One store transaction: verify (including the client binding), delete the old token, insert the new pair.
        rotated = self.store.rotate_and_issue(refresh_token.token, client.client_id, scopes or None,
                                              self.settings.access_ttl, self.settings.refresh_ttl)
        if rotated is None:
            raise TokenError(error="invalid_grant", error_description="refresh token invalid")
        rec, at, rt = rotated
        return self._oauth_token(at, rt, scopes or rec.scopes)

    # access
    async def load_access_token(self, token: str) -> AccessToken | None:
        rec = self.store.load_token(token, "access")
        if not rec or not self._resource_ok(rec.resource):
            return None
        return AccessToken(token=token, client_id=rec.client_id, scopes=rec.scopes, expires_at=int(rec.expires),
                           resource=rec.resource, subject=self.store.grant_subject(rec.grant_id))

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        # The SDK hands us a token it loaded through our load_* methods, but never act on a string that
        # has not been verified (delete_token matches on id alone). Revoking a refresh token ends the
        # whole grant, so the access tokens issued from it die with it; an access token dies alone.
        rec = self.store.load_token(token.token, "refresh")
        if rec is not None:
            self.store.revoke_grant(rec.grant_id)
        elif self.store.load_token(token.token, "access") is not None:
            self.store.delete_token(token.token)

    async def exchange_identity_assertion(self, client, params: IdentityAssertionParams) -> OAuthToken:
        raise TokenError(error="unsupported_grant_type", error_description="not supported")
