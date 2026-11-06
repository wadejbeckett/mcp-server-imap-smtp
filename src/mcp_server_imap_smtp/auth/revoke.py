# SPDX-License-Identifier: AGPL-3.0-or-later
"""Token revocation (RFC 7009) that public clients can use.

The SDK's RevocationHandler validates the form with a model whose client_secret field is required (it may
be empty, but it must be present), so a public client (token_endpoint_auth_method "none"), which has no
secret to send, gets 400 and cannot end its own connection. RFC 7009 section 2.1 lets such a client
revoke its own tokens identified by client_id. This handler is the SDK's with that one field optional:
client authentication is still the SDK's ClientAuthenticator (a confidential client must still present its
secret), a token is still only revoked when it was issued to the calling client, and an unknown token
still answers 200."""
from __future__ import annotations

from typing import Literal

from mcp.server.auth.handlers.revoke import RevocationErrorResponse, RevocationHandler
from mcp.server.auth.json_response import PydanticJSONResponse
from mcp.server.auth.middleware.client_auth import AuthenticationError, ClientAuthenticator
from mcp.server.auth.provider import OAuthAuthorizationServerProvider
from mcp.server.auth.routes import REVOCATION_PATH
from mcp.server.transport_security import DEFAULT_MAX_REQUEST_BODY_SIZE, RequestBodyLimitMiddleware
from mcp.shared.inbound import MCP_PROTOCOL_VERSION_HEADER
from pydantic import BaseModel, ValidationError
from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route, request_response


class RevocationForm(BaseModel):
    token: str
    token_type_hint: Literal["access_token", "refresh_token"] | None = None
    client_id: str
    client_secret: str | None = None     # absent for a public client; checked by the authenticator when set


class PublicClientRevocationHandler(RevocationHandler):
    async def handle(self, request: Request) -> Response:
        try:
            client = await self.client_authenticator.authenticate_request(request)
        except AuthenticationError as exc:
            return PydanticJSONResponse(status_code=401, content=RevocationErrorResponse(
                error="unauthorized_client", error_description=exc.message))
        try:
            form = RevocationForm.model_validate(dict(await request.form()))
        except ValidationError:
            return PydanticJSONResponse(status_code=400, content=RevocationErrorResponse(
                error="invalid_request", error_description="token and client_id are required"))
        loaders = [self.provider.load_access_token, lambda t: self.provider.load_refresh_token(client, t)]
        if form.token_type_hint == "refresh_token":
            loaders.reverse()
        for loader in loaders:
            token = await loader(form.token)
            if token is not None:
                break
        # Only a token issued to this client is revoked; anything else answers 200 too (RFC 7009 section 2.2),
        # so the endpoint says nothing about tokens that are not the caller's.
        if token is not None and token.client_id == client.client_id:
            await self.provider.revoke_token(token)
        return Response(status_code=200, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})


def install_public_revocation(app: Starlette, provider: OAuthAuthorizationServerProvider) -> None:
    """Swap the SDK's /revoke route for one using PublicClientRevocationHandler, wrapped the way the SDK
    wraps it (CORS for browser-based clients, the request body limit). Raises when the SDK app has no such
    route, so an SDK upgrade that moves it fails loudly at start-up instead of silently keeping the 400."""
    for i, route in enumerate(app.router.routes):
        if isinstance(route, Route) and route.path == REVOCATION_PATH:
            handler = PublicClientRevocationHandler(provider, ClientAuthenticator(provider))
            endpoint = CORSMiddleware(
                RequestBodyLimitMiddleware(request_response(handler.handle), DEFAULT_MAX_REQUEST_BODY_SIZE),
                allow_origins="*", allow_methods=["POST", "OPTIONS"], allow_headers=[MCP_PROTOCOL_VERSION_HEADER])
            app.router.routes[i] = Route(REVOCATION_PATH, endpoint=endpoint, methods=["POST", "OPTIONS"])
            return
    raise RuntimeError(f"the MCP SDK app has no {REVOCATION_PATH} route to replace")
