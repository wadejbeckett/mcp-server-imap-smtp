# SPDX-License-Identifier: AGPL-3.0-or-later
"""The sign-in and manage pages (ticket 81 split them out of auth/login.py, which stays their import
surface): common.py holds what both share, login.py and manage.py one page each, and totp.py,
identities.py and keys.py are the sections later tickets add to the manage page."""
from __future__ import annotations

from starlette.routing import Route

from ...config import Settings
from ...mail.resolve import Resolver
from ...mail.sessions import Sessions
from ...ratelimit import RateLimiter
from ..provider import GatewayProvider
from . import login, manage
from .common import LoginLimits, Pages, Verifier, moved


def login_routes(provider: GatewayProvider, resolver: Resolver, verifier: Verifier,
                 limiter: RateLimiter | LoginLimits, settings: Settings, sessions: Sessions | None = None) -> list[Route]:
    """sessions: the mail servers' session caps (mail/sessions.py), shared with the tools; password checks
    then wait their turn for a session like tool calls. None (tests): checks are limited only below."""
    p = Pages(provider, resolver, verifier, limiter, settings, sessions)
    routes = [*login.routes(p), *manage.routes(p)]
    base = settings.service_path
    if base:
        # Before 21 October 2026 the pages were at the site root. Links already sent (/manage) and sign-ins
        # in flight (/login?req=...) are sent on; 308 keeps a POST a POST.
        for page_name in ("login", "manage"):
            routes.append(Route(f"/{page_name}", moved(f"{base}/{page_name}"), methods=["GET", "POST"]))
    return routes
