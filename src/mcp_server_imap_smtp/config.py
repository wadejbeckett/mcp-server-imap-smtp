# SPDX-License-Identifier: AGPL-3.0-or-later
"""Runtime settings, loaded from one TOML file. Environment-specific values live only here."""
from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from .mail.hosts import MailServer

DEFAULT_REDIRECTS = (
    "https://claude.ai/api/mcp/auth_callback",
    "https://chatgpt.com/connector_platform_oauth_redirect",
    "https://chatgpt.com/connector/oauth/",  # trailing slash = this URL or anything under it
    "https://grok.com/connectors-oauth-exchange-code/",
    "cursor://anysphere.cursor-mcp/oauth/callback",          # Cursor desktop
    "https://www.cursor.com/agents/mcp/oauth/callback",      # Cursor agents on the web
)


SEND_MODES = ("send", "draft_only", "off")


@dataclass(frozen=True)
class Settings:
    issuer_url: str
    mail_resource_url: str
    mail_servers: tuple[MailServer, ...]   # at least one; see load_settings for the TOML forms
    db_path: Path
    operator_name: str = "the operator"   # the hosting company, as users see it
    product_name: str = "Mail Connector"  # the connector's name: MCP server name, instructions, sign-in page
    support_url: str = ""                 # shown to users when set (http or https only)
    support_email: str = ""               # shown to users when set
    legacy_mail_host: str = ""            # server for mailboxes sealed before servers were (see legacy_server)
    listen_host: str = "127.0.0.1"
    listen_port: int = 8765
    redirect_allowlist: tuple[str, ...] = DEFAULT_REDIRECTS
    allow_loopback_redirects: bool = True
    access_ttl: int = 3600
    refresh_ttl: int = 30 * 86400
    code_ttl: int = 300
    pending_ttl: int = 300        # a sign-in page left open longer must be started again from the AI app
    login_failures: int = 5       # wrong passwords per client IP (IPv6: per /64) and per mailbox, per login_window
    login_window: int = 900
    login_daily_failures: int = 20    # wrong passwords per mailbox per 24 hours
    host_login_failures: int = 50     # wrong passwords per mail server, all clients together, per login_window
    request_login_failures: int = 5   # wrong passwords on one sign-in page before the user must start again
    register_limit: int = 30      # POST /register per client IP per login_window
    register_overall_limit: int = 1000   # POST /register from all clients together per login_window
    authorize_limit: int = 30     # GET and POST /authorize together, per client IP per login_window
    token_limit: int = 120        # POST /token per client IP per login_window
    trusted_proxy: bool = False
    forwarded_allow_ips: str = "127.0.0.1"   # reverse proxy address(es) whose X-Forwarded-For is trusted
    extra_allowed_hosts: tuple[str, ...] = field(default_factory=tuple)
    # Mailboxes in one connection (grant): 0 means no limit. The sign-in form is still bounded in bytes.
    max_mailboxes: int = 0
    # mail_search mailbox="*" searches at most this many of a grant's mailboxes per call (in sign-in
    # order; the rest are listed as not searched). 0 means every mailbox.
    search_max_mailboxes: int = 0
    # Sending. "send": mail_send and mail_draft; "draft_only": mail_draft but no mail_send (the AI prepares
    # replies, a person sends them from the mail app); "off": neither. The per-grant caps below are off
    # (0 = unlimited) unless the operator sets them; they count in memory. The mail server's own outgoing
    # limits apply either way.
    send_mode: str = "send"
    send_hourly_limit: int = 0        # messages sent per grant per hour; 0 = no cap
    send_daily_limit: int = 0         # messages sent per grant per 24 hours; 0 = no cap
    send_max_recipients: int = 0      # To + Cc + Bcc on one message; 0 = no cap
    send_allow_bcc: bool = True
    # Mail server sessions (mail/sessions.py). Each [[mail_servers]] entry caps the sessions open on it at once
    # (max_sessions, default 8); max_sessions_per_mailbox caps the IMAP sessions one mailbox has open, below
    # Dovecot's mail_max_userip_connections (10 on Plesk), since every client connects from this one address.
    # A logged-in IMAP session is kept for imap_idle_seconds after a call and reused by the next call for the
    # same connection and mailbox; 0 turns reuse off. It is never reused once imap_max_session_age seconds have
    # passed since its login, so a password changed on the mail server takes effect within that time.
    max_sessions_per_mailbox: int = 4
    # Tool calls one connection (grant) runs at once; a further call waits its turn, and is told the
    # connection is busy if none comes free in 30 seconds. mail_search mailbox="*" counts as one call.
    max_calls_per_grant: int = 4
    imap_idle_seconds: int = 60
    imap_max_session_age: int = 300
    # Client ID Metadata Document URLs are fetched only from these hosts (exact or subdomain): SSRF guard.
    cimd_allowed_hosts: tuple[str, ...] = ("chatgpt.com", "openai.com", "claude.ai", "claude.com", "anthropic.com")
    # A file holding the server's sealing secret (at least 32 bytes), mixed into the key that wraps each grant
    # key. Kept outside the database and its backups. Unset: the systemd credential "sealing-secret" is used
    # when the unit loads one (LoadCredential=), otherwise none (grant keys are wrapped with the token alone).
    sealing_secret_file: str = ""

    def __post_init__(self):
        if isinstance(self.mail_servers, list):
            object.__setattr__(self, "mail_servers", tuple(self.mail_servers))
        if not self.mail_servers or not all(isinstance(m, MailServer) for m in self.mail_servers):
            raise ValueError("mail_servers must hold at least one MailServer")
        for name in ("operator_name", "product_name"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name).strip():
                raise ValueError(f"{name} must be a non-empty string")
        if self.support_url and urlparse(self.support_url).scheme not in ("http", "https"):
            raise ValueError("support_url must be an http or https URL")
        if self.legacy_mail_host and self.legacy_mail_host not in {m.host for m in self.mail_servers}:
            raise ValueError("legacy_mail_host must be the host of one of the configured mail servers")
        if self.send_mode not in SEND_MODES:
            raise ValueError(f"send_mode must be one of {', '.join(SEND_MODES)}")
        for name in ("max_mailboxes", "search_max_mailboxes", "send_hourly_limit", "send_daily_limit",
                     "send_max_recipients"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a whole number, 0 or more (0 means no limit)")
        if type(self.max_sessions_per_mailbox) is not int or self.max_sessions_per_mailbox < 1:
            raise ValueError("max_sessions_per_mailbox must be a whole number, 1 or more")
        if type(self.max_calls_per_grant) is not int or self.max_calls_per_grant < 1:
            raise ValueError("max_calls_per_grant must be a whole number, 1 or more")
        if type(self.imap_idle_seconds) is not int or self.imap_idle_seconds < 0:
            raise ValueError("imap_idle_seconds must be a whole number of seconds, 0 or more (0 turns reuse off)")
        if type(self.imap_max_session_age) is not int or self.imap_max_session_age < 0:
            raise ValueError("imap_max_session_age must be a whole number of seconds, 0 or more (0 turns reuse off)")
        if self.support_email and ("@" not in self.support_email or any(c in self.support_email for c in " <>\"'")):
            raise ValueError("support_email must be a plain email address")

    @property
    def legacy_server(self) -> MailServer | None:
        """Where a mailbox sealed as a bare password (before its server was sealed with it) signs in:
        the server named by legacy_mail_host; when that is unset, the only server if exactly one is
        configured; otherwise None, and such a mailbox must be reconnected (never guessed)."""
        if self.legacy_mail_host:
            return next(m for m in self.mail_servers if m.host == self.legacy_mail_host)
        return self.mail_servers[0] if len(self.mail_servers) == 1 else None

    @property
    def mail_path(self) -> str:
        return urlparse(self.mail_resource_url).path or "/"

    @property
    def service_url(self) -> str:
        """Where the mail service's own pages live: the MCP endpoint's URL (mail_resource_url), so the sign-in
        and manage pages sit under the same service path ("/mail/login") and another service mounted on the
        same gateway cannot clash with them. The OAuth endpoints and metadata stay at the issuer's root."""
        return self.mail_resource_url.rstrip("/")

    @property
    def service_path(self) -> str:
        """service_url's path without a trailing slash: "/mail", or "" when the service is the whole site."""
        return self.mail_path.rstrip("/")

    @property
    def public_host(self) -> str:
        return urlparse(self.issuer_url).netloc


_SERVER_KEYS = {"host", "imap_port", "smtp_port", "domains", "match_mx", "max_sessions"}


def _mail_servers(raw: dict) -> tuple[MailServer, ...]:
    """Either `[[mail_servers]]` tables or the legacy `mail_host = "..."` (one server for every
    address, no DNS), never both. Top-level imap_port/smtp_port are the default ports for each."""
    imap_port, smtp_port = raw.pop("imap_port", 993), raw.pop("smtp_port", 465)
    tables, legacy = raw.pop("mail_servers", None), raw.pop("mail_host", None)
    if tables is not None and legacy is not None:
        raise ValueError("set either mail_host or [[mail_servers]], not both")
    if legacy is not None:
        return (MailServer(host=legacy, imap_port=imap_port, smtp_port=smtp_port, domains=("*",), match_mx=False),)
    if not tables:
        raise ValueError("no mail server configured: add [[mail_servers]] (or the legacy mail_host)")
    if not isinstance(tables, list) or not all(isinstance(t, dict) for t in tables):
        raise ValueError("mail_servers must be an array of tables ([[mail_servers]])")
    servers = []
    for table in tables:
        unknown = set(table) - _SERVER_KEYS
        if unknown or "host" not in table:
            raise ValueError(f"[[mail_servers]] entry {table.get('host', '?')!r}: "
                             + (f"unknown key(s) {sorted(unknown)}" if unknown else "host is required"))
        if not isinstance(table.get("domains", []), list):
            raise ValueError(f"[[mail_servers]] entry {table['host']!r}: domains must be a list")
        servers.append(MailServer(**{"imap_port": imap_port, "smtp_port": smtp_port, **table,
                                     "domains": tuple(table.get("domains", ()))}))
    hosts = [s.host for s in servers]
    if len(set(hosts)) != len(hosts):
        raise ValueError("each [[mail_servers]] host may appear only once")
    return tuple(servers)


def load_settings(path: Path) -> Settings:
    raw = tomllib.loads(Path(path).read_text())
    raw["db_path"] = Path(raw["db_path"])
    raw["mail_servers"] = _mail_servers(raw)
    for key in ("redirect_allowlist", "extra_allowed_hosts", "cimd_allowed_hosts"):
        if key in raw:
            raw[key] = tuple(raw[key])
    return Settings(**raw)


SEALING_SECRET_MIN = 32
SEALING_CREDENTIAL = "sealing-secret"


def load_sealing_secret(settings: Settings, env: dict | None = None) -> bytes | None:
    """The sealing secret from settings.sealing_secret_file, else from $CREDENTIALS_DIRECTORY/sealing-secret
    (systemd LoadCredential=), else None. Surrounding whitespace is ignored. A configured file that is
    missing or shorter than 32 bytes stops the service rather than running without it."""
    env = os.environ if env is None else env
    path = settings.sealing_secret_file
    if not path and env.get("CREDENTIALS_DIRECTORY"):
        candidate = Path(env["CREDENTIALS_DIRECTORY"]) / SEALING_CREDENTIAL
        path = str(candidate) if candidate.exists() else ""
    if not path:
        return None
    try:
        secret = Path(path).read_bytes().strip()
    except OSError as exc:
        raise ValueError(f"sealing secret {path} cannot be read ({exc.__class__.__name__})") from None
    if len(secret) < SEALING_SECRET_MIN:
        raise ValueError(f"sealing secret {path} is shorter than {SEALING_SECRET_MIN} bytes")
    return secret


_UNSAFE_REMAINDER = re.compile(r"\.\.|\\|%2e|#", re.IGNORECASE)


def redirect_allowed(uri: str, settings: Settings) -> bool:
    parsed = urlparse(uri)
    # RFC 8252 section 7.3: native apps use an http loopback redirect on any port, IPv4 or IPv6 ([::1]).
    if settings.allow_loopback_redirects and parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "localhost", "::1"):
        return True
    for allowed in settings.redirect_allowlist:
        if allowed.endswith("/"):
            # The entry itself or anything under it, but nothing that could climb out of the prefix once
            # a client or browser normalises the path ("..", backslashes, encoded dots) and no fragment.
            if uri.startswith(allowed) and not _UNSAFE_REMAINDER.search(uri[len(allowed):]):
                return True
        elif uri == allowed:
            return True
    return False
