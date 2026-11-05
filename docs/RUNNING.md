# Running mcp-server-imap-smtp

Local development, operator commands, configuration reference and testing. Production deployment on a dedicated server is in [DEPLOY.md](DEPLOY.md).

## Install

Work from the root of a clone of the repository. You need Python 3.11 or later and [uv](https://docs.astral.sh/uv/).

```bash
cd mcp-server-imap-smtp
uv venv && uv pip install -e '.[dev]'
cp config.example.toml local.toml            # local.toml is git-ignored
```

Optional: `poppler-utils` (Debian/Ubuntu apt package, provides `pdftotext`) lets `mail_attachment` return PDF attachments as text; without it they come back as base64. `pdftotext` parses untrusted PDFs from incoming mail, so it runs as a subprocess with a 30-second timeout; keep the package patched.

## Run

```bash
.venv/bin/mcp-server-imap-smtp --config local.toml
```

It listens on `127.0.0.1:8765`. Run exactly one uvicorn worker process (the default; do not add `--workers`): the sign-in and request rate limits, the client-metadata cache, the mail server session caps and the kept IMAP sessions live in process memory, so several workers would each keep their own counters and each open their own sessions to the mail servers. Quick check (no credentials needed):

```bash
curl -s http://127.0.0.1:8765/.well-known/oauth-protected-resource/mail
curl -si -X POST http://127.0.0.1:8765/mail -H 'content-type: application/json' \
     -H 'accept: application/json, text/event-stream' -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'   # expect 401
```

The first returns the protected-resource metadata (`resource`, `authorization_servers`); the second returns `401` with a `WWW-Authenticate` header pointing at that metadata.

### Scopes

The gateway has one OAuth scope, `offline_access`, advertised as `scopes_supported` in both the authorization-server and the protected-resource metadata. ChatGPT needs it advertised, or it may drop the connection when the one-hour access token expires instead of using the refresh token. Claude and Claude Code are expected to request it too, because it is advertised. It gates nothing: a grant is always to the mailboxes signed in, and a refresh token is issued whether or not the scope is asked for, so clients that send no scope also still work. Unknown scopes are ignored, never refused (RFC 6749 section 3.3 lets the server grant less than asked): a registration naming any scope (`openid`, `offline_access`, none) is accepted and recorded and echoed as `offline_access`; at `/authorize` any client, whatever it registered or its metadata document lists, is granted `offline_access` if it asked for it and nothing else, and the token response's `scope` shows what was granted (absent when nothing was). Whitespace and repeats in the requested scope are ignored. A refresh keeps the scopes of the original grant and cannot add new ones (`400 invalid_scope`, RFC 6749 section 6; the refresh token stays usable); a repeated scope on refresh is collapsed. Known limit: on refresh the SDK splits the scope on single spaces, so a padded value such as `"offline_access "` gets `400 invalid_scope`; clients normally send no scope on refresh. There is no `required_scopes`: bearer tokens issued without a scope stay valid, and the `401` from `/mail` carries no `scope=` hint (clients read `scopes_supported` instead). Both metadata documents answer `HEAD` with the same headers as `GET`.

## Connect a client

**Claude Code**

```bash
claude mcp add --transport http mail-dev http://127.0.0.1:8765/mail
```

Then run `/mcp` inside Claude Code and choose the server to authenticate. A browser opens the sign-in page: enter the mailbox address and password. To add more mailboxes to the same connection, open "Add more mailboxes" on that same form and put one mailbox per line: the address, a space (or a tab), then that mailbox's password. There is no limit on how many unless `max_mailboxes` is set. Signing in again later creates a separate connection with its own grant; it does not add a mailbox to the first. Passwords go only into that page.

**MCP Inspector**

```bash
npx @modelcontextprotocol/inspector
```

Choose transport "Streamable HTTP", URL `http://127.0.0.1:8765/mail`, then use the OAuth flow.

Both use loopback redirect URIs, which need `allow_loopback_redirects = true` (the default).

## Admin CLI

```bash
.venv/bin/mcp-server-imap-smtp-admin --config local.toml servers list
.venv/bin/mcp-server-imap-smtp-admin --config local.toml grants list
.venv/bin/mcp-server-imap-smtp-admin --config local.toml grants revoke --grant <grant id>
.venv/bin/mcp-server-imap-smtp-admin --config local.toml grants revoke --mailbox user@example.com
.venv/bin/mcp-server-imap-smtp-admin --config local.toml grants revoke --host mail.example.com
.venv/bin/mcp-server-imap-smtp-admin --config local.toml grants add-mailboxes <grant id> --subject <main mailbox> < lines.txt
```

- `servers list` prints each configured mail server: host, IMAP and SMTP ports, `domains` and whether `match_mx` is on. It reads only the configuration.
- `grants list` prints one line per grant: id, creation time, `active` or `revoked`, and each mailbox address followed by its mail server in brackets. Mailboxes connected before servers were recorded show the `legacy_mail_host` server, the only server when there is one, or otherwise "unknown server". It never prints passwords, tokens or keys.
- `grants revoke --grant ID` revokes one grant; `--mailbox ADDRESS` (case-insensitive) revokes every grant that includes that mailbox; `--host HOST` revokes every grant with a mailbox on that mail server. All three delete the grant's tokens and codes, so the client must sign in again. Output is `revoked N`, counting only grants that were still active; `0` means nothing matched or it was already revoked.
- `grants add-mailboxes GRANT --subject MAIN` adds mailboxes to an existing connection without the user reconnecting: the operator's version of the manage page. It reads "address password" lines from stdin, or asks for them without echo on a terminal. `--subject` must be the connection's main mailbox, and the connection is printed before anything is checked. Each new mailbox is checked on its server over IMAP; mailboxes already present are skipped; checking stops after 5 wrong passwords; nothing is saved unless every line passes. Each addition writes an `admin_add_mailbox` audit line to syslog. A connection created by an older version is refused until its AI app has used it once. Keep the input file readable only by you and delete it afterwards (`shred -u`).
- The CLI works on the database directly and can run while the server is up. `--config` defaults to `$MCP_SERVER_IMAP_SMTP_CONFIG`, or `local.toml` in the current directory (the server's `--config` works the same way). If `db_path` does not exist it stops with exit status 2 instead of creating an empty database.

## Configuration reference

One TOML file, read by both `mcp-server-imap-smtp` and `mcp-server-imap-smtp-admin`. Required keys first.

| Key | Default | Meaning |
|---|---|---|
| `issuer_url` | required | Public base URL of the gateway, as clients see it (for example `https://mcp.example.com`). It is the OAuth issuer, the origin allowed for browser requests, and its host is allowed by the host check. |
| `mail_resource_url` | required | Public URL of the mail MCP endpoint (for example `https://mcp.example.com/mail`). Its path is where the service is mounted: the MCP endpoint itself, and under it the service's own pages, the sign-in page (`<path>/login`) and the manage page (`<path>/manage`). Tokens are bound to this URL (audience). Mount it anywhere, for example `https://example.com/tools/mail` or the site root. |
| `mail_servers` | required, unless `mail_host` is set | The mail servers the connector may sign in to, as `[[mail_servers]]` tables (below). Sign-in can never be aimed at a server that is not listed. |
| `mail_host` | none | Legacy single-server form. `mail_host = "mail.example.com"` alone means one server that serves every address (`domains = ["*"]`, `match_mx = false`), so no DNS lookup is made. Use it, or `[[mail_servers]]`, not both. |
| `legacy_mail_host` | none | Only for a database that holds mailboxes connected before each mailbox's server was recorded with its password. Names the `host` of the configured server those mailboxes sign in to. When unset and exactly one server is configured, that server is used; when unset and several are configured, such a mailbox is refused and its user must reconnect (the server is never guessed). Must be the `host` of a configured server. |
| `operator_name` | `the operator` | The name of the organisation running the connector, for example `Example Hosting`. Shown on the sign-in page and in error messages such as "Mail for client.example is not hosted by Example Hosting." |
| `product_name` | `Mail Connector` | The connector's name as users see it, for example `Example Mail`. Used as the MCP server name, in the instructions sent to the AI app and on the sign-in page. |
| `support_url` | none | Support page shown to users, for example `https://www.example.com/support`. |
| `support_email` | none | Support address shown to users, for example `support@example.com`. |
| `db_path` | required | SQLite file for clients, grants, sealed mailbox credentials, tokens and codes. Created with mode 0600. |
| `listen_host` | `127.0.0.1` | Address the server binds. Keep it on loopback behind a proxy. |
| `listen_port` | `8765` | Port the server binds. Also used for the `127.0.0.1:<port>` and `localhost:<port>` Host values that are always allowed. |
| `imap_port` | `993` | Default IMAP-over-TLS port for `mail_host` and for any `[[mail_servers]]` entry that does not set its own. |
| `smtp_port` | `465` | Default SMTP-over-TLS port, used the same way. |
| `redirect_allowlist` | claude.ai, ChatGPT, Grok and Cursor callback URLs (`DEFAULT_REDIRECTS` in `config.py`) | OAuth redirect URIs accepted at registration and authorisation. An entry ending in `*` matches by prefix (the part before the `*`), except that the part after the prefix may not contain `..`, a backslash, `;`, `#`, or an encoded dot, slash, backslash or `%` (`%2e`, `%2f`, `%5c`, `%25`, any case); any other entry, one ending in `/` included, must match exactly. Setting it replaces the default list. A stored client keeps only the redirect URIs the current list accepts. |
| `allow_loopback_redirects` | `true` | When true, any `http://127.0.0.1` or `http://localhost` redirect URI (any port or path) is accepted, in addition to the allowlist. This is what Claude Code, MCP Inspector and other desktop clients use. Set it to `false` on a public deployment that only serves claude.ai and ChatGPT: it removes the ability for any locally running program on a user's machine to register as a client and receive an authorisation code (PKCE still applies either way). With `false`, Claude Code and the Inspector can no longer connect. |
| `access_ttl` | `3600` | Access token lifetime, seconds. |
| `refresh_ttl` | `2592000` | Refresh token lifetime, seconds (30 days); refresh tokens rotate on use. |
| `code_ttl` | `300` | Authorisation code lifetime, seconds. |
| `grant_max_age` | `7776000` (90 days) | A connection ends this long after sign-in however often its tokens are refreshed; the user then signs in again. `0` means no limit. |
| `pending_ttl` | `300` | How long a sign-in page stays valid after the client sends the user to it, seconds. |
| `login_failures` | `5` | Sign-in attempts allowed per client and per mailbox within `login_window`; further attempts get HTTP 429. An IPv6 client counts as its whole /64 (one host can rotate through its /64), an IPv4-mapped address as its IPv4 address. Wrong passwords count against both; malformed input, an address not hosted here and a DNS failure count against the client only; a success or a mail-server outage does not count. A mailbox's attempt is counted only when its own password is tried, so a wrong first password on a form does not count against the other mailboxes on it. When several wrong passwords on one form are found at once (the list is checked a few at a time, see "Many mailboxes in one connection"), each counts against its own mailbox and against the client. Mailbox keys use the normalised address, so case, Unicode dot and fullwidth variants of one address share a key. |
| `login_window` | `900` | The lockout window, seconds. Also sent as `Retry-After`, and the window for the three limits below. |
| `login_daily_failures` | `20` | Wrong passwords allowed per mailbox per 24 hours from one client network (IPv4 /24, IPv6 /48); five times this from all networks together. |
| `host_login_failures` | `50` | Wrong passwords sent to one mail server within `login_window`, from all clients together. Beyond it, new sign-ins to that server are refused (HTTP 429) until the window passes, and a warning is logged (`sign-in limit reached for mail server …`). This stops an attacker who rotates addresses from guessing passwords on the mail server through the gateway, which the mail server's own brute-force protection usually trusts. Connected users are not affected, and mailboxes that have signed in through the gateway before can still sign in. |
| `request_login_failures` | `5` | Wrong passwords allowed on one sign-in page; then the user must start again from the AI app. |
| `register_limit` | `30` | `POST /register` (dynamic client registration) requests allowed per client IP within `login_window`; further requests get HTTP 429. |
| `register_overall_limit` | `1000` | `POST /register` requests from all clients together within `login_window`. Registration also takes only `application/json` bodies of at most 8 KB (HTTP 415 and 413 otherwise), a `client_name` of at most 100 characters and at most 10 redirect URIs of at most 512 characters each; registered clients that never complete a sign-in are deleted after 24 hours. |
| `authorize_limit` | `30` | `GET` and `POST /authorize` requests together, allowed per client IP within `login_window`; further requests get HTTP 429. |
| `token_limit` | `120` | `POST /token` (code exchange and refresh) requests allowed per client IP within `login_window`; further requests get HTTP 429. |
| `max_mailboxes` | `0` | Mailboxes one connection (grant) may hold, the main one included. `0` means no limit. When set, the sign-in page says how many more can be added and refuses a longer list. |
| `search_max_mailboxes` | `0` | Mailboxes searched by one `mail_search` call with `mailbox="*"`, in sign-in order; the rest are listed in the result's `errors` as not searched. `0` means every mailbox in the connection. |
| `max_sessions_per_mailbox` | `4` | IMAP sessions the connector holds open for one mailbox at once, for all connections that include it together (see "Mail server sessions"). Keep it below the mail server's per-user, per-address limit (Dovecot's `mail_max_userip_connections`, 10 by default), since every user reaches the mail server from the connector's one address. At least 1. |
| `max_calls_per_grant` | `4` | Tool calls one connection runs at once. A further call waits its turn and is told the connection is busy (audit outcome `busy`) if no slot comes free in 30 seconds. `mail_search` with `mailbox="*"` counts as one call. At least 1. A `folder="*"` search visits at most 100 folders per mailbox and starts no new folder after 60 seconds (the result counts the rest in `not_searched`); `mail_folders` stops counting messages after 60 seconds but still lists every folder. |
| `sealing_secret_file` | `""` | A file holding the server's sealing secret (at least 32 bytes), mixed into the key that wraps each connection's key, so a copy of the database or a backup plus a token cannot open mailbox passwords. Unset: the systemd credential `sealing-secret` is used when the unit loads one (the deploy kit does), otherwise none. Connections made before a secret was configured keep working and move over at their next token refresh. Keep the secret out of backups; if it is lost, users sign in again. |
| `imap_idle_seconds` | `60` | How long a logged-in IMAP session is kept after a tool call for the next call on the same connection and mailbox (see "Mail server sessions"). `0` turns reuse off: every call logs in and out. |
| `imap_max_session_age` | `300` | Seconds after its login that a kept IMAP session is no longer reused, however often it is used (see "Mail server sessions"). A password change takes effect for the connector within at most `imap_max_session_age` seconds. `0` turns reuse off. |
| `send_mode` | `send` | `send`: the AI may send mail (`mail_send`) and save drafts. `draft_only`: no `mail_send`; the AI saves drafts and a person sends them from the mail app. `off`: neither tool. Only the listed tools are offered to the AI app. `mail_send` is marked as an action that changes things outside the mailbox, so AI apps ask the user to approve each message unless the user has turned that off, and the connector's instructions tell the AI to confirm first. A prompt-injected email could still lead an AI to send mail if the user approves without reading; choose `draft_only` where that risk is not accepted. |
| `send_hourly_limit` | `0` | Messages sent per connection (grant) per hour. `0` means no cap. Counted in memory, so a restart resets it. The three send caps are off by default because most mail servers already limit outgoing volume themselves (for example Postfix rate limits or a control panel's outgoing mail limits); set them where the mail server has no such controls. |
| `send_daily_limit` | `0` | Messages sent per connection per 24 hours. `0` means no cap. |
| `send_max_recipients` | `0` | To, Cc and Bcc together on one message. `0` means no cap. |
| `send_allow_bcc` | `true` | Whether `mail_send` accepts Bcc recipients. |
| `trusted_proxy` | `false` | Set `true` when the gateway sits behind nginx, Cloudflare Tunnel or any reverse proxy. uvicorn then takes the client IP from `X-Forwarded-For`, so the sign-in rate limits see real client addresses. If left `false` behind a proxy, every user shares the proxy's IP and one person's failures lock everyone out. |
| `forwarded_allow_ips` | `127.0.0.1` | Proxy address(es) whose `X-Forwarded-For` is trusted; comma-separated. Only used when `trusted_proxy = true`. Set it to the proxy's address as seen by the gateway (for nginx on the same box, `127.0.0.1`; `*` trusts everything and lets any caller spoof its IP, so do not use it unless the port is reachable only by the proxy). |
| `extra_allowed_hosts` | `[]` | Extra `Host` header values accepted (DNS-rebinding protection). The host of `issuer_url` and loopback are always allowed; add other names or `host:port` forms the proxy forwards, for example a tunnel hostname. |
| `cimd_allowed_hosts` | `chatgpt.com`, `openai.com`, `claude.ai`, `claude.com`, `anthropic.com` | Hosts (exact or subdomain) from which a client may use an https URL as its `client_id` (Client ID Metadata Documents). The gateway fetches that URL, so this is the SSRF guard: nothing outside the list is fetched. Setting it replaces the default list. |

### Mail servers

Each `[[mail_servers]]` table describes one server:

| Key | Default | Meaning |
|---|---|---|
| `host` | required | Host name the connector connects to. The TLS certificate must be valid for this exact name; there is no fallback name. |
| `imap_port` | top-level `imap_port` (993) | IMAP over TLS. |
| `smtp_port` | top-level `smtp_port` (465) | SMTP over TLS. |
| `domains` | `[]` | Mail domains this server serves: exact names (`client.example`) or `*.suffix` wildcards (every subdomain, not the suffix itself). `"*"` alone sends every address that no other rule matched to this server, including addresses at domains you do not host: their owners' passwords would then be tried on your server. Use it only for a private deployment where every user is yours. |
| `max_sessions` | `8` | IMAP and SMTP sessions the connector holds open on this server at once, for all users together, kept sessions included (see "Mail server sessions"). At least 2: `mail_send` holds one of each. Raise it for a server that is close to the connector or built for many connections. |
| `match_mx` | `true` | Also serve any domain whose MX points at this server, by name or by address. By name: with `host = "mail.example.net"`, a domain whose MX is `mail.example.net` or `mx1.mail.example.net` matches. By address: a domain whose MX host (for example `mail.client.example`, as some control panels such as Plesk publish for every domain) has an A or AAAA address that `host` also has matches. A domain whose MX is elsewhere does not. |

When a user signs in, the connector checks the address's domain against every server's `domains` first. If none matches and any server has `match_mx = true`, it looks up the domain's MX records and picks the first `match_mx` server (in configuration order) whose `host` is an MX host or a parent of one. If no name matches, it looks up the A and AAAA addresses of the first five MX hosts and of each `match_mx` server's `host`, and picks the first server that shares an address with an MX host. Every lookup has a 5-second limit; answers are cached for 10 minutes and a DNS failure for 30 seconds, during which sign-in for that domain reports the mail server as unreachable. DNS only decides whether an address may sign in and on which configured server: the connection always goes to that server's `host`, and TLS verifies the certificate against that name, whatever the MX records or their addresses say. If nothing matches, the sign-in page says the mail is not hosted by the operator and no password is tried. The server chosen is sealed into the grant with the password, so a later DNS change cannot move an existing connection to another server. Each time a tool opens a mailbox, its sealed host must still be a configured server: if the server has been removed from the configuration, the tool refuses and asks the user to reconnect (audit outcome `server_removed`). The IMAP and SMTP ports are taken from the current configuration, so changing a server's ports takes effect for existing connections.

### Mail server sessions

Every user of the connector reaches the mail servers from the connector's one address, so a mail server sees them all as one very busy client. A shared server slows for all its users when that client logs in too often: in testing against a typical shared Dovecot server, logins slowed for everyone at about two connector logins a second, about ten sessions. Three things keep the connector within what a server takes:

- **A cap per server.** Each `[[mail_servers]]` entry's `max_sessions` (default 8) caps the IMAP and SMTP sessions open on that server at once, from all tool calls and sign-in password checks together. `mail_send` holds two (IMAP for the original and the Sent copy, SMTP for the message). A cap per mailbox, `max_sessions_per_mailbox` (default 4, IMAP only), stays below the server's own per-user limit.
- **A fair queue.** A call that finds its server full waits its turn. Turns go to connections (grants), not calls: the connection served least recently goes next, so one connection searching dozens of mailboxes cannot hold up anyone else's call, and within a connection its calls naming one mailbox go before its `mailbox="*"` work. A sign-in is one more party in the queue. A call naming one mailbox that has not been served after 30 seconds gets "The mail server is busy right now. Try again shortly." (audit outcome `busy`); nothing is changed and the connection stays. A busy answer from the mail server itself (`[INUSE]` or `[LIMIT]` at login) is also reported as busy.
- **Session reuse.** After a call, a healthy IMAP session stays logged in for `imap_idle_seconds` (default 60) and the next call on the same connection and mailbox uses it, so a search followed by two reads is one login instead of three, and each later call is about a second faster on a distant server. Before reuse the connector checks the session (UNSELECT, which unlike CLOSE never deletes anything, or NOOP) and clears what the last call left behind, so the call opens its folder read-only (EXAMINE) and reads with BODY.PEEK exactly as on a fresh login: nothing is marked read. The check waits at most 5 seconds, so a session the network dropped without telling either side costs a call no more than that. If the server dropped the session meanwhile, the connector logs in once more; it never retries after a rejected password. A kept session is never reused once `imap_max_session_age` (default 300) seconds have passed since its login, even when calls keep it busy: a password change takes effect for the connector within at most `imap_max_session_age` seconds, since the mail server checks the password only at login. A kept session counts toward both caps, and is closed when another call needs its place, after an error that may have left it out of step, when the mail server rejects that mailbox's password (then every connection's kept sessions for that mailbox on that server are closed, and none logged in before the rejection is kept), when its connection is revoked in the running service, when it has been idle for `imap_idle_seconds`, and when it reaches `imap_max_session_age`. A session being closed keeps its place under both caps until its LOGOUT has finished (at most 5 seconds; at most four closes run at once), so the caps hold while sessions are replaced. A revocation with `mcp-server-imap-smtp-admin` (a separate process) stops new calls at once; the connection's kept sessions then close after `imap_idle_seconds`. Connections never share sessions, even for the same mailbox.

The connector runs mail work in its own threads, as many as the servers' `max_sessions` added together. With the defaults one connector holds at most 8 sessions on each server, and fewer than the 10 Dovecot allows per mailbox from one address.

### Many mailboxes in one connection

A business owner can connect every staff mailbox in one sign-in by pasting the whole list into the "Several mailboxes" box, one mailbox per line (address, whitespace, password; blank lines are skipped and the password is the rest of the line, trimmed). The email and password fields above it may then stay empty; the first line becomes the main mailbox. Later changes go through the manage page (`<mail URL>/manage`): the main mailbox signs in there and can add mailboxes, enter new passwords, remove mailboxes or disconnect, without the AI app reconnecting. Each mailbox is checked with its own address and password on its own server, so nothing changes on the mail servers.

- **Form size.** The whole form may be at most 2 MB (HTTP 413 beyond it), a limit the gateway enforces itself; nginx allows larger requests (32 MB) for tool calls with attachments.
- **Order of checks.** The list is validated first; a bad line is named by its number ("Line 12: ...") and never quoted, since it may hold a password. Each domain is then resolved once, four domains at a time per sign-in; the first domain not hosted here or a DNS failure stops the rest. Then the main mailbox's password is checked on its own, and only if it is right are the listed passwords checked, eight at a time per sign-in and at most 32 at a time for all sign-ins together (a private thread pool, so sign-ins never hold up tool calls). Each check is an IMAP login, so it also takes its turn under its server's session cap ("Mail server sessions"); if no session comes free within the sign-in's time budget, nothing is connected and the page says the check took too long.
- **Stopping.** Nothing new starts after a wrong password, a mail-server outage, a locked mailbox or the time budget (60 seconds plus 2 seconds per mailbox on the form); checks already under way finish. A wrong password names its line and address ("Line 12 (name@example.com): address or password incorrect."), and nothing is connected. The re-rendered page keeps the main address but never the list: the person pastes the corrected list again.
- **Limits.** The sign-in limits above apply unchanged: each mailbox's attempt is reserved only when its own password is tried, correct ones are given back, and the limiter holds at most one key per mailbox on the form plus the client's.

Every tool takes a `mailbox` argument naming one connected mailbox. `mail_search` also takes `mailbox="*"`: it searches every mailbox in the connection (or the first `search_max_mailboxes`). Each mailbox waits its turn for a session on its own server like any other call ("Mail server sessions"), behind the connection's own single-mailbox calls and taking turns with other connections, and uses a kept session where there is one, so a large search queues instead of flooding the server. Results are merged newest first with a `mailbox` field on each row, `offset + limit` may be at most 500, and no new mailbox is started after 45 seconds: a mailbox still waiting for a session then is listed in `errors` as "not searched: mail server busy; search this mailbox on its own shortly" (audit outcome `busy`), and the others are returned. A mailbox that cannot be searched is listed in `errors` with a short reason and the others are still returned. A rejected password there does not end the connection, unlike a call naming that one mailbox, which revokes the grant as before: with dozens of staff mailboxes in one connection, one person changing their password must not cut the owner off from the rest. Each mailbox searched gets its own audit line.

`mcp-server-imap-smtp-admin grants list` prints a grant with more than three mailboxes as a header line with the count, followed by one line per mailbox, each starting with the grant id.

Example behind nginx or a Cloudflare Tunnel:

```toml
issuer_url = "https://mcp.example.com"
mail_resource_url = "https://mcp.example.com/mail"
db_path = "/var/lib/mcp-server-imap-smtp/mcp-server-imap-smtp.sqlite"
trusted_proxy = true
forwarded_allow_ips = "127.0.0.1"
allow_loopback_redirects = false
operator_name = "Example Hosting"
product_name = "Example Mail"
support_url = "https://www.example.com/support"
support_email = "support@example.com"

[[mail_servers]]
host = "mail.example.com"
match_mx = true

[[mail_servers]]
host = "mail.client.example"
domains = ["client.example"]
```

TOML puts every key after a `[[mail_servers]]` line into that table, so keep the top-level keys above the first one.

### Attachments, forwards and quoting

`mail_draft` and `mail_send` take `attachments`, a list of flat objects. Each is either a new file, `{filename, content_type, base64}`, or a reference to a part of a message already in a connected mailbox, `{source_folder, source_uid, source_part}` with `source_mailbox` when that is another mailbox of the same connection; exactly one of `base64` or `source_uid` is given. A reference without `source_part` attaches the whole message as an `.eml` file. `source_part` is a `part_id` from `mail_read`'s `attachments` (IMAP section numbers: `2`, `1.2`). Either kind takes `disposition` (`attachment`, the default, or `inline`) and, with `inline`, a `content_id` that an `<img src="cid:...">` in `html` can name. The connector keeps nothing: there are no upload handles, and a referenced part is read from the mail server during the call. Filenames lose any directory part, may not hold CR, LF or NUL, and are written with RFC 2231 encoding when they are not ASCII; at most 100 attachments go in one message.

- **The message tree** is `multipart/mixed( multipart/alternative( text/plain, multipart/related( text/html, images ) ), files )`, each layer only when it has more than one part. Every `multipart/related` carries `type="text/html"` (RFC 2387). A `message/rfc822` file is attached as a message, never base64.
- **Replies** quote the original below the text (`> ` lines) and, when the reply has `html`, below the HTML as a `<blockquote type="cite">` of the original's safe HTML: only plain formatting tags survive, links keep only http, https and mailto targets, and scripts, styles, images, hidden elements and every other attribute are removed. `quote="none"` quotes nothing. `References` falls back to the original's `In-Reply-To` when it has no `References` (RFC 5322 s3.6.4).
- **Forwards** take `forward_mode`: `attachment` (default) puts a plain-text note above the original as `forwarded.eml`; `inline` puts the original's header block and text (and safe HTML below an `html` note) under the note and carries the original's attachments as files. `mail_draft` takes `forward_folder` and `forward_uid` too.
- **Size limits are the mail server's.** Before sending, the connector compares the message's size with the `SIZE` the SMTP server announces in EHLO and refuses before signing in to SMTP or sending MAIL FROM, naming the limit; `SIZE` without a number, or 0, means no limit. Before saving a draft it compares with the IMAP `APPENDLIMIT` (RFC 7889, for the server or for that folder) when the server lists it; when the Sent copy of a sent message would be over that limit, the message is still sent and the result says no copy was saved. A server that announces neither has no limit set by the connector.
- **Request size.** Attachments travel inside the tool call as base64, so the request is about 4/3 of the files. The deploy kit's nginx allows 32 MB of request (`client_max_body_size` in `deploy/nginx-site.conf`), about 23 MB of files per message; raise it together with the service's memory limit, since a call holds several copies of its message while it builds and sends it.
- **Results** list each file of the built message (`attachments`: filename, content type, size) with `content_notice`, since names taken from stored mail were written by other people. `mail_draft` also returns the stored `size`.
- **Reading parts.** `mail_read` lists every leaf with `part_id`, and `disposition` and `content_id` when the part has them, so inline cid: images are listed with attachments. `mail_attachment` takes exactly one of `index`, `part` (a `part_id`) or `content_id`. `part="raw"` and `tnef:N` are not available yet.

## Security notes

- **Loopback redirects.** `allow_loopback_redirects = true` lets desktop and CLI clients on the user's own machine connect. It is right for local development and for deployments that must serve Claude Code. It is wrong to leave on when only claude.ai and ChatGPT are needed, because it widens who may register as a client. Setting `false` is safe but breaks those local clients.
- **The database holds credentials.** `db_path` is created with mode 0600 (and its WAL files too) and contains each user's mailbox password, sealed with AES-256-GCM under a key that exists only inside that grant's live tokens. A copy of the file alone does not reveal passwords, but treat it as sensitive: keep it out of Git, backups shared with others and logs. `*.sqlite*` and `local.toml` are git-ignored.
- **Backups.** Stop the service and copy the file together with any `-wal` and `-shm` siblings, or take an online backup with `sqlite3 /path/mcp-server-imap-smtp.sqlite ".backup '/path/backup.sqlite'"`. Do not plain-copy a running database. Keep backups at 0600.
- **Revoking.** `mcp-server-imap-smtp-admin grants revoke` takes effect immediately for new tool calls. A password change on the mail server also revokes the grant on the next failed call.
- **Logs.** The access log records request paths without their query strings (so `/mail/login?req=…` is logged as `/mail/login`); passwords and tokens are never logged by the gateway.
- **Housekeeping.** At startup and then hourly the gateway deletes expired sign-in requests, codes and tokens, grants revoked more than 30 days ago (with their sealed passwords; grants revoked before the gateway recorded revocation times age from creation), abandoned grants (not revoked, created more than `refresh_ttl` ago, with no token or code left, so nothing can unlock them) with their sealed passwords, and dynamically registered clients older than 24 hours that never completed a sign-in (clients identified by an https metadata document, CIMD, are not purged by this rule).

## Tests

```bash
.venv/bin/pytest                    # unit suite, no network
.venv/bin/pytest -m integration     # real mailboxes on a real IMAP/SMTP server; needs credentials (below)
```

## Live testing

These steps need real test mailboxes on a mail server you operate and, for the last part, a public HTTPS URL.

### Integration tests

1. Create a test mailbox, for example `mcp-test@example.com`, and a second one for the shared-mailbox case, for example `mcp-shared@example.com`. Use mailboxes that hold nothing you need. Never put their passwords in the repository.
2. Give the tests the credentials, either as environment variables or in a `KEY=value` file named by `MCP_TEST_ENV_FILE`. Keep such a file outside the repository and readable only by you:

   ```bash
   install -m 600 /dev/null ~/.config/mcp-imap-smtp-test.env
   # then edit it to contain these keys (the last two are optional):
   MCP_TEST_IMAP_HOST=mail.example.com
   MCP_TEST_ADDRESS=mcp-test@example.com
   MCP_TEST_PASSWORD=...
   MCP_TEST_SHARED_ADDRESS=mcp-shared@example.com
   MCP_TEST_SHARED_PASSWORD=...
   ```

While testing sign-in by hand, wrong passwords and refused domains count against `login_failures` (5 per 15 minutes per client address); raise it in `local.toml` for a test session rather than waiting out a lockout.

3. Run `MCP_TEST_ENV_FILE=~/.config/mcp-imap-smtp-test.env .venv/bin/pytest -m integration`. Without `MCP_TEST_IMAP_HOST`, `MCP_TEST_ADDRESS` and `MCP_TEST_PASSWORD` the tests skip, and the shared-mailbox tests skip without the shared pair. They only use the folder `mcp-imap-smtp-tests`, tag subjects `mcp-imap-smtp-test <ns>`, send only to the test address itself, never touch untagged messages and never expunge; tagged leftovers end up in `mcp-imap-smtp-tests` or Trash.

### Manual checklist (local server, Claude Code)

Run the server locally, connect Claude Code as above and sign in with the test mailbox. Then:

1. List folders. Note the server's INBOX prefix and hierarchy separator.
2. Search, then read an HTML mail.
3. Flag a message, then move one to Trash.
4. Save a draft.
5. Send a mail to the test address itself and confirm it appears in Sent.
6. Open `http://127.0.0.1:8765/mail/manage`, sign in with the test mailbox and add the shared mailbox as one line (address, a space, password). Then, without reconnecting, search the shared mailbox (pass it as `mailbox`).
7. Change the mailbox password on the mail server and confirm the next call asks you to reconnect (the grant is revoked on the failed login).

### claude.ai and ChatGPT web

Both need a public HTTPS URL: either a production deployment ([DEPLOY.md](DEPLOY.md)) or a temporary tunnel to the local server, for example a Cloudflare Tunnel (`cloudflared`) on `mcp-dev.example.com`. With a tunnel, set `issuer_url` and `mail_resource_url` to the tunnel host and `trusted_proxy = true` (`forwarded_allow_ips` to the address `cloudflared` connects from, normally `127.0.0.1`), and add the tunnel host to `extra_allowed_hosts` if the proxy forwards a different `Host`.

Then:

- claude.ai: Settings, Connectors, Add custom connector, paste `https://<host>/mail`.
- ChatGPT: enable developer mode, then create a custom MCP connector and paste the URL. Which ChatGPT plans allow write tools changes over time; check OpenAI's current documentation.

## Paths

- **At the site root:** the OAuth authorisation server's endpoints `/authorize`, `/token`, `/register`, `/revoke`, and the metadata `/.well-known/oauth-authorization-server` and `/.well-known/oauth-protected-resource/<path>`. AI apps discover these from the metadata.
- **Under `mail_resource_url`'s path (`/mail` in the examples):** the MCP endpoint itself, the sign-in page `/mail/login` and the manage page `/mail/manage`. `/login` and `/manage` at the root redirect there (308), so links in a user guide may use either.

Mounting the connector under a path leaves the rest of the host free for other services. Set `mail_resource_url` to the site root to give it the whole host.

## Mail servers with a private certificate authority

The connector verifies every mail server's TLS certificate against the system's trusted CAs and the configured `host` name. For a server whose certificate comes from your own CA, add the CA to the system store (Debian: copy the PEM file to `/usr/local/share/ca-certificates/<name>.crt`, run `update-ca-certificates`, then restart the service). A certificate the connector does not trust makes sign-in say the mail server could not be reached; the log says why ("could not reach mail.example.com: unable to get local issuer certificate").
