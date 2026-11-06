# mcp-server-imap-smtp

A remote MCP server that lets AI apps work with email in IMAP and SMTP mailboxes. Once a user connects it, their AI app can search, read, summarise, flag, file, draft and send mail, and open attachments.

It is built for anyone who runs mail servers for other people, such as a hosting company, an IT provider or a business with its own mail server, and for individuals who run their own. You run one copy on a public HTTPS address and bind it to your own mail servers. Each user adds that address to their AI app and signs in with their own mailbox address and password.

It speaks IMAP and SMTP only.

## Bind it to your own mail servers

The connector signs in only to the mail servers listed in its configuration, under `[[mail_servers]]`. An address that matches none of them is refused before any password is sent anywhere, so it can never be used to reach someone else's mail server.

```toml
[[mail_servers]]
host = "mail.example.com"        # IMAPS 993 and SMTPS 465 unless imap_port / smtp_port say otherwise
match_mx = true                  # serve every domain whose MX record points at this host
max_sessions = 8                 # IMAP and SMTP sessions open on this server at once, for all users together

[[mail_servers]]
host = "mail.client.example"
domains = ["client.example", "*.client.example"]   # exact domains, or "*.suffix" for every subdomain
match_mx = false
max_sessions = 16
```

- **Explicit domains first.** `domains` lists the domains a server hosts. `"*.client.example"` matches every subdomain of client.example, not client.example itself. A lone `"*"` would send every otherwise unmatched address to that server, including addresses you do not host; keep it out of any public deployment.
- **Then MX matching.** With `match_mx = true`, a domain is served by this host when its MX record names the host, a name under it, or one of its addresses. DNS only decides whether an address is served. The TLS certificate is always checked against the `host` you configured, so a DNS answer cannot send passwords to another machine.
- **The server is sealed in with the password.** When a mailbox connects, its server is sealed together with its password, so a later DNS change or a database edit cannot redirect it.
- **Per-server caps.** `max_sessions` limits how many sessions the connector holds open on that server for all users together. Further requests wait their turn fairly, connection by connection. Mail servers see every user arriving from the connector's one address, so set this below the point where the server starts slowing down. Keep `max_sessions_per_mailbox` below Dovecot's `mail_max_userip_connections`.
- **No servers, no service.** Every other server is refused. A configuration with no mail servers does not start.

The full reference is in [docs/RUNNING.md](docs/RUNNING.md), "Mail servers".

## How it works

1. **The AI app connects.** It adds the connector's URL (for example `https://mcp.example.com/mail`) and signs in with OAuth 2.1, using dynamic client registration or a client ID metadata document, and PKCE.
2. **The user signs in on the connector's own page,** with their mailbox address and password. To connect several mailboxes, such as a company's staff mailboxes, they paste one "address password" line per mailbox.
3. **Each password is checked first.** The connector finds the configured server for each address and checks each password by logging in over IMAP.
4. **The password is sealed.** It is stored encrypted under a key that exists only inside that connection's tokens. The server cannot open stored passwords by itself, and the AI app never sees them.
5. **Every tool call works as the mailbox owner.** It unseals the password and logs in to the mailbox as that user, so the connector can do nothing the user could not do in their own mail app.

Users can add or remove mailboxes, or enter a changed password, later on the connector's manage page (`<mail URL>/manage`), without reconnecting their AI app.

**Tools:** `mail_accounts`, `mail_folders`, `mail_search` (one mailbox or all of them), `mail_read`, `mail_thread`, `mail_attachment` (text and PDF), `mail_flag`, `mail_move` (never deletes permanently), `mail_draft` (returns the saved draft's UID and Message-ID) and `mail_send` (returns the Message-ID). Sending can be turned off or limited to drafts (`send_mode`). Images in an HTML body (an `<img>` whose source is an https URL or a `data:` URI) are fetched or decoded and sent inside the message as inline `cid:` parts, so mail clients show them without loading remote content; any other image source is refused.

**AI apps:** any MCP client that supports remote servers with OAuth. The user guide template for your customers, [docs/CONNECT.template.md](docs/CONNECT.template.md), has set-up steps for Claude (web, desktop, mobile and Claude Code), ChatGPT, Grok and Codex. Cursor connects too.

## Quick start

- **Run it locally,** configure it and use the admin CLI: [docs/RUNNING.md](docs/RUNNING.md).
- **Deploy it** to a Debian 12 or 13 server behind nginx with Let's Encrypt, a sandboxed systemd unit, a firewall that only lets it reach your mail servers, and nightly backups: [docs/DEPLOY.md](docs/DEPLOY.md).
- **Check it end to end:** `deploy/smoke.sh` tests a running instance without signing in; `deploy/e2e.py` signs in with a test mailbox the way an AI app does, uses the tools (with `--write` and `--send`, drafts and a message to itself) and removes everything it made: [docs/DEPLOY.md](docs/DEPLOY.md), "Check the whole path".

```
uv venv && uv pip install -e ".[dev]"
cp config.example.toml local.toml      # then list your own mail servers
.venv/bin/mcp-server-imap-smtp --config local.toml
.venv/bin/pytest
```

## Security

How credentials are handled, what the connector logs, and how to report a vulnerability: [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Support this project

mcp-server-imap-smtp is free software from Noiz. If it is useful to you, the main way to support its development is a donation in Monero (XMR):

```text
44BtMn9izxH8mK2yFbSdY6Di7TNobkLbnHdZ6gZQjukCME5vsNhtPRtH4TcVkDHKHLhSpAJbsjv8gCdYuSZVMpXgMkUC1hV
```

You can also help by reporting bugs, sending fixes or starring the repository.

## Licence

Copyright the mcp-server-imap-smtp contributors.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. See [LICENSE](LICENSE).

The AGPL applies to network use. If you run a modified version for users over a network, you must offer those users the source code of your version.
