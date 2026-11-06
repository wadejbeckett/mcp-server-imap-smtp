# Changelog

All notable changes to this project are written down here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

Nothing has been tagged or published yet. `pyproject.toml` says 0.1.0; every change since the repository was made public on 22 October 2026 is listed here, reconstructed from the git history.

### Added

- The connector: a remote MCP server with its own OAuth 2.1 sign-in (dynamic client registration, client ID metadata documents, PKCE S256), bound to the mail servers in its configuration, with the tools `mail_accounts`, `mail_folders`, `mail_search`, `mail_read`, `mail_thread`, `mail_attachment`, `mail_flag`, `mail_move`, `mail_draft` and `mail_send`, a manage page and an admin CLI.
- Deploy kit for Debian 12 and 13: `build.sh`, `install.sh` (nginx, Let's Encrypt, a sandboxed systemd unit, a restricted outbound firewall, unattended upgrades, nightly backups) and `smoke.sh`.
- `install.sh` serves an operator-supplied certificate with `TLS_CERT` and `TLS_KEY`, for a gateway Let's Encrypt cannot reach; renewing it is the operator's job.
- `deploy/e2e.py`: an end-to-end check of a running instance with a real mailbox, the way an AI app uses it.
- STARTTLS for IMAP (143) and SMTP submission (587), per server, verified before any password is sent.
- Outgoing attachments, forwarding (`forward_mode`) and quoting in `mail_send` and `mail_draft`, with size checks.
- Images in an HTML body are sent inside the message as inline `cid:` parts.
- Token revocation for public clients (RFC 7009).
- A server-held sealing secret mixed into the key that protects each connection's stored passwords.
- Limits on tool calls per connection, and bounds on searches across all folders.
- A container test lab (Dovecot 2.4 with Pigeonhole, and Postfix) for `pytest -m lab`, and a lab test that runs `e2e.py` against the real connector.
- `scripts/install-test.sh`: installs from the docs on a throwaway Debian 13 VM in front of a lab mail server, as a fresh install or as an upgrade.
- Package metadata for an index page: project URLs, classifiers and this changelog.

### Changed

- Mail content returned to the AI app is marked as untrusted, hidden HTML text is dropped and link targets are listed apart from the text.
- The sign-in page caps and labels the app's name, names the site it returns to, expires after 5 minutes and refuses posts from other sites.
- The service stops within seconds of SIGTERM: calls in flight get 3 seconds, then kept IMAP sessions are logged out.
- The service unit is tightened (no privileged or resource system calls, its own port only, memory and task caps), and services restart after security updates.
- The deploy kit's firewall rules and TLS checks follow each mail server's own ports and security mode.
- The docs cover a clean install from `git clone`, a private CA for the mail servers, and what to do without Let's Encrypt.

### Fixed

- Many defects found in reviews and in the lab: MIME structure and encodings of composed mail, IDNA 2008 addresses, servers without NAMESPACE, malformed or unclosed hidden HTML, quotes cut from what the AI was shown, and send slots given back when a message is refused before MAIL FROM.
- `install.sh` reads `/etc/os-release` without overwriting the install name.
- `build.sh` quotes the bundle path in the commands it prints.

### Security

- SDK tool-error text is kept out of the journal, and journal retention is set by the deploy kit.
- OAuth hardening from a security review: allowlist-filtered clients, exact callback matching, RFC 9207 `iss`, a bounded rate limiter and an absolute grant lifetime.
