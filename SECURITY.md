# Security

## Reporting a vulnerability

Please report security problems privately, through the repository's private vulnerability reporting ("Report a vulnerability" on the Security tab). Do not open a public issue. Include the version or commit, what you found and how to reproduce it.

## How credentials are handled

- **Sealing.** Mailbox passwords are checked on the mail server over IMAP before they are stored. They are then sealed with AES-256-GCM under a random per-connection key, and bound to the connection id and mailbox address.
- **Where the key lives.** The connection key is held only inside that connection's OAuth tokens, wrapped by the token secrets. The database stores token hashes, not tokens, so neither the database nor a database backup alone can open a password.
- **Manage page additions.** Mailboxes added on the manage page are sealed to the connection's X25519 public key, because the page has no token. They are re-sealed under the connection key the next time the AI app uses the connection. A public key that does not match its private key stops the connection.
- **Server binding.** A password is only ever sent to a server listed in `[[mail_servers]]`, over TLS verified against the configured host name. The server is sealed together with the password, so a DNS change or a database edit cannot redirect it.
- **No admin access to mail.** The connector never shows a password back. The admin CLI cannot unseal anything; it can list, revoke and add, never read.

## What is logged

One audit line per tool call: time, connection id, mailbox, mail server, tool, folder, result count and outcome. Never message content, recipients, subjects, tokens or passwords. The nginx configuration in `deploy/` leaves query strings out of the access log.

## Abuse limits

- **Sign-in limits.** Wrong passwords are limited per client address (IPv6 per /64), per mailbox, per sign-in page and per mail server, with a daily ceiling per mailbox. The anonymous OAuth endpoints are rate-limited too.
- **Server load.** Sessions per mail server and per mailbox are capped.
- **Sending.** The `send_mode` setting can limit sending to drafts or turn it off, and per-connection send caps are available. Each mail server's own outgoing limits still apply.

## Deployment hardening (deploy/)

- **Sandboxing.** A dedicated service user and a sandboxed systemd unit.
- **Network.** Listens on loopback behind nginx with TLS. A firewall allows outbound IMAP and SMTP only to the configured mail servers.
- **Maintenance.** Unattended security upgrades, and nightly integrity-checked database backups.
