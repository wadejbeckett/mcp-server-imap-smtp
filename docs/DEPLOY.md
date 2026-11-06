# Deploying mcp-server-imap-smtp to production

How to put the gateway on its own Debian server at, for example, `https://mcp.example.com/mail`, keep it updated, back it up and remove it. Run it on a dedicated server rather than on a mail server: every user's IMAP and SMTP sign-ins then come from one known address, and the gateway's firewall and sandbox are not shared with anything else. The connector lives under a path (`/mail`), so the rest of the host stays free. Install one copy per server: the nginx site claims the default server and fixed upstream and log names. Local development and the configuration reference are in [RUNNING.md](RUNNING.md).

The kit lives in `deploy/`:

| File | Purpose |
|---|---|
| `build.sh` | Run on the workstation. Builds the wheel and a hash-pinned `requirements.lock`, bundles the files below into `deploy/dist/mcp-server-imap-smtp-<release>.tar.gz` (git-ignored), test-installs it in a throwaway venv and prints the ship commands. |
| `install.sh` | Run as root on the server from the unpacked bundle. Installs or updates everything; safe to re-run. |
| `service.unit` | systemd unit template, sandboxed (exposure score 1.5 in `systemd-analyze security`). Rendered as `$NAME.service`. |
| `nginx-site.conf` | nginx site template: HTTP to HTTPS redirect, ACME webroot, TLS, streaming proxy to `127.0.0.1:8765`. Rendered as `$NAME.conf`. |
| `config.prod.toml.template` | Becomes `/etc/$NAME/config.toml` on the first install only. |
| `backup.sh`, `backup.service.unit`, `backup.timer.unit` | Nightly online SQLite backup. Installed as `$NAME-backup`, `$NAME-backup.service` and `$NAME-backup.timer`. |
| `smoke.sh` | Credential-free checks against a deployed URL. |

### The install name

`install.sh` takes an optional `NAME` (default `mcp-server-imap-smtp`; lowercase letters, digits and hyphens, at most 32 characters). It names the service user and group, the directories `/opt/$NAME`, `/etc/$NAME`, `/var/lib/$NAME` and `/var/backups/$NAME`, the units `$NAME.service`, `$NAME-backup.service` and `$NAME-backup.timer`, the commands `/usr/local/sbin/$NAME-admin`, `$NAME-backup` and `$NAME-smoke`, the nginx site `$NAME.conf` and its logs `/var/log/nginx/$NAME.access.log` and `$NAME.error.log`. Keep the same `NAME` on every update of one server. The examples below use the default name.

## 1. What the server needs

- Debian 13 (trixie) or Debian 12 (bookworm), nothing else installed. 1 vCPU, 2 GB RAM, 20 GB disk is plenty.
- A public IPv4 address (IPv6 too if available) and root SSH access with a key.
- Inbound TCP 22 (or your SSH port), 80 and 443 open in the provider's firewall or security group. Outbound must reach every configured mail server (`[[mail_servers]]` in the config, or the legacy `mail_host`) on its IMAP and SMTP ports, normally 993 and 465. It must also reach DNS on 53 for MX lookups, PyPI on 443 (installs only), Let's Encrypt on 443, the internet on 443 for client metadata documents (chatgpt.com, claude.ai), and the internet on 443 for images in HTML mail, which are fetched to embed them (public addresses only). Default egress rules allow all of this.

`install.sh` uses Debian archive packages only: `python3`, `python3-venv`, `nginx`, `certbot`, `ufw`, `unattended-upgrades`, `poppler-utils`, `sqlite3`, `rsync`, `curl`, `openssl`, `ca-certificates`, `iproute2`. Python libraries come from PyPI into a virtualenv, pinned with hashes.

## 2. DNS

In your DNS zone (here `example.com`) add:

| Type | Name | Content |
|---|---|---|
| A | `mcp` | server's public IPv4 |
| AAAA | `mcp` | server's public IPv6 (if it has one) |

If the zone is on Cloudflare, set these records to **DNS only** (grey cloud), not proxied: the Cloudflare proxy would terminate TLS itself, cut long MCP responses at its timeout and hide each user's IP behind Cloudflare's (the sign-in rate limits key on the client IP). The same applies to any other CDN or proxy in front of the name. Let's Encrypt also needs the name to reach the server on port 80.

Do this before installing and check it from the workstation: `dig +short mcp.example.com A` (and `AAAA`) must return the server's addresses.

## 3. Build (workstation)

```bash
cd mcp-server-imap-smtp        # root of the repository
deploy/build.sh
```

It needs `uv`, `python3`, `git`, PyPI access and the project's `.venv` (see [RUNNING.md](RUNNING.md)). The release id is `<version>-<UTC time>-<git sha>`, with `-dirty` added when `src/`, `pyproject.toml` or `deploy/` has uncommitted or untracked changes. Commit the code and the kit first, so a production bundle can be rebuilt from the git id in its `BUILD_INFO`; do not ship a `-dirty` release. The lock is compiled from the runtime dependencies in `pyproject.toml` alone. It pins every dependency to the version in the project's `.venv`, the one the unit tests ran against, and carries hashes for every platform so it installs on Debian 12 (Python 3.11) and 13 (Python 3.13). The build ends by installing the bundle the way the server will (hashes required, wheels only, `pip check`), importing the app and running both commands' `--help`. Set `VERIFY_PYTHON=3.11` to run that check on Python 3.11 when `uv` has it.

**Which bundle to ship.** `deploy/dist/` keeps every bundle ever built, including `-dirty` ones from uncommitted trees, so do not pick one by eye. Ship the file `build.sh` printed on its last run, and check that its name ends in the commit being released and has no `-dirty`: it must end in `-$(git rev-parse --short=12 HEAD).tar.gz`, and `tar -xzOf <bundle> --wildcards '*/BUILD_INFO'` must show that same `git=` id. Old bundles may be deleted from `deploy/dist/` at any time; it is git-ignored.

## 4. Ship and install (first time)

`build.sh` prints these with the real file name filled in:

```bash
VPS=root@<server address>
scp deploy/dist/mcp-server-imap-smtp-<release>.tar.gz $VPS:/root/
ssh $VPS 'tar -xzf /root/mcp-server-imap-smtp-<release>.tar.gz -C /root && \
    systemd-run --quiet --unit mcp-server-imap-smtp-install --collect --wait \
      -p StandardOutput=truncate:/root/mcp-server-imap-smtp-install.log -p StandardError=inherit \
      --setenv MCP_HOSTNAME=mcp.example.com --setenv NAME=mcp-server-imap-smtp \
      --setenv ADMIN_EMAIL=you@example.com --setenv LE_AGREE_TOS=yes \
      --setenv "SSH_CONNECTION=$SSH_CONNECTION" /root/mcp-server-imap-smtp-<release>/install.sh; \
    rc=$?; cat /root/mcp-server-imap-smtp-install.log; exit $rc'
```

`install.sh` runs as a transient systemd unit rather than as a child of the SSH session, so a dropped connection cannot kill it half-way (for example during certbot or between the release switch and the restart). The command waits, prints the log and returns the script's exit status. If the connection drops, the install carries on; check it with `ssh $VPS 'systemctl status mcp-server-imap-smtp-install; tail -n 40 /root/mcp-server-imap-smtp-install.log'`. A second install cannot start while one is running (the unit name is taken). Running `install.sh` directly in `tmux` or `screen` works too.

- `MCP_HOSTNAME` (required, no default): the public host name. The variable is `MCP_HOSTNAME`, not `HOSTNAME`: bash always sets `HOSTNAME` to the machine name.
- `NAME` (optional): the install name described above.
- `ADMIN_EMAIL`: the Let's Encrypt account address (expiry warnings go there). Needed only while no certificate exists.
- `LE_AGREE_TOS=yes`: you accept the [Let's Encrypt Subscriber Agreement](https://letsencrypt.org/repository/) for that account. The script refuses to request a certificate without it.
- Optional: `LE_STAGING=1` gets an untrusted test certificate first (useful if DNS is still settling, since the live CA rate-limits failures); delete it with `certbot delete --cert-name mcp.example.com` and re-run without it. `SSH_PORT=<n>` adds an extra SSH port to the firewall; the ports `sshd` listens on and the port of your current session are always allowed, so the firewall cannot lock you out. `EGRESS=open` allows all outbound traffic (step 5 below). `SSH_HARDEN=0` skips the SSH drop-in. `KEEP_RELEASES` sets how many releases are kept (default 3, minimum 2). `ALLOW_UNSUPPORTED_OS=1` tries an OS other than Debian 12 or 13.

What `install.sh` does, in order:

1. Checks the OS, the bundle's SHA256SUMS and, while no certificate exists, that `ADMIN_EMAIL` and `LE_AGREE_TOS=yes` are set (before anything on the host changes).
2. Installs the packages and creates the `$NAME` system user (no login, no home).
3. Builds `/opt/$NAME/releases/<release>/venv` (root-owned, read-only to the service). An already-installed release is reused only if its virtualenv still imports the app; otherwise it is rebuilt.
4. Writes `/etc/$NAME/config.toml` from the template if it does not exist, then loads it with the new release's own `load_settings` and checks it: `issuer_url` and `mail_resource_url` are https and on `MCP_HOSTNAME`, loopback listener, database under `/var/lib/$NAME`; it warns if the trusted proxy is not set.
5. Enables ufw: SSH, 80 and 443 in; out only IMAP/SMTP to the configured mail servers' current addresses, DNS, NTP, DHCP, HTTP and HTTPS (`EGRESS=open` allows all outbound; re-run `install.sh` after a mail server's address changes, and remove rules for an old address with `ufw status numbered` and `ufw delete <n>`). Writes `/etc/ssh/sshd_config.d/10-$NAME.conf` (keys only, no forwarding; `SSH_HARDEN=0` skips it, and it is skipped when root has no `authorized_keys`). Enables unattended security upgrades (an existing `20auto-upgrades` it did not write is kept as `20auto-upgrades.$NAME.bak`).
6. Installs a bootstrap nginx site, gets the certificate with `certbot certonly --webroot` (renewed by Debian's `certbot.timer`, which reloads nginx) and installs the full site. Debian's `default` site is unlinked only once ours passes `nginx -t`; if ours fails, everything is put back.
7. Only now installs the units and the `$NAME-admin`, `$NAME-backup` and `$NAME-smoke` commands, points `/opt/$NAME/venv` at the new release and restarts the gateway. If it does not answer within 30 seconds, the link goes back to the previous release, which is restarted, and the script fails. Old releases are pruned only after the new one answers.
8. Prints a summary, including the server's global addresses and a TLS handshake (no sign-in) from the server to each configured mail server on its IMAP and SMTP ports, and fails if the gateway does not answer through nginx or the unauthenticated request does not get 401.

A failure in steps 1 to 6 leaves the running release and `/opt/$NAME/venv` untouched.

certbot runs in webroot mode rather than `certbot --nginx`, so certbot never edits the nginx site and `install.sh` can rewrite it on every run.

Before anyone signs in, edit `/etc/$NAME/config.toml`: set `operator_name`, `product_name`, `support_url` and `support_email`, and replace the example `[[mail_servers]]` tables with your own mail servers (see [RUNNING.md](RUNNING.md), "Mail servers"). Then re-run `install.sh`, so the firewall opens outbound IMAP and SMTP to the new servers, or restart the service if `EGRESS=open`.

The production configuration (`config.prod.toml.template`) sets `trusted_proxy = true` with `forwarded_allow_ips = "127.0.0.1"`; nginx overwrites `X-Forwarded-For` with the connecting address, so the rate limits see each user's real IP and a client cannot inject a fake one. It keeps `allow_loopback_redirects = true` so Claude Code, MCP Inspector and managed Claude Desktop deployments can connect (their sign-in callback is a `http://127.0.0.1` address on the user's own machine; PKCE still applies and a remote party cannot receive the code). Set it to `false` and restart if only claude.ai and ChatGPT should ever connect. (RUNNING.md's example uses `false`; the production template keeps `true` on purpose.)

**Rate limits.** The anonymous OAuth endpoints are limited per client IP per 15 minutes (`login_window`); beyond the limit the client gets HTTP 429 with `Retry-After: 900`. claude.ai and ChatGPT call `/register` and `/token` from their own shared backend addresses, so all your users of one platform share each budget, and every connected user's hourly token refresh counts against `/token`. The code defaults (30 registrations, 120 token calls) would block an office of more than 30 Claude users onboarding within 15 minutes, so the production template sets `register_limit = 300`, `token_limit = 1200` and `authorize_limit = 120` (`/authorize` comes from each user's browser, about two requests per sign-in, so an office behind one NAT address shares it). `login_failures = 5` wrong passwords per IP and per mailbox is left at the default. Before onboarding a larger group, raise these in `/etc/$NAME/config.toml` and restart; the journal shows 429 responses.

## 5. Verify

From the workstation:

```bash
deploy/smoke.sh https://mcp.example.com
```

It checks: certificate valid and more than 14 days from expiry; `http://` redirects to `https://`; `/.well-known/oauth-protected-resource/mail` returns 200 with `resource` equal to `https://mcp.example.com/mail`, the base URL in `authorization_servers` and `offline_access` in `scopes_supported`; `/.well-known/oauth-authorization-server` returns 200 with S256 PKCE, a registration endpoint, `client_id_metadata_document_supported` and `offline_access` in `scopes_supported`; an unauthenticated `POST /mail` gets 401 with `WWW-Authenticate: ... resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mail"`; `GET /mail/login` without a request id gets 400 with `X-Frame-Options`, CSP, `Cache-Control: no-store`, `Referrer-Policy` and HSTS; nginx hides its version. Any failure exits 1. Set `MAIL_PATH` if the service is mounted somewhere other than `/mail`.

Before DNS points at the server: `SMOKE_RESOLVE=mcp.example.com:443:<server address> deploy/smoke.sh https://mcp.example.com`. The script is also on the server as `mcp-server-imap-smtp-smoke`.

## 6. Trust the gateway on each mail server, then check mail from the gateway (go-live gate)

Every user's IMAP and SMTP sign-in reaches the mail servers from the gateway's one address, so anything on a mail server that blocks that address cuts off every user on that server at once. Two kinds of protection commonly do it:

- **Login-failure blocking** (fail2ban, a control panel's IP banning, or a similar tool) counts failed logins per source IP. A few users mistyping passwords (or one attacker) would ban the gateway. The gateway has its own per-IP, per-mailbox and per-server sign-in limits (see `login_failures` and `host_login_failures` in [RUNNING.md](RUNNING.md)), so the mail server does not need to police this address.
- **IP reputation blocking** (for example Imunify360's cloud lists, or a firewall fed by public block lists) can silently drop every non-web port, 993 and 465 included, for any address on those lists, while the login-failure tool shows nothing. Datacenter and VPS addresses often land on such lists.

On each mail server, with the gateway's public IPv4 and, if it has one, its IPv6 address (`install.sh` prints them as "Global addresses"; behind a floating IP or NAT, use the public address the mail server sees):

1. **Check the addresses first:** see whether either is already banned or blocked, and note anything found in your change record.
2. **Exempt the addresses from login-failure blocking.** On Plesk this is **Tools & Settings → IP Address Banning (Fail2Ban) → Trusted IP Addresses** (or `plesk bin ip_ban --add-trusted`); with plain fail2ban, add them to `ignoreip`; other control panels have an equivalent trusted or allow list.
3. **Exempt the addresses from reputation blocking**, permanently (no expiry). On a server with Imunify360 this is its white list (`imunify360-agent ip-list local add --purpose white <ip> --comment '<gateway name>'`; confirm the options with `--help` for your version). An allow-list entry there overrides its grey and black lists.
4. If either system already blocked the gateway, unban or remove the address there.
5. **Record both entries** in the mail server's change records (what, why, how to verify, how to reverse: section 12).
6. **Go-live check, from the gateway** (not the workstation, whose address is different), for each mail server:

   ```bash
   for port in 993 465; do
     timeout 15 openssl s_client -connect mail.example.com:$port -servername mail.example.com \
       -verify_hostname mail.example.com -verify_return_error -brief </dev/null && echo "port $port ok"
   done
   ```

   Both must print the TLS session details and `port ... ok`. A hang or timeout means the mail server (or a firewall in front of it) is dropping the gateway; a certificate error means something else answered, or the `host` in the configuration is not the name on the mail server's certificate. The `install.sh` summary runs the same handshake for every configured server ("Mail servers TLS"). Then sign in once with a real test mailbox from Claude Code (section 7) before onboarding any users.

Recheck these entries if the gateway's address ever changes.

### 6a. Mail servers behind a firewall

Some mail servers, for example a customer's own server, sit behind a firewall that only lets known addresses reach IMAP and SMTP. The connector signs in from the gateway, so its public IPv4 address and, if it has one, its IPv6 address must be on that firewall's allowlist for the server's IMAP and SMTP ports, normally 993 and 465. Until they are, sign-in for that server's addresses fails with "The mail server could not be reached."

1. Add both addresses to the firewall for those ports. Where someone else owns the server, get their agreement first.
2. Run the go-live check from section 6, step 6, on the gateway, with that server's host.
3. Record the entry: which firewall, which rule, the addresses, the date, and how to remove it. Recheck it if the gateway's address ever changes.

## 7. Connect a client

Write a user guide for your users from [CONNECT.template.md](CONNECT.template.md). The URL is always `https://mcp.example.com/mail`; the AI app opens the sign-in page, where the user enters the mailbox address and password, and optionally more mailboxes with their own passwords on the same form (as many as `max_mailboxes` allows; no limit by default). For a quick operator test from the workstation: `claude mcp add --transport http example-mail https://mcp.example.com/mail`, then `/mcp` in Claude Code to sign in.

## 8. Updates

```bash
deploy/build.sh                     # workstation, from a clean commit
scp deploy/dist/mcp-server-imap-smtp-<release>.tar.gz $VPS:/root/
ssh $VPS 'tar -xzf /root/mcp-server-imap-smtp-<release>.tar.gz -C /root && \
    systemd-run --quiet --unit mcp-server-imap-smtp-install --collect --wait \
      -p StandardOutput=truncate:/root/mcp-server-imap-smtp-install.log -p StandardError=inherit \
      --setenv MCP_HOSTNAME=mcp.example.com --setenv NAME=mcp-server-imap-smtp \
      --setenv "SSH_CONNECTION=$SSH_CONNECTION" /root/mcp-server-imap-smtp-<release>/install.sh; \
    rc=$?; cat /root/mcp-server-imap-smtp-install.log; exit $rc'
deploy/smoke.sh https://mcp.example.com
```

No email or agreement is needed once the certificate exists. Use the same `NAME` as the first install. The new release gets its own virtualenv and is checked against the live config; only after nginx and the certificate are done does the symlink switch and the service restart (a few seconds; connected clients keep their tokens). If the new release does not answer within 30 seconds, `install.sh` switches back to the previous one and fails. Old releases are pruned after the new one answers: the new one, the one it replaced and the newest others up to three in total are kept (`KEEP_RELEASES`). `config.toml` is never overwritten: new settings from a newer template must be added by hand.

During the restart nginx answers 502 for a few seconds; those requests are logged in `mcp-server-imap-smtp.error.log` (section 10). The old process exits within 7 seconds of the stop, normally in under a second; a tool call still running gets 3 seconds, then kept IMAP sessions are logged out ([RUNNING.md](RUNNING.md), "Stopping"), and the journal shows `Deactivated successfully`. The unit's `TimeoutStopSec=30s` is only a backstop: a line `State 'stop-sigterm' timed out. Killing` means the process ignored the stop, which is a bug worth reporting.

**Rollback** to an earlier release by hand:

```bash
ls -t /opt/mcp-server-imap-smtp/releases                     # newest first
ln -sfn releases/<older release>/venv /opt/mcp-server-imap-smtp/venv.new && mv -Tf /opt/mcp-server-imap-smtp/venv.new /opt/mcp-server-imap-smtp/venv
systemctl restart mcp-server-imap-smtp
```

**Debian upgrade (12 to 13):** the release virtualenvs are tied to the old Python and break when it is removed. After a dist-upgrade, re-run `install.sh` from the current bundle: it notices that the installed release no longer imports and rebuilds it. Older releases kept for rollback are equally broken; rebuild one by installing its bundle if you need it.

**Security updates:** unattended-upgrades installs Debian security updates daily but does not restart services. After Python, OpenSSL or nginx updates, run `systemctl restart mcp-server-imap-smtp nginx`, or reboot the server monthly.

**Configuration changes:** edit `/etc/mcp-server-imap-smtp/config.toml` (keep `root:mcp-server-imap-smtp 0640`), then `systemctl restart mcp-server-imap-smtp`. Re-running `install.sh` re-validates it, and updates the outbound firewall rules when mail servers were added or changed.

## 9. Backups

`mcp-server-imap-smtp-backup.timer` runs `/usr/local/sbin/mcp-server-imap-smtp-backup` nightly at about 02:30 (server time, with up to 30 minutes' random delay; a missed run is caught up at boot). It takes an online SQLite backup (as the service user, so the live database's files stay owned by the service), moves it to `/var/backups/mcp-server-imap-smtp/mcp-server-imap-smtp-<UTC time>.sqlite` (root, 0600), converts it to a single self-contained file, runs `PRAGMA integrity_check`, and deletes local copies (and `*.failed-check` files) older than 14 days (`RETAIN_DAYS`). A copy that fails the check is kept as `mcp-server-imap-smtp-<time>.sqlite.failed-check` and the run fails, so it shows in `systemctl --failed` and `systemctl status mcp-server-imap-smtp-backup`. Run it by hand any time: `mcp-server-imap-smtp-backup`. Check the last run with `journalctl -u mcp-server-imap-smtp-backup -n 5`.

The database holds registered clients, grants, hashed tokens and mailbox passwords sealed under keys that exist only in live tokens; a copy alone does not reveal passwords, but treat backups as sensitive.

**Off-box copies.** `backup.sh` keeps its copies on the server only, so losing the server loses them. Add an off-box copy if you need one: for example `rsync` over SSH to a backup host with a key restricted to that one command, or upload to object storage, run after the local backup (a `systemctl edit mcp-server-imap-smtp-backup` drop-in with an extra `ExecStartPost=`, or a separate timer). Keep the copies at 0600 and encrypted at rest where you can. Without any backup, a lost database only means every user signs in again; no mail data lives on the gateway.

**Restore:**

```bash
systemctl stop mcp-server-imap-smtp
install -o mcp-server-imap-smtp -g mcp-server-imap-smtp -m 0600 /var/backups/mcp-server-imap-smtp/mcp-server-imap-smtp-<time>.sqlite /var/lib/mcp-server-imap-smtp/mcp-server-imap-smtp.sqlite.restore
cd /var/lib/mcp-server-imap-smtp && rm -f mcp-server-imap-smtp.sqlite-wal mcp-server-imap-smtp.sqlite-shm && mv mcp-server-imap-smtp.sqlite.restore mcp-server-imap-smtp.sqlite
systemctl start mcp-server-imap-smtp
```

Tokens issued after the backup are not in it; those users reconnect.

## 10. Logs and admin

```bash
journalctl -u mcp-server-imap-smtp -f                                   # gateway: requests (no query strings) and audit lines
journalctl -u mcp-server-imap-smtp | grep mcp_server_imap_smtp.audit    # one JSON line per tool call: grant, mailbox, tool, outcome
tail -f /var/log/nginx/mcp-server-imap-smtp.access.log                  # nginx access log, without query strings
tail -f /var/log/nginx/mcp-server-imap-smtp.error.log                   # nginx errors for this site: CAN contain query strings
certbot certificates; certbot renew --dry-run                           # certificate status and a renewal test
systemctl --failed                                                      # includes a failed nightly backup
```

The access log leaves out query strings, but nginx's error log cannot: on any upstream error, such as the few seconds of each restart, it records the full request line, for example `/authorize?...state=...&code_challenge=...` or `/mail/login?req=<sign-in request id>`. These values are short-lived (a sign-in request expires after 5 minutes, the PKCE challenge is public by design), but they are kept out of the shared `/var/log/nginx/error.log`: the site logs errors to its own `mcp-server-imap-smtp.error.log`, rotated with Debian's nginx logs (daily, 14 kept, compressed). Do not raise its level to `info` or `debug`. The gateway's own journal lines and the nginx access log also contain client IP addresses.

Admin CLI (lists and revokes grants; never prints secrets; full description in [RUNNING.md](RUNNING.md), "Admin CLI"):

```bash
mcp-server-imap-smtp-admin servers list
mcp-server-imap-smtp-admin grants list
mcp-server-imap-smtp-admin grants revoke --grant <grant id>
mcp-server-imap-smtp-admin grants revoke --mailbox user@example.com
mcp-server-imap-smtp-admin grants revoke --host mail.example.com
```

To add mailboxes to a user's existing connection without them reconnecting (the manage page's check and save, run by an operator), pipe "address password" lines on stdin. Never put the passwords on the command line. Keep the list in a file readable only by you (`chmod 600`), and delete it with `shred -u` once it is no longer needed:

```
ssh $VPS 'mcp-server-imap-smtp-admin grants add-mailboxes <grant id> --subject <main mailbox>' < mailboxes.txt
```

Run it without `< file` on a terminal to type the lines without echo. The password is everything after the single space or tab that follows the address, spaces at either end included. `--subject` must be the grant's main mailbox, so a mistyped grant id is refused. The command prints the grant's main mailbox and app first. It checks every new line on its mail server, skips mailboxes already there, stops after 5 wrong passwords and saves nothing unless every line passes. Each addition writes an audit line (`admin_add_mailbox`) to the journal. A grant created by a version without manage keys is refused until its AI app has used it once.

`/usr/local/sbin/mcp-server-imap-smtp-admin` is a wrapper for `runuser -u mcp-server-imap-smtp -- /opt/mcp-server-imap-smtp/venv/bin/mcp-server-imap-smtp-admin --config /etc/mcp-server-imap-smtp/config.toml`. Always run the CLI as the service user, never as root: SQLite would create root-owned `-wal`/`-shm` files and the service could no longer open its database.

## 11. Files on the server

With the default `NAME`:

| Path | Owner, mode | Contents |
|---|---|---|
| `/opt/mcp-server-imap-smtp/releases/<release>/` | root, 0755 | virtualenv, `BUILD_INFO`, `requirements.lock` |
| `/opt/mcp-server-imap-smtp/venv` | symlink | active release |
| `/etc/mcp-server-imap-smtp/config.toml` | root:mcp-server-imap-smtp 0640 | configuration (no secrets) |
| `/var/lib/mcp-server-imap-smtp/` | mcp-server-imap-smtp 0700 | `mcp-server-imap-smtp.sqlite` (+ `-wal`, `-shm`), 0600 |
| `/var/backups/mcp-server-imap-smtp/` | root 0700 | nightly backups, 0600 |
| `/etc/systemd/system/mcp-server-imap-smtp.service`, `mcp-server-imap-smtp-backup.service`, `mcp-server-imap-smtp-backup.timer` | root 0644 | units |
| `/usr/local/sbin/mcp-server-imap-smtp-admin`, `mcp-server-imap-smtp-backup`, `mcp-server-imap-smtp-smoke` | root 0755 | commands |
| `/etc/nginx/sites-available/mcp-server-imap-smtp.conf` (+ link in `sites-enabled`) | root 0644 | nginx site; Debian's `default` site is unlinked (if it was a file rather than a link, it is kept as `/etc/nginx/sites-enabled-default.mcp-server-imap-smtp-saved`) |
| `/var/www/acme` | root 0755 | ACME webroot |
| `/etc/letsencrypt/live/mcp.example.com/` | certbot | certificate |
| `/etc/ssh/sshd_config.d/10-mcp-server-imap-smtp.conf` | root 0644 | SSH hardening (keys only, no forwarding), unless `SSH_HARDEN=0` |
| `/etc/apt/apt.conf.d/20auto-upgrades` | root 0644 | enables daily unattended upgrades; the original, if `install.sh` replaced one, is `20auto-upgrades.mcp-server-imap-smtp.bak` |
| `/var/log/nginx/mcp-server-imap-smtp.access.log`, `mcp-server-imap-smtp.error.log` | nginx | access log (no query strings, client IPs); error log (may contain query strings) |
| `/root/mcp-server-imap-smtp-install.log` | root | output of the last `install.sh` run started with `systemd-run` |

## 12. Complete reversal

On a dedicated server, the full reversal is:

1. On each mail server: remove the gateway's IPv4/IPv6 addresses from the login-failure trusted list and the reputation allow list added in section 6 (on Plesk, **IP Address Banning → Trusted IP Addresses** or `plesk bin ip_ban --remove-trusted`; with Imunify360, `imunify360-agent ip-list local delete --purpose white <ip>`), and from any firewall allowlist added in section 6a. Update the change records. Do this before the address can be reused by anyone else.
2. DNS: delete the `mcp` A and AAAA records.
3. Optionally take a last backup off the server (`mcp-server-imap-smtp-backup`, then copy the newest file from `/var/backups/mcp-server-imap-smtp`).
4. Destroy the server. That removes everything `install.sh` created. Users' connectors stop working; they can remove them in their apps.

The HSTS header tells browsers to use HTTPS for `mcp.example.com` for two years; that is harmless if the name is reused later over HTTPS.

To remove the gateway but keep the server:

```bash
systemctl disable --now mcp-server-imap-smtp.service mcp-server-imap-smtp-backup.timer
rm -f /etc/systemd/system/mcp-server-imap-smtp.service /etc/systemd/system/mcp-server-imap-smtp-backup.{service,timer}
systemctl daemon-reload
rm -f /etc/nginx/sites-enabled/mcp-server-imap-smtp.conf /etc/nginx/sites-available/mcp-server-imap-smtp.conf
ln -s /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default && systemctl reload nginx
certbot delete --cert-name mcp.example.com
rm -rf /opt/mcp-server-imap-smtp /etc/mcp-server-imap-smtp /var/lib/mcp-server-imap-smtp /var/backups/mcp-server-imap-smtp /var/www/acme
rm -f /usr/local/sbin/mcp-server-imap-smtp-admin /usr/local/sbin/mcp-server-imap-smtp-backup /usr/local/sbin/mcp-server-imap-smtp-smoke
userdel mcp-server-imap-smtp
# SSH hardening drop-in, if you no longer want it.
rm -f /etc/ssh/sshd_config.d/10-mcp-server-imap-smtp.conf && systemctl reload ssh
# Logs: client IPs, mailbox addresses in audit lines, and query strings in the nginx error log.
rm -f /var/log/nginx/mcp-server-imap-smtp.access.log* /var/log/nginx/mcp-server-imap-smtp.error.log* /root/mcp-server-imap-smtp-install.log
journalctl --rotate && journalctl --vacuum-time=1s   # drops ALL archived journal entries on the server, not only the gateway's
# Unattended upgrades: put back the original file, if install.sh replaced one.
[ -f /etc/apt/apt.conf.d/20auto-upgrades.mcp-server-imap-smtp.bak ] && mv /etc/apt/apt.conf.d/20auto-upgrades.mcp-server-imap-smtp.bak /etc/apt/apt.conf.d/20auto-upgrades
```

`/var/lib/mcp-server-imap-smtp` and `/var/backups/mcp-server-imap-smtp` hold sealed credentials; delete them only when the service is gone for good. journald cannot delete one unit's entries, so `--vacuum-time` removes the whole archived journal; skip it if other services' logs on the server matter, and the gateway's entries then age out under journald's normal size limits. The ufw rules, `20auto-upgrades` and the Debian packages can stay (remove with `ufw disable` and `apt purge` if wanted).

## 13. Troubleshooting

- **certbot fails:** `dig +short mcp.example.com` must return the server's address (DNS only, not proxied) and `curl -I http://mcp.example.com/.well-known/acme-challenge/x` from outside must reach the server (a 404 from nginx is fine). Fix and re-run `install.sh`.
- **Sign-in says the mail server could not be reached, for one server only:** `journalctl -u <NAME> | grep 'could not reach'` shows the reason. A certificate problem ("unable to get local issuer certificate", a hostname mismatch) means the mail server's certificate is not trusted for the configured `host`; see RUNNING.md, "Mail servers with a private certificate authority".
- **Gateway does not start:** `journalctl -u mcp-server-imap-smtp -n 50`. `install.sh` prints the same log when its 30-second health check fails.
- **Everyone gets 429 at sign-in:** check `trusted_proxy = true` and `forwarded_allow_ips = "127.0.0.1"`; without them all users share nginx's address.
- **Sign-in fails for every user of one mail server with a correct password:** run the go-live check in section 6, step 6, from the gateway. A timeout means the mail server or a firewall in front of it is dropping the gateway: check the reputation allow list first (for example Imunify360's white list), then login-failure blocking (fail2ban or the control panel's IP banning), then any firewall allowlist (section 6a). If the server's address changed, re-run `install.sh` so the outbound firewall allows the new address.
- **429 for many users at once on claude.ai or ChatGPT:** the shared-platform budget for `/register` or `/token` is used up (section 4, "Rate limits"); raise the limit and restart.
