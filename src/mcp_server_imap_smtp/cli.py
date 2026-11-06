# SPDX-License-Identifier: AGPL-3.0-or-later
"""Operator commands: list mail servers, list and revoke grants, add mailboxes to a grant. Never prints secrets."""
from __future__ import annotations

import argparse
import datetime as dt
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable

from . import audit
from .auth.login import MailUnavailable, parse_more
from .config import Settings, load_settings
from .mail.hosts import HostNotAllowed
from .mail.resolve import ResolveUnavailable, Resolver, normalise_address
from .store import Store

INLINE_MAILBOXES = 3     # grants with more mailboxes list them one per line
ADD_WORKERS = 4          # passwords checked at once by add-mailboxes
MAX_WRONG = 5            # add-mailboxes stops checking after this many wrong passwords


def add_mailboxes(store: Store, settings: Settings, grant_id: str, subject: str, text: str,
                  verifier: Callable | None = None, resolver: Resolver | None = None,
                  say: Callable[[str], None] = print) -> tuple[int, list[str]]:
    """The manage page's check and save, for an operator: each "address password" line of text is checked
    on its own mail server over IMAP, then sealed to the grant's public key. `subject` must be the grant's
    main mailbox, so a mistyped grant id cannot give another client's AI app the mailboxes. Mailboxes
    already in the grant are skipped; checking stops after MAX_WRONG wrong passwords; nothing is saved
    unless every new line passes. Each addition is audited. Returns (exit status, report lines); the
    report names lines and addresses, never passwords."""
    if verifier is None:
        from .auth.login import imap_verifier as verifier
    resolver = resolver or Resolver(settings.mail_servers)
    grant = next((g for g in store.list_grants() if g["id"] == grant_id), None)
    if grant is None or grant["revoked"]:
        return 2, [f"grant {grant_id} not found or revoked"]
    if grant["subject"] != subject.strip().lower():
        return 2, [f"grant {grant_id} belongs to {grant['subject']}, not {subject.strip().lower()}: nothing was checked"]
    client = store.get_client(grant["client_id"])
    present = (grant["mailboxes"] or "").split()
    say(f"grant {grant_id}: main mailbox {grant['subject']}, app {client.client_name if client else 'unknown'!r}, "
        f"{len(present)} mailboxes now")
    if not store._q("SELECT 1 FROM grant_keys WHERE grant_id=?", (grant_id,)):
        return 3, [f"grant {grant_id} has no key for adding mailboxes yet: it gets one the next time its AI app "
                   "uses it. Ask the user to use the connection once, then run this again."]
    entries, problem = parse_more(text, keep_spaces=True)
    if problem:
        return 2, [problem]
    report: list[str] = []
    todo: list[tuple[int, str, str, object]] = []     # line, address, password, server
    seen: dict[str, str] = {}
    refused = False
    for entry in entries:
        try:
            address = normalise_address(entry.address)[0]
        except HostNotAllowed:
            report.append(f"line {entry.line}: refused, the first part is not an email address")
            refused = True
            continue
        if address in seen:
            if seen[address] != entry.password:
                report.append(f"line {entry.line} {address}: refused, listed again with another password")
                refused = True
            else:
                report.append(f"line {entry.line} {address}: listed twice, skipped")
            continue
        seen[address] = entry.password
        if address in present:
            report.append(f"line {entry.line} {address}: already in the grant, skipped")
            continue
        try:
            server = resolver.resolve(address)[1]
        except HostNotAllowed:
            report.append(f"line {entry.line} {address}: refused, not hosted on a configured mail server")
            refused = True
            continue
        except ResolveUnavailable:
            report.append(f"line {entry.line} {address}: refused, DNS lookup failed")
            refused = True
            continue
        todo.append((entry.line, address, entry.password, server))

    wrong = threading.Lock()
    state = {"wrong": 0}

    def check(item) -> str:
        line, address, password, server = item
        with wrong:
            if state["wrong"] >= MAX_WRONG:
                return f"not checked, stopped after {MAX_WRONG} wrong passwords"
        try:
            if verifier(address, password, server):
                return "ok"
        except MailUnavailable:
            return "refused, the mail server could not be reached or was busy"
        with wrong:
            state["wrong"] += 1
        return "refused, address or password incorrect"
    if not refused:
        with ThreadPoolExecutor(ADD_WORKERS) as pool:
            verdicts = list(pool.map(check, todo))
    else:
        verdicts = ["not checked, other lines were refused"] * len(todo)
    for (line, address, _, server), verdict in zip(todo, verdicts):
        report.append(f"line {line} {address}: {verdict}" + (f" ({server.host})" if verdict == "ok" else ""))
        refused = refused or verdict != "ok"
    if refused:
        report.append("nothing was saved: fix or remove the refused lines and run again")
        return 1, sorted(report, key=_line_order)
    added = store.add_mailboxes(grant_id, [(address, password, server) for _, address, password, server in todo])
    if added is None:
        return 3, sorted(report, key=_line_order) + [f"grant {grant_id} was revoked or lost its key meanwhile; "
                                                      "nothing was saved"]
    hosts = {address: server.host for _, address, _, server in todo}
    for address in added:
        audit.record(grant=grant_id, mailbox=address, host=hosts[address], tool="admin_add_mailbox", folder=None,
                     count=None, outcome="ok")
    report.append(f"added {len(added)} mailboxes; the grant now holds {len(present) + len(added)}")
    return 0, sorted(report, key=_line_order)


def _read_lines() -> str:
    """The "address password" lines: from a pipe or file as given, or typed without echo on a terminal."""
    if not sys.stdin.isatty():
        return sys.stdin.read()
    import getpass
    print("Type one mailbox per line (the address, a space, the password); nothing is shown. "
          "An empty line ends the list.", file=sys.stderr)
    lines = []
    while line := getpass.getpass(f"line {len(lines) + 1}: "):
        lines.append(line)
    return "\n".join(lines)


def _audit_to_syslog() -> None:
    """Operator additions go to the same journal as the service's audit lines (tagged mcp-server-imap-smtp-admin)."""
    import logging
    import logging.handlers
    log = logging.getLogger("mcp_server_imap_smtp.audit")
    log.setLevel(logging.INFO)
    try:
        handler = logging.handlers.SysLogHandler(address="/dev/log")
    except OSError:
        handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("mcp-server-imap-smtp-admin: %(message)s"))
    log.addHandler(handler)


def _line_order(text: str) -> tuple[int, int]:
    parts = text.split()
    return (0, int(parts[1])) if parts[0] == "line" and parts[1].isdigit() else (1, 0)


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="mcp-server-imap-smtp-admin")
    ap.add_argument("--config", default=os.environ.get("MCP_SERVER_IMAP_SMTP_CONFIG", "local.toml"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("servers").add_subparsers(dest="action", required=True).add_parser("list")
    g = sub.add_parser("grants").add_subparsers(dest="action", required=True)
    g.add_parser("list")
    rv = g.add_parser("revoke"); grp = rv.add_mutually_exclusive_group(required=True)
    grp.add_argument("--grant"); grp.add_argument("--mailbox"); grp.add_argument("--host")
    add = g.add_parser("add-mailboxes", help='add mailboxes to a grant: "address password" lines on stdin')
    add.add_argument("grant")
    add.add_argument("--subject", required=True, help="the grant's main mailbox, as a check on the grant id")
    args = ap.parse_args(argv)
    settings = load_settings(Path(args.config))
    if args.cmd == "servers":
        for m in settings.mail_servers:
            domains = " ".join(m.domains) or "-"
            print(f"{m.host}  imap {m.imap_port} {m.imap_security}  smtp {m.smtp_port} {m.smtp_security}  "
                  f"domains {domains}  "
                  f"match_mx {'yes' if m.match_mx else 'no'}")
        return
    db_path = settings.db_path
    if not db_path.exists():      # Store() would create an empty database (and its directory) here
        print(f"mcp-server-imap-smtp-admin: database not found: {db_path} (check db_path in {args.config})", file=sys.stderr)
        sys.exit(2)
    # Never unseals; the legacy server names the host of mailboxes stored before hosts were recorded.
    legacy = settings.legacy_server
    store = Store(db_path, legacy_server=legacy)
    legacy_host = legacy.host if legacy else "unknown server"
    if args.action == "add-mailboxes":
        _audit_to_syslog()
        status, report = add_mailboxes(store, settings, args.grant, args.subject, _read_lines())
        print("\n".join(report))
        sys.exit(status)
    if args.action == "list":
        rows = store.list_grants()
        if not rows:
            print("no grants")
        for row in rows:
            when = dt.datetime.fromtimestamp(row["created"]).isoformat(timespec="minutes")
            state = "revoked" if row["revoked"] else "active"
            boxes = [f"{a} ({h or legacy_host})" for a, h in zip((row["mailboxes"] or "").split(), row["hosts"])]
            if len(boxes) <= INLINE_MAILBOXES:
                print(f"{row['id']}  {when}  {state:7}  {' '.join(boxes) or None}")
                continue
            # A large grant (an owner with all staff mailboxes): one line per mailbox, each starting with the
            # grant id so grep still finds the grant.
            print(f"{row['id']}  {when}  {state:7}  {len(boxes)} mailboxes")
            for box in boxes:
                print(f"{row['id']}    {box}")
    elif args.host:
        print(f"revoked {store.revoke_host(args.host)}")
    elif args.grant:
        print(f"revoked {store.revoke_grant(args.grant)}")
    else:
        print(f"revoked {store.revoke_address(args.mailbox.lower())}")
