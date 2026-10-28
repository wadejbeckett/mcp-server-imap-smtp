# SPDX-License-Identifier: AGPL-3.0-or-later
"""SQLite persistence for OAuth clients, pending logins, grants, codes and tokens.
Passwords are stored only as AES-GCM ciphertext under the grant key (see crypto.py)."""
from __future__ import annotations

import contextlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from mcp.server.auth.provider import AuthorizationParams
from mcp.shared.auth import OAuthClientInformationFull

from . import crypto
from .mail.hosts import MailServer

log = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (client_id TEXT PRIMARY KEY, info TEXT NOT NULL, created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS pending (id TEXT PRIMARY KEY, client_id TEXT NOT NULL, params TEXT NOT NULL, expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS grants (id TEXT PRIMARY KEY, client_id TEXT NOT NULL, resource TEXT NOT NULL,
    subject TEXT NOT NULL, created REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, revoked_at REAL);
CREATE TABLE IF NOT EXISTS mailboxes (grant_id TEXT NOT NULL, position INTEGER NOT NULL, address TEXT NOT NULL,
    sealed BLOB NOT NULL, host TEXT, PRIMARY KEY (grant_id, address));
CREATE TABLE IF NOT EXISTS codes (id TEXT PRIMARY KEY, grant_id TEXT NOT NULL, secret_hash TEXT NOT NULL,
    wrapped BLOB NOT NULL, client_id TEXT NOT NULL, params TEXT NOT NULL, expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS tokens (id TEXT PRIMARY KEY, kind TEXT NOT NULL, grant_id TEXT NOT NULL,
    secret_hash TEXT NOT NULL, wrapped BLOB NOT NULL, client_id TEXT NOT NULL, scopes TEXT NOT NULL,
    resource TEXT NOT NULL, expires REAL NOT NULL);
CREATE INDEX IF NOT EXISTS tokens_grant ON tokens(grant_id);
CREATE TABLE IF NOT EXISTS spent (id TEXT NOT NULL, kind TEXT NOT NULL, grant_id TEXT NOT NULL,
    secret_hash TEXT NOT NULL, spent_at REAL NOT NULL, expires REAL NOT NULL, PRIMARY KEY (kind, id));
CREATE TABLE IF NOT EXISTS grant_keys (grant_id TEXT PRIMARY KEY, public BLOB NOT NULL, private BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS manage (id TEXT PRIMARY KEY, secret_hash TEXT NOT NULL, subject TEXT NOT NULL,
    expires REAL NOT NULL);
"""


_PREFIX = {"access": "at", "refresh": "rt", "code": "ac"}
REVOKED_GRANT_KEEP = 30 * 86400      # a revoked grant is deleted this long after it was revoked (revoked_at)
UNUSED_CLIENT_KEEP = 86400           # a registered client that never completed a sign-in is dropped after this


@dataclass(frozen=True)
class MailboxCred:
    """One connected mailbox's password and the server it signed in to, both sealed in the grant."""
    password: str = field(repr=False)
    server: MailServer


class MailboxNeedsReconnect(ValueError):
    """A sealed mailbox cannot be opened with the current configuration (a legacy row with no legacy
    server configured). The user must reconnect; the server is never guessed."""


def _seal_blob(password: str, server: MailServer) -> bytes:
    return json.dumps({"password": password, "host": server.host, "imap_port": server.imap_port,
                       "smtp_port": server.smtp_port}).encode()


def _unseal_blob(plain: bytes, legacy_server: MailServer | None) -> MailboxCred:
    """JSON {password, host, imap_port, smtp_port}; a row written before servers were sealed holds
    the bare password and belongs to legacy_server (Settings.legacy_server); without one it refuses."""
    text = plain.decode()
    if text.startswith("{"):
        try:
            data = json.loads(text)
        except ValueError:
            data = None
        if isinstance(data, dict) and {"password", "host", "imap_port", "smtp_port"} <= set(data):
            return MailboxCred(data["password"], MailServer(host=data["host"], imap_port=data["imap_port"],
                                                           smtp_port=data["smtp_port"], match_mx=False))
    if legacy_server is None:
        raise MailboxNeedsReconnect("mailbox sealed before servers were recorded, and no legacy server is configured")
    return MailboxCred(text, legacy_server)


@dataclass
class CodeRecord:
    code: str = field(repr=False)
    grant_id: str
    client_id: str
    params: AuthorizationParams
    expires: float


@dataclass
class TokenRecord:
    token: str = field(repr=False)
    kind: str
    grant_id: str
    client_id: str
    scopes: list[str]
    resource: str
    expires: float


def _id() -> str:
    return secrets.token_hex(12)


def _parts(token: str, kind: str) -> tuple[str, str] | None:
    parts = crypto.split_token(token)
    if not parts or parts[0] != _PREFIX[kind]:
        return None
    return parts[1], parts[2]


class Store:
    def __init__(self, path: Path, legacy_server: MailServer | None = None, sealing_secret: bytes | None = None):
        """legacy_server: where a mailbox sealed as a bare password (before the server was sealed with it)
        signs in (Settings.legacy_server). Without it such a mailbox cannot be opened.
        sealing_secret: the server's secret mixed into every token's key-encryption key
        (config.load_sealing_secret); None wraps with the token alone, as before."""
        self.legacy_server = legacy_server
        self.sealing_secret = sealing_secret
        # Called with the grant id whenever a grant is revoked in this process (the mail tools close the
        # IMAP sessions they keep for it). A revocation from another process (the admin CLI) is not seen:
        # its kept sessions are closed after imap_idle_seconds, and its tokens no longer work anyway.
        self.revoke_listeners: list[Callable[[str], None]] = []
        # Called with (grant id, address) when the manage page replaces a mailbox's password or removes it.
        self.change_listeners: list[Callable[[str, str], None]] = []
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Set umask to 0o077 to ensure secure file permissions for main, WAL, and SHM files
        old_umask = os.umask(0o077)
        try:
            self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
            self._db.row_factory = sqlite3.Row
            self._lock = threading.RLock()
            with self._lock:
                self._db.execute("PRAGMA journal_mode=WAL")
                self._db.executescript(SCHEMA)
                # Databases created before revoked_at existed gain the column; their old revoked
                # grants keep NULL and age from `created` instead.
                if "revoked_at" not in {r["name"] for r in self._db.execute("PRAGMA table_info(grants)")}:
                    self._db.execute("ALTER TABLE grants ADD COLUMN revoked_at REAL")
                # mailboxes.host: a plain copy of the sealed server's host, for listing and revoking by
                # server only (the sealed copy is the one used). Older rows keep NULL: the legacy server.
                columns = {r["name"] for r in self._db.execute("PRAGMA table_info(mailboxes)")}
                if "host" not in columns:
                    self._db.execute("ALTER TABLE mailboxes ADD COLUMN host TEXT")
                # boxed: 1 when sealed to the grant's public key (added on the manage page), 0 under the
                # grant key. failed_at: when the mail server last rejected the sealed password, else NULL.
                if "boxed" not in columns:
                    self._db.execute("ALTER TABLE mailboxes ADD COLUMN boxed INTEGER NOT NULL DEFAULT 0")
                if "failed_at" not in columns:
                    self._db.execute("ALTER TABLE mailboxes ADD COLUMN failed_at REAL")
        finally:
            os.umask(old_umask)
        # chmod main file and any WAL/SHM siblings that exist
        for suffix in ["", "-wal", "-shm"]:
            p = Path(str(path) + suffix)
            if p.exists():
                p.chmod(0o600)

    def _q(self, sql: str, args: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._db.execute(sql, args).fetchall()

    @contextlib.contextmanager
    def _tx(self):
        """Context manager for transactional writes (BEGIN IMMEDIATE ... COMMIT/ROLLBACK)."""
        with self._lock:
            # BEGIN sits outside the try: if it fails there is nothing of ours to roll back,
            # and a ROLLBACK here could mask the real error (or undo an enclosing transaction).
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield
                self._db.execute("COMMIT")
            except BaseException:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")
                raise

    # clients
    def save_client(self, info: OAuthClientInformationFull) -> None:
        self._q("INSERT OR REPLACE INTO clients VALUES (?,?,?)", (info.client_id, info.model_dump_json(), time.time()))

    def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        rows = self._q("SELECT info FROM clients WHERE client_id=?", (client_id,))
        return OAuthClientInformationFull.model_validate_json(rows[0]["info"]) if rows else None

    # pending authorization requests (between /authorize and the login POST)
    def create_pending(self, client_id: str, params: AuthorizationParams, ttl: int) -> str:
        req = secrets.token_urlsafe(24)
        self._q("INSERT INTO pending VALUES (?,?,?,?)", (req, client_id, params.model_dump_json(), time.time() + ttl))
        return req

    def peek_pending(self, req: str) -> tuple[str, AuthorizationParams] | None:
        rows = self._q("SELECT client_id, params FROM pending WHERE id=? AND expires>?", (req, time.time()))
        if not rows:
            return None
        return rows[0]["client_id"], AuthorizationParams.model_validate_json(rows[0]["params"])

    def take_pending(self, req: str) -> tuple[str, AuthorizationParams] | None:
        # Atomic DELETE RETURNING to prevent race condition with concurrent take_pending calls
        with self._lock:
            rows = self._db.execute(
                "DELETE FROM pending WHERE id=? AND expires>? RETURNING client_id, params",
                (req, time.time())
            ).fetchall()
            if not rows:
                return None
            return rows[0]["client_id"], AuthorizationParams.model_validate_json(rows[0]["params"])

    # grants and sealed mailbox credentials
    def create_grant(self, client_id: str, resource: str,
                     mailboxes: list[tuple[str, str, MailServer]]) -> tuple[str, bytes]:
        """mailboxes: (address, password, server) for each, the first being the grant's subject. The
        password and server are sealed together under the grant key, bound to grant id and address, so
        neither a database edit nor a later DNS change can point a mailbox at another server. (A mailbox
        added on the manage page is sealed to the grant's public key until the grant is next used, and
        is then sealed under the grant key too: until then, someone able to write the database could
        replace it.)"""
        gid, key = _id(), crypto.new_key()
        mailboxes = [(address.lower(), password, server) for address, password, server in mailboxes]
        with self._tx():
            self._q("INSERT INTO grants (id, client_id, resource, subject, created) VALUES (?,?,?,?,?)",
                    (gid, client_id, resource, mailboxes[0][0], time.time()))
            for pos, (address, password, server) in enumerate(mailboxes):
                sealed = crypto.seal(key, _seal_blob(password, server), f"{gid}|{address}".encode())
                self._q("INSERT INTO mailboxes (grant_id, position, address, sealed, host) VALUES (?,?,?,?,?)",
                        (gid, pos, address, sealed, server.host))
            self._new_grant_keys(gid, key)
        return gid, key

    def _new_grant_keys(self, grant_id: str, key: bytes) -> None:
        """The grant's keypair: mailboxes added later on the manage page are sealed to the public key, and
        only the grant key (held in its tokens) opens the private one."""
        public, private = crypto.new_keypair()
        self._q("INSERT OR IGNORE INTO grant_keys (grant_id, public, private) VALUES (?,?,?)",
                (grant_id, public, crypto.seal(key, private, f"{grant_id}|private".encode())))

    def open_mailboxes(self, grant_id: str, key: bytes) -> dict[str, MailboxCred]:
        rows = self._q("SELECT address, sealed, boxed FROM mailboxes WHERE grant_id=? ORDER BY position", (grant_id,))
        keys = self._q("SELECT public, private FROM grant_keys WHERE grant_id=?", (grant_id,))
        if not keys:     # a grant made before keypairs existed gets one the first time it is used
            with self._tx():
                self._new_grant_keys(grant_id, key)
            keys = self._q("SELECT public, private FROM grant_keys WHERE grant_id=?", (grant_id,))
        private = crypto.unseal(key, keys[0]["private"], f"{grant_id}|private".encode())
        # The stored public key must be the private key's: one swapped in the database would let whoever
        # swapped it read the next password entered on the manage page. Checked on every use, so a swap
        # stops the connection before the manage page can be used with it for long.
        if crypto.public_of(private) != keys[0]["public"]:
            log.error("grant %s: stored public key does not match its private key", grant_id)
            raise crypto.CryptoError("grant keypair does not match")
        out = {}
        for r in rows:
            aad = f"{grant_id}|{r['address']}".encode()
            if r["boxed"]:
                plain = crypto.open_sealed(private, r["sealed"], aad)
                # Sealed again under the grant key, which only the tokens hold: from now on a database edit
                # cannot have planted it.
                self._q("UPDATE mailboxes SET sealed=?, boxed=0 WHERE grant_id=? AND address=? AND sealed=?",
                        (crypto.seal(key, plain, aad), grant_id, r["address"], r["sealed"]))
            else:
                plain = crypto.unseal(key, r["sealed"], aad)
            out[r["address"]] = _unseal_blob(plain, self.legacy_server)
        return out

    # managing a grant's mailboxes without its tokens (the manage page)
    def live_grants(self, subject: str) -> list[dict]:
        """Unrevoked grants for this subject that an AI app can still use (a token is left), newest first,
        each with its mailboxes in order: address, host, failed_at."""
        grants = [dict(r) for r in self._q(
            """SELECT id, client_id, created FROM grants g WHERE subject=? AND revoked=0
               AND EXISTS (SELECT 1 FROM tokens t WHERE t.grant_id=g.id) ORDER BY created DESC""", (subject.lower(),))]
        for g in grants:
            g["mailboxes"] = [dict(r) for r in self._q(
                "SELECT address, host, failed_at FROM mailboxes WHERE grant_id=? ORDER BY position", (g["id"],))]
            g["can_add"] = bool(self._q("SELECT 1 FROM grant_keys WHERE grant_id=?", (g["id"],)))
        return grants

    def put_mailbox(self, grant_id: str, address: str, password: str, server: MailServer) -> bool:
        """Add the mailbox to the grant, or replace its password and server, sealed to the grant's public
        key. False when the grant has no keypair yet (not used since keypairs were introduced)."""
        address = address.lower()
        with self._tx():
            keys = self._q("SELECT public FROM grant_keys WHERE grant_id=?", (grant_id,))
            if not keys:
                return False
            sealed = crypto.seal_to(keys[0]["public"], _seal_blob(password, server), f"{grant_id}|{address}".encode())
            if self._db.execute("UPDATE mailboxes SET sealed=?, boxed=1, host=?, failed_at=NULL "
                                "WHERE grant_id=? AND address=?", (sealed, server.host, grant_id, address)).rowcount:
                self._changed(grant_id, address)
                return True
            pos = self._q("SELECT COALESCE(MAX(position), -1) + 1 AS p FROM mailboxes WHERE grant_id=?", (grant_id,))[0]["p"]
            self._q("INSERT INTO mailboxes (grant_id, position, address, sealed, host, boxed) VALUES (?,?,?,?,?,1)",
                    (grant_id, pos, address, sealed, server.host))
        return True

    def add_mailboxes(self, grant_id: str, mailboxes: list[tuple[str, str, MailServer]]) -> list[str] | None:
        """Add mailboxes not yet in the grant, in one transaction that re-checks the grant is active and has
        its keypair, sealed to its public key. Never replaces a mailbox already there. Returns the addresses
        added, or None (nothing written) if the grant is revoked, unknown or has no keypair."""
        added = []
        with self._tx():
            if not self._q("SELECT 1 FROM grants WHERE id=? AND revoked=0", (grant_id,)):
                return None
            keys = self._q("SELECT public FROM grant_keys WHERE grant_id=?", (grant_id,))
            if not keys:
                return None
            pos = self._q("SELECT COALESCE(MAX(position), -1) + 1 AS p FROM mailboxes WHERE grant_id=?",
                          (grant_id,))[0]["p"]
            for address, password, server in mailboxes:
                address = address.lower()
                sealed = crypto.seal_to(keys[0]["public"], _seal_blob(password, server), f"{grant_id}|{address}".encode())
                if self._db.execute("INSERT OR IGNORE INTO mailboxes (grant_id, position, address, sealed, host, boxed) "
                                    "VALUES (?,?,?,?,?,1)", (grant_id, pos, address, sealed, server.host)).rowcount:
                    added.append(address)
                    pos += 1
        return added

    def remove_mailbox(self, grant_id: str, address: str) -> bool:
        """Remove a mailbox that is not the grant's subject. False if it is the subject or not there."""
        address = address.lower()
        with self._tx():
            n = self._db.execute("DELETE FROM mailboxes WHERE grant_id=? AND address=? AND address != "
                                 "(SELECT subject FROM grants WHERE id=?)", (grant_id, address, grant_id)).rowcount
            if n:
                self._changed(grant_id, address)
        return bool(n)

    def _changed(self, grant_id: str, address: str) -> None:
        """One mailbox of a grant was changed or removed: close the IMAP sessions kept for it."""
        for listener in self.change_listeners:
            try:
                listener(grant_id, address)
            except Exception:
                log.exception("change listener failed")

    def mark_mailbox(self, grant_id: str, address: str, failed: bool) -> None:
        """Record whether the mail server last accepted (failed=False) or rejected the sealed password, for the
        manage page. Writes only when that changes, and never raises: a tool call's result must not depend on it."""
        try:
            rows = self._q("SELECT failed_at FROM mailboxes WHERE grant_id=? AND address=?", (grant_id, address))
            if not rows or (rows[0]["failed_at"] is not None) == failed:
                return
            self._q("UPDATE mailboxes SET failed_at=? WHERE grant_id=? AND address=?",
                    (time.time() if failed else None, grant_id, address))
        except sqlite3.Error:
            log.exception("could not record the state of a mailbox")

    def open_manage(self, subject: str, ttl: int) -> str:
        ident, secret = _id(), crypto.new_secret()
        self._q("INSERT INTO manage (id, secret_hash, subject, expires) VALUES (?,?,?,?)",
                (ident, crypto.hash_secret(secret), subject.lower(), time.time() + ttl))
        return crypto.make_token("mg", ident, secret)

    def manage_subject(self, token: str) -> str | None:
        parts = crypto.split_token(token)
        if not parts or parts[0] != "mg":
            return None
        rows = self._q("SELECT secret_hash, subject FROM manage WHERE id=? AND expires>?", (parts[1], time.time()))
        if not rows or not hmac.compare_digest(rows[0]["secret_hash"], crypto.hash_secret(parts[2])):
            return None
        return rows[0]["subject"]

    def close_manage(self, token: str) -> None:
        parts = crypto.split_token(token)
        if parts:
            self._q("DELETE FROM manage WHERE id=?", (parts[1],))

    def _revoke(self, grant_id: str) -> int:
        """Revoke inside the caller's transaction; returns 1 if the grant was active, else 0."""
        changed = self._db.execute("UPDATE grants SET revoked=1, revoked_at=? WHERE id=? AND revoked=0",
                                   (time.time(), grant_id)).rowcount
        self._q("DELETE FROM tokens WHERE grant_id=?", (grant_id,))
        self._q("DELETE FROM codes WHERE grant_id=?", (grant_id,))
        for listener in self.revoke_listeners:
            try:
                listener(grant_id)
            except Exception:     # closing kept sessions must never undo or fail a revocation
                log.exception("revoke listener failed")
        return changed

    def revoke_grant(self, grant_id: str) -> int:
        """Returns 1 if the grant existed and was active, 0 if it is unknown or already revoked."""
        with self._tx():
            return self._revoke(grant_id)

    def grant_subject(self, grant_id: str) -> str | None:
        rows = self._q("SELECT subject FROM grants WHERE id=?", (grant_id,))
        return rows[0]["subject"] if rows else None

    def known_mailbox(self, address: str, host: str) -> bool:
        """Whether the address has signed in on host through the gateway before (any grant, even revoked)."""
        return bool(self._q("SELECT 1 FROM mailboxes WHERE address=? AND host=? LIMIT 1", (address.lower(), host)))

    def list_grants(self) -> list[dict]:
        grants = [dict(r) for r in self._q("SELECT id, client_id, subject, created, revoked, revoked_at FROM grants "
                                           "ORDER BY created")]
        boxes: dict[str, list[tuple[str, str | None]]] = {}
        # Built here, in position order: group_concat's order is not guaranteed by SQLite.
        for r in self._q("SELECT grant_id, address, host FROM mailboxes ORDER BY grant_id, position"):
            boxes.setdefault(r["grant_id"], []).append((r["address"], r["host"]))
        for g in grants:
            g["mailboxes"] = " ".join(a for a, _ in boxes[g["id"]]) if g["id"] in boxes else None
            g["hosts"] = [h for _, h in boxes.get(g["id"], [])]   # per mailbox; None = sealed before hosts were kept
        return grants

    def revoke_address(self, address: str) -> int:
        """Revoke every grant that includes the address; returns how many were still active."""
        address = address.lower()
        with self._tx():
            ids = [r["grant_id"] for r in self._q("SELECT DISTINCT grant_id FROM mailboxes WHERE address=?", (address,))]
            return sum(self._revoke(gid) for gid in ids)

    def revoke_host(self, host: str) -> int:
        """Revoke every grant with a mailbox on host (rows from before hosts were recorded count as the
        legacy server's); returns how many were still active."""
        host = host.strip().lower()
        legacy = self.legacy_server.host if self.legacy_server else None
        with self._tx():
            ids = [r["grant_id"] for r in self._q(
                "SELECT DISTINCT grant_id FROM mailboxes WHERE host=? OR (host IS NULL AND ?=?)", (host, legacy, host))]
            return sum(self._revoke(gid) for gid in ids)

    def purge_expired(self, now: float | None = None, refresh_ttl: float | None = None) -> dict[str, int]:
        """Delete what can never be used again: expired pending sign-ins, codes and tokens; grants revoked
        more than 30 days ago (aged from `created` when revoked_at is unknown), with their sealed mailboxes;
        abandoned grants (not revoked, created more than refresh_ttl ago, no token or code left, so nothing
        can ever unlock them again), with their sealed mailboxes; and dynamically registered clients
        (client_id not an https URL) created more than 7 days ago that hold no grant. refresh_ttl=None skips
        the abandoned-grant rule. Returns the counts."""
        now = time.time() if now is None else now
        with self._tx():
            out = {table: self._db.execute(f"DELETE FROM {table} WHERE expires<=?", (now,)).rowcount
                   for table in ("pending", "codes", "tokens", "spent", "manage")}
            old = [r["id"] for r in self._q("SELECT id FROM grants WHERE revoked=1 AND COALESCE(revoked_at, created)<?",
                                              (now - REVOKED_GRANT_KEEP,))]
            abandoned = [] if refresh_ttl is None else [r["id"] for r in self._q(
                """SELECT id FROM grants g WHERE revoked=0 AND created<?
                   AND NOT EXISTS (SELECT 1 FROM tokens t WHERE t.grant_id=g.id)
                   AND NOT EXISTS (SELECT 1 FROM codes c WHERE c.grant_id=g.id)""", (now - refresh_ttl,))]
            for gid in old + abandoned:
                for table, col in (("mailboxes", "grant_id"), ("tokens", "grant_id"), ("codes", "grant_id"),
                                   ("spent", "grant_id"), ("grant_keys", "grant_id"), ("grants", "id")):
                    self._q(f"DELETE FROM {table} WHERE {col}=?", (gid,))
            out["grants"] = len(old)
            out["abandoned"] = len(abandoned)
            out["clients"] = self._db.execute(
                """DELETE FROM clients WHERE client_id NOT LIKE 'https://%' AND created<?
                   AND NOT EXISTS (SELECT 1 FROM grants g WHERE g.client_id=clients.client_id)""",
                (now - UNUSED_CLIENT_KEEP,)).rowcount
        return out

    # authorization codes (single use, bound to the grant key)
    def issue_code(self, grant_id: str, key: bytes, client_id: str, params: AuthorizationParams, ttl: int) -> str:
        ident, secret = _id(), crypto.new_secret()
        wrapped = crypto.wrap_key(key, secret, f"code:{ident}", self.sealing_secret)
        self._q("INSERT INTO codes VALUES (?,?,?,?,?,?,?)", (ident, grant_id, crypto.hash_secret(secret), wrapped,
                client_id, params.model_dump_json(), time.time() + ttl))
        return crypto.make_token("ac", ident, secret)

    def _code_row(self, code: str):
        p = _parts(code, "code")
        if not p:
            return None, None
        rows = self._q("SELECT * FROM codes WHERE id=? AND expires>?", (p[0], time.time()))
        if not rows or not secrets.compare_digest(rows[0]["secret_hash"], crypto.hash_secret(p[1])):
            return None, None
        return rows[0], p

    def load_code(self, code: str) -> CodeRecord | None:
        row, _ = self._code_row(code)
        if row is None:
            return None
        return CodeRecord(code, row["grant_id"], row["client_id"],
                          AuthorizationParams.model_validate_json(row["params"]), row["expires"])

    def consume_code(self, code: str) -> bytes | None:
        """Verify, unwrap and delete in one transaction: exactly one caller gets the key, and a
        wrong secret never deletes the row."""
        with self._tx():
            row, p = self._code_row(code)
            if row is None:
                return None
            key = crypto.unwrap_key(row["wrapped"], p[1], f"code:{p[0]}", self.sealing_secret)
            self._q("DELETE FROM codes WHERE id=?", (p[0],))
            self._spend("code", p[0], row)
            return key

    # used codes and refresh tokens, kept until they would have expired, to recognise a replay
    def _spend(self, kind: str, ident: str, row) -> None:
        """Remember a consumed code or rotated-out refresh token (its hash only). The caller owns the transaction."""
        self._q("INSERT OR REPLACE INTO spent VALUES (?,?,?,?,?,?)",
                (ident, kind, row["grant_id"], row["secret_hash"], time.time(), row["expires"]))

    def spent_grant(self, token: str, kind: str) -> str | None:
        """The grant of a code or refresh token that was already used (right secret, not expired), else None."""
        p = _parts(token, kind)
        if not p:
            return None
        rows = self._q("SELECT grant_id, secret_hash FROM spent WHERE kind=? AND id=? AND expires>?",
                       (kind, p[0], time.time()))
        if not rows or not secrets.compare_digest(rows[0]["secret_hash"], crypto.hash_secret(p[1])):
            return None
        return rows[0]["grant_id"]

    def replayed_grant(self, token: str, kind: str, grace: float) -> str | None:
        """If token is a code or refresh token that was already used (right secret, not yet expired) more
        than `grace` seconds ago, revoke its grant and return the grant id. Otherwise None, nothing changed."""
        p = _parts(token, kind)
        if not p:
            return None
        with self._tx():
            rows = self._q("SELECT * FROM spent WHERE kind=? AND id=? AND expires>?", (kind, p[0], time.time()))
            if not rows or not secrets.compare_digest(rows[0]["secret_hash"], crypto.hash_secret(p[1])):
                return None
            if time.time() - rows[0]["spent_at"] <= grace:
                return None
            gid = rows[0]["grant_id"]
            self._revoke(gid)
            return gid

    # access and refresh tokens
    def _insert_tokens(self, grant_id, key, client_id, scopes, resource, access_ttl, refresh_ttl) -> tuple[str, str]:
        """Insert an access+refresh pair. The caller owns the transaction."""
        out = []
        for kind, ttl in (("access", access_ttl), ("refresh", refresh_ttl)):
            ident, secret = _id(), crypto.new_secret()
            wrapped = crypto.wrap_key(key, secret, f"{kind}:{ident}", self.sealing_secret)
            self._q("INSERT INTO tokens VALUES (?,?,?,?,?,?,?,?,?)", (ident, kind, grant_id,
                    crypto.hash_secret(secret), wrapped, client_id, json.dumps(scopes), resource,
                    time.time() + ttl))
            out.append(crypto.make_token(_PREFIX[kind], ident, secret))
        return out[0], out[1]

    def issue_tokens(self, grant_id, key, client_id, scopes, resource, access_ttl, refresh_ttl) -> tuple[str, str]:
        with self._tx():
            return self._insert_tokens(grant_id, key, client_id, scopes, resource, access_ttl, refresh_ttl)

    def _token_row(self, token: str, kind: str):
        p = _parts(token, kind)
        if not p:
            return None, None
        rows = self._q("""SELECT t.* FROM tokens t JOIN grants g ON g.id=t.grant_id
                          WHERE t.id=? AND t.kind=? AND t.expires>? AND g.revoked=0""", (p[0], kind, time.time()))
        if not rows or not secrets.compare_digest(rows[0]["secret_hash"], crypto.hash_secret(p[1])):
            return None, None
        return rows[0], p

    @staticmethod
    def _token_record(token: str, kind: str, row) -> TokenRecord:
        return TokenRecord(token, kind, row["grant_id"], row["client_id"], json.loads(row["scopes"]),
                           row["resource"], row["expires"])

    def load_token(self, token: str, kind: str) -> TokenRecord | None:
        row, _ = self._token_row(token, kind)
        return None if row is None else self._token_record(token, kind, row)

    def key_for(self, token: str, kind: str) -> bytes | None:
        row, p = self._token_row(token, kind)
        return None if row is None else crypto.unwrap_key(row["wrapped"], p[1], f"{kind}:{p[0]}", self.sealing_secret)

    def delete_token(self, token: str) -> None:
        parts = crypto.split_token(token)
        if parts:
            self._q("DELETE FROM tokens WHERE id=?", (parts[1],))

    def rotate_and_issue(self, refresh_token: str, client_id: str, scopes: list[str] | None,
                         access_ttl: int, refresh_ttl: int) -> tuple[TokenRecord, str, str] | None:
        """Refresh-token grant in ONE transaction: verify the token (secret, kind, expiry, grant not
        revoked, issued to client_id), delete it and insert the new access+refresh pair. Returns
        (old record, access, refresh), or None with nothing changed: a replay, a wrong secret or the
        wrong client never consumes the token. scopes=None keeps the old token's scopes."""
        with self._tx():
            row, p = self._token_row(refresh_token, "refresh")
            if row is None or row["client_id"] != client_id:
                return None
            key = crypto.unwrap_key(row["wrapped"], p[1], f"refresh:{p[0]}", self.sealing_secret)
            rec = self._token_record(refresh_token, "refresh", row)
            self._q("DELETE FROM tokens WHERE id=?", (p[0],))
            self._spend("refresh", p[0], row)
            at, rt = self._insert_tokens(rec.grant_id, key, client_id, rec.scopes if scopes is None else scopes,
                                         rec.resource, access_ttl, refresh_ttl)
            return rec, at, rt

    def unlock(self, access_token: str) -> tuple[str, dict[str, MailboxCred]] | None:
        row, p = self._token_row(access_token, "access")
        if row is None:
            return None
        key = crypto.unwrap_key(row["wrapped"], p[1], f"access:{p[0]}", self.sealing_secret)
        return row["grant_id"], self.open_mailboxes(row["grant_id"], key)
