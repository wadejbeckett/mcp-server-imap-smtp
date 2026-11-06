# SPDX-License-Identifier: AGPL-3.0-or-later
"""Thin, typed IMAP client over imaplib. One connection serves one tool call at a time; mail/sessions.py
may keep it logged in between calls (reset() makes it behave like a fresh one)."""
from __future__ import annotations

import imaplib
import re
import socket
import time
from dataclasses import dataclass
from datetime import date
from email.parser import BytesHeaderParser
from email import policy as email_policy

from . import utf7
from .hosts import Connector, MailServer
from .resolve import normalise_address

SPECIAL = {"\\sent": "sent", "\\drafts": "drafts", "\\trash": "trash", "\\junk": "junk", "\\archive": "archive"}
FALLBACK = {"sent": ("sent", "sent items", "sent messages"), "drafts": ("drafts",),
            "trash": ("trash", "deleted items", "deleted messages"), "junk": ("spam", "junk"), "archive": ("archive",)}
# Folder names an AI app may give for a role, in any case; resolve_folder maps them to the server's folder.
ROLE_NAMES = {"inbox": "inbox",
              "sent": "sent", "sent items": "sent", "sent messages": "sent", "sent mail": "sent",
              "drafts": "drafts", "draft": "drafts",
              "trash": "trash", "deleted": "trash", "deleted items": "trash", "deleted messages": "trash", "bin": "trash",
              "junk": "junk", "spam": "junk", "junk e-mail": "junk", "junk email": "junk", "junk mail": "junk",
              "archive": "archive", "archives": "archive"}
_PERSONAL_PREFIXES = ("INBOX.", "INBOX/")   # common personal-namespace prefixes, removed when this server has none
_LIST = re.compile(rb'\((?P<flags>[^)]*)\) (?P<delim>"[^"]*"|NIL) (?P<name>.+)$')
_CTRL = re.compile(r"[\r\n\0]")
_FLAG = re.compile(r"\\?[A-Za-z0-9$_.-]+")
_UNSELECTABLE = {"\\noselect", "\\nonexistent"}


TIMEOUT = 30          # seconds a command may wait for the mail server
CHECK_TIMEOUT = 5     # seconds the check of a kept session, and LOGOUT, may wait: a silent server costs no more
_UNCHANGED = object()

_TRANSIENT_LOGIN = re.compile(r"\[(UNAVAILABLE|SERVERBUG|INUSE|LIMIT)\]", re.IGNORECASE)
_BUSY_LOGIN = re.compile(r"\[(INUSE|LIMIT)\]", re.IGNORECASE)   # may be sent after the password was accepted

class MailError(Exception):
    pass


class MailAuthError(MailError):
    pass


class MailBusy(MailError):
    """[INUSE] or [LIMIT] at login: not a wrong password, but possibly sent only after a right one."""


@dataclass(frozen=True)
class Folder:
    name: str
    delimiter: str
    flags: tuple[str, ...]
    special: str | None


@dataclass(frozen=True)
class SearchQuery:
    text: str | None = None
    from_: str | None = None
    to: str | None = None
    subject: str | None = None
    since: date | None = None
    before: date | None = None
    unread: bool | None = None
    flagged: bool | None = None


def _quote(s: str) -> str:
    if _CTRL.search(s):
        raise MailError("CR, LF and NUL are not allowed in IMAP arguments")
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _mbox(name: str) -> str:
    if _CTRL.search(name):
        raise MailError("CR, LF and NUL are not allowed in folder names")
    return _quote(utf7.encode(name))


def _check_flags(flags) -> None:
    for f in flags:
        if not _FLAG.fullmatch(f):
            raise MailError(f"invalid flag {f!r}")


def _uid_seq(uids) -> str:
    if not uids:
        raise MailError("no messages given")
    for u in uids:
        if type(u) is not int or u <= 0:
            raise MailError("message ids must be positive integers")
    return ",".join(map(str, uids))


def _parse_sexp(data: bytes) -> list:
    """Parse the parenthesised lists, quoted strings and NIL atoms of an IMAP response into
    nested Python lists, bytes and None. Raises ValueError on malformed input."""
    pos = 0

    def skip_space():
        nonlocal pos
        while data[pos:pos + 1] == b" ":
            pos += 1

    def item():
        nonlocal pos
        skip_space()
        ch = data[pos:pos + 1]
        if ch == b"(":
            pos += 1
            out = []
            while True:
                skip_space()
                if data[pos:pos + 1] == b")":
                    pos += 1
                    return out
                out.append(item())
        if ch == b'"':
            pos += 1
            buf = bytearray()
            while True:
                c = data[pos:pos + 1]
                if not c:
                    raise ValueError("unterminated string")
                if c == b"\\":
                    buf += data[pos + 1:pos + 2]
                    pos += 2
                elif c == b'"':
                    pos += 1
                    return bytes(buf)
                else:
                    buf += c
                    pos += 1
        m = re.compile(rb'[^\s()"]+').match(data, pos)
        if not m:
            raise ValueError("unexpected input")
        pos = m.end()
        return None if m.group().upper() == b"NIL" else m.group()

    items = []
    while True:
        skip_space()
        if pos >= len(data):
            return items
        items.append(item())


def _imap_date(d: date) -> str:
    return d.strftime("%d-%b-%Y")


class _Conn(imaplib.IMAP4):
    """IMAP4 over a socket that Connector has already opened and verified. The base class's
    open() wires up the socket and file attributes, which differ between Python 3.11 and 3.14.

    `broken` turns true once a command ends in a dropped or garbled connection (imaplib's abort, or a
    socket error), even if the caller catches it: such a connection is never reused."""
    def __init__(self, sock):
        self._presock = sock
        self.broken = False
        super().__init__(host="", port=0)

    def _create_socket(self, timeout):
        return self._presock

    def _simple_command(self, name, *args):
        try:
            return super()._simple_command(name, *args)
        except (imaplib.IMAP4.abort, OSError):
            self.broken = True
            raise


def _drop(conn) -> None:
    try:
        conn.shutdown()
    except Exception:
        pass


_RESP_CODE = re.compile(r"\s*\[([A-Za-z-]+)")
_APPENDUID = re.compile(rb"\[APPENDUID (\d+) (\d+)\]", re.IGNORECASE)
_CODE_REASONS = {
    "NONEXISTENT": "it does not exist", "TRYCREATE": "the folder does not exist",
    "ALREADYEXISTS": "it already exists", "NOPERM": "no permission", "OVERQUOTA": "the mailbox is over quota",
    "LIMIT": "a mail server limit was reached", "INUSE": "in use; try again shortly",
    "UNAVAILABLE": "temporarily unavailable; try again shortly", "SERVERBUG": "mail server error",
    "CANNOT": "the mail server cannot do this", "EXPUNGEISSUED": "messages were removed meanwhile; try again",
}


_DIGITS = re.compile(r"[0-9]{1,15}")


def limit_value(text: str) -> int | None:
    """A size limit a server announced (SMTP SIZE, IMAP APPENDLIMIT) as bytes; None for anything but ASCII
    digits, and for 0, which both define as no fixed limit."""
    text = (text or "").strip()
    return int(text) if _DIGITS.fullmatch(text) and int(text) > 0 else None


class ImapClient:
    def __init__(self, conn: imaplib.IMAP4, address: str):
        self.c, self.address = conn, address
        self._folders: list[Folder] | None = None
        self._ns: dict | None = None
        self._caps: frozenset[str] | None = None

    @classmethod
    def open(cls, server: MailServer, address: str, password: str) -> "ImapClient":
        """Log in to address's mailbox on server (port server.imap_port). The caller has already
        chosen the server (resolve.Resolver or a stored grant); the address is still validated."""
        address, _ = normalise_address(address)
        # Decided here, outside any except block, so no exception that mentions the password
        # can end up as __context__ of the error we raise.
        unusable = bool(_CTRL.search(password))
        if not unusable and not password.isascii():
            try:
                password.encode("utf-8")
            except UnicodeEncodeError:
                unusable = True
        if unusable:
            raise MailAuthError("password contains characters the mail server login cannot accept")
        sock = Connector(server).tls_connect(server.imap_port)
        try:
            sock.settimeout(TIMEOUT)
            conn = _Conn(sock)
        except (imaplib.IMAP4.abort, OSError) as exc:
            sock.close()
            raise MailError("mail server connection failed") from exc
        except imaplib.IMAP4.error as exc:   # "* BYE" / "* NO" greeting, or no CAPABILITY: an outage, not a password verdict
            sock.close()
            raise MailError("mail server refused the connection") from exc
        except BaseException:
            sock.close()
            raise
        try:
            if password.isascii():
                conn.login(address, password)
            else:  # LOGIN is ASCII-only; AUTHENTICATE PLAIN carries UTF-8
                secret = b"\0" + address.encode() + b"\0" + password.encode("utf-8")
                conn.authenticate("PLAIN", lambda _: secret)
        except (imaplib.IMAP4.abort, OSError) as exc:
            _drop(conn)
            raise MailError("mail server connection failed") from exc
        except imaplib.IMAP4.error as exc:
            _drop(conn)
            # RFC 5530 codes for a server-side fault, not a verdict on the password (Dovecot answers
            # "[UNAVAILABLE] Temporary authentication failure" when its auth backend is down). Treating them
            # as a wrong password would revoke every connected grant during a short outage.
            if _BUSY_LOGIN.search(str(exc)):
                raise MailBusy("mail server is busy for this mailbox") from exc
            if _TRANSIENT_LOGIN.search(str(exc)):
                raise MailError("mail server could not check the password right now") from exc
            raise MailAuthError("mailbox rejected the address or password") from exc
        except BaseException:
            _drop(conn)
            raise
        return cls(conn, address)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    @property
    def broken(self) -> bool:
        return bool(getattr(self.c, "broken", False))

    def reset(self) -> None:
        """Make a session kept from an earlier call behave exactly like a freshly logged-in one, and prove
        the server still answers. A selected folder is closed with UNSELECT (RFC 3691; unlike CLOSE it never
        expunges); otherwise NOOP. Leftover untagged responses, the read-only marker and the cached folder
        list and namespaces are cleared, so the call SELECTs or EXAMINEs as if new. Raises if the connection
        has dropped or does not answer within CHECK_TIMEOUT; the caller then logs in again."""
        if self.broken:
            raise MailError("session is no longer usable")
        previous = self._timeout(CHECK_TIMEOUT)     # a session the network silently dropped fails fast
        try:
            if self.c.state == "SELECTED":
                try:
                    typ, _ = self.c.unselect()
                except imaplib.IMAP4.abort:
                    raise
                except imaplib.IMAP4.error:
                    # BAD: no UNSELECT on this server, but it answered. Every command that reads or changes
                    # messages SELECTs or EXAMINEs first, so the folder left open does not matter.
                    typ = "OK"
            else:
                typ, _ = self.c.noop()
        finally:
            self._timeout(previous)
        if typ != "OK":
            raise MailError("session check failed")
        self.c.untagged_responses = {}
        self.c.is_readonly = False
        self._folders = None
        self._ns = None

    def close(self) -> None:
        """LOGOUT (waiting at most CHECK_TIMEOUT), then shut the connection whatever happened. A session known
        to be broken is not logged out: its socket is shut at once."""
        try:
            if not self.broken:
                self._timeout(CHECK_TIMEOUT)
                self.c.logout()
        except Exception:
            pass
        finally:
            _drop(self.c)        # imaplib's logout() leaves the socket open when LOGOUT fails

    def drop(self) -> None:
        """Shut the connection without LOGOUT (no network wait)."""
        _drop(self.c)

    def interrupt(self) -> None:
        """From another thread, while a command may be waiting on the mail server (the service is stopping):
        shut the socket for both directions, so the waiting read ends at once and the session counts as broken.
        Only the plain socket call is made: closing imaplib's file or the TLS layer here could block on, or
        pull state from under, the thread that is reading."""
        sock = getattr(self.c, "sock", None)
        if sock is None:
            return
        try:
            socket.socket.shutdown(sock, socket.SHUT_RDWR)
        except (OSError, ValueError):
            pass

    def _timeout(self, seconds):
        """Set the socket timeout; returns the one it replaces (_UNCHANGED if there was nothing to set)."""
        sock = getattr(self.c, "sock", None)
        if sock is None or seconds is _UNCHANGED:
            return _UNCHANGED
        try:
            previous = sock.gettimeout()
            sock.settimeout(seconds)
            return previous
        except OSError:
            return _UNCHANGED

    def _ok(self, typ, data, what):
        """The server's free text never goes back to the AI (it can hold internal host names, addresses and
        policy text; security review 2026-10-20, A8): only the RFC 5530 response code and a short reason."""
        if typ != "OK":
            text = data[0].decode(errors="replace") if data and isinstance(data[0], bytes) else ""
            m = _RESP_CODE.match(text)
            code = m.group(1).upper() if m else None
            reason = _CODE_REASONS.get(code, "the mail server refused it")
            raise MailError(f"{what} failed: {reason}" + (f" [{code}]" if code else ""))
        return data

    # folders
    def folders(self) -> list[Folder]:
        if self._folders is None:
            data = self._ok(*self.c.list(), "LIST")
            out = []
            for line in data:
                literal = None
                if isinstance(line, tuple) and len(line) == 2:  # the name arrived as an IMAP literal
                    line, literal = line[0], line[1]
                if not isinstance(line, bytes):
                    continue
                m = _LIST.match(line)
                if not m:
                    continue
                flags = tuple(m["flags"].decode().split())
                delim = m["delim"].decode().strip('"') if m["delim"] != b"NIL" else ""
                raw = m["name"].decode().strip()
                if literal is not None:
                    name = utf7.decode(literal.decode(errors="replace"))
                else:
                    name = utf7.decode(re.sub(r'\\(["\\])', r"\1", raw[1:-1]) if raw.startswith('"') else raw)
                special = next((SPECIAL[f.lower()] for f in flags if f.lower() in SPECIAL), None)
                if name.upper() == "INBOX":
                    special = "inbox"
                out.append(Folder(name, delim, flags, special))
            self._folders = out
        return self._folders

    def special(self, kind: str) -> str | None:
        folders = [f for f in self.folders() if not _UNSELECTABLE & {x.lower() for x in f.flags}]
        for f in folders:
            if f.special == kind:
                return f.name
        for f in folders:
            leaf = f.name.split(f.delimiter)[-1].lower() if f.delimiter else f.name.lower()
            if leaf in FALLBACK.get(kind, ()):
                return f.name
        return None

    def status(self, folder: str) -> dict:
        folder = self.resolve_folder(folder)
        data = self._ok(*self.c.status(_mbox(folder), "(MESSAGES UNSEEN)"), "STATUS")
        nums = dict(re.findall(rb"(MESSAGES|UNSEEN) (\d+)", data[0]))
        return {"messages": int(nums.get(b"MESSAGES", 0)), "unseen": int(nums.get(b"UNSEEN", 0))}

    def capabilities(self) -> frozenset[str]:
        """The capabilities the server lists after login, upper case. imaplib keeps the list from before login,
        which may be shorter (Dovecot), so CAPABILITY is asked once per session."""
        if self._caps is None:
            try:
                typ, data = self.c.capability()
                text = data[0].decode(errors="replace") if typ == "OK" and data and data[0] else ""
            except imaplib.IMAP4.error:
                text = ""
            self._caps = frozenset(text.upper().split()) or frozenset(
                str(c).upper() for c in (getattr(self.c, "capabilities", None) or ()))
        return self._caps

    def append_limit(self, folder: str) -> int | None:
        """The largest message the server accepts into folder (RFC 7889 APPENDLIMIT), or None when it does not
        say. APPENDLIMIT=n holds for every folder; a bare APPENDLIMIT means each folder's STATUS tells."""
        caps = self.capabilities()
        for cap in caps:
            if cap.startswith("APPENDLIMIT="):
                return limit_value(cap.partition("=")[2])
        if "APPENDLIMIT" not in caps:
            return None
        try:
            data = self._ok(*self.c.status(_mbox(self.resolve_folder(folder)), "(APPENDLIMIT)"), "STATUS")
        except (MailError, imaplib.IMAP4.error):
            return None
        m = re.search(rb"APPENDLIMIT ([0-9]+)", data[0] or b"", re.IGNORECASE)
        return limit_value(m.group(1).decode("ascii")) if m else None

    def namespaces(self) -> dict:
        """The server's namespaces (RFC 2342). A server without NAMESPACE has one personal namespace with no
        prefix, which is what an empty answer means here."""
        empty = {"personal": [], "other": [], "shared": []}
        caps = getattr(self.c, "capabilities", None)
        if caps is not None and "NAMESPACE" not in {str(c).upper() for c in caps}:
            # imaplib keeps the capabilities from before login, and Dovecot lists NAMESPACE only after it,
            # so ask the server again before deciding it has none.
            try:
                typ, data = self.c.capability()
                caps = data[0].decode(errors="replace").upper().split() if typ == "OK" and data and data[0] else []
            except imaplib.IMAP4.error:
                caps = []
            if "NAMESPACE" not in caps:
                return empty
        try:
            typ, data = self.c.namespace()
        except imaplib.IMAP4.error:          # BAD from a server that does not support it after all
            return empty
        if typ != "OK" or not data or not data[0]:
            return {"personal": [], "other": [], "shared": []}
        try:
            groups = _parse_sexp(data[0])
        except ValueError:
            return {"personal": [], "other": [], "shared": []}
        groups = (groups + [None] * 3)[:3]

        def parse(group):  # each entry is [prefix, delimiter, *extension data]
            return [[utf7.decode(e[0].decode()), e[1].decode() if len(e) > 1 and e[1] else ""]
                    for e in group or [] if isinstance(e, list) and e and e[0] is not None]
        return {"personal": parse(groups[0]), "other": parse(groups[1]), "shared": parse(groups[2])}

    def resolve_folder(self, name: str) -> str:
        """Map a folder name as a person or AI app gives it ("Sent", "INBOX.Sent", "sent items", "Archive")
        to this server's name for it, so one name works on every server whatever its naming.

        In order: INBOX; an existing folder of exactly that name; the name with any personal-namespace
        prefix ("INBOX." or "INBOX/", as Plesk/Courier-style Dovecot uses) removed or this server's prefix
        added, if that folder exists; the same names ignoring case; a role name or common alias (inbox,
        sent, drafts, trash, junk, spam, archive, "Sent Items", "Deleted Items" ...) as the folder with
        that role (RFC 6154 flag, then the usual names). A name that matches nothing is kept, inside this server's
        personal namespace if it has a prefix, so CREATE puts a new folder there. Names in other-users/shared namespaces are
        unchanged."""
        if name.upper() == "INBOX":
            return name
        if self._ns is None:
            self._ns = self.namespaces()
        if any(p and name.startswith(p) for p, _ in self._ns["other"] + self._ns["shared"]):
            return name
        names = {f.name for f in self.folders()}
        if name in names:
            return name
        personal = self._ns["personal"]
        prefix = personal[0][0] if personal else ""
        bare = name
        for p in dict.fromkeys(x for x in (prefix, *_PERSONAL_PREFIXES) if x):
            if len(name) > len(p) and name.upper().startswith(p.upper()):
                bare = name[len(p):]
                break
        candidates = list(dict.fromkeys(x for x in (bare, prefix + bare) if x))
        for c in candidates:
            if c in names:
                return c
        by_lower = {n.lower(): n for n in sorted(names)}
        for c in candidates:
            if c.lower() in by_lower:
                return by_lower[c.lower()]
        role = ROLE_NAMES.get(bare.strip().lower())
        if role == "inbox":
            return "INBOX"
        if role and (found := self.special(role)):
            return found
        return name if not prefix or name.upper().startswith(prefix.upper()) else prefix + name

    def myrights(self, folder: str) -> str | None:
        try:
            typ, data = self.c.myrights(_mbox(folder))
        except imaplib.IMAP4.error:
            return None
        if typ != "OK" or not data or not data[0]:
            return None
        return data[0].split()[-1].decode().strip('"')

    def _select(self, folder: str, readonly: bool) -> None:
        folder = self.resolve_folder(folder)
        self._ok(*self.c.select(_mbox(folder), readonly=readonly), f"SELECT {folder}")

    # search and fetch
    def _criteria(self, q: SearchQuery) -> tuple[list[str], bytes | None]:
        crit: list[str] = []
        literal_key: str | None = None
        literal: bytes | None = None
        for key, val in (("TEXT", q.text), ("FROM", q.from_), ("TO", q.to), ("SUBJECT", q.subject)):
            if not val:
                continue
            if val.isascii():
                crit += [key, _quote(val)]
            elif _CTRL.search(val):
                raise MailError("CR, LF and NUL are not allowed in search terms")
            elif literal is None:
                literal_key, literal = key, val.encode()
            else:
                raise MailError("only one non-ASCII search term is supported per search")
        if q.since:
            crit += ["SINCE", _imap_date(q.since)]
        if q.before:
            crit += ["BEFORE", _imap_date(q.before)]
        if q.unread is True:
            crit.append("UNSEEN")
        elif q.unread is False:
            crit.append("SEEN")
        if q.flagged is True:
            crit.append("FLAGGED")
        elif q.flagged is False:
            crit.append("UNFLAGGED")
        if literal_key:
            crit.append(literal_key)  # imaplib sends the literal after the last argument
        return crit or ["ALL"], literal

    def search(self, folder: str, query: SearchQuery, limit: int = 25, offset: int = 0) -> tuple[int, list[dict]]:
        crit, literal = self._criteria(query)
        self._select(folder, readonly=True)
        if literal is not None:
            self.c.literal = literal
            data = self._ok(*self.c.uid("SEARCH", "CHARSET", "UTF-8", *crit), "SEARCH")
        else:
            data = self._ok(*self.c.uid("SEARCH", *crit), "SEARCH")
        uids = sorted((int(u) for u in (data[0] or b"").split()), reverse=True)
        page = uids[offset:offset + limit]
        return len(uids), self._summaries(page)

    def _summaries(self, uids: list[int]) -> list[dict]:
        if not uids:
            return []
        data = self._ok(*self.c.uid("FETCH", ",".join(map(str, uids)),
                        "(UID FLAGS RFC822.SIZE BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE MESSAGE-ID)])"), "FETCH")
        rows = {}
        for i, item in enumerate(data):
            if not isinstance(item, tuple):
                continue
            meta, header = item
            if i + 1 < len(data) and isinstance(data[i + 1], bytes):
                meta += b" " + data[i + 1]  # some servers send FLAGS/UID after the header literal
            uid = int(re.search(rb"UID (\d+)", meta).group(1))
            flags = re.search(rb"FLAGS \(([^)]*)\)", meta)
            size = re.search(rb"RFC822\.SIZE (\d+)", meta)
            h = BytesHeaderParser(policy=email_policy.default).parsebytes(header)
            rows[uid] = {"uid": uid, "date": str(h.get("Date", "")), "from": str(h.get("From", "")),
                         "subject": str(h.get("Subject", "")), "message_id": str(h.get("Message-ID", "")),
                         "flags": flags.group(1).decode().split() if flags else [],
                         "size": int(size.group(1)) if size else 0}
        return [rows[u] for u in uids if u in rows]

    def fetch_raw(self, folder: str, uid: int, max_bytes: int = 25_000_000) -> bytes:
        _uid_seq([uid])
        self._select(folder, readonly=True)
        data = self._ok(*self.c.uid("FETCH", str(uid), "(RFC822.SIZE)"), "FETCH")
        m = re.search(rb"RFC822\.SIZE (\d+)", data[0] or b"")
        if not m:
            raise MailError(f"message {uid} not found in {folder}")
        if int(m.group(1)) > max_bytes:
            raise MailError(f"message {uid} is too large ({int(m.group(1))} bytes; cap {max_bytes})")
        data = self._ok(*self.c.uid("FETCH", str(uid), "(BODY.PEEK[])"), "FETCH")
        for item in data:
            if isinstance(item, tuple):
                return item[1]
        raise MailError(f"message {uid} not found in {folder}")

    def find_by_message_id(self, folder: str, message_id: str, references: bool = True) -> list[int]:
        """UIDs of the messages with this Message-ID and, with references=True, those that refer to it."""
        if not message_id.isascii():
            raise MailError("message id must be ASCII")
        quoted = _quote(message_id)
        self._select(folder, readonly=True)
        crit = (["OR", "HEADER", "Message-ID", quoted, "HEADER", "References", quoted] if references
                else ["HEADER", "Message-ID", quoted])
        data = self._ok(*self.c.uid("SEARCH", *crit), "SEARCH")
        return [int(u) for u in (data[0] or b"").split()]

    # changes
    def set_flags(self, folder: str, uids: list[int], add: list[str], remove: list[str]) -> None:
        seq = _uid_seq(uids)
        _check_flags(add)
        _check_flags(remove)
        self._select(folder, readonly=False)
        if add:
            self._ok(*self.c.uid("STORE", seq, "+FLAGS.SILENT", "(" + " ".join(add) + ")"), "STORE")
        if remove:
            self._ok(*self.c.uid("STORE", seq, "-FLAGS.SILENT", "(" + " ".join(remove) + ")"), "STORE")

    def ensure_folder(self, name: str) -> str:
        """Create the folder if it does not exist; return the name it has on the server."""
        name = self.resolve_folder(name)
        if not any(f.name == name for f in self.folders()):
            self._ok(*self.c.create(_mbox(name)), f"CREATE {name}")
            self._folders = None
        return name

    def move(self, folder: str, uids: list[int], dest: str, copy: bool = False) -> None:
        """Move or copy to an existing folder. A missing one is never created here: the server's [TRYCREATE]
        comes back as "the folder does not exist"."""
        seq = _uid_seq(uids)
        target = _mbox(self.resolve_folder(dest))
        self._select(folder, readonly=False)
        self._ok(*self.c.uid("COPY" if copy else "MOVE", seq, target), "COPY" if copy else "MOVE")

    def append(self, folder: str, raw: bytes, flags: tuple[str, ...], message_id: str | None = None) -> int | None:
        """APPEND a message; returns its UID: from APPENDUID (RFC 4315 UIDPLUS) when the server sends it, else,
        given the message's Message-ID, from a search for it (the newest match), else None."""
        _check_flags(flags)
        folder = self.resolve_folder(folder)
        data = self._ok(*self.c.append(_mbox(folder), "(" + " ".join(flags) + ")" if flags else None,
                                       imaplib.Time2Internaldate(time.time()), raw), "APPEND")
        text = data[0] if data and isinstance(data[0], bytes) else b""
        m = _APPENDUID.search(text)
        if m:
            return int(m.group(2))
        if not message_id or not str(message_id).isascii():
            return None
        try:
            found = self.find_by_message_id(folder, str(message_id), references=False)
        except (MailError, imaplib.IMAP4.error, OSError):     # best effort: the message is already stored
            return None
        return max(found) if found else None
