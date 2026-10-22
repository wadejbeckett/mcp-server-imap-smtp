# SPDX-License-Identifier: AGPL-3.0-or-later
"""Offline tests: ImapClient driven by a stub imaplib-like connection returning canned (typ, data)."""
import base64
import imaplib
import socket
import threading
from datetime import date

import pytest

from mcp_server_imap_smtp.mail import imap
from mcp_server_imap_smtp.mail.hosts import Connector, MailServer
from mcp_server_imap_smtp.mail.imap import ImapClient, MailAuthError, MailError, SearchQuery


class StubConn:
    """Records every call as (name, args, literal-at-call-time); replies from `resp`."""

    def __init__(self, **resp):
        self.resp = resp
        self.calls = []
        self.literal = None

    def _do(self, key, *args):
        self.calls.append((key, args, self.literal))
        r = self.resp.get(key, ("OK", [None]))
        return r(*args) if callable(r) else r

    def list(self): return self._do("list")
    def status(self, mbox, what): return self._do("status", mbox, what)
    def namespace(self): return self._do("namespace")
    def capability(self): return self._do("capability")
    def myrights(self, mbox): return self._do("myrights", mbox)
    def select(self, mbox, readonly=False): return self._do("select", mbox, readonly)
    def create(self, mbox): return self._do("create", mbox)
    def append(self, mbox, flags, date_time, raw): return self._do("append", mbox, flags, raw)
    def uid(self, cmd, *args): return self._do(f"uid {cmd}", *args)
    def logout(self): return self._do("logout")


def client(**resp):
    stub = StubConn(select=("OK", [b"1"]), **resp)
    return ImapClient(stub, "me@x.co.za"), stub


LIST = [
    rb'(\HasNoChildren) "." INBOX',
    rb'(\HasNoChildren \Sent) "." INBOX.Sent',
    rb'(\HasNoChildren) "." INBOX.Trash',
    rb'(\HasNoChildren) "." "INBOX.Entw&APw-rfe"',
    rb'(\HasNoChildren) "." "INBOX.say \"hi\" \\ there"',
    rb'(\Noselect \HasChildren) "." INBOX.Archive',
    ("not-bytes",),
    b"garbage line",
]


def test_folders_parse_decode_and_roles():
    c, _ = client(list=("OK", LIST))
    folders = c.folders()
    by_name = {f.name: f for f in folders}
    assert list(by_name) == ["INBOX", "INBOX.Sent", "INBOX.Trash", "INBOX.Entwürfe",
                             'INBOX.say "hi" \\ there', "INBOX.Archive"]
    assert all(f.delimiter == "." for f in folders)
    assert by_name["INBOX"].special == "inbox"
    assert by_name["INBOX.Sent"].flags == ("\\HasNoChildren", "\\Sent")
    assert by_name["INBOX.Sent"].special == "sent"
    assert by_name["INBOX.Trash"].special is None
    assert by_name["INBOX.Archive"].flags == ("\\Noselect", "\\HasChildren")


def test_folders_cached_single_list_call():
    c, stub = client(list=("OK", LIST))
    c.folders(); c.folders()
    assert [k for k, *_ in stub.calls].count("list") == 1


def test_folders_list_failure_is_mailerror():
    c, _ = client(list=("NO", [b"nope"]))
    with pytest.raises(MailError, match="LIST failed: nope"):
        c.folders()


def test_special_by_flag_fallback_name_and_noselect():
    c, _ = client(list=("OK", LIST))
    assert c.special("sent") == "INBOX.Sent"       # by \Sent flag
    assert c.special("trash") == "INBOX.Trash"     # by leaf-name fallback
    assert c.special("archive") is None            # INBOX.Archive is \Noselect
    assert c.special("junk") is None
    assert c.special("inbox") == "INBOX"


def test_namespaces_personal_and_shared():
    c, _ = client(namespace=("OK", [b'(("INBOX." ".")) NIL (("shared." "."))']))
    assert c.namespaces() == {"personal": [["INBOX.", "."]], "other": [], "shared": [["shared.", "."]]}


def test_namespaces_several_entries_per_group():
    c, _ = client(namespace=("OK", [b'(("" "/") ("#mbox/" "/")) (("~" "/")) NIL']))
    assert c.namespaces() == {"personal": [["", "/"], ["#mbox/", "/"]], "other": [["~", "/"]], "shared": []}


def test_namespaces_all_nil_and_failure():
    c, _ = client(namespace=("OK", [b"NIL NIL NIL"]))
    assert c.namespaces() == {"personal": [], "other": [], "shared": []}
    c, _ = client(namespace=("NO", [b"x"]))
    assert c.namespaces() == {"personal": [], "other": [], "shared": []}


def test_status_and_myrights():
    c, stub = client(status=("OK", [b'"INBOX.Entw&APw-rfe" (MESSAGES 12 UNSEEN 3)']),
                     myrights=("OK", [b"INBOX.Sent lrswipkxtecda"]))
    assert c.status("INBOX.Entwürfe") == {"messages": 12, "unseen": 3}
    assert [a for k, a, _ in stub.calls if k == "status"][0][0] == '"INBOX.Entw&APw-rfe"'
    assert c.myrights("INBOX.Sent") == "lrswipkxtecda"


def test_myrights_none_when_unsupported():
    c, _ = client(myrights=("NO", [b"no acl"]))
    assert c.myrights("INBOX") is None
    c, _ = client(myrights=("OK", [None]))
    assert c.myrights("INBOX") is None

    def boom(_):
        raise imaplib.IMAP4.error("BAD unknown command")
    c, _ = client(myrights=boom)
    assert c.myrights("INBOX") is None


def uid_calls(stub, cmd):
    return [(a, lit) for k, a, lit in stub.calls if k == f"uid {cmd}"]


def test_search_ascii_criteria_quoting_and_dates():
    c, stub = client(**{"uid SEARCH": ("OK", [b"3 9 5"]), "uid FETCH": ("OK", [])})
    q = SearchQuery(text='say "hi"', from_="a\\b@x.co.za", since=date(2026, 1, 5), before=date(2026, 10, 31),
                    unread=True, flagged=False)
    total, rows = c.search("INBOX", q)
    assert total == 3 and rows == []
    (args, literal), = uid_calls(stub, "SEARCH")
    assert literal is None
    assert args == ("TEXT", '"say \\"hi\\""', "FROM", '"a\\\\b@x.co.za"', "SINCE", "05-Jan-2026",
                    "BEFORE", "31-Oct-2026", "UNSEEN", "UNFLAGGED")


def test_search_read_and_flagged_and_all():
    c, stub = client(**{"uid SEARCH": ("OK", [b""])})
    c.search("INBOX", SearchQuery(unread=False, flagged=True))
    c.search("INBOX", SearchQuery())
    (a1, _), (a2, _) = uid_calls(stub, "SEARCH")
    assert a1 == ("SEEN", "FLAGGED") and a2 == ("ALL",)


def test_search_opens_folder_readonly_and_encodes_name():
    c, stub = client(**{"uid SEARCH": ("OK", [None])})
    assert c.search("INBOX.Entwürfe", SearchQuery()) == (0, [])
    assert [x for x in stub.calls if x[0] not in ("namespace", "list")][0] == ("select", ('"INBOX.Entw&APw-rfe"', True), None)


def test_search_one_non_ascii_term_uses_utf8_literal_as_last_token():
    c, stub = client(**{"uid SEARCH": ("OK", [b"1"]), "uid FETCH": ("OK", [])})
    c.search("INBOX", SearchQuery(subject="Entwürfe", since=date(2026, 1, 5), from_="a@x.co.za"))
    (args, literal), = uid_calls(stub, "SEARCH")
    assert literal == "Entwürfe".encode()
    # imaplib appends the literal after the final argument, so the non-ASCII key must be last.
    assert args == ("CHARSET", "UTF-8", "FROM", '"a@x.co.za"', "SINCE", "05-Jan-2026", "SUBJECT")


def test_search_two_non_ascii_terms_is_mailerror():
    c, stub = client()
    with pytest.raises(MailError, match="only one non-ASCII"):
        c.search("INBOX", SearchQuery(subject="Entwürfe", text="café"))
    assert not uid_calls(stub, "SEARCH")


def header(**h):
    return "".join(f"{k}: {v}\r\n" for k, v in h.items()).encode() + b"\r\n"


FETCH = [
    (b"1 (UID 5 FLAGS (\\Seen \\Flagged) RFC822.SIZE 321 BODY[HEADER.FIELDS (FROM SUBJECT DATE MESSAGE-ID)] {99}",
     header(From="Ann <a@x.co.za>", Subject="=?utf-8?q?Entw=C3=BCrfe?=", Date="Mon, 05 Oct 2026 10:00:00 +0200",
            **{"Message-ID": "<m5@x>"})),
    b")",
    (b"2 (UID 9 FLAGS () RFC822.SIZE 100 BODY[HEADER.FIELDS (FROM SUBJECT DATE MESSAGE-ID)] {40}",
     header(Subject="plain")),
    b")",
    # server that puts FLAGS after the literal
    (b"3 (UID 3 RFC822.SIZE 7 BODY[HEADER.FIELDS (FROM SUBJECT DATE MESSAGE-ID)] {20}", header(Subject="late")),
    b" FLAGS (\\Answered))",
]


def test_summaries_parse_in_requested_order():
    c, stub = client(**{"uid FETCH": ("OK", FETCH)})
    rows = c._summaries([9, 5, 3, 77])           # 77 not returned by the server
    assert [r["uid"] for r in rows] == [9, 5, 3]
    assert uid_calls(stub, "FETCH")[0][0][0] == "9,5,3,77"
    five = rows[1]
    assert five == {"uid": 5, "date": "Mon, 05 Oct 2026 10:00:00 +0200", "from": "Ann <a@x.co.za>",
                    "subject": "Entwürfe", "message_id": "<m5@x>", "flags": ["\\Seen", "\\Flagged"], "size": 321}
    assert rows[0]["flags"] == [] and rows[0]["from"] == "" and rows[0]["subject"] == "plain"
    assert rows[2]["flags"] == ["\\Answered"] and rows[2]["size"] == 7


def test_summaries_empty_makes_no_call():
    c, stub = client()
    assert c._summaries([]) == []
    assert not stub.calls


def test_search_pages_newest_first_with_total():
    def fetch(seq, _what):
        return "OK", [(f"{i} (UID {u} FLAGS () RFC822.SIZE 1 BODY[HEADER.FIELDS ()] {{2}}".encode(), b"\r\n")
                       for i, u in enumerate(seq.split(","))]
    c, stub = client(**{"uid SEARCH": ("OK", [b"4 1 7 2 9"]), "uid FETCH": fetch})
    total, first = c.search("INBOX", SearchQuery(), limit=2)
    assert total == 5 and [r["uid"] for r in first] == [9, 7]
    _, second = c.search("INBOX", SearchQuery(), limit=2, offset=2)
    assert [r["uid"] for r in second] == [4, 2]
    _, third = c.search("INBOX", SearchQuery(), limit=2, offset=4)
    assert [r["uid"] for r in third] == [1]


def test_fetch_raw_returns_body():
    def fetch(uid, what):
        if what == "(RFC822.SIZE)":
            return "OK", [b"1 (UID 5 RFC822.SIZE 20)"]
        return "OK", [(b"1 (UID 5 BODY[] {20}", b"Subject: hi\r\n\r\nbody"), b")"]
    c, _ = client(**{"uid FETCH": fetch})
    assert c.fetch_raw("INBOX", 5) == b"Subject: hi\r\n\r\nbody"


def test_fetch_raw_oversize_never_downloads_body():
    c, stub = client(**{"uid FETCH": ("OK", [b"1 (UID 5 RFC822.SIZE 20000)"])})
    with pytest.raises(MailError, match="too large"):
        c.fetch_raw("INBOX", 5, max_bytes=10_000)
    assert len(uid_calls(stub, "FETCH")) == 1


def test_fetch_raw_missing_message():
    c, _ = client(**{"uid FETCH": ("OK", [None])})
    with pytest.raises(MailError, match="not found"):
        c.fetch_raw("INBOX", 5)


def test_fetch_raw_body_missing_after_size():
    answers = iter([("OK", [b"1 (UID 5 RFC822.SIZE 20)"]), ("OK", [None])])
    c, _ = client(**{"uid FETCH": lambda *a: next(answers)})
    with pytest.raises(MailError, match="not found"):
        c.fetch_raw("INBOX", 5)


def test_find_by_message_id_and_flags_and_move_and_append():
    c, stub = client(**{"uid SEARCH": ("OK", [b"4 8"]), "uid STORE": ("OK", [None]), "uid MOVE": ("OK", [None]),
                        "uid COPY": ("OK", [None])},
                     list=("OK", [rb'(\HasNoChildren) "." INBOX']), create=("OK", [None]), append=("OK", [None]))
    assert c.find_by_message_id("INBOX", "<a@b>") == [4, 8]
    assert uid_calls(stub, "SEARCH")[0][0] == ("OR", "HEADER", "Message-ID", '"<a@b>"', "HEADER", "References", '"<a@b>"')
    c.set_flags("INBOX", [4, 8], add=["\\Seen"], remove=["\\Flagged"])
    assert [a for a, _ in uid_calls(stub, "STORE")] == [("4,8", "+FLAGS.SILENT", "(\\Seen)"),
                                                       ("4,8", "-FLAGS.SILENT", "(\\Flagged)")]
    c.move("INBOX", [4], "Entwürfe ✓")
    assert ("create", ('"Entw&APw-rfe &JxM-"',), None) in stub.calls
    assert uid_calls(stub, "MOVE")[0][0] == ("4", '"Entw&APw-rfe &JxM-"')
    c.move("INBOX", [4], "INBOX", copy=True)
    assert uid_calls(stub, "COPY")[0][0] == ("4", '"INBOX"')
    assert [k for k, *_ in stub.calls].count("create") == 1
    c.append("INBOX", b"raw", ("\\Seen",))
    assert stub.calls[-1][:2] == ("append", ('"INBOX"', "(\\Seen)", b"raw"))
    c.append("INBOX", b"raw", ())
    assert stub.calls[-1][1][1] is None


# open()

class FakeSock:
    def __init__(self): self.timeout = None; self.closed = False
    def settimeout(self, t): self.timeout = t
    def close(self): self.closed = True


def patch_open(monkeypatch, login=None, authenticate=None, construct=None):
    sock = FakeSock()
    holder = {"calls": []}

    class FakeConn:
        def __init__(self, s):
            holder["conn"] = self
            holder["sock"] = s
            self.shut = False
            if construct:
                construct()
        def login(self, user, password):
            holder["calls"].append(("login", user, password))
            return login(user, password)
        def authenticate(self, mech, cb):
            holder["calls"].append(("authenticate", mech, cb(b"")))
            return authenticate(mech, cb)
        def shutdown(self): self.shut = True
        def logout(self): pass

    monkeypatch.setattr(Connector, "tls_connect", lambda self, port, timeout=10.0: sock)
    monkeypatch.setattr(imap, "_Conn", FakeConn)
    return sock, holder


SERVER = MailServer("mail1.hosting.example")


def test_open_success_normalises_address(monkeypatch):
    sock, holder = patch_open(monkeypatch, lambda u, p: ("OK", [b"done"]))
    c = ImapClient.open(SERVER, " Me@X.co.za ", "pw")
    assert c.address == "me@x.co.za" and holder["calls"] == [("login", "me@x.co.za", "pw")] and sock.timeout == 30


def assert_no_leak(exc, password):
    for text in (str(exc), repr(exc), repr(exc.__cause__), repr(exc.__context__)):
        assert password not in text


def test_open_login_no_is_autherror_without_password(monkeypatch):
    password = "S3cret-Passw0rd!"

    def reject(user, pw):
        raise imaplib.IMAP4.error(b"[AUTHENTICATIONFAILED] Authentication failed.")
    _, holder = patch_open(monkeypatch, reject)
    with pytest.raises(MailAuthError) as ei:
        ImapClient.open(SERVER, "me@x.co.za", password)
    assert_no_leak(ei.value, password)
    assert holder["conn"].shut


@pytest.mark.parametrize("exc", [imaplib.IMAP4.abort("socket error: EOF"), ConnectionResetError("reset"),
                                 TimeoutError("timed out")])
def test_open_connection_failure_during_login_is_not_autherror(monkeypatch, exc):
    def drop(user, pw):
        raise exc
    _, holder = patch_open(monkeypatch, drop)
    with pytest.raises(MailError, match="connection failed") as ei:
        ImapClient.open(SERVER, "me@x.co.za", "pw")
    assert not isinstance(ei.value, MailAuthError)
    assert holder["conn"].shut


def test_open_connection_failure_during_greeting_closes_socket(monkeypatch):
    def boom():
        raise imaplib.IMAP4.abort("bad greeting")
    sock, _ = patch_open(monkeypatch, lambda u, p: ("OK", []), construct=boom)
    with pytest.raises(MailError, match="connection failed") as ei:
        ImapClient.open(SERVER, "me@x.co.za", "pw")
    assert not isinstance(ei.value, MailAuthError)
    assert sock.closed


def test_open_non_ascii_password_uses_authenticate_plain(monkeypatch):
    password = "pässword-S3cret"
    _, holder = patch_open(monkeypatch, authenticate=lambda m, cb: ("OK", [b"done"]))
    ImapClient.open(SERVER, "me@x.co.za", password)
    assert holder["calls"] == [("authenticate", "PLAIN", b"\0me@x.co.za\0" + password.encode("utf-8"))]


def test_open_non_ascii_password_failure_does_not_leak_it(monkeypatch):
    password = "pässword-S3cret"

    def reject(m, cb):
        cb(b"")
        raise imaplib.IMAP4.error(b"[AUTHENTICATIONFAILED] nope")
    _, holder = patch_open(monkeypatch, authenticate=reject)
    with pytest.raises(MailAuthError) as ei:
        ImapClient.open(SERVER, "me@x.co.za", password)
    assert_no_leak(ei.value, password)
    assert holder["conn"].shut


@pytest.mark.parametrize("password", ["bad\ud800-S3cret", "line\r\nA1 DELETE INBOX", "nul\0pw"])
def test_open_unusable_password_rejected_before_connecting(monkeypatch, password):
    _, holder = patch_open(monkeypatch, lambda u, p: ("OK", []))
    with pytest.raises(MailAuthError) as ei:
        ImapClient.open(SERVER, "me@x.co.za", password)
    assert_no_leak(ei.value, password)
    assert ei.value.__cause__ is None and ei.value.__context__ is None
    assert "conn" not in holder


class ScriptedServer:
    """Real socket pair; `handler(tag, command_line, readline, send) -> bytes` answers each client command."""

    def __init__(self, handler, greeting=b"* OK ready\r\n"):
        self.client, self.server = socket.socketpair()
        self.client.settimeout(5); self.server.settimeout(5)
        self.seen = []
        self.thread = threading.Thread(target=self._run, args=(handler,), daemon=True)
        self.server.sendall(greeting)
        self.thread.start()

    def _run(self, handler):
        f = self.server.makefile("rb")
        try:
            while line := f.readline():
                tag = line.split()[0]
                if line.split()[1:2] == [b"CAPABILITY"]:  # imaplib asks right after the greeting
                    self.server.sendall(b"* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\n" + tag + b" OK done\r\n")
                    continue
                self.seen.append(line)
                self.server.sendall(handler(tag, line, f.readline, self.server.sendall))
        except OSError:
            pass

    def close(self):
        self.server.close(); self.thread.join(5)


def logout_ok(tag, line, readline, send):
    return b"* BYE bye\r\n" + tag + b" OK done\r\n"


def test_real_conn_over_socketpair_constructs_and_logs_out():
    srv = ScriptedServer(logout_ok)
    try:
        conn = imap._Conn(srv.client)        # reads the canned greeting through the real imaplib
        assert conn.state == "NONAUTH" and "AUTH=PLAIN" in conn.capabilities
        conn.logout()                         # real LOGOUT round trip, then shutdown closes the socket
        assert srv.client.fileno() == -1
        assert srv.seen[0].split()[1] == b"LOGOUT"
    finally:
        srv.close()


def open_over_socketpair(monkeypatch, handler, **kw):
    srv = ScriptedServer(handler, **kw)
    monkeypatch.setattr(Connector, "tls_connect", lambda self, port, timeout=10.0: srv.client)
    return srv


def test_open_real_conn_login_ok_and_no(monkeypatch):
    def handler(tag, line, readline, send):
        if b" LOGIN " in line:
            ok = b'"pw"' in line
            return tag + (b" OK logged in\r\n" if ok else b" NO [AUTHENTICATIONFAILED] bad\r\n")
        return logout_ok(tag, line, readline, send)
    srv = open_over_socketpair(monkeypatch, handler)
    try:
        with ImapClient.open(SERVER, "me@x.co.za", "pw") as c:
            assert c.address == "me@x.co.za"
        assert srv.seen[0].split()[1:3] == [b"LOGIN", b"me@x.co.za"]
    finally:
        srv.close()
    srv = open_over_socketpair(monkeypatch, handler)
    try:
        with pytest.raises(MailAuthError):
            ImapClient.open(SERVER, "me@x.co.za", "wrong")
    finally:
        srv.close()


@pytest.mark.parametrize("greeting", [b"* BYE Too many connections from your IP\r\n",
                                      b"* NO Server temporarily unavailable\r\n"])
def test_open_real_conn_refusing_greeting_is_mailerror_and_closes_socket(monkeypatch, greeting):
    srv = open_over_socketpair(monkeypatch, logout_ok, greeting=greeting)
    try:
        with pytest.raises(MailError, match="mail server refused the connection") as ei:
            ImapClient.open(SERVER, "me@x.co.za", "pw")
        assert not isinstance(ei.value, MailAuthError)
        assert srv.client.fileno() == -1 and srv.seen == []
    finally:
        srv.close()


def test_open_greeting_without_capability_is_mailerror(monkeypatch):
    def no_capability():
        raise imaplib.IMAP4.error("no CAPABILITY response from server")
    sock, _ = patch_open(monkeypatch, lambda u, p: ("OK", []), construct=no_capability)
    with pytest.raises(MailError, match="mail server refused the connection") as ei:
        ImapClient.open(SERVER, "me@x.co.za", "pw")
    assert not isinstance(ei.value, MailAuthError) and sock.closed


def test_open_real_conn_non_ascii_password_authenticate_plain(monkeypatch):
    password = "pässword"
    got = []

    def handler(tag, line, readline, send):
        if b" AUTHENTICATE PLAIN" in line:
            send(b"+ \r\n")
            got.append(base64.b64decode(readline().strip()))
            return tag + b" OK authenticated\r\n"
        return logout_ok(tag, line, readline, send)
    srv = open_over_socketpair(monkeypatch, handler)
    try:
        with ImapClient.open(SERVER, "me@x.co.za", password):
            pass
    finally:
        srv.close()
    assert got == [b"\0me@x.co.za\0" + password.encode("utf-8")]


def test_context_manager_logs_out_and_swallows_logout_errors():
    def bad_logout():
        raise OSError("gone")
    c, stub = client(logout=bad_logout)
    with c:
        pass
    assert stub.calls[-1][0] == "logout"


def test_namespaces_nil_delimiter():
    c, _ = client(namespace=("OK", [b'(("" NIL)) NIL NIL']))
    assert c.namespaces()["personal"] == [["", ""]]


# injection and input validation

EVIL = 'x\r\nA1 DELETE INBOX.Sent'


@pytest.mark.parametrize("field", ["text", "from_", "to", "subject"])
@pytest.mark.parametrize("bad", ["x\r\nA1 DELETE INBOX.Sent", "x\ny", "x\ry", "x\0y"])
def test_search_rejects_control_chars_in_every_field(field, bad):
    c, stub = client()
    with pytest.raises(MailError):
        c.search("INBOX", SearchQuery(**{field: bad}))
    assert not uid_calls(stub, "SEARCH")


@pytest.mark.parametrize("field", ["text", "from_", "to", "subject"])
def test_search_rejects_control_chars_in_non_ascii_literal(field):
    c, stub = client()
    with pytest.raises(MailError):
        c.search("INBOX", SearchQuery(**{field: "Entwürfe\r\nA1 DELETE INBOX"}))
    assert stub.literal is None and not uid_calls(stub, "SEARCH")


def test_message_id_rejects_crlf_and_non_ascii():
    c, stub = client()
    for bad in (EVIL, "<ü@x>"):
        with pytest.raises(MailError):
            c.find_by_message_id("INBOX", bad)
    assert not uid_calls(stub, "SEARCH")


@pytest.mark.parametrize("name", ["INBOX.a\r\nA1 DELETE INBOX", "a\nb", "a\rb", "a\0b"])
def test_folder_names_reject_control_chars(name):
    c, stub = client(list=("OK", [rb'(\HasNoChildren) "." INBOX']))
    with pytest.raises(MailError):
        c.search(name, SearchQuery())
    with pytest.raises(MailError):
        c.status(name)
    with pytest.raises(MailError):
        c.myrights(name)
    with pytest.raises(MailError):
        c.move("INBOX", [1], name)
    with pytest.raises(MailError):
        c.append(name, b"raw", ())
    assert [k for k, *_ in stub.calls if k in ("select", "status", "create", "append", "myrights")] == []


@pytest.mark.parametrize("flag", ["\\Seen\r\nA1 DELETE INBOX", "Seen)", "\\\\Seen", "", "\\", "a b", "\\Seen\n"])
def test_bad_flags_rejected(flag):
    c, stub = client()
    with pytest.raises(MailError, match="flag"):
        c.set_flags("INBOX", [1], add=[flag], remove=[])
    with pytest.raises(MailError, match="flag"):
        c.set_flags("INBOX", [1], add=[], remove=[flag])
    with pytest.raises(MailError, match="flag"):
        c.append("INBOX", b"raw", (flag,))
    assert not [k for k, *_ in stub.calls if k in ("uid STORE", "append")]


def test_good_flags_accepted():
    c, stub = client(**{"uid STORE": ("OK", [None])})
    c.set_flags("INBOX", [1], add=["\\Seen", "$Forwarded", "Work-Item_1.x"], remove=[])
    assert uid_calls(stub, "STORE")[0][0] == ("1", "+FLAGS.SILENT", "(\\Seen $Forwarded Work-Item_1.x)")


@pytest.mark.parametrize("uids", [[], [0], [-3], ["1"], ["1:*"], [1.5], [True], ["1\r\nA1 DELETE INBOX"]])
def test_bad_uids_rejected(uids):
    c, stub = client()
    with pytest.raises(MailError):
        c.set_flags("INBOX", uids, add=["\\Seen"], remove=[])
    with pytest.raises(MailError):
        c.move("INBOX", uids, "INBOX")
    assert not [k for k, *_ in stub.calls if k in ("uid STORE", "uid MOVE", "select")]


def test_empty_uids_message():
    c, _ = client()
    with pytest.raises(MailError, match="no messages given"):
        c.set_flags("INBOX", [], add=["\\Seen"], remove=[])


def test_fetch_raw_rejects_bad_uid():
    c, stub = client()
    with pytest.raises(MailError):
        c.fetch_raw("INBOX", "5\r\nA1 DELETE INBOX")
    assert not stub.calls


# namespaces, LIST edge cases

def test_namespaces_extension_data_does_not_shift_groups():
    c, _ = client(namespace=("OK", [b'(("INBOX." "." "X-PARAM" ("a" "b"))) NIL NIL']))
    assert c.namespaces() == {"personal": [["INBOX.", "."]], "other": [], "shared": []}
    c, _ = client(namespace=("OK", [b'NIL (("Users/" "/" "X-PARAM" ("a"))) (("Public/" "/"))']))
    assert c.namespaces() == {"personal": [], "other": [["Users/", "/"]], "shared": [["Public/", "/"]]}


def test_namespaces_unparseable_is_empty():
    c, _ = client(namespace=("OK", [b'(("INBOX." "."']))
    assert c.namespaces() == {"personal": [], "other": [], "shared": []}


def test_folders_literal_names_are_kept():
    lines = [(rb'(\HasNoChildren) "." {17}', "INBOX.Entw&APw-rfe ✓".encode()), b"",
             (rb'(\HasNoChildren \Trash) "." {11}', b"INBOX.Bin  1"), rb'(\HasNoChildren) "." INBOX']
    c, _ = client(list=("OK", lines))
    assert [f.name for f in c.folders()] == ["INBOX.Entwürfe ✓", "INBOX.Bin  1", "INBOX"]
    assert c.special("trash") == "INBOX.Bin  1"


def test_special_skips_noselect_and_nonexistent_case_insensitively():
    lines = [rb'(\NOSELECT \Sent) "." INBOX.Sent', rb'(\nonexistent \Trash) "." INBOX.Gone',
             rb'(\HasNoChildren \SENT) "." INBOX.Sent2', rb'(\noselect) "." INBOX.Trash']
    c, _ = client(list=("OK", lines))
    assert c.special("sent") == "INBOX.Sent2"
    assert c.special("trash") is None


# personal namespace prefix (Plesk/Courier-style Dovecot "INBOX." vs empty prefix)
NS_PLESK = ("OK", [b'(("INBOX." ".")) (("#users." ".")) (("#shared." "."))'])
NS_EMPTY = ("OK", [b'(("" "/")) NIL NIL'])
LIST_PLESK = [rb'(\HasNoChildren) "." INBOX', rb'(\HasNoChildren) "." INBOX.Archive',
              rb'(\HasNoChildren) "." Legacy']
LIST_EMPTY = [rb'(\HasNoChildren) "/" INBOX', rb'(\HasNoChildren) "/" Archive']


def test_resolve_folder_with_inbox_prefix():
    c, _ = client(namespace=NS_PLESK, list=("OK", LIST_PLESK))
    assert c.resolve_folder("INBOX") == "INBOX"
    assert c.resolve_folder("inbox") == "inbox"
    assert c.resolve_folder("Archive") == "INBOX.Archive"           # exists only prefixed
    assert c.resolve_folder("INBOX.Archive") == "INBOX.Archive"
    assert c.resolve_folder("Legacy") == "Legacy"                   # an existing exact match wins
    assert c.resolve_folder("Drafts") == "INBOX.Drafts"             # not there yet: inside the namespace
    assert c.resolve_folder("#shared.team") == "#shared.team"       # other namespaces untouched
    assert c.resolve_folder("#users.bob.INBOX") == "#users.bob.INBOX"


def test_ensure_folder_creates_inside_prefix_and_returns_name():
    c, stub = client(namespace=NS_PLESK, list=("OK", LIST_PLESK), create=("OK", [None]))
    assert c.ensure_folder("mcp-imap-smtp-tests") == "INBOX.mcp-imap-smtp-tests"
    assert ("create", ('"INBOX.mcp-imap-smtp-tests"',), None) in stub.calls
    assert c.ensure_folder("Archive") == "INBOX.Archive"
    assert [k for k, *_ in stub.calls].count("create") == 1


def test_move_append_select_use_resolved_name():
    c, stub = client(namespace=NS_PLESK, list=("OK", LIST_PLESK), create=("OK", [None]),
                     append=("OK", [None]), **{"uid MOVE": ("OK", [None])})
    c.move("INBOX", [3], "Trash")
    assert ("create", ('"INBOX.Trash"',), None) in stub.calls
    assert uid_calls(stub, "MOVE")[0][0] == ("3", '"INBOX.Trash"')
    c.append("Archive", b"x", ())
    assert [a[0] for k, a, _ in stub.calls if k == "append"] == ['"INBOX.Archive"']
    c._select("Archive", readonly=True)
    assert [a[0] for k, a, _ in stub.calls if k == "select"][-1] == '"INBOX.Archive"'


def test_empty_prefix_leaves_names_alone():
    c, stub = client(namespace=NS_EMPTY, list=("OK", LIST_EMPTY), create=("OK", [None]))
    assert c.resolve_folder("Archive") == "Archive"
    assert c.ensure_folder("mcp-imap-smtp-tests") == "mcp-imap-smtp-tests"
    assert ("create", ('"mcp-imap-smtp-tests"',), None) in stub.calls


def test_no_namespace_support_leaves_names_alone():
    def bad():
        raise imaplib.IMAP4.error("BAD unknown command")
    c, _ = client(namespace=bad, list=("OK", LIST_EMPTY))
    assert c.resolve_folder("Drafts") == "Drafts"


# One folder name works on every server (21 Oct 2026: "INBOX.Sent" failed on ISPConfig, where it is "Sent")
LIST_PLESK_ROLES = [rb'(\HasNoChildren) "." INBOX', rb'(\HasNoChildren \Sent) "." INBOX.Sent',
                    rb'(\HasNoChildren) "." INBOX.Drafts', rb'(\HasNoChildren) "." INBOX.Trash',
                    rb'(\HasNoChildren) "." INBOX.Spam']
LIST_ISPCONFIG_ROLES = [rb'(\HasNoChildren) "." INBOX', rb'(\HasNoChildren \Sent) "." Sent',
                        rb'(\HasNoChildren \Drafts) "." Drafts', rb'(\HasNoChildren \Trash) "." Trash',
                        rb'(\HasNoChildren \Junk) "." Junk']
NS_EMPTY_DOT = ("OK", [b'(("" ".")) NIL NIL'])


@pytest.mark.parametrize("given", ["Sent", "INBOX.Sent", "sent", "SENT", "Sent Items", "Sent Messages", "inbox/Sent"])
def test_sent_resolves_on_both_naming_schemes(given):
    plesk, _ = client(namespace=NS_PLESK, list=("OK", LIST_PLESK_ROLES))
    ispconfig, _ = client(namespace=NS_EMPTY_DOT, list=("OK", LIST_ISPCONFIG_ROLES))
    assert plesk.resolve_folder(given) == "INBOX.Sent"
    assert ispconfig.resolve_folder(given) == "Sent"


@pytest.mark.parametrize("given,plesk_name,ispconfig_name", [
    ("drafts", "INBOX.Drafts", "Drafts"), ("INBOX.Drafts", "INBOX.Drafts", "Drafts"),
    ("trash", "INBOX.Trash", "Trash"), ("Deleted Items", "INBOX.Trash", "Trash"),
    ("junk", "INBOX.Spam", "Junk"), ("spam", "INBOX.Spam", "Junk"), ("INBOX.Junk", "INBOX.Spam", "Junk"),
    ("inbox", "inbox", "inbox"), ("INBOX", "INBOX", "INBOX")])
def test_role_names_and_aliases_resolve_on_both(given, plesk_name, ispconfig_name):
    plesk, _ = client(namespace=NS_PLESK, list=("OK", LIST_PLESK_ROLES))
    ispconfig, _ = client(namespace=NS_EMPTY_DOT, list=("OK", LIST_ISPCONFIG_ROLES))
    assert plesk.resolve_folder(given) == plesk_name
    assert ispconfig.resolve_folder(given) == ispconfig_name


def test_an_existing_folder_beats_a_role_alias():
    lines = [rb'(\HasNoChildren) "/" INBOX', rb'(\HasNoChildren) "/" Archive', rb'(\HasNoChildren \Archive) "/" Archives']
    c, _ = client(namespace=NS_EMPTY, list=("OK", lines))
    assert c.resolve_folder("ARCHIVE") == "Archive" and c.resolve_folder("archives") == "Archives"


def test_unknown_names_keep_the_old_rules():
    plesk, _ = client(namespace=NS_PLESK, list=("OK", LIST_PLESK_ROLES))
    ispconfig, _ = client(namespace=NS_EMPTY_DOT, list=("OK", LIST_ISPCONFIG_ROLES))
    assert plesk.resolve_folder("Projects") == "INBOX.Projects"          # created inside the namespace
    assert ispconfig.resolve_folder("Projects") == "Projects"
    assert ispconfig.resolve_folder("INBOX.Projects") == "INBOX.Projects"   # a real child of INBOX stays one
    assert plesk.resolve_folder("inbox.sent") == "INBOX.Sent"              # case only


def test_search_in_the_other_schemes_sent_selects_this_servers_sent():
    c, stub = client(namespace=NS_EMPTY_DOT, list=("OK", LIST_ISPCONFIG_ROLES), **{"uid SEARCH": ("OK", [None])})
    assert c.search("INBOX.Sent", SearchQuery()) == (0, [])
    assert [a for k, a, _ in stub.calls if k == "select"] == [('"Sent"', True)]


def test_namespaces_on_a_server_without_namespace_support():
    # GreenMail and other small servers answer NAMESPACE with BAD (clean-room test, 22 Oct 2026).
    def bad():
        raise imaplib.IMAP4.error("BAD unknown command")
    c, _ = client(namespace=bad, list=("OK", LIST_EMPTY))
    assert c.namespaces() == {"personal": [], "other": [], "shared": []}
    c, stub = client(namespace=bad, list=("OK", LIST_EMPTY))
    stub.capabilities = ("IMAP4REV1", "IDLE")           # not advertised: never asked
    assert c.namespaces() == {"personal": [], "other": [], "shared": []}
    assert "namespace" not in [k for k, *_ in stub.calls]
    c, stub = client(namespace=bad, list=("OK", LIST_EMPTY), capability=("OK", [b"IMAP4rev1 IDLE"]))
    stub.capabilities = ("IMAP4REV1", "IDLE")           # not advertised after login either: never asked
    assert c.namespaces() == {"personal": [], "other": [], "shared": []}
    assert "namespace" not in [k for k, *_ in stub.calls]
    c2, stub2 = client(namespace=NS_PLESK, list=("OK", LIST_PLESK))
    stub2.capabilities = ("IMAP4REV1", "NAMESPACE")
    assert c2.namespaces()["personal"] == [["INBOX.", "."]]


def test_namespace_listed_only_after_login_is_still_used():
    # Dovecot's greeting lacks NAMESPACE; imaplib keeps that list, so the server is asked again (22 Oct 2026).
    c, stub = client(namespace=NS_PLESK, list=("OK", LIST_PLESK),
                     capability=("OK", [b"IMAP4rev1 SASL-IR IDLE NAMESPACE SPECIAL-USE"]))
    stub.capabilities = ("IMAP4REV1", "SASL-IR", "AUTH=PLAIN")
    assert c.namespaces()["personal"] == [["INBOX.", "."]]
    assert c.resolve_folder("mcp-imap-smtp-tests") == "INBOX.mcp-imap-smtp-tests"
