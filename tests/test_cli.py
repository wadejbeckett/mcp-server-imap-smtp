# SPDX-License-Identifier: AGPL-3.0-or-later
import re

import pytest

from mcp_server_imap_smtp import cli
from mcp_server_imap_smtp.store import Store
from mcp_server_imap_smtp.mail.hosts import MailServer as _MailServer
MAIL1 = _MailServer("mail1.hosting.example")


@pytest.fixture
def env(tmp_path):
    cfg = tmp_path / "c.toml"
    db = tmp_path / "s.sqlite"
    cfg.write_text(f'issuer_url="http://127.0.0.1:8765"\nmail_resource_url="http://127.0.0.1:8765/mail"\n'
                   f'mail_host="mail1.hosting.example"\ndb_path="{db}"\n')
    return cfg, Store(db)


def run(cfg, *args):
    cli.main(["--config", str(cfg), *args])


def test_list_and_revoke(env, capsys):
    cfg, s = env
    s.create_grant("c1", "r", [("me@x.co.za", "pw", MAIL1)])
    run(cfg, "grants", "list"); assert "me@x.co.za" in capsys.readouterr().out
    run(cfg, "grants", "revoke", "--mailbox", "me@x.co.za")
    assert "revoked 1" in capsys.readouterr().out


def test_revoke_mailbox_is_case_insensitive_and_marks_grant_revoked(env, capsys):
    cfg, s = env
    gid, _ = s.create_grant("c1", "r", [("me@x.co.za", "pw", MAIL1)])
    run(cfg, "grants", "revoke", "--mailbox", "Me@X.co.za")
    assert "revoked 1" in capsys.readouterr().out
    assert [g["revoked"] for g in s.list_grants()] == [1]
    run(cfg, "grants", "list"); assert "revoked" in capsys.readouterr().out


def test_revoke_unknown_mailbox_reports_zero(env, capsys):
    cfg, s = env
    s.create_grant("c1", "r", [("me@x.co.za", "pw", MAIL1)])
    run(cfg, "grants", "revoke", "--mailbox", "nobody@x.co.za")
    assert "revoked 0" in capsys.readouterr().out
    assert [g["revoked"] for g in s.list_grants()] == [0]


def test_revoke_by_grant_id_revokes_only_that_grant(env, capsys):
    cfg, s = env
    g1, _ = s.create_grant("c1", "r", [("a@x.co.za", "pw", MAIL1)])
    s.create_grant("c2", "r", [("b@x.co.za", "pw", MAIL1)])
    run(cfg, "grants", "revoke", "--grant", g1)
    assert "revoked 1" in capsys.readouterr().out
    assert {g["subject"]: g["revoked"] for g in s.list_grants()} == {"a@x.co.za": 1, "b@x.co.za": 0}


def test_revoke_unknown_grant_id_reports_zero(env, capsys):
    cfg, s = env
    s.create_grant("c1", "r", [("a@x.co.za", "pw", MAIL1)])
    run(cfg, "grants", "revoke", "--grant", "nope")
    assert "revoked 0" in capsys.readouterr().out
    assert [g["revoked"] for g in s.list_grants()] == [0]


def test_list_never_prints_secrets(env, capsys):
    cfg, s = env
    gid, key = s.create_grant("c1", "r", [("me@x.co.za", "hunter2-secret", MAIL1), ("shared@x.co.za", "other-secret", MAIL1)])
    s.issue_tokens(gid, key, "c1", ["mail"], "r", 3600, 86400)
    run(cfg, "grants", "list")
    out = capsys.readouterr().out
    assert "me@x.co.za" in out and "shared@x.co.za" in out
    for needle in ("hunter2-secret", "other-secret", key.hex(), "at_", "rt_", "ac_"):
        assert needle not in out
    assert not re.search(r"\b[A-Za-z0-9_-]{40,}\b", out)


def test_list_empty_prints_no_grants(env, capsys):
    cfg, _ = env
    run(cfg, "grants", "list")
    assert capsys.readouterr().out == "no grants\n"


def test_revoke_already_revoked_grant_reports_zero(env, capsys):
    cfg, s = env
    gid, _ = s.create_grant("c1", "r", [("a@x.co.za", "pw", MAIL1)])
    run(cfg, "grants", "revoke", "--grant", gid)
    assert capsys.readouterr().out == "revoked 1\n"
    run(cfg, "grants", "revoke", "--grant", gid)
    assert capsys.readouterr().out == "revoked 0\n"


def test_revoke_mailbox_counts_only_grants_not_yet_revoked(env, capsys):
    cfg, s = env
    g1, _ = s.create_grant("c1", "r", [("a@x.co.za", "pw", MAIL1)])
    s.create_grant("c2", "r", [("a@x.co.za", "pw", MAIL1), ("b@x.co.za", "pw", MAIL1)])
    s.revoke_grant(g1)
    run(cfg, "grants", "revoke", "--mailbox", "a@x.co.za")
    assert capsys.readouterr().out == "revoked 1\n"
    run(cfg, "grants", "revoke", "--mailbox", "a@x.co.za")
    assert capsys.readouterr().out == "revoked 0\n"
    assert [g["revoked"] for g in s.list_grants()] == [1, 1]


@pytest.mark.parametrize("args", [("grants", "list"), ("grants", "revoke", "--mailbox", "a@x.co.za"),
                                  ("grants", "revoke", "--grant", "abc")])
def test_missing_database_is_refused_not_created(tmp_path, capsys, args):
    db = tmp_path / "nowhere" / "s.sqlite"
    cfg = tmp_path / "c.toml"
    cfg.write_text(f'issuer_url="http://127.0.0.1:8765"\nmail_resource_url="http://127.0.0.1:8765/mail"\n'
                   f'mail_host="mail1.hosting.example"\ndb_path="{db}"\n')
    with pytest.raises(SystemExit) as info:
        run(cfg, *args)
    assert info.value.code == 2
    assert f"database not found: {db}" in capsys.readouterr().err
    assert not db.exists() and not db.parent.exists()


def test_revoke_requires_a_target(env):
    cfg, _ = env
    with pytest.raises(SystemExit):
        run(cfg, "grants", "revoke")


ISP = _MailServer("mail.client.example", domains=("client.example",), match_mx=False)


def test_servers_list_prints_the_configured_servers(tmp_path, capsys):
    cfg = tmp_path / "c.toml"
    cfg.write_text(f'issuer_url="http://i"\nmail_resource_url="http://i/mail"\ndb_path="{tmp_path / "none.sqlite"}"\n'
                   '[[mail_servers]]\nhost="mail1.hosting.example"\n'
                   '[[mail_servers]]\nhost="mail.client.example"\ndomains=["client.example"]\nmatch_mx=false\n'
                   'smtp_security="starttls"\n')
    run(cfg, "servers", "list")          # needs no database
    assert capsys.readouterr().out.splitlines() == [
        "mail1.hosting.example  imap 993 tls  smtp 465 tls  domains -  match_mx yes",
        "mail.client.example  imap 993 tls  smtp 587 starttls  domains client.example  match_mx no"]
    assert not (tmp_path / "none.sqlite").exists()


def test_grants_list_shows_the_host_of_each_mailbox(env, capsys):
    cfg, s = env
    s.create_grant("c1", "r", [("me@x.co.za", "pw", MAIL1), ("ops@client.example", "pw", ISP)])
    run(cfg, "grants", "list")
    assert "me@x.co.za (mail1.hosting.example) ops@client.example (mail.client.example)" in capsys.readouterr().out


def test_mailboxes_stored_before_hosts_were_recorded_show_the_legacy_server(env, capsys):
    cfg, s = env
    gid, _ = s.create_grant("c1", "r", [("me@x.co.za", "pw", ISP)])
    s._q("UPDATE mailboxes SET host=NULL")
    run(cfg, "grants", "list")
    assert "me@x.co.za (mail1.hosting.example)" in capsys.readouterr().out      # mail_host is the first server
    run(cfg, "grants", "revoke", "--host", "mail1.hosting.example")
    assert capsys.readouterr().out == "revoked 1\n"


def test_revoke_by_host_revokes_every_grant_with_a_mailbox_there(env, capsys):
    cfg, s = env
    s.create_grant("c1", "r", [("me@x.co.za", "pw", MAIL1)])
    s.create_grant("c2", "r", [("a@x.co.za", "pw", MAIL1), ("ops@client.example", "pw", ISP)])
    s.create_grant("c3", "r", [("b@client.example", "pw", ISP)])
    run(cfg, "grants", "revoke", "--host", "mail.client.example")
    assert capsys.readouterr().out == "revoked 2\n"
    assert {g["client_id"]: g["revoked"] for g in s.list_grants()} == {"c1": 0, "c2": 1, "c3": 1}
    run(cfg, "grants", "revoke", "--host", "other.example")
    assert capsys.readouterr().out == "revoked 0\n"


def test_host_column_is_added_to_an_existing_database(tmp_path):
    import sqlite3
    path = tmp_path / "old.sqlite"
    db = sqlite3.connect(path)
    db.executescript("""CREATE TABLE mailboxes (grant_id TEXT NOT NULL, position INTEGER NOT NULL,
        address TEXT NOT NULL, sealed BLOB NOT NULL, PRIMARY KEY (grant_id, address));""")
    db.close()
    s = Store(path)
    Store(path)                                   # opening twice must not add it again
    assert "host" in [r["name"] for r in s._q("PRAGMA table_info(mailboxes)")]


def test_a_large_grant_lists_one_mailbox_per_line(env, capsys):
    cfg, s = env
    gid, _ = s.create_grant("c1", "r", [("owner@client.example", "pw", ISP)] +
                            [(f"staff{i}@client.example", "pw", ISP) for i in range(1, 88)])
    s.create_grant("c2", "r", [("me@x.co.za", "pw", MAIL1)])
    run(cfg, "grants", "list")
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].startswith(gid) and lines[0].endswith("active   88 mailboxes")
    assert lines[1] == f"{gid}    owner@client.example (mail.client.example)"
    assert lines[88] == f"{gid}    staff87@client.example (mail.client.example)"
    assert lines[89].endswith("active   me@x.co.za (mail1.hosting.example)") and len(lines) == 90


# grants add-mailboxes: the manage page's check and save, from the operator's shell (21 Oct 2026)
from mcp_server_imap_smtp import crypto  # noqa: E402
from mcp_server_imap_smtp.auth.login import MailUnavailable  # noqa: E402
from mcp_server_imap_smtp.config import load_settings  # noqa: E402
from mcp_server_imap_smtp.mail.resolve import Resolver  # noqa: E402

X = _MailServer("mail1.hosting.example", domains=("x.co.za",), match_mx=False)
GOOD = {"me@x.co.za": "pw", "a@x.co.za": "pa", "b@x.co.za": "pb", "c@x.co.za": "pc"}


def check(address, password, server):
    if address == "down@x.co.za":
        raise MailUnavailable("down")
    return GOOD.get(address) == password


def add(env, gid, text, verifier=check, subject="me@x.co.za"):
    cfg, store = env
    return cli.add_mailboxes(store, load_settings(cfg), gid, subject, text, verifier=verifier,
                             resolver=Resolver((X,)), say=lambda _: None)


@pytest.fixture
def grant(env):
    _, store = env
    gid, key = store.create_grant("c1", "r", [("me@x.co.za", "pw", X), ("a@x.co.za", "pa", X)])
    return gid, key


def test_add_mailboxes_checks_seals_and_skips_present(env, grant):
    gid, key = grant
    status, report = add(env, gid, "a@x.co.za pa\n\nb@x.co.za pb\nB@x.co.za pb\nc@x.co.za pc\n")
    assert status == 0
    assert report == ["line 1 a@x.co.za: already in the grant, skipped", "line 3 b@x.co.za: ok (mail1.hosting.example)",
                      "line 4 b@x.co.za: listed twice, skipped", "line 5 c@x.co.za: ok (mail1.hosting.example)",
                      "added 2 mailboxes; the grant now holds 4"]
    opened = env[1].open_mailboxes(gid, key)
    assert list(opened) == ["me@x.co.za", "a@x.co.za", "b@x.co.za", "c@x.co.za"]
    assert opened["c@x.co.za"].password == "pc"


def test_add_mailboxes_saves_nothing_when_a_line_fails(env, grant):
    gid, key = grant
    status, report = add(env, gid, "b@x.co.za pb\nc@x.co.za WRONG-secret\ndown@x.co.za x")
    assert status == 1
    assert "line 2 c@x.co.za: refused, address or password incorrect" in report
    assert "line 3 down@x.co.za: refused, the mail server could not be reached or was busy" in report
    status, report = add(env, gid, "b@x.co.za pb\nsomeone@gmail.com hidden-pw")
    assert "line 2 someone@gmail.com: refused, not hosted on a configured mail server" in report
    assert "line 1 b@x.co.za: not checked, other lines were refused" in report
    assert report[-1].startswith("nothing was saved")
    assert not any("WRONG-secret" in r or "hidden-pw" in r for r in report)
    assert list(env[1].open_mailboxes(gid, key)) == ["me@x.co.za", "a@x.co.za"]


def test_add_mailboxes_needs_the_grants_key(env, grant):
    gid, key = grant
    env[1]._q("DELETE FROM grant_keys WHERE grant_id=?", (gid,))
    status, report = add(env, gid, "b@x.co.za pb")
    assert status == 3 and "next time its AI app uses it" in report[0]
    env[1].open_mailboxes(gid, key)           # the AI app uses it
    assert add(env, gid, "b@x.co.za pb")[0] == 0


def test_add_mailboxes_refuses_unknown_or_revoked_grant(env, grant):
    gid, _ = grant
    assert add(env, "nope", "b@x.co.za pb")[0] == 2
    env[1].revoke_grant(gid)
    assert add(env, gid, "b@x.co.za pb")[0] == 2


def test_add_mailboxes_command_reads_stdin(env, grant, monkeypatch, capsys):
    gid, _ = grant
    cfg, _ = env
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO("a@x.co.za pa\n"))
    with pytest.raises(SystemExit) as done:
        run(cfg, "grants", "add-mailboxes", gid, "--subject", "ME@x.co.za")
    assert done.value.code == 0
    out = capsys.readouterr().out
    assert out.startswith(f"grant {gid}: main mailbox me@x.co.za, app 'unknown', 2 mailboxes now")
    assert "already in the grant, skipped" in out and "added 0 mailboxes" in out and " pa\n" not in out


def test_add_mailboxes_refuses_a_grant_of_another_main_mailbox(env, grant):
    gid, key = grant
    status, report = add(env, gid, "b@x.co.za pb", subject="other@x.co.za")
    assert status == 2 and "belongs to me@x.co.za, not other@x.co.za" in report[0]
    assert list(env[1].open_mailboxes(gid, key)) == ["me@x.co.za", "a@x.co.za"]


def test_add_mailboxes_stops_after_five_wrong_passwords(env, grant):
    gid, _ = grant
    tried = []

    def wrong(address, password, server):
        tried.append(address)
        return False
    text = "\n".join(f"s{i}@x.co.za bad" for i in range(20))
    status, report = add(env, gid, text, verifier=wrong)
    assert status == 1 and len(tried) <= 5 + cli.ADD_WORKERS
    assert sum("stopped after 5 wrong passwords" in r for r in report) >= 20 - 5 - cli.ADD_WORKERS


def test_add_mailboxes_is_audited_and_never_replaces(env, grant, caplog):
    gid, key = grant
    caplog.set_level("INFO", logger="mcp_server_imap_smtp.audit")
    assert add(env, gid, "b@x.co.za pb")[0] == 0
    assert '"tool":"admin_add_mailbox"' in caplog.text and '"mailbox":"b@x.co.za"' in caplog.text
    assert env[1].add_mailboxes(gid, [("a@x.co.za", "other", X)]) == []          # insert only
    assert env[1].open_mailboxes(gid, key)["a@x.co.za"].password == "pa"
    env[1].revoke_grant(gid)
    assert env[1].add_mailboxes(gid, [("z@x.co.za", "pz", X)]) is None


def test_add_mailboxes_keeps_spaces_at_the_ends_of_a_password(env, grant):
    gid, key = grant
    seen = []

    def spy(address, password, server):
        seen.append(password)
        return True
    assert add(env, gid, "b@x.co.za  two lead and trail  \nc@x.co.za\tpc\n", verifier=spy)[0] == 0
    assert seen == [" two lead and trail  ", "pc"]
    assert env[1].open_mailboxes(gid, key)["b@x.co.za"].password == " two lead and trail  "
