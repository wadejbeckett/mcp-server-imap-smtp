# SPDX-License-Identifier: AGPL-3.0-or-later
"""Security review 2026-10-20, finding 14 (L8): a server-held secret mixed into the key that wraps each
grant key, so a database or backup plus a token is not enough to open passwords."""
import pytest

from mcp_server_imap_smtp import crypto
from mcp_server_imap_smtp.config import Settings, load_sealing_secret
from mcp_server_imap_smtp.mail.hosts import MailServer
from mcp_server_imap_smtp.store import Store

MAIL1 = MailServer("mail1.hosting.example")
PEPPER = b"p" * 32
RES = "http://127.0.0.1:8765/mail"


def test_peppered_wrap_needs_the_pepper():
    key = crypto.new_key()
    blob = crypto.wrap_key(key, "s", "access:1", pepper=PEPPER)
    assert crypto.unwrap_key(blob, "s", "access:1", pepper=PEPPER) == key
    with pytest.raises(crypto.CryptoError):
        crypto.unwrap_key(blob, "s", "access:1")
    with pytest.raises(crypto.CryptoError):
        crypto.unwrap_key(blob, "s", "access:1", pepper=b"q" * 32)


def test_old_wrappings_still_open_with_a_pepper_loaded():
    key = crypto.new_key()
    blob = crypto.wrap_key(key, "s", "access:1")
    assert crypto.unwrap_key(blob, "s", "access:1", pepper=PEPPER) == key


def test_store_with_pepper_issues_tokens_a_copy_without_it_cannot_open(tmp_path):
    store = Store(tmp_path / "s.sqlite", sealing_secret=PEPPER)
    gid, key = store.create_grant("c1", RES, [("me@x.co.za", "pw", MAIL1)])
    at, rt = store.issue_tokens(gid, key, "c1", [], RES, 3600, 86400)
    assert store.unlock(at)[1]["me@x.co.za"].password == "pw"
    stolen = Store(tmp_path / "s.sqlite")
    with pytest.raises(crypto.CryptoError):
        stolen.unlock(at)


def test_grants_from_before_the_pepper_move_over_on_refresh(tmp_path):
    old = Store(tmp_path / "s.sqlite")
    gid, key = old.create_grant("c1", RES, [("me@x.co.za", "pw", MAIL1)])
    at, rt = old.issue_tokens(gid, key, "c1", [], RES, 3600, 86400)
    new = Store(tmp_path / "s.sqlite", sealing_secret=PEPPER)
    assert new.unlock(at)[1]["me@x.co.za"].password == "pw"      # existing tokens keep working
    _, at2, _ = new.rotate_and_issue(rt, "c1", None, 3600, 86400)
    assert new.unlock(at2)[1]["me@x.co.za"].password == "pw"
    with pytest.raises(crypto.CryptoError):
        old.unlock(at2)                                          # re-wrapped under the pepper


def settings(**kw):
    return Settings(issuer_url="https://m.example", mail_resource_url="https://m.example/mail",
                    mail_servers=(MAIL1,), db_path="x", **kw)


def test_secret_from_file(tmp_path):
    f = tmp_path / "sealing-secret"
    f.write_bytes(b"z" * 40 + b"\n")
    assert load_sealing_secret(settings(sealing_secret_file=str(f)), env={}) == b"z" * 40


def test_secret_from_systemd_credential(tmp_path):
    (tmp_path / "sealing-secret").write_bytes(b"y" * 32)
    assert load_sealing_secret(settings(), env={"CREDENTIALS_DIRECTORY": str(tmp_path)}) == b"y" * 32


def test_no_secret_configured_means_none(tmp_path):
    assert load_sealing_secret(settings(), env={}) is None


def test_short_or_missing_secret_is_refused(tmp_path):
    f = tmp_path / "s"
    f.write_bytes(b"short")
    with pytest.raises(ValueError):
        load_sealing_secret(settings(sealing_secret_file=str(f)), env={})
    with pytest.raises(ValueError):
        load_sealing_secret(settings(sealing_secret_file=str(tmp_path / "missing")), env={})


def test_deploy_kit_creates_and_loads_the_secret():
    from pathlib import Path
    deploy = Path(__file__).resolve().parent.parent / "deploy"
    assert "LoadCredential=sealing-secret:/etc/@NAME@/sealing-secret" in (deploy / "service.unit").read_text()
    install = (deploy / "install.sh").read_text()
    assert "SEALING_SECRET=$ETC/sealing-secret" in install and 'chmod 0400 "$SEALING_SECRET"' in install
    assert "sealing-secret" not in (deploy / "backup.sh").read_text()
