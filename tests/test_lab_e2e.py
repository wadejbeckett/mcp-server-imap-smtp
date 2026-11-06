# SPDX-License-Identifier: AGPL-3.0-or-later
"""Lab end to end: the real connector, started as a process against a lab profile, walked by deploy/e2e.py
the way an operator would run it, read, write and send sweeps included."""
import imaplib
import json
import os
import subprocess
import sys
import time
from email.message import EmailMessage
from pathlib import Path

import pytest

from tests._lab import FLAT, HOST, PREFIXED, STRIPPED, context, require_lab, running_connector, users

pytestmark = pytest.mark.lab

SCRIPT = Path(__file__).resolve().parent.parent / "deploy" / "e2e.py"
ALICE = "alice@example.test"
# Over http on loopback the script cannot check TLS; every other check must pass.
HTTP_ONLY_SKIPS = {"TLS"}


@pytest.fixture(scope="module", autouse=True)
def _lab_up():
    require_lab()


def seed_inbox(profile, address: str) -> None:
    """One message in INBOX, so the read sweep has a row to read and thread (the lab starts empty)."""
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = "bob@example.test", address, f"lab e2e seed {time.time_ns()}"
    msg["Message-ID"] = f"<seed.{time.time_ns()}@example.test>"
    msg.set_content("A message for the end-to-end read sweep.")
    c = imaplib.IMAP4_SSL(HOST, profile.imaps, ssl_context=context())
    try:
        c.login(address, users()[address])
        typ, _ = c.append("INBOX", None, None, msg.as_bytes())
        assert typ == "OK"
    finally:
        c.logout()


def run_script(base: str, env_file: Path, *args: str) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if not k.startswith("MCP_E2E_")}
    return subprocess.run([sys.executable, str(SCRIPT), base, "--env-file", str(env_file), "--json", *args],
                          capture_output=True, text=True, timeout=600, env=env)


@pytest.mark.parametrize("profile", [FLAT, PREFIXED, STRIPPED], ids=lambda p: p.name)
def test_e2e_script_passes_against_the_running_connector(profile, tmp_path):
    seed_inbox(profile, ALICE)
    env_file = tmp_path / "e2e.env"
    env_file.write_text(f"MCP_E2E_ADDRESS={ALICE}\nMCP_E2E_PASSWORD={users()[ALICE]}\n")
    env_file.chmod(0o600)
    with running_connector(profile, tmp_path) as base:
        result = run_script(base, env_file, "--write", "--send")
    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout)
    steps = {s["name"]: s for s in summary["steps"]}
    assert [s for s in summary["steps"] if s["outcome"] == "FAIL"] == []
    assert {n for n, s in steps.items() if s["outcome"] == "SKIP"} == HTTP_ONLY_SKIPS, result.stderr
    for name in ("sign-in", "cross-site sign-in refused", "token refresh", "tools/list", "mail_read", "mail_thread",
                 "draft saved", "draft read back", "attachments fetched", "flag set and cleared", "draft removed",
                 "message sent to the mailbox itself", "message arrived", "received message read",
                 "sent messages removed", "revocation", "revoked token refused"):
        assert steps[name]["outcome"] == "PASS", name
    assert summary["ok"] is True and summary["removal"] in ("mail_delete", "mail_move to Trash")
    assert {"mail_accounts", "mail_folders", "mail_search", "mail_read"} <= set(summary["tools"])
    assert users()[ALICE] not in result.stdout + result.stderr
    assert ALICE not in result.stdout + result.stderr
