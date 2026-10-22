# SPDX-License-Identifier: AGPL-3.0-or-later
import os
from pathlib import Path
import pytest
from mcp_server_imap_smtp.mail.hosts import MailServer
from tests._mailtest import TEST_FOLDER  # noqa: F401  (re-exported for fixtures that need it)

# Integration tests (pytest -m integration) sign in to a real mailbox. Credentials come from the environment
# or from the KEY=value file named by MCP_TEST_ENV_FILE: MCP_TEST_IMAP_HOST, MCP_TEST_ADDRESS,
# MCP_TEST_PASSWORD, and optionally MCP_TEST_SHARED_ADDRESS / MCP_TEST_SHARED_PASSWORD.
SECRETS = Path(os.environ.get("MCP_TEST_ENV_FILE", "/nonexistent"))


def _load_env() -> dict:
    env = dict(os.environ)
    if SECRETS.exists():
        for line in SECRETS.read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if "=" in line:
                k, v = line.split("=", 1); env.setdefault(k.strip(), v.strip())
    return env


@pytest.fixture(scope="session")
def mailserver():
    env = _load_env()
    if not all(env.get(k) for k in ("MCP_TEST_IMAP_HOST", "MCP_TEST_ADDRESS", "MCP_TEST_PASSWORD")):
        pytest.skip("no test mailbox: set MCP_TEST_IMAP_HOST, MCP_TEST_ADDRESS and MCP_TEST_PASSWORD")
    return MailServer(env["MCP_TEST_IMAP_HOST"]), env["MCP_TEST_ADDRESS"], env["MCP_TEST_PASSWORD"]


@pytest.fixture(scope="session")
def shared_mailbox():
    env = _load_env()
    if not env.get("MCP_TEST_SHARED_ADDRESS"):
        pytest.skip("no shared test mailbox configured")
    return env["MCP_TEST_SHARED_ADDRESS"], env["MCP_TEST_SHARED_PASSWORD"]
