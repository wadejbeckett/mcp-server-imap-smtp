# SPDX-License-Identifier: AGPL-3.0-or-later
"""Security review 2026-10-20, finding 13: the MCP SDK's INFO lines with tool error text stay out of the
journal, the audit docstring says what an audit line holds, and the deploy kit sets journal retention."""
import logging
import subprocess
from pathlib import Path

import pytest
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from mcp_server_imap_smtp import app, audit

DEPLOY = Path(__file__).resolve().parent.parent / "deploy"


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_sdk_tool_error_text_is_not_logged(caplog):
    app.quiet_sdk_logs()
    caplog.set_level(logging.INFO)
    srv = MCPServer("t")

    @srv.tool()
    def boom() -> str:
        raise ToolError("SELECT failed: [NONEXISTENT] Folder Private/HR-salaries for ceo@example.com")
    try:
        await srv.call_tool("boom", {})
    except ToolError:
        pass
    assert "HR-salaries" not in caplog.text


def test_audit_docstring_names_the_personal_data():
    assert "mailbox address" in audit.__doc__ and "folder name" in audit.__doc__


def test_install_sets_journal_retention():
    text = (DEPLOY / "install.sh").read_text()
    assert "/etc/systemd/journald.conf.d/" in text and "MaxRetentionSec=" in text and "SystemMaxUse=" in text
    subprocess.run(["bash", "-n", str(DEPLOY / "install.sh")], check=True)
