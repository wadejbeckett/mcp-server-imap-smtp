# SPDX-License-Identifier: AGPL-3.0-or-later
"""One JSON line per tool call: grant id, mailbox address, mail server, tool, folder name, count and
outcome. The mailbox address and folder name are personal data, so the operator sets a retention period
for the journal (deploy/install.sh: 30 days) and names it in their privacy notice. Never recipients,
subjects, bodies, tokens, passwords or exception text."""
import json
import logging
import time

log = logging.getLogger("mcp_server_imap_smtp.audit")


def record(**fields) -> None:
    log.info(json.dumps({"ts": round(time.time(), 3), **fields}, separators=(",", ":")))
