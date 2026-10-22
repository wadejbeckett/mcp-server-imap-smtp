# SPDX-License-Identifier: AGPL-3.0-or-later
"""One JSON line per tool call. Only identifiers and counts: never recipients, subjects,
bodies, tokens, passwords or exception text."""
import json
import logging
import time

log = logging.getLogger("mcp_server_imap_smtp.audit")


def record(**fields) -> None:
    log.info(json.dumps({"ts": round(time.time(), 3), **fields}, separators=(",", ":")))
