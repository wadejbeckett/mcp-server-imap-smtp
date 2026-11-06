#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Client side of scripts/install-test.sh: runs deploy/e2e.py against the test VM from the host.

    install-test-client.py CONNECT e2e  [e2e.py arguments...]
    install-test-client.py CONNECT keep  STATE_FILE [e2e.py arguments...]
    install-test-client.py CONNECT resume STATE_FILE [e2e.py arguments...]

CONNECT is "name:port:address:port[,...]": a connection to name:port goes to address:port instead, like curl's
--connect-to. The VM's HTTPS port is forwarded to an unprivileged port on the host's loopback, while the
gateway must be reached as https://<its name> on 443 (the Host header, the token audience and the
certificate all name it), so only the socket address is changed; TLS still verifies the certificate.

"e2e" runs e2e.py unchanged. "keep" runs it with --keep and saves the client id and refresh token in
STATE_FILE (mode 0600, test VM only), so "resume" can show after an upgrade that the connection made
before it still refreshes, opens an MCP session and reads mail; "resume" then revokes it.
"""
from __future__ import annotations

import importlib.util
import json
import os
import socket
import sys
from pathlib import Path

E2E = Path(__file__).resolve().parent.parent / "deploy" / "e2e.py"


def redirect_connections(spec: str) -> None:
    table = {}
    for item in spec.split(","):
        name, port, address, new_port = item.rsplit(":", 3)
        table[(name, int(port))] = (address, int(new_port))
    real = socket.getaddrinfo

    def getaddrinfo(host, port, *args, **kwargs):
        target = table.get((host, int(port or 0)))
        return real(*target, *args, **kwargs) if target else real(host, port, *args, **kwargs)

    socket.getaddrinfo = getaddrinfo


def load_e2e():
    spec = importlib.util.spec_from_file_location("e2e", E2E)
    module = importlib.util.module_from_spec(spec)
    sys.modules["e2e"] = module
    spec.loader.exec_module(module)
    return module


def walk_for(e2e, argv: list[str], keep: bool):
    """A Walk set up the way e2e.main sets it up, for the keep and resume modes."""
    args = e2e.parse_args(argv)
    base = e2e.check_base(args.base_url)
    address, password = e2e.credentials(args.env_file, os.environ)
    context = e2e.ssl.create_default_context(cafile=args.cafile)
    report = e2e.Report(e2e.Redactor(), sys.stdout)
    walk = e2e.Walk(base, args.mail_path, address, password, e2e.Http(args.timeout, context), report,
                    write=args.write, send=args.send, keep=keep)
    return walk, report


def keep(e2e, state_file: Path, argv: list[str]) -> int:
    walk, report = walk_for(e2e, argv, keep=True)
    walk.run()
    if report.failed or not walk.s.refresh:
        print("install-test-client: the walk failed; no connection saved")
        return 1
    fd = os.open(state_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"client_id": walk.s.client_id, "refresh": walk.s.refresh}, f)
    print("install-test-client: connection kept for the upgrade check")
    return 0


def resume(e2e, state_file: Path, argv: list[str]) -> int:
    saved = json.loads(state_file.read_text())
    walk, report = walk_for(e2e, argv, keep=False)
    walk.redact.add(saved["refresh"])
    try:
        walk.discovery()
        walk.s.client_id = saved["client_id"]
        with walk.step("refresh of the connection made before the upgrade", required=True) as d:
            r = walk.http.post_form(walk.s.asm["token_endpoint"], {
                "grant_type": "refresh_token", "refresh_token": saved["refresh"], "client_id": saved["client_id"]})
            tok = r.json() if r.status == 200 else {}
            walk.redact.add(tok.get("access_token"), tok.get("refresh_token"))
            if not tok.get("access_token") or not tok.get("refresh_token"):
                raise e2e.StepFailed(f"HTTP {r.status}: the old connection was not refreshed")
            walk.s.access, walk.s.refresh = tok["access_token"], tok["refresh_token"]
            d.append("the refresh token issued before the upgrade still works")
        walk.session()
        walk.read_sweep()
    except e2e.Abort:
        pass
    finally:
        walk.cleanup()
    state_file.unlink()
    print("install-test-client: old connection " + ("FAILED" if report.failed else "works after the upgrade"))
    return 1 if report.failed else 0


def main(argv: list[str]) -> int:
    redirect_connections(argv[0])
    e2e = load_e2e()
    mode = argv[1]
    if mode == "e2e":
        return e2e.main(argv[2:])
    if mode == "keep":
        return keep(e2e, Path(argv[2]), argv[3:])
    if mode == "resume":
        return resume(e2e, Path(argv[2]), argv[3:])
    print(f"unknown mode {mode}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
