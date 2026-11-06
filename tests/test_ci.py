# SPDX-License-Identifier: AGPL-3.0-or-later
"""The GitHub Actions workflow runs code from outside contributors, so its supply-chain guards are checked here
cheaply, by reading the files as text: a change that loosens one fails the unit suite before it reaches CI."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"


def workflows() -> list[Path]:
    found = sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))
    assert found, "no workflow files"
    return found


def code_lines(path: Path) -> list[str]:
    """Each line without its comment, so a note that mentions a forbidden word does not trip the checks."""
    return [re.sub(r"(^|\s)#.*$", "", line) for line in path.read_text().splitlines()]


def test_no_pull_request_target():
    # pull_request_target runs with a write token and secrets in the base repository's context.
    for path in workflows():
        assert not any("pull_request_target" in line for line in code_lines(path)), path.name


def test_top_level_token_is_read_only():
    for path in workflows():
        text = path.read_text()
        block = re.search(r"^permissions:\n((?:[ \t]+\S.*\n)+)", text, re.MULTILINE)
        assert block, f"{path.name}: no top-level permissions block"
        grants = dict(line.split(":", 1) for line in block[1].split("\n") if line.strip())
        assert {k.strip(): v.split("#")[0].strip() for k, v in grants.items()} == {"contents": "read"}, path.name
        # A job may narrow its token, never widen it.
        assert not re.search(r":\s*write\b", text), f"{path.name}: grants write"
        assert "write-all" not in text, path.name


def test_every_action_is_pinned_to_a_commit():
    for path in workflows():
        uses = [line for line in code_lines(path) if re.match(r"\s*(-\s*)?uses:", line)]
        assert uses, path.name
        for line in uses:
            ref = line.split("uses:", 1)[1].strip().strip("'\"")
            if ref.startswith("./"):
                continue    # a local action is part of the checked-out code
            assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", ref), f"{path.name}: {ref} not pinned to a SHA"


def test_pinned_actions_name_their_version():
    # The SHA is what runs; the trailing version comment is what a reviewer and Dependabot read.
    for path in workflows():
        for line in path.read_text().splitlines():
            if re.match(r"\s*(-\s*)?uses:\s*[\w.-]+/", line):
                assert re.search(r"@[0-9a-f]{40}\s+#\s*v\d", line), f"{path.name}: {line.strip()}"


def test_no_secrets_are_used():
    for path in workflows():
        assert not any(re.search(r"\bsecrets\.|\bsecrets\[", line) for line in code_lines(path)), path.name


def test_checkout_does_not_keep_the_token():
    for path in workflows():
        lines = path.read_text().splitlines()
        for i, line in enumerate(lines):
            if "actions/checkout@" in line:
                following = "\n".join(lines[i + 1:i + 4])
                assert re.search(r"persist-credentials:\s*false", following), f"{path.name} line {i + 1}"


def test_integration_tests_never_run_in_ci():
    # They need a real mailbox and its password; CI has neither and must not be given them.
    for path in workflows():
        text = "\n".join(code_lines(path))
        assert not re.search(r"-m\s+['\"]?integration", text), path.name
        assert "MCP_TEST_ENV_FILE" not in text, path.name


def test_dependabot_watches_python_packages_and_actions():
    text = (ROOT / ".github" / "dependabot.yml").read_text()
    ecosystems = set(re.findall(r'package-ecosystem:\s*"?([\w-]+)"?', text))
    assert {"uv", "github-actions"} <= ecosystems
