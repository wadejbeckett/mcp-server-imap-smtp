# SPDX-License-Identifier: AGPL-3.0-or-later
"""scripts/lab.sh down runs at the end of every lab cycle, locally and in CI: it must say so when docker fails
rather than report a stopped lab, and it must run on the bash contributors have, including macOS's bash 3.2."""
import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LAB = ROOT / "scripts" / "lab.sh"


def fake_docker(tmp_path: Path, script: str) -> dict:
    """A PATH whose first `docker` is the given shell script, which logs its arguments to calls.log."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text(f'#!/usr/bin/env bash\necho "$*" >> "{tmp_path}/calls.log"\n{script}\n')
    docker.chmod(0o755)
    return {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"}


def down(env: dict) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", str(LAB), "down"], env=env, capture_output=True, text=True, timeout=30)


def test_down_fails_when_docker_cannot_list_the_containers(tmp_path):
    env = fake_docker(tmp_path, 'echo "Cannot connect to the Docker daemon" >&2; exit 1')
    result = down(env)
    assert result.returncode != 0
    assert "lab stopped" not in result.stdout


def test_down_removes_every_lab_container(tmp_path):
    env = fake_docker(tmp_path, '[ "$1" = ps ] && printf "%s\\n" 0123abcd 4567ef01; exit 0')
    result = down(env)
    assert result.returncode == 0, result.stderr
    assert "lab stopped" in result.stdout
    assert "rm -f 0123abcd 4567ef01" in (tmp_path / "calls.log").read_text()


def test_down_with_no_lab_containers_removes_nothing(tmp_path):
    env = fake_docker(tmp_path, "exit 0")
    result = down(env)
    assert result.returncode == 0, result.stderr
    assert "rm" not in (tmp_path / "calls.log").read_text().split()


def test_contributor_scripts_need_no_bash_4_builtins():
    # macOS ships bash 3.2, which `#!/usr/bin/env bash` finds unless a newer bash comes first on PATH.
    for path in sorted((ROOT / "scripts").glob("*.sh")):
        code = [line for line in path.read_text().splitlines() if not line.lstrip().startswith("#")]
        assert not any(re.search(r"\b(mapfile|readarray|coproc)\b|declare -A", line) for line in code), path.name
