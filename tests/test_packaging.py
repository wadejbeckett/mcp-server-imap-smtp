# SPDX-License-Identifier: AGPL-3.0-or-later
"""Ticket 76: the package metadata a package index page shows, and what the sdist carries."""
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
REPOSITORY = "https://github.com/wadejbeckett/mcp-server-imap-smtp"


def test_index_page_metadata():
    assert PROJECT["description"] and len(PROJECT["description"]) <= 200
    assert PROJECT["readme"] == "README.md"
    assert PROJECT["license"] == "AGPL-3.0-or-later" and PROJECT["license-files"] == ["LICENSE"]
    assert {"mcp", "imap", "smtp", "email", "oauth"} <= set(PROJECT["keywords"])


def test_urls_point_at_the_repository_its_issues_docs_and_changelog():
    urls = PROJECT["urls"]
    assert urls["Repository"] == REPOSITORY
    assert urls["Issues"] == REPOSITORY + "/issues"
    assert urls["Documentation"].startswith(REPOSITORY + "/")
    assert urls["Changelog"] == REPOSITORY + "/blob/main/CHANGELOG.md"


def test_classifiers_name_each_supported_python_version():
    classifiers = PROJECT["classifiers"]
    minimum = re.fullmatch(r">=3\.(\d+)", PROJECT["requires-python"])[1]
    assert f"Programming Language :: Python :: 3.{minimum}" in classifiers
    assert "Programming Language :: Python :: 3 :: Only" in classifiers
    # PEP 639: the licence is the SPDX expression above; setuptools refuses a licence classifier beside it.
    assert not [c for c in classifiers if c.startswith("License ::")]


def test_sdist_carries_the_changelog_and_example_config_but_no_partial_test_suite():
    manifest = (ROOT / "MANIFEST.in").read_text().splitlines()
    for line in ("include CHANGELOG.md", "include SECURITY.md", "include config.example.toml", "prune tests"):
        assert line in manifest, line


def test_changelog_follows_keep_a_changelog():
    text = (ROOT / "CHANGELOG.md").read_text()
    assert text.startswith("# Changelog\n")
    assert "## [Unreleased]" in text
    # Nothing has been tagged or published yet: the version in pyproject.toml is named, not given a release date.
    assert PROJECT["version"] in text.split("## [Unreleased]")[1].split("\n### ")[0]
