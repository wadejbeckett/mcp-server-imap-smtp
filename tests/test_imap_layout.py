# SPDX-License-Identifier: AGPL-3.0-or-later
"""The seams in the IMAP client: wire helpers and types live in modules of their own, the extension
families are mixins in mail/imap_ext/, and imap.py re-exports everything it used to define, so every
existing import and test patch keeps working on the same objects."""
import ast
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_server_imap_smtp.mail import imap, imap_types, imap_wire

PKG = "mcp_server_imap_smtp.mail"
EXT_DIR = Path(imap.__file__).with_name("imap_ext")

# module -> (class, ticket that fills it)
MIXINS = {
    "expunge": "Expunge", "folder_admin": "FolderAdmin", "listing": "Listing", "keywords": "Keywords",
    "sort": "Sort", "thread": "Threading", "sync": "Sync", "quota": "QuotaAcl", "drafts": "Drafts",
    "sections": "Sections", "ids": "Ids",
}
TYPES = ("MailError", "MailAuthError", "MailBusy", "Folder", "SearchQuery")
WIRE = ("_quote", "_mbox", "_check_flags", "_uid_seq", "_parse_sexp", "_imap_date", "limit_value",
        "_login_kind", "_RESP_CODE", "_APPENDUID", "_CTRL", "_FLAG", "_LIST", "_DIGITS", "_UNSELECTABLE",
        "_TRANSIENT_LOGIN", "_BUSY_LOGIN")
# Names the tests patch or read on the imap module: they stay defined there.
STAYS = ("_Conn", "_drop", "Connector", "CHECK_TIMEOUT", "TIMEOUT", "ImapClient", "_CODE_REASONS", "SPECIAL")


def _fresh_import(module: str) -> list[str]:
    """Import one module alone in a new isolated interpreter; returns the package modules that got loaded."""
    code = (f"import sys, {module}; "
            f"print('\\n'.join(sorted(m for m in sys.modules if m.startswith('mcp_server_imap_smtp'))))")
    out = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    return out.stdout.split()


@pytest.mark.parametrize("module", [f"{PKG}.imap_types", f"{PKG}.imap_wire"]
                         + [f"{PKG}.imap_ext.{m}" for m in MIXINS] + [f"{PKG}.imap_ext"])
def test_module_imports_alone_without_the_client(module):
    loaded = _fresh_import(module)
    assert module in loaded
    assert f"{PKG}.imap" not in loaded


def test_imap_imports_alone():
    assert f"{PKG}.imap" in _fresh_import(f"{PKG}.imap")


@pytest.mark.parametrize("name", TYPES)
def test_types_are_the_same_objects_through_imap(name):
    assert getattr(imap, name) is getattr(imap_types, name)


@pytest.mark.parametrize("name", WIRE)
def test_wire_helpers_are_the_same_objects_through_imap(name):
    assert getattr(imap, name) is getattr(imap_wire, name)


@pytest.mark.parametrize("name", STAYS)
def test_patched_names_stay_in_imap(name):
    assert hasattr(imap, name)
    assert not hasattr(imap_wire, name) and not hasattr(imap_types, name)


def test_imap_client_bases():
    import importlib
    bases = tuple(getattr(importlib.import_module(f"{PKG}.imap_ext.{m}"), c) for m, c in MIXINS.items())
    assert imap.ImapClient.__bases__ == bases
    assert [b.__name__ for b in imap.ImapClient.__bases__] == [
        "Expunge", "FolderAdmin", "Listing", "Keywords", "Sort", "Threading", "Sync", "QuotaAcl", "Drafts",
        "Sections", "Ids"]


@pytest.mark.parametrize("module", MIXINS)
def test_mixin_stub_is_named_and_documented(module):
    import importlib
    cls = getattr(importlib.import_module(f"{PKG}.imap_ext.{module}"), MIXINS[module])
    assert cls.__doc__ and "ticket" in cls.__doc__.lower()
    assert cls.__bases__ == (object,)


def _imports(path: Path) -> list[str]:
    """Every module an import statement in path names, relative imports resolved inside the mail package."""
    names = []
    for node in ast.walk(ast.parse(path.read_text(), str(path))):
        if isinstance(node, ast.Import):
            names += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                base = node.module or ""
            else:                       # files in imap_ext/ sit one level below mail/
                parts = f"{PKG}.imap_ext".split(".")
                base = ".".join(parts[:len(parts) - node.level + 1] + ([node.module] if node.module else []))
            names.append(base)
            names += [f"{base}.{a.name}" for a in node.names]
    return names


@pytest.mark.parametrize("path", sorted(EXT_DIR.glob("*.py")), ids=lambda p: p.name)
def test_no_imap_ext_module_imports_the_client(path):
    assert f"{PKG}.imap" not in _imports(path)
    assert not any(n.startswith(f"{PKG}.imap.") for n in _imports(path))


@pytest.mark.parametrize("name", ["imap_wire.py", "imap_types.py"])
def test_wire_and_types_do_not_import_the_client(name):
    path = Path(imap.__file__).with_name(name)
    parts = PKG.split(".")
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.ImportFrom) and node.level:
            base = ".".join(parts[:len(parts) - node.level + 1] + ([node.module] if node.module else []))
            assert base != f"{PKG}.imap"
            assert f"{PKG}.imap" not in {f"{base}.{a.name}" for a in node.names}


def test_every_mixin_module_is_listed():
    assert {p.stem for p in EXT_DIR.glob("*.py")} - {"__init__"} == set(MIXINS)
