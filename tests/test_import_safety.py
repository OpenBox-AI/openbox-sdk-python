"""Import-safety harness — the standing guard every later phase runs against.

Asserts that importing ``openbox_core`` and each ``openbox_core.contracts.*``
module in a fresh subprocess does NOT pull in heavy/side-effectful modules:
httpx, cryptography, requests, or any OTel instrumentation. Constrained
framework paths (e.g. the Temporal workflow sandbox) depend on this.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

# Modules that must never appear in sys.modules after importing a pure module.
FORBIDDEN_MODULES = (
    "httpx",
    "cryptography",
    "requests",
    "urllib3",
    "opentelemetry.instrumentation",
)

# Modules whose import must stay side-effect free.
PURE_IMPORT_TARGETS = (
    "openbox_core",
    "openbox_core.errors",
    "openbox_core.contracts",
    "openbox_core.contracts.events",
    "openbox_core.contracts.results",
    "openbox_core.contracts.context",
    "openbox_core.contracts.otel_spans",
)

_SNIPPET = """
import importlib, json, sys
importlib.import_module({target!r})
loaded = sorted(
    name for name in sys.modules
    if any(name == f or name.startswith(f + ".") for f in {forbidden!r})
)
print(json.dumps(loaded))
"""


def _loaded_forbidden_modules(target: str) -> list[str]:
    """Import ``target`` in a fresh interpreter; return forbidden modules seen."""
    snippet = _SNIPPET.format(target=target, forbidden=FORBIDDEN_MODULES)
    result = subprocess.run(
        [sys.executable, "-c", snippet],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, (
        f"importing {target} failed:\n{result.stderr}"
    )
    return json.loads(result.stdout)


@pytest.mark.parametrize("target", PURE_IMPORT_TARGETS)
def test_pure_import_pulls_no_heavy_modules(target: str) -> None:
    loaded = _loaded_forbidden_modules(target)
    assert loaded == [], (
        f"importing {target} pulled in forbidden modules: {loaded}. "
        "Keep httpx/cryptography/requests/OTel-instrumentation lazy-imported "
        "inside their modules — never at import time of pure modules."
    )


def test_import_performs_zero_file_io():
    """`import openbox_core` must never open a file — not even package
    metadata. Frameworks patch builtins.open/io.open with governed wrappers
    that can (re)import this package mid-evaluation; any import-time file
    read becomes a circular import or unbounded recursion under those hooks.
    """
    code = (
        "import builtins, io\n"
        "def _forbidden(*a, **k):\n"
        "    raise AssertionError(f'file open during import: {a[:1]}')\n"
        "builtins.open = _forbidden\n"
        "io.open = _forbidden\n"
        "import openbox_core\n"
        "assert openbox_core.__version__\n"
        "print('PURE')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
    assert "PURE" in result.stdout
