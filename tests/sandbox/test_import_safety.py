from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

_FORBIDDEN_PREFIXES = (
    "cryptography",
    "httpx",
    "openbox_core.client",
    "openbox_core.identity",
    "openbox_sandbox.engine",
    "openbox_sandbox.receipts",
    "openbox_sandbox.runtime",
    "ssl",
)


@pytest.mark.parametrize(
    "statement",
    [
        "import openbox_sandbox.contracts",
        "from openbox_sandbox import SandboxCommandRequest",
    ],
)
def test_history_contract_import_does_not_load_runtime_or_signing(statement: str) -> None:
    snippet = f"""
import json
import sys
{statement}
forbidden = {repr(_FORBIDDEN_PREFIXES)}
print(json.dumps(sorted(
    name for name in sys.modules
    if any(name == prefix or name.startswith(prefix + '.') for prefix in forbidden)
)))
"""
    package_root = str(Path(__file__).resolve().parents[1])
    result = subprocess.run(
        [sys.executable, "-c", snippet],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
        env={**os.environ, "PYTHONPATH": package_root},
    )
    assert json.loads(result.stdout) == []
