from __future__ import annotations

import ast
import tomllib
from pathlib import Path

import openbox_sandbox

ROOT = Path(__file__).resolve().parents[2]


def test_console_script_exposes_existing_executor_only_agent() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert project["project"]["scripts"] == {
        "openbox-sandbox-agent": "openbox_sandbox.runtime.agent_server:main"
    }


def test_distribution_embeds_no_approved_release_or_policy() -> None:
    package_files = {
        path.relative_to(ROOT / "openbox_sandbox").as_posix()
        for path in (ROOT / "openbox_sandbox").rglob("*")
        if path.is_file()
    }
    assert not any(
        "approved" in name or name.endswith((".yaml", ".json")) for name in package_files
    )


def test_deployment_module_has_no_core_temporal_or_process_imports() -> None:
    source = (ROOT / "openbox_sandbox" / "deployment.py").read_text()
    tree = ast.parse(source)
    imports = {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)} | {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    for forbidden in ("openbox_core", "temporalio", "subprocess", "multiprocessing"):
        assert not any(name == forbidden or name.startswith(forbidden + ".") for name in imports)


def test_lazy_top_level_exports_match_type_stub() -> None:
    stub = (ROOT / "openbox_sandbox" / "__init__.pyi").read_text()
    for name in (
        "SandboxDeployment",
        "SandboxDeploymentConfig",
        "SandboxHealth",
        "SandboxReleaseMaterial",
        "AuthorizedConstrain",
        "ReceiptSigner",
        "issue_sandbox_receipt",
        "load_approved_sandbox_release",
        "load_sandbox_deployment",
        "materialize_approved_sandbox_release",
    ):
        assert name in openbox_sandbox.__all__
        assert name in stub
