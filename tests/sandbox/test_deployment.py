from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

import openbox_sandbox.deployment as deployment_module
from openbox_sandbox import (
    GovernedCommandDeploymentError,
    SandboxDeployment,
    SandboxExecutionConfig,
    UnixAgentExecutionConfig,
    load_approved_sandbox_release,
    load_sandbox_deployment,
)
from openbox_sandbox.release import _clear_approved_sandbox_release_for_testing
from openbox_sandbox.runtime import ServiceResponse

from .deployment_helpers import (
    POLICY_BODY,
    deployment_value,
    prepare_files,
    release_value,
    write_file,
    write_manifest,
)


class FakeRuntime:
    def __init__(self, response: ServiceResponse | None = None) -> None:
        self.response = response or healthy_response()
        self.config: object | None = None
        self.health_deadlines: list[int] = []
        self.calls: list[str] = []

    async def health(self, deadline_ms: int = 5_000) -> ServiceResponse:
        self.health_deadlines.append(deadline_ms)
        return self.response

    async def delete(self, *args: Any) -> ServiceResponse:
        self.calls.append("delete")
        return ServiceResponse("deleted", {"outcome": "deleted"})

    async def wait_deleted(self, *args: Any) -> ServiceResponse:
        self.calls.append("wait_deleted")
        return ServiceResponse("terminally_absent", {})


def healthy_response() -> ServiceResponse:
    return ServiceResponse(
        "health",
        {
            "status": {
                "ready": True,
                "draining": False,
                "startup_reconciled": True,
                "active_operations": 0,
                "pending_cleanup_records": 0,
            }
        },
    )


@pytest.fixture(autouse=True)
def clear_release() -> None:
    _clear_approved_sandbox_release_for_testing()


def prepared_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    uds: bool = False,
    runtime: FakeRuntime | None = None,
):
    files = prepare_files(tmp_path)
    load_approved_sandbox_release(files["release"])
    commands, value = deployment_value(tmp_path, files, uds=uds)
    selected_runtime = runtime or FakeRuntime()
    target = "UnixAgentRuntimeClient" if uds else "SandboxRuntimeClient"

    def runtime_factory(config: object) -> FakeRuntime:
        selected_runtime.config = config
        return selected_runtime

    monkeypatch.setattr(deployment_module, target, runtime_factory)
    manifest = write_manifest(tmp_path / "deployment.json", value)
    return files, commands, value, manifest, selected_runtime


def test_deployment_requires_validated_factory() -> None:
    with pytest.raises(TypeError, match="SandboxDeployment.load"):
        SandboxDeployment()


@pytest.mark.asyncio
async def test_direct_tls_deployment_preflight_and_cleanup_wiring(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    files, registry, _, manifest, runtime = prepared_manifest(tmp_path, monkeypatch)
    deployment = load_sandbox_deployment(manifest, registry=registry)

    assert isinstance(deployment, SandboxDeployment)
    assert isinstance(deployment.config.sandbox, SandboxExecutionConfig)
    assert deployment.config.transport_kind == "direct_tls"
    assert deployment.config.registry_fingerprint == registry.fingerprint
    assert deployment.profiles.fingerprint == registry.fingerprint
    assert deployment.structured_profiles.fingerprint == registry.fingerprint
    assert deployment.cleanup_backlog.directory == files["cleanup"]
    assert deployment.engine.asset_bundle == deployment.asset_bundle
    assert runtime.config is not None
    assert runtime.config.asset_bundle == deployment.asset_bundle  # type: ignore[union-attr]

    health = await deployment.preflight(deadline_ms=1_234)
    assert health.ready is True
    assert runtime.health_deadlines == [1_234]
    await deployment.cleanup_backlog.record(
        "sbx-550e8400-e29b-41d4-a716-446655440000",
        "delete_unconfirmed",
        "2026-07-23T03:00:00Z",
    )
    cleanup = await deployment.reconcile_cleanup()
    assert (cleanup.attempted, cleanup.deleted, cleanup.remaining) == (1, 1, 0)
    assert runtime.calls == ["delete", "wait_deleted"]


@pytest.mark.asyncio
async def test_uds_deployment_selects_exactly_one_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, registry, _, manifest, _ = prepared_manifest(tmp_path, monkeypatch, uds=True)
    deployment = SandboxDeployment.load(manifest, registry=registry)
    assert deployment.config.transport_kind == "uds_agent"
    assert isinstance(deployment.config.sandbox, UnixAgentExecutionConfig)
    assert deployment.config.sandbox.registry_fingerprint == registry.fingerprint
    assert (await deployment.preflight()).ready is True


def test_manifest_kill_switch_is_preserved(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _, registry, value, _, _ = prepared_manifest(tmp_path, monkeypatch)
    value["enabled"] = False
    manifest = write_manifest(tmp_path / "disabled.json", value)
    deployment = SandboxDeployment.load(manifest, registry=registry)
    assert deployment.config.sandbox.enabled is False


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.update(extra=True),
        lambda value: value.update(schema_version=2),
        lambda value: value.update(enabled=1),
        lambda value: value["transport"].update(socket_path="/tmp/also.sock"),
        lambda value: value["transport"].update(host="192.0.2.1"),
        lambda value: value["transport"].update(port=True),
        lambda value: value["output_limits"].update(stdout_bytes=1024 * 1024 + 1),
        lambda value: value["output_limits"].update(stderr_bytes=1024 * 1024 + 1),
        lambda value: value["output_limits"].update(combined_bytes=2 * 1024 * 1024 + 1),
        lambda value: value["output_limits"].update(chunk_bytes=4 * 1024 * 1024 + 1),
        lambda value: value["output_limits"].update(combined_bytes=1),
        lambda value: value["deadlines"].update(exec_deadline_ms=45_001),
        lambda value: value["profiles"].update(registry_fingerprint="d" * 64),
        lambda value: value["profiles"].update(command_ids=[]),
    ],
)
def test_manifest_rejects_unknown_noncanonical_and_oversized_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutate,
) -> None:
    _, registry, value, _, _ = prepared_manifest(tmp_path, monkeypatch)
    mutate(value)
    manifest = write_manifest(tmp_path / "invalid-deployment.json", value)
    with pytest.raises(GovernedCommandDeploymentError):
        load_sandbox_deployment(manifest, registry=registry)


@pytest.mark.parametrize(
    "body",
    [
        b'{"schema_version":1,"schema_version":1}',
        b'{"schema_version":NaN}',
        b"\xff",
        b"[]",
    ],
)
def test_manifest_rejects_duplicate_keys_constants_utf8_and_nonobject(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    body: bytes,
) -> None:
    _, registry, _, _, _ = prepared_manifest(tmp_path, monkeypatch)
    manifest = write_file(tmp_path / "malformed.json", body, 0o644)
    with pytest.raises(GovernedCommandDeploymentError):
        load_sandbox_deployment(manifest, registry=registry)


def test_manifest_rejects_more_than_one_mib(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, registry, _, _, _ = prepared_manifest(tmp_path, monkeypatch)
    manifest = write_file(tmp_path / "oversized.json", b"{" + b" " * (1024 * 1024), 0o644)
    with pytest.raises(GovernedCommandDeploymentError):
        load_sandbox_deployment(manifest, registry=registry)


def test_manifest_requires_absolute_explicit_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, registry, _, _, _ = prepared_manifest(tmp_path, monkeypatch)
    with pytest.raises(GovernedCommandDeploymentError):
        load_sandbox_deployment(Path("deployment.json"), registry=registry)


def test_secure_file_modes_symlinks_and_owner_are_enforced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    files, registry, value, manifest, _ = prepared_manifest(tmp_path, monkeypatch)

    manifest.chmod(0o666)
    with pytest.raises(GovernedCommandDeploymentError):
        load_sandbox_deployment(manifest, registry=registry)
    manifest.chmod(0o644)

    for credential in ("certificate", "private_key"):
        files[credential].chmod(0o640)
        with pytest.raises(GovernedCommandDeploymentError):
            load_sandbox_deployment(manifest, registry=registry)
        files[credential].chmod(0o600)

    symlink = tmp_path / "linked-policy.yaml"
    symlink.symlink_to(files["policy"])
    value["release"] = release_value(symlink)
    linked_manifest = write_manifest(tmp_path / "linked.json", value)
    with pytest.raises(GovernedCommandDeploymentError):
        load_sandbox_deployment(linked_manifest, registry=registry)

    value["release"] = release_value(files["policy"])
    owner_manifest = write_manifest(tmp_path / "owner.json", value)
    current_uid = os.getuid()
    monkeypatch.setattr("openbox_sandbox._trusted_files.os.getuid", lambda: current_uid + 1)
    with pytest.raises(GovernedCommandDeploymentError):
        load_sandbox_deployment(owner_manifest, registry=registry)


def test_cleanup_backlog_directory_must_be_existing_private_owner_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    files, registry, value, manifest, _ = prepared_manifest(tmp_path, monkeypatch)
    files["cleanup"].chmod(0o755)
    with pytest.raises(GovernedCommandDeploymentError):
        load_sandbox_deployment(manifest, registry=registry)
    files["cleanup"].chmod(0o700)

    linked = tmp_path / "linked-cleanup"
    linked.symlink_to(files["cleanup"], target_is_directory=True)
    value["cleanup_backlog_directory"] = str(linked)
    linked_manifest = write_manifest(tmp_path / "linked-cleanup.json", value)
    with pytest.raises(GovernedCommandDeploymentError):
        load_sandbox_deployment(linked_manifest, registry=registry)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("runtime_contract_version",), 2),
        (("adapter_build_sha256",), "d" * 64),
        (("template",), "registry.invalid/other@sha256:" + "d" * 64),
        (("compatibility_id",), "other-client-v1"),
        (("policy", "id"), "other-policy"),
        (("policy", "version"), 2),
        (("policy", "sha256"), "d" * 64),
        (("policy", "media_type"), "application/json"),
    ],
)
def test_manifest_release_mismatch_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    path: tuple[str, ...],
    value: object,
) -> None:
    _, registry, manifest_value, _, _ = prepared_manifest(tmp_path, monkeypatch)
    target = manifest_value["release"]
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    manifest = write_manifest(tmp_path / "mismatched.json", manifest_value)
    with pytest.raises(GovernedCommandDeploymentError):
        load_sandbox_deployment(manifest, registry=registry)


def test_manifest_policy_body_mismatch_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, registry, value, _, _ = prepared_manifest(tmp_path, monkeypatch)
    other = write_file(tmp_path / "other-policy.yaml", b"version: 2\n", 0o644)
    value["release"]["policy"]["path"] = str(other)
    manifest = write_manifest(tmp_path / "body-mismatch.json", value)
    with pytest.raises(GovernedCommandDeploymentError):
        load_sandbox_deployment(manifest, registry=registry)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [
        ServiceResponse("boundary_failed", {"failure": {"code": "asset_bundle_mismatch"}}),
        ServiceResponse("health", {}),
        ServiceResponse("health", {"status": {"ready": True}}),
        ServiceResponse(
            "health",
            {
                "status": {
                    "ready": False,
                    "draining": False,
                    "startup_reconciled": True,
                    "active_operations": 0,
                    "pending_cleanup_records": 0,
                }
            },
        ),
    ],
)
async def test_preflight_rejects_service_identity_or_shape_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    response: ServiceResponse,
) -> None:
    runtime = FakeRuntime(response)
    _, registry, _, manifest, _ = prepared_manifest(
        tmp_path,
        monkeypatch,
        runtime=runtime,
    )
    deployment = SandboxDeployment.load(manifest, registry=registry)
    with pytest.raises(GovernedCommandDeploymentError):
        await deployment.preflight()


def test_deployment_repr_redacts_paths_credentials_and_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    files, registry, _, manifest, _ = prepared_manifest(tmp_path, monkeypatch)
    value = SandboxDeployment.load(manifest, registry=registry)
    rendered = repr(value)
    for forbidden in (
        str(manifest),
        str(files["private_key"]),
        str(files["cleanup"]),
        POLICY_BODY.decode(),
    ):
        assert forbidden not in rendered
    assert "<redacted>" in rendered


def test_deployment_source_and_imports_have_no_framework_core_or_process_control() -> None:
    source = Path(deployment_module.__file__).read_text()
    for forbidden in ("openbox_core", "temporalio", "subprocess", "Popen", "docker", "cargo"):
        assert forbidden not in source.lower()

    snippet = """
import json, sys
before = set(sys.modules)
import openbox_sandbox.deployment
forbidden = ('temporalio', 'openbox_core.client')
print(json.dumps(sorted(name for name in set(sys.modules) - before if any(
    name == prefix or name.startswith(prefix + '.') for prefix in forbidden
))))
"""
    result = subprocess.run(
        [sys.executable, "-c", snippet],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    assert json.loads(result.stdout) == []
