from __future__ import annotations

import base64
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from openbox_core.contracts.context import ActivityContext
from openbox_sandbox import (
    CommandProfileBundle,
    InMemoryTelemetrySink,
    SandboxAuthorization,
    SandboxCommand,
    SandboxEngineConfig,
    SandboxExecutionConfig,
    SandboxExecutionEngine,
)
from openbox_sandbox.profiles import _sign_for_test
from openbox_sandbox.runtime import (
    AssetBundleIdentity,
    OutputLimits,
    PolicyDocument,
    PolicyIdentity,
    ServiceResponse,
)
from openbox_sandbox.telemetry import CleanupBacklog, TelemetrySink

NOW = datetime(2026, 7, 17, tzinfo=UTC)
SECRET = b"0123456789abcdef0123456789abcdef"
KEY_ID = "profiles-2026-01"
SANDBOX_ID = "sbx-550e8400-e29b-41d4-a716-446655440000"
LIFECYCLE_TOKEN = "550e8400-e29b-41d4-a716-446655440001"
READY_TOKEN = "550e8400-e29b-41d4-a716-446655440003"


def payload(profiles: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "bundle_version": "2026-07-17.1",
        "key_id": KEY_ID,
        "issued_at": "2026-07-16T00:00:00Z",
        "expires_at": "2027-07-17T00:00:00Z",
        "profiles": profiles
        or [
            {
                "id": "echo-fixed",
                "executable": "/bin/echo",
                "arguments": [],
                "sensitive": False,
                "free_form": False,
            }
        ],
    }


def bundle(profiles: list[dict[str, Any]] | None = None) -> CommandProfileBundle:
    return CommandProfileBundle.load(
        _sign_for_test(payload(profiles), SECRET, KEY_ID),
        secret=SECRET,
        expected_key_id=KEY_ID,
        now=NOW,
    )


def asset_bundle() -> AssetBundleIdentity:
    return AssetBundleIdentity(
        runtime_contract_version=1,
        adapter_build_sha256="a" * 64,
        template="registry.invalid/openbox@sha256:" + "c" * 64,
        policy=PolicyIdentity("deny-network", 1, "b" * 64),
        compatibility_id="linux-arm64-v1",
    )


def config(
    *,
    profiles: CommandProfileBundle | None = None,
    telemetry: TelemetrySink | None = None,
    enabled: bool = True,
    cleanup_backlog: CleanupBacklog | None = None,
) -> SandboxEngineConfig:
    return SandboxEngineConfig(
        profiles=profiles or bundle(),
        sandbox=SandboxExecutionConfig(
            host="127.0.0.1",
            port=7443,
            server_name="sandbox.service.invalid",
            ca_path=Path("/credentials/ca.pem"),
            certificate_path=Path("/credentials/client.pem"),
            private_key_path=Path("/credentials/client.key"),
            asset_bundle=asset_bundle(),
            policy_document=PolicyDocument("application/yaml", b"version: 1\n"),
            output_limits=OutputLimits(1024, 1024, 1536, 4096),
            enabled=enabled,
        ),
        telemetry=telemetry,
        cleanup_backlog=cleanup_backlog,
    )


class FakeSandbox:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...]]] = []
        self.values: dict[str, Any] = {
            "create": ServiceResponse(
                "created", {"request_id": SANDBOX_ID, "lifecycle_token": LIFECYCLE_TOKEN}
            ),
            "wait_ready": ServiceResponse(
                "ready",
                {
                    "request_id": SANDBOX_ID,
                    "lifecycle_token": READY_TOKEN,
                    "active_policy": asset_bundle().policy.to_wire(),
                },
            ),
            "exec": ServiceResponse(
                "executed",
                {
                    "result": {
                        "exit_code": 7,
                        "stdout_base64": base64.b64encode(b"sandbox-out\x00").decode(),
                        "stderr_base64": base64.b64encode(b"sandbox-err\xff").decode(),
                        "timeout": "not_observed",
                    }
                },
            ),
            "delete": ServiceResponse("deleted", {"outcome": "deleted"}),
            "wait_deleted": ServiceResponse("terminally_absent", {}),
        }

    async def _call(self, name: str, *args: Any) -> Any:
        self.calls.append((name, args))
        value = self.values[name]
        if isinstance(value, BaseException):
            raise value
        return value

    async def create(self, *args: Any) -> Any:
        return await self._call("create", *args)

    async def wait_ready(self, *args: Any) -> Any:
        return await self._call("wait_ready", *args)

    async def exec(self, *args: Any) -> Any:
        return await self._call("exec", *args)

    async def delete(self, *args: Any) -> Any:
        return await self._call("delete", *args)

    async def wait_deleted(self, *args: Any) -> Any:
        return await self._call("wait_deleted", *args)


def command(**overrides: Any) -> SandboxCommand:
    values: dict[str, Any] = {
        "context": ActivityContext(
            workflow_id="wf-123",
            run_id="run-456",
            activity_id="act-789",
            workflow_type="ProofWorkflow",
            task_queue="governed",
            metadata={"attempt": 1},
        ),
        "argv": ["/bin/echo"],
        "profile_id": "echo-fixed",
    }
    values.update(overrides)
    return SandboxCommand(**values)


def authorization() -> SandboxAuthorization:
    return SandboxAuthorization.trusted_application("trusted:wf-123:run-456:act-789")


def engine(
    *,
    configuration: SandboxEngineConfig | None = None,
    sandbox: FakeSandbox | None = None,
) -> tuple[SandboxExecutionEngine, FakeSandbox]:
    fake_sandbox = sandbox or FakeSandbox()
    value = SandboxExecutionEngine._from_components(
        configuration or config(),
        sandbox=fake_sandbox,
        clock=lambda: NOW,
        sandbox_id=lambda: SANDBOX_ID,
    )
    return value, fake_sandbox


__all__ = [
    "InMemoryTelemetrySink",
    "NOW",
    "SANDBOX_ID",
    "authorization",
    "bundle",
    "command",
    "config",
    "engine",
]
