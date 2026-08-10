"""Provider-neutral, owner-controlled sandbox deployment materialization.

This module configures an existing client-side sandbox runtime. It does not call
OpenBox Core, import a workflow framework, spawn processes, build artifacts,
select governance verdicts, execute on the host, or retry commands.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ._trusted_files import (
    load_strict_json,
    validate_secure_directory,
    validate_trusted_file,
)
from .command_profiles import StructuredCommandProfileBundle
from .engine import (
    SandboxEngineConfig,
    SandboxExecutionConfig,
    SandboxExecutionEngine,
    UnixAgentExecutionConfig,
)
from .errors import GovernedCommandDeploymentError
from .profiles import CommandProfileBundle
from .registry import GovernedCommandRegistry
from .release import (
    ApprovedSandboxRelease,
    _declaration_matches,
    _parse_release_declaration,
    approved_sandbox_release,
    materialize_approved_sandbox_release,
)
from .result import CleanupReconciliationResult
from .runtime import (
    AssetBundleIdentity,
    OutputLimits,
    PolicyDocument,
    SandboxRuntimeClient,
    SandboxRuntimeClientConfig,
    ServiceResponse,
    UnixAgentRuntimeClient,
    UnixAgentRuntimeClientConfig,
)
from .telemetry import CleanupBacklog, TelemetrySink

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_DNS_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")


def _exact(value: object, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise GovernedCommandDeploymentError()
    return value


def _string(value: object, *, maximum: int = 4096) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\x00" in value
        or any(ord(character) < 32 for character in value)
        or len(value.encode("utf-8")) > maximum
    ):
        raise GovernedCommandDeploymentError()
    return value


def _integer(value: object, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise GovernedCommandDeploymentError()
    return value


def _boolean(value: object) -> bool:
    if type(value) is not bool:
        raise GovernedCommandDeploymentError()
    return value


def _absolute_path(value: object) -> Path:
    path = Path(_string(value))
    if not path.is_absolute():
        raise GovernedCommandDeploymentError()
    return path


def _server_name(value: object) -> str:
    name = _string(value, maximum=253)
    if name.endswith("."):
        name = name[:-1]
    labels = name.split(".")
    if not labels or any(_DNS_LABEL.fullmatch(label) is None for label in labels):
        raise GovernedCommandDeploymentError()
    return name


@dataclass(frozen=True, slots=True, repr=False)
class SandboxDeploymentConfig:
    """Validated immutable deployment configuration."""

    deployment_id: str
    manifest_path: Path
    transport_kind: str
    sandbox: SandboxExecutionConfig | UnixAgentExecutionConfig
    registry_fingerprint: str
    profile_bundle_version: str
    cleanup_backlog_directory: Path

    def __repr__(self) -> str:
        return (
            "SandboxDeploymentConfig("
            f"deployment_id={self.deployment_id!r}, "
            f"transport_kind={self.transport_kind!r}, "
            f"registry_fingerprint={self.registry_fingerprint!r}, "
            f"profile_bundle_version={self.profile_bundle_version!r}, "
            f"sandbox={self.sandbox!r}, manifest_path=<redacted>, "
            "cleanup_backlog_directory=<redacted>)"
        )


@dataclass(frozen=True, slots=True)
class SandboxHealth:
    """Strictly validated sandbox-service health state."""

    ready: bool
    draining: bool
    startup_reconciled: bool
    active_operations: int
    pending_cleanup_records: int


@dataclass(frozen=True, slots=True, repr=False, init=False)
class SandboxDeployment:
    """Materialized client-side sandbox deployment and lifecycle owner."""

    config: SandboxDeploymentConfig
    release: ApprovedSandboxRelease
    asset_bundle: AssetBundleIdentity
    policy_document: PolicyDocument = field(repr=False)
    registry: GovernedCommandRegistry
    profiles: CommandProfileBundle
    structured_profiles: StructuredCommandProfileBundle
    cleanup_backlog: CleanupBacklog
    engine: SandboxExecutionEngine
    _runtime: SandboxRuntimeClient | UnixAgentRuntimeClient = field(repr=False, compare=False)

    def __init__(self) -> None:
        raise TypeError("use SandboxDeployment.load()")

    @classmethod
    def load(
        cls,
        manifest_path: Path,
        *,
        registry: GovernedCommandRegistry,
        telemetry: TelemetrySink | None = None,
    ) -> SandboxDeployment:
        """Load one explicit manifest and materialize its validated runtime."""
        return load_sandbox_deployment(
            manifest_path,
            registry=registry,
            telemetry=telemetry,
        )

    async def preflight(self, *, deadline_ms: int = 5_000) -> SandboxHealth:
        """Validate readiness through the exact approved request identity.

        Both transports place ``asset_bundle`` in the authenticated request
        boundary. A mismatched service or agent fails before a health response
        can be accepted; the response itself is then checked with an exact
        schema.
        """
        if type(deadline_ms) is not int or not 1 <= deadline_ms <= 120_000:
            raise GovernedCommandDeploymentError()
        if (
            self.engine.asset_bundle != self.asset_bundle
            or self.config.sandbox.asset_bundle != self.asset_bundle
            or self.release != approved_sandbox_release()
        ):
            raise GovernedCommandDeploymentError()
        try:
            response = await self._runtime.health(deadline_ms)
            return _parse_health(response)
        except asyncio.CancelledError:
            raise
        except GovernedCommandDeploymentError:
            raise GovernedCommandDeploymentError() from None
        except Exception:
            raise GovernedCommandDeploymentError() from None

    async def reconcile_cleanup(self) -> CleanupReconciliationResult:
        """Retry engine-owned terminal-absence confirmation from the backlog."""
        try:
            result = await self.engine.reconcile_cleanup()
        except asyncio.CancelledError:
            raise
        except Exception:
            raise GovernedCommandDeploymentError() from None
        if not isinstance(result, CleanupReconciliationResult):
            raise GovernedCommandDeploymentError()
        return result

    def __repr__(self) -> str:
        return (
            "SandboxDeployment("
            f"config={self.config!r}, release={self.release!r}, "
            f"registry={self.registry!r}, profiles={self.profiles!r}, "
            "policy_document=<redacted>, runtime=<redacted>)"
        )


def _parse_health(response: ServiceResponse) -> SandboxHealth:
    if (
        not isinstance(response, ServiceResponse)
        or response.response != "health"
        or set(response.fields) != {"status"}
    ):
        raise GovernedCommandDeploymentError()
    status = response.fields["status"]
    fields = {
        "ready",
        "draining",
        "startup_reconciled",
        "active_operations",
        "pending_cleanup_records",
    }
    if not isinstance(status, dict) or set(status) != fields:
        raise GovernedCommandDeploymentError()
    active = status["active_operations"]
    pending = status["pending_cleanup_records"]
    if (
        status["ready"] is not True
        or status["draining"] is not False
        or status["startup_reconciled"] is not True
        or type(active) is not int
        or type(pending) is not int
        or active < 0
        or pending < 0
    ):
        raise GovernedCommandDeploymentError()
    return SandboxHealth(True, False, True, active, pending)


def _parse_profiles(value: object, registry: GovernedCommandRegistry) -> None:
    profiles = _exact(
        value,
        {"registry_fingerprint", "bundle_version", "command_ids"},
    )
    fingerprint = _string(profiles["registry_fingerprint"], maximum=64)
    command_ids = profiles["command_ids"]
    if (
        _SHA256.fullmatch(fingerprint) is None
        or fingerprint != registry.fingerprint
        or profiles["bundle_version"] != registry.bundle_version
        or not isinstance(command_ids, list)
        or command_ids != list(registry.command_ids)
    ):
        raise GovernedCommandDeploymentError()


def _parse_output_limits(value: object) -> OutputLimits:
    limits = _exact(
        value,
        {"stdout_bytes", "stderr_bytes", "combined_bytes", "chunk_bytes"},
    )
    stdout = _integer(limits["stdout_bytes"], 1, 1024 * 1024)
    stderr = _integer(limits["stderr_bytes"], 1, 1024 * 1024)
    combined = _integer(limits["combined_bytes"], 1, 2 * 1024 * 1024)
    chunk = _integer(limits["chunk_bytes"], 1, 4 * 1024 * 1024)
    if combined < max(stdout, stderr):
        raise GovernedCommandDeploymentError()
    try:
        return OutputLimits(stdout, stderr, combined, chunk)
    except (TypeError, ValueError):
        raise GovernedCommandDeploymentError() from None


def _parse_deadlines(value: object) -> dict[str, int]:
    deadlines = _exact(
        value,
        {
            "create_deadline_ms",
            "readiness_deadline_ms",
            "exec_deadline_ms",
            "delete_deadline_ms",
            "wait_deleted_deadline_ms",
        },
    )
    return {
        "create_deadline_ms": _integer(deadlines["create_deadline_ms"], 1, 60_000),
        "readiness_deadline_ms": _integer(deadlines["readiness_deadline_ms"], 1, 120_000),
        "exec_deadline_ms": _integer(deadlines["exec_deadline_ms"], 1, 45_000),
        "delete_deadline_ms": _integer(deadlines["delete_deadline_ms"], 1, 60_000),
        "wait_deleted_deadline_ms": _integer(deadlines["wait_deleted_deadline_ms"], 1, 60_000),
    }


def _direct_transport(
    value: dict[str, Any],
    *,
    asset_bundle: AssetBundleIdentity,
    policy_document: PolicyDocument,
    output_limits: OutputLimits,
    deadlines: dict[str, int],
    enabled: bool,
) -> tuple[SandboxExecutionConfig, SandboxRuntimeClient]:
    transport = _exact(
        value,
        {
            "kind",
            "host",
            "port",
            "server_name",
            "ca_path",
            "certificate_path",
            "private_key_path",
        },
    )
    if transport["kind"] != "direct_tls":
        raise GovernedCommandDeploymentError()
    host = _string(transport["host"], maximum=64)
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise GovernedCommandDeploymentError() from None
    if not address.is_loopback:
        raise GovernedCommandDeploymentError()
    ca_path = _absolute_path(transport["ca_path"])
    certificate_path = _absolute_path(transport["certificate_path"])
    private_key_path = _absolute_path(transport["private_key_path"])
    validate_trusted_file(ca_path)
    validate_trusted_file(certificate_path, private=True)
    validate_trusted_file(private_key_path, private=True)
    server_name = _server_name(transport["server_name"])
    port = _integer(transport["port"], 1, 65_535)
    sandbox = SandboxExecutionConfig(
        host=str(address),
        port=port,
        server_name=server_name,
        ca_path=ca_path,
        certificate_path=certificate_path,
        private_key_path=private_key_path,
        asset_bundle=asset_bundle,
        policy_document=policy_document,
        output_limits=output_limits,
        enabled=enabled,
        **deadlines,
    )
    runtime = SandboxRuntimeClient(
        SandboxRuntimeClientConfig(
            host=sandbox.host,
            port=sandbox.port,
            server_name=sandbox.server_name,
            ca_path=sandbox.ca_path,
            certificate_path=sandbox.certificate_path,
            private_key_path=sandbox.private_key_path,
            asset_bundle=asset_bundle,
        )
    )
    return sandbox, runtime


def _uds_transport(
    value: dict[str, Any],
    *,
    registry: GovernedCommandRegistry,
    asset_bundle: AssetBundleIdentity,
    policy_document: PolicyDocument,
    output_limits: OutputLimits,
    deadlines: dict[str, int],
    enabled: bool,
) -> tuple[UnixAgentExecutionConfig, UnixAgentRuntimeClient]:
    transport = _exact(value, {"kind", "socket_path"})
    if transport["kind"] != "uds_agent":
        raise GovernedCommandDeploymentError()
    socket_path = _absolute_path(transport["socket_path"])
    sandbox = UnixAgentExecutionConfig(
        socket_path=socket_path,
        registry_fingerprint=registry.fingerprint,
        asset_bundle=asset_bundle,
        policy_document=policy_document,
        output_limits=output_limits,
        enabled=enabled,
        **deadlines,
    )
    runtime = UnixAgentRuntimeClient(
        UnixAgentRuntimeClientConfig(
            socket_path=socket_path,
            asset_bundle=asset_bundle,
            registry_fingerprint=registry.fingerprint,
        )
    )
    return sandbox, runtime


def _load_sandbox_deployment(
    manifest_path: Path,
    *,
    registry: GovernedCommandRegistry,
    telemetry: TelemetrySink | None,
) -> SandboxDeployment:
    if not isinstance(manifest_path, Path) or not manifest_path.is_absolute():
        raise GovernedCommandDeploymentError()
    if not isinstance(registry, GovernedCommandRegistry):
        raise GovernedCommandDeploymentError()
    root = _exact(
        load_strict_json(manifest_path),
        {
            "schema_version",
            "deployment_id",
            "transport",
            "release",
            "profiles",
            "cleanup_backlog_directory",
            "output_limits",
            "deadlines",
            "enabled",
        },
    )
    if type(root["schema_version"]) is not int or root["schema_version"] != 1:
        raise GovernedCommandDeploymentError()
    deployment_id = _string(root["deployment_id"], maximum=128)
    if _IDENTIFIER.fullmatch(deployment_id) is None:
        raise GovernedCommandDeploymentError()

    release = approved_sandbox_release()
    declaration = _parse_release_declaration(root["release"])
    if not _declaration_matches(declaration, release):
        raise GovernedCommandDeploymentError()
    material = materialize_approved_sandbox_release()

    _parse_profiles(root["profiles"], registry)
    profiles = registry.admission_profile_bundle()
    structured_profiles = registry.structured_profile_bundle()
    if (
        profiles.fingerprint != registry.fingerprint
        or structured_profiles.fingerprint != registry.fingerprint
        or profiles.bundle_version != structured_profiles.bundle_version
    ):
        raise GovernedCommandDeploymentError()

    cleanup_directory = _absolute_path(root["cleanup_backlog_directory"])
    validate_secure_directory(cleanup_directory)
    cleanup_backlog = CleanupBacklog(cleanup_directory, release.compatibility_id)
    output_limits = _parse_output_limits(root["output_limits"])
    deadlines = _parse_deadlines(root["deadlines"])
    enabled = _boolean(root["enabled"])

    transport = root["transport"]
    if not isinstance(transport, dict):
        raise GovernedCommandDeploymentError()
    sandbox: SandboxExecutionConfig | UnixAgentExecutionConfig
    runtime: SandboxRuntimeClient | UnixAgentRuntimeClient
    if transport.get("kind") == "direct_tls":
        sandbox, runtime = _direct_transport(
            transport,
            asset_bundle=material.asset_bundle,
            policy_document=material.policy_document,
            output_limits=output_limits,
            deadlines=deadlines,
            enabled=enabled,
        )
        transport_kind = "direct_tls"
    elif transport.get("kind") == "uds_agent":
        sandbox, runtime = _uds_transport(
            transport,
            registry=registry,
            asset_bundle=material.asset_bundle,
            policy_document=material.policy_document,
            output_limits=output_limits,
            deadlines=deadlines,
            enabled=enabled,
        )
        transport_kind = "uds_agent"
    else:
        raise GovernedCommandDeploymentError()

    engine_config = SandboxEngineConfig(
        profiles=profiles,
        sandbox=sandbox,
        telemetry=telemetry,
        cleanup_backlog=cleanup_backlog,
    )
    engine = SandboxExecutionEngine._from_components(
        engine_config,
        sandbox=runtime,
        clock=lambda: datetime.now(UTC),
        sandbox_id=lambda: f"sbx-{uuid.uuid4().hex[:15]}",
    )
    config = SandboxDeploymentConfig(
        deployment_id=deployment_id,
        manifest_path=manifest_path,
        transport_kind=transport_kind,
        sandbox=sandbox,
        registry_fingerprint=registry.fingerprint,
        profile_bundle_version=registry.bundle_version,
        cleanup_backlog_directory=cleanup_directory,
    )
    result = object.__new__(SandboxDeployment)
    object.__setattr__(result, "config", config)
    object.__setattr__(result, "release", release)
    object.__setattr__(result, "asset_bundle", material.asset_bundle)
    object.__setattr__(result, "policy_document", material.policy_document)
    object.__setattr__(result, "registry", registry)
    object.__setattr__(result, "profiles", profiles)
    object.__setattr__(result, "structured_profiles", structured_profiles)
    object.__setattr__(result, "cleanup_backlog", cleanup_backlog)
    object.__setattr__(result, "engine", engine)
    object.__setattr__(result, "_runtime", runtime)
    return result


def load_sandbox_deployment(
    manifest_path: Path,
    *,
    registry: GovernedCommandRegistry,
    telemetry: TelemetrySink | None = None,
) -> SandboxDeployment:
    """Load one deployment while exposing only a constant public failure."""
    try:
        return _load_sandbox_deployment(
            manifest_path,
            registry=registry,
            telemetry=telemetry,
        )
    except GovernedCommandDeploymentError:
        raise GovernedCommandDeploymentError() from None
    except Exception:
        raise GovernedCommandDeploymentError() from None
