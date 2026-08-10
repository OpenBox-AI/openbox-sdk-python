from __future__ import annotations

import asyncio
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .authorization import SandboxAuthorization
from .command import SandboxCommand
from .errors import NormalizedSandboxError, SandboxErrorCode
from .profiles import CommandProfileBundle
from .result import (
    CleanupReconciliationResult,
    CleanupStatus,
    Disposition,
    ExecutionMetadata,
    SandboxExecutionResult,
    TimeoutStatus,
)
from .runtime import (
    AssetBundleIdentity,
    CreateRequest,
    ExecCompleted,
    ExecRequest,
    OutputLimits,
    PolicyDocument,
    ProtocolValidationError,
    SandboxRuntimeClient,
    SandboxRuntimeClientConfig,
    SandboxServiceTransportError,
    SubmissionState,
    UnixAgentRuntimeClient,
    UnixAgentRuntimeClientConfig,
)
from .telemetry import CleanupBacklog, NullTelemetrySink, TelemetryEvent, TelemetrySink


@dataclass(frozen=True, slots=True, repr=False)
class SandboxExecutionConfig:
    host: str
    port: int
    server_name: str
    ca_path: Path
    certificate_path: Path
    private_key_path: Path
    asset_bundle: AssetBundleIdentity
    policy_document: PolicyDocument
    output_limits: OutputLimits = OutputLimits(
        stdout_bytes=1024 * 1024,
        stderr_bytes=1024 * 1024,
        combined_bytes=2 * 1024 * 1024,
        chunk_bytes=4 * 1024 * 1024,
    )
    create_deadline_ms: int = 60_000
    readiness_deadline_ms: int = 120_000
    exec_deadline_ms: int = 45_000
    delete_deadline_ms: int = 60_000
    wait_deleted_deadline_ms: int = 60_000
    enabled: bool = True

    def __post_init__(self) -> None:
        for value, maximum in (
            (self.create_deadline_ms, 60_000),
            (self.readiness_deadline_ms, 120_000),
            (self.exec_deadline_ms, 45_000),
            (self.delete_deadline_ms, 60_000),
            (self.wait_deleted_deadline_ms, 60_000),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
                raise ValueError("sandbox deadline rejected")
        if type(self.enabled) is not bool:
            raise ValueError("sandbox kill switch rejected")

    def __repr__(self) -> str:
        return (
            f"SandboxExecutionConfig(host={self.host!r}, port={self.port}, "
            f"server_name={self.server_name!r}, credentials=<redacted>, "
            f"asset_bundle={self.asset_bundle!r}, policy_document=<redacted>, "
            f"output_limits={self.output_limits!r}, enabled={self.enabled})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class UnixAgentExecutionConfig:
    socket_path: Path
    registry_fingerprint: str
    asset_bundle: AssetBundleIdentity
    policy_document: PolicyDocument
    output_limits: OutputLimits = OutputLimits(
        stdout_bytes=1024 * 1024,
        stderr_bytes=1024 * 1024,
        combined_bytes=2 * 1024 * 1024,
        chunk_bytes=4 * 1024 * 1024,
    )
    create_deadline_ms: int = 60_000
    readiness_deadline_ms: int = 120_000
    exec_deadline_ms: int = 45_000
    delete_deadline_ms: int = 60_000
    wait_deleted_deadline_ms: int = 60_000
    enabled: bool = True

    def __post_init__(self) -> None:
        for value, maximum in (
            (self.create_deadline_ms, 60_000),
            (self.readiness_deadline_ms, 120_000),
            (self.exec_deadline_ms, 45_000),
            (self.delete_deadline_ms, 60_000),
            (self.wait_deleted_deadline_ms, 60_000),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
                raise ValueError("sandbox deadline rejected")
        if type(self.enabled) is not bool or not self.socket_path.is_absolute():
            raise ValueError("sandbox execution configuration rejected")

    def __repr__(self) -> str:
        return (
            "UnixAgentExecutionConfig(socket_path=<redacted>, "
            f"asset_bundle={self.asset_bundle!r}, policy_document=<redacted>, "
            f"output_limits={self.output_limits!r}, enabled={self.enabled})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class SandboxEngineConfig:
    profiles: CommandProfileBundle
    sandbox: SandboxExecutionConfig | UnixAgentExecutionConfig
    telemetry: TelemetrySink | None = None
    cleanup_backlog: CleanupBacklog | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.profiles, CommandProfileBundle)
            or not isinstance(
                self.sandbox,
                (SandboxExecutionConfig, UnixAgentExecutionConfig),
            )
            or (self.telemetry is not None and not callable(getattr(self.telemetry, "emit", None)))
            or (
                self.cleanup_backlog is not None
                and not isinstance(self.cleanup_backlog, CleanupBacklog)
            )
        ):
            raise ValueError("sandbox engine configuration rejected")

    def __repr__(self) -> str:
        return (
            f"SandboxEngineConfig(profiles={self.profiles!r}, sandbox={self.sandbox!r}, "
            f"telemetry={'configured' if self.telemetry else 'disabled'}, "
            f"cleanup_backlog={'configured' if self.cleanup_backlog else 'disabled'})"
        )


class SandboxExecutionEngine:
    """Execute only caller-authorized ``CONSTRAIN`` commands in a sandbox."""

    def __init__(self, config: SandboxEngineConfig) -> None:
        if not isinstance(config, SandboxEngineConfig):
            raise TypeError("SandboxEngineConfig required")
        runtime: SandboxRuntimeClient | UnixAgentRuntimeClient
        if isinstance(config.sandbox, UnixAgentExecutionConfig):
            runtime = UnixAgentRuntimeClient(
                UnixAgentRuntimeClientConfig(
                    socket_path=config.sandbox.socket_path,
                    asset_bundle=config.sandbox.asset_bundle,
                    registry_fingerprint=config.sandbox.registry_fingerprint,
                )
            )
        else:
            runtime = SandboxRuntimeClient(
                SandboxRuntimeClientConfig(
                    host=config.sandbox.host,
                    port=config.sandbox.port,
                    server_name=config.sandbox.server_name,
                    ca_path=config.sandbox.ca_path,
                    certificate_path=config.sandbox.certificate_path,
                    private_key_path=config.sandbox.private_key_path,
                    asset_bundle=config.sandbox.asset_bundle,
                )
            )
        self._configure(
            config,
            runtime,
            lambda: datetime.now(UTC),
            lambda: f"sbx-{uuid.uuid4()}",
        )

    @classmethod
    def _from_components(
        cls,
        config: SandboxEngineConfig,
        *,
        sandbox: Any,
        clock: Callable[[], datetime],
        sandbox_id: Callable[[], str] = lambda: f"sbx-{uuid.uuid4()}",
    ) -> SandboxExecutionEngine:
        instance = cls.__new__(cls)
        instance._configure(config, sandbox, clock, sandbox_id)
        return instance

    def _configure(
        self,
        config: SandboxEngineConfig,
        sandbox: Any,
        clock: Callable[[], datetime],
        sandbox_id: Callable[[], str],
    ) -> None:
        self._config = config
        self._sandbox = sandbox
        self._clock = clock
        self._sandbox_id = sandbox_id
        self._telemetry = config.telemetry or NullTelemetrySink()

    @property
    def profiles(self) -> CommandProfileBundle:
        """Return the immutable profile admission bundle owned by this engine."""
        return self._config.profiles

    @property
    def asset_bundle(self) -> AssetBundleIdentity:
        """Return the runtime/image/policy identity bound to this engine."""
        return self._config.sandbox.asset_bundle

    @property
    def telemetry_sink(self) -> TelemetrySink:
        """Return the sink receiving lifecycle events from this engine."""
        return self._telemetry

    async def execute(
        self, command: SandboxCommand, authorization: SandboxAuthorization
    ) -> SandboxExecutionResult:
        if not isinstance(command, SandboxCommand) or not isinstance(
            authorization, SandboxAuthorization
        ):
            raise TypeError("authorized sandbox execution rejected")
        now = self._clock().astimezone(UTC)
        if not self._config.profiles.admits(command.profile_id, command.argv, now=now):
            return await self._terminal(
                command,
                authorization,
                Disposition.NOT_EXECUTED,
                None,
                SandboxErrorCode.PROFILE_REJECTED,
            )
        await self._emit(command, authorization, "authorization_accepted")
        if not self._config.sandbox.enabled:
            return await self._terminal(
                command,
                authorization,
                Disposition.NOT_EXECUTED,
                None,
                SandboxErrorCode.SANDBOX_DISABLED,
            )
        return await self._dispatch_sandbox(command, authorization)

    async def reconcile_cleanup(self) -> CleanupReconciliationResult:
        backlog = self._config.cleanup_backlog
        if backlog is None:
            return CleanupReconciliationResult(attempted=0, deleted=0, remaining=0)
        async with backlog.reconciliation_lock():
            request_ids = await backlog.request_ids()
            deleted = 0
            for request_id in request_ids:
                try:
                    await self._sandbox.delete(request_id, self._config.sandbox.delete_deadline_ms)
                    absent = await self._sandbox.wait_deleted(
                        request_id, self._config.sandbox.wait_deleted_deadline_ms
                    )
                    if absent.response != "terminally_absent":
                        continue
                    await backlog.remove(request_id)
                    deleted += 1
                except (
                    SandboxServiceTransportError,
                    ProtocolValidationError,
                    ValueError,
                    TypeError,
                    OSError,
                ):
                    continue
            remaining = len(await backlog.request_ids())
            return CleanupReconciliationResult(
                attempted=len(request_ids), deleted=deleted, remaining=remaining
            )

    async def _dispatch_sandbox(
        self, command: SandboxCommand, authorization: SandboxAuthorization
    ) -> SandboxExecutionResult:
        sandbox_id = self._sandbox_id()
        ownership = [False]
        try:
            return await self._dispatch_sandbox_lifecycle(
                command, authorization, sandbox_id, ownership
            )
        except asyncio.CancelledError:
            if ownership[0]:
                cleanup_task = asyncio.create_task(
                    self._cleanup(command, authorization, sandbox_id)
                )
                try:
                    await asyncio.shield(cleanup_task)
                except asyncio.CancelledError:
                    await cleanup_task
            raise

    async def _dispatch_sandbox_lifecycle(
        self,
        command: SandboxCommand,
        authorization: SandboxAuthorization,
        sandbox_id: str,
        ownership: list[bool],
    ) -> SandboxExecutionResult:
        cleanup_required = False
        lifecycle_token: str | None = None
        await self._emit(
            command,
            authorization,
            "sandbox_create_started",
            sandbox_id=sandbox_id,
            lifecycle_phase="create",
        )
        try:
            response = await self._sandbox.create(
                CreateRequest(
                    request_id=sandbox_id,
                    template=self._config.sandbox.asset_bundle.template,
                    policy_document=self._config.sandbox.policy_document,
                    expected_policy=self._config.sandbox.asset_bundle.policy,
                ),
                self._config.sandbox.create_deadline_ms,
            )
        except SandboxServiceTransportError as error:
            cleanup_required = error.submission_state is SubmissionState.POSSIBLY_SUBMITTED
            ownership[0] = cleanup_required
            return await self._sandbox_terminal(
                command,
                authorization,
                sandbox_id,
                cleanup_required,
                Disposition.NOT_EXECUTED,
                SandboxErrorCode.SANDBOX_CREATE,
                None,
            )
        except (ProtocolValidationError, ValueError, TypeError):
            return await self._sandbox_terminal(
                command,
                authorization,
                sandbox_id,
                False,
                Disposition.NOT_EXECUTED,
                SandboxErrorCode.SANDBOX_PROTOCOL,
                None,
            )
        if response.response == "created":
            cleanup_required = True
            ownership[0] = True
            if response.fields.get("request_id") != sandbox_id or not isinstance(
                response.fields.get("lifecycle_token"), str
            ):
                return await self._sandbox_terminal(
                    command,
                    authorization,
                    sandbox_id,
                    True,
                    Disposition.NOT_EXECUTED,
                    SandboxErrorCode.SANDBOX_PROTOCOL,
                    None,
                )
            lifecycle_token = response.fields["lifecycle_token"]
        elif response.response == "create_failed":
            failure = response.fields.get("failure")
            state = failure.get("state") if isinstance(failure, dict) else None
            cleanup_required = state == "possibly_created"
            if state not in {"not_created", "possibly_created", "conflict"}:
                cleanup_required = True
            ownership[0] = cleanup_required
            return await self._sandbox_terminal(
                command,
                authorization,
                sandbox_id,
                cleanup_required,
                Disposition.NOT_EXECUTED,
                SandboxErrorCode.SANDBOX_CREATE,
                None,
            )
        elif response.response == "boundary_failed":
            failure = response.fields.get("failure")
            cleanup_required = (
                isinstance(failure, dict) and failure.get("cleanup_target") is not None
            )
            ownership[0] = cleanup_required
            return await self._sandbox_terminal(
                command,
                authorization,
                sandbox_id,
                cleanup_required,
                Disposition.NOT_EXECUTED,
                SandboxErrorCode.SANDBOX_CREATE,
                None,
            )
        else:
            ownership[0] = True
            return await self._sandbox_terminal(
                command,
                authorization,
                sandbox_id,
                True,
                Disposition.NOT_EXECUTED,
                SandboxErrorCode.SANDBOX_PROTOCOL,
                None,
            )
        await self._emit(
            command,
            authorization,
            "sandbox_create_finished",
            sandbox_id=sandbox_id,
            lifecycle_phase="create",
        )
        try:
            ready = await self._sandbox.wait_ready(
                sandbox_id,
                lifecycle_token,
                self._config.sandbox.asset_bundle.policy,
                self._config.sandbox.readiness_deadline_ms,
            )
        except (
            SandboxServiceTransportError,
            ProtocolValidationError,
            ValueError,
            TypeError,
        ):
            return await self._sandbox_terminal(
                command,
                authorization,
                sandbox_id,
                cleanup_required,
                Disposition.NOT_EXECUTED,
                SandboxErrorCode.SANDBOX_READINESS,
                None,
            )
        ready_token = ready.fields.get("lifecycle_token")
        if (
            ready.response != "ready"
            or ready.fields.get("request_id") != sandbox_id
            or not isinstance(ready_token, str)
            or ready.fields.get("active_policy")
            != self._config.sandbox.asset_bundle.policy.to_wire()
        ):
            return await self._sandbox_terminal(
                command,
                authorization,
                sandbox_id,
                cleanup_required,
                Disposition.NOT_EXECUTED,
                SandboxErrorCode.SANDBOX_READINESS,
                None,
            )
        lifecycle_token = ready_token
        await self._emit(
            command,
            authorization,
            "sandbox_ready",
            sandbox_id=sandbox_id,
            lifecycle_phase="ready",
        )
        await self._emit(
            command,
            authorization,
            "sandbox_exec_started",
            sandbox_id=sandbox_id,
            lifecycle_phase="exec",
        )
        try:
            executed = await self._sandbox.exec(
                sandbox_id,
                lifecycle_token,
                ExecRequest(
                    command.argv,
                    command.timeout_seconds,
                    self._config.sandbox.output_limits,
                ),
                self._config.sandbox.exec_deadline_ms,
            )
        except SandboxServiceTransportError as error:
            disposition = (
                Disposition.NOT_EXECUTED
                if error.submission_state is SubmissionState.NOT_SUBMITTED
                else Disposition.EXECUTION_INDETERMINATE
            )
            code = (
                SandboxErrorCode.SANDBOX_EXEC_NOT_DISPATCHED
                if disposition is Disposition.NOT_EXECUTED
                else SandboxErrorCode.SANDBOX_EXEC_INDETERMINATE
            )
            return await self._sandbox_terminal(
                command,
                authorization,
                sandbox_id,
                cleanup_required,
                disposition,
                code,
                None,
            )
        except (ProtocolValidationError, ValueError, TypeError):
            return await self._sandbox_terminal(
                command,
                authorization,
                sandbox_id,
                cleanup_required,
                Disposition.EXECUTION_INDETERMINATE,
                SandboxErrorCode.SANDBOX_PROTOCOL,
                None,
            )
        if executed.response == "executed":
            try:
                completed = ExecCompleted.from_wire(executed.fields.get("result"))
                limits = self._config.sandbox.output_limits
                if (
                    len(completed.stdout) > limits.stdout_bytes
                    or len(completed.stderr) > limits.stderr_bytes
                    or len(completed.stdout) + len(completed.stderr) > limits.combined_bytes
                ):
                    raise ProtocolValidationError()
            except (ProtocolValidationError, TypeError):
                return await self._sandbox_terminal(
                    command,
                    authorization,
                    sandbox_id,
                    cleanup_required,
                    Disposition.EXECUTION_INDETERMINATE,
                    SandboxErrorCode.SANDBOX_PROTOCOL,
                    None,
                )
            execution = ExecutionMetadata(
                sandbox_id=sandbox_id,
                exit_code=completed.exit_code,
                stdout=completed.stdout,
                stderr=completed.stderr,
                timeout_status=_timeout_status(completed.timeout),
                cleanup_status=CleanupStatus.FAILED,
            )
            await self._emit(
                command,
                authorization,
                "sandbox_exec_finished",
                sandbox_id=sandbox_id,
                lifecycle_phase="exec",
                disposition=Disposition.EXECUTED_IN_SANDBOX.value,
                execution=execution,
            )
            return await self._sandbox_terminal(
                command,
                authorization,
                sandbox_id,
                cleanup_required,
                Disposition.EXECUTED_IN_SANDBOX,
                None,
                execution,
            )
        if executed.response in {"exec_failed", "boundary_failed"}:
            failure = executed.fields.get("failure")
            dispatch_state = failure.get("dispatch_state") if isinstance(failure, dict) else None
            disposition = (
                Disposition.NOT_EXECUTED
                if dispatch_state == "not_dispatched"
                else Disposition.EXECUTION_INDETERMINATE
            )
            code = (
                SandboxErrorCode.SANDBOX_EXEC_NOT_DISPATCHED
                if disposition is Disposition.NOT_EXECUTED
                else SandboxErrorCode.SANDBOX_EXEC_INDETERMINATE
            )
            return await self._sandbox_terminal(
                command,
                authorization,
                sandbox_id,
                cleanup_required,
                disposition,
                code,
                None,
            )
        return await self._sandbox_terminal(
            command,
            authorization,
            sandbox_id,
            cleanup_required,
            Disposition.EXECUTION_INDETERMINATE,
            SandboxErrorCode.SANDBOX_PROTOCOL,
            None,
        )

    async def _sandbox_terminal(
        self,
        command: SandboxCommand,
        authorization: SandboxAuthorization,
        sandbox_id: str,
        cleanup_required: bool,
        disposition: Disposition,
        error_code: SandboxErrorCode | None,
        execution: ExecutionMetadata | None,
    ) -> SandboxExecutionResult:
        cleanup = (
            await self._cleanup(command, authorization, sandbox_id)
            if cleanup_required
            else CleanupStatus.NOT_NEEDED
        )
        if execution is None and disposition is Disposition.EXECUTION_INDETERMINATE:
            execution = ExecutionMetadata(
                sandbox_id=sandbox_id,
                exit_code=None,
                stdout=b"",
                stderr=b"",
                timeout_status=TimeoutStatus.UNKNOWN,
                cleanup_status=cleanup,
            )
        elif execution is not None:
            execution = ExecutionMetadata(
                sandbox_id=execution.sandbox_id,
                exit_code=execution.exit_code,
                stdout=execution.stdout,
                stderr=execution.stderr,
                timeout_status=execution.timeout_status,
                cleanup_status=cleanup,
            )
        return await self._terminal(
            command,
            authorization,
            disposition,
            execution,
            error_code,
        )

    async def _cleanup(
        self, command: SandboxCommand, authorization: SandboxAuthorization, sandbox_id: str
    ) -> CleanupStatus:
        await self._emit(
            command,
            authorization,
            "sandbox_delete_started",
            sandbox_id=sandbox_id,
            lifecycle_phase="delete",
        )
        status = CleanupStatus.FAILED
        try:
            await self._sandbox.delete(sandbox_id, self._config.sandbox.delete_deadline_ms)
            absent = await self._sandbox.wait_deleted(
                sandbox_id, self._config.sandbox.wait_deleted_deadline_ms
            )
            if absent.response == "terminally_absent":
                status = CleanupStatus.DELETED
        except (
            SandboxServiceTransportError,
            ProtocolValidationError,
            ValueError,
            TypeError,
        ):
            status = CleanupStatus.FAILED
        if status is CleanupStatus.DELETED:
            if self._config.cleanup_backlog is not None:
                try:
                    await self._config.cleanup_backlog.remove(sandbox_id)
                except OSError:
                    pass
            await self._emit(
                command,
                authorization,
                "sandbox_deleted",
                sandbox_id=sandbox_id,
                lifecycle_phase="delete",
                cleanup_status=status.value,
            )
        else:
            if self._config.cleanup_backlog is not None:
                try:
                    await self._config.cleanup_backlog.record(
                        sandbox_id,
                        "unconfirmed_absence",
                        _iso8601(self._clock()),
                    )
                except OSError:
                    pass
            await self._emit(
                command,
                authorization,
                "sandbox_execution_failed",
                sandbox_id=sandbox_id,
                lifecycle_phase="delete",
                cleanup_status=status.value,
            )
        return status

    async def _terminal(
        self,
        command: SandboxCommand,
        authorization: SandboxAuthorization,
        disposition: Disposition,
        execution: ExecutionMetadata | None,
        error_code: SandboxErrorCode | None,
    ) -> SandboxExecutionResult:
        result = SandboxExecutionResult(
            disposition=disposition,
            execution=execution,
            error=None if error_code is None else NormalizedSandboxError(error_code),
            _authorization=authorization.raw,
        )
        await self._emit(
            command,
            authorization,
            "dispatch_terminal",
            disposition=disposition.value,
            execution=execution,
            error_code=None if error_code is None else error_code.value,
        )
        return result

    async def _emit(
        self,
        command: SandboxCommand,
        authorization: SandboxAuthorization,
        event: str,
        *,
        disposition: str | None = None,
        directive: str | None = None,
        sandbox_id: str | None = None,
        lifecycle_phase: str | None = None,
        execution: ExecutionMetadata | None = None,
        duration_ms: int | None = None,
        error_code: str | None = None,
        cleanup_status: str | None = None,
    ) -> None:
        raw = authorization.raw
        bundle = self._config.sandbox.asset_bundle
        value = TelemetryEvent(
            event=event,
            workflow_id=command.workflow_id,
            run_id=command.run_id,
            activity_id=command.activity_id,
            attempt=command.attempt,
            governance_event_id=raw["governance_event_id"],
            verdict="constrain",
            action="constrain",
            disposition=disposition,
            sandbox_id=sandbox_id,
            lifecycle_phase=lifecycle_phase,
            timeout_seconds=command.timeout_seconds,
            timeout_status=None if execution is None else execution.timeout_status.value,
            exit_code=None if execution is None else execution.exit_code,
            stdout_bytes=None if execution is None else len(execution.stdout),
            stderr_bytes=None if execution is None else len(execution.stderr),
            duration_ms=duration_ms,
            error_code=error_code,
            cleanup_status=(
                cleanup_status
                if cleanup_status is not None
                else None
                if execution is None
                else execution.cleanup_status.value
            ),
            runtime_contract_version=bundle.runtime_contract_version,
            policy_id=bundle.policy.id,
            policy_version=bundle.policy.version,
            template_digest=bundle.template,
            profile_bundle_version=self._config.profiles.bundle_version,
        )
        try:
            await self._telemetry.emit(value)
        except Exception:
            pass


def _iso8601(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _timeout_status(value: str) -> TimeoutStatus:
    return {
        "not_observed": TimeoutStatus.NOT_OBSERVED,
        "confirmed": TimeoutStatus.CONFIRMED_TIMEOUT,
        "possible": TimeoutStatus.POSSIBLE_TIMEOUT,
    }[value]
