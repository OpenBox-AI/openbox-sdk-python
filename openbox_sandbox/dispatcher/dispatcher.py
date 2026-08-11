from __future__ import annotations

import asyncio
import hashlib
import re
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from openbox_sandbox.runtime_client import (
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
    generate_request_owned_id,
)

from ._host import _HostConfig, _HostExecutor, _HostFailure
from .command import GovernedCommand
from .errors import (
    DispatchErrorCode,
    GovernanceProtocolError,
    GovernanceTransportError,
    NormalizedDispatchError,
)
from .governance import GovernanceClient, GovernanceClientConfig, GovernanceDecision
from .profiles import CommandProfileBundle
from .result import (
    CleanupReconciliationResult,
    CleanupStatus,
    Directive,
    DispatchResult,
    Disposition,
    ExecutionMetadata,
    TimeoutStatus,
)
from .telemetry import CleanupBacklog, NullTelemetrySink, TelemetryEvent, TelemetrySink

_SAFE_EVIDENCE_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,511}\Z")


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
    policy_resolver: Callable[[str], PolicyDocument] | None = None

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
    """Local typed-agent transport; identical lifecycle semantics to TCP mTLS."""

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
    policy_resolver: Callable[[str], PolicyDocument] | None = None

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
        if not self.socket_path.is_absolute():
            raise ValueError("sandbox agent socket path rejected")

    def __repr__(self) -> str:
        return (
            "UnixAgentExecutionConfig(socket_path=<local>, "
            f"asset_bundle={self.asset_bundle!r}, policy_document=<redacted>, "
            f"output_limits={self.output_limits!r}, enabled={self.enabled})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class DispatcherConfig:
    governance: GovernanceClientConfig | None
    profiles: CommandProfileBundle
    sandbox: SandboxExecutionConfig | UnixAgentExecutionConfig
    host_workdir: Path
    telemetry: TelemetrySink | None = None
    cleanup_backlog: CleanupBacklog | None = None
    host_environment: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.host_workdir.is_absolute():
            raise ValueError("host workdir rejected")
        if not isinstance(self.host_environment, Mapping) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in self.host_environment.items()
        ):
            raise ValueError("host environment rejected")

    def __repr__(self) -> str:
        return (
            f"DispatcherConfig(governance={self.governance!r}, profiles={self.profiles!r}, "
            f"sandbox={self.sandbox!r}, host_workdir=<trusted>, "
            f"telemetry={'configured' if self.telemetry else 'disabled'}, "
            f"cleanup_backlog={'configured' if self.cleanup_backlog else 'disabled'})"
        )


class GovernedDispatcher:
    def __init__(self, config: DispatcherConfig) -> None:
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
            None if config.governance is None else GovernanceClient(config.governance),
            runtime,
            _HostExecutor(
                _HostConfig(config.host_workdir, environment=config.host_environment)
            ),
            lambda: datetime.now(UTC),
            time.monotonic,
            generate_request_owned_id,
        )

    @classmethod
    def _from_components(
        cls,
        config: DispatcherConfig,
        *,
        governance: Any,
        sandbox: Any,
        host: Any,
        clock: Callable[[], datetime],
        monotonic: Callable[[], float] = time.monotonic,
        sandbox_id: Callable[[], str] = generate_request_owned_id,
    ) -> GovernedDispatcher:
        instance = cls.__new__(cls)
        instance._configure(config, governance, sandbox, host, clock, monotonic, sandbox_id)
        return instance

    def _configure(
        self,
        config: DispatcherConfig,
        governance: Any,
        sandbox: Any,
        host: Any,
        clock: Callable[[], datetime],
        monotonic: Callable[[], float],
        sandbox_id: Callable[[], str],
    ) -> None:
        self._config = config
        self._governance = governance
        self._sandbox = sandbox
        self._host = host
        self._clock = clock
        self._monotonic = monotonic
        self._sandbox_id = sandbox_id
        self._telemetry = config.telemetry or NullTelemetrySink()

    @property
    def governance_signer_did(self) -> str | None:
        governance = self._config.governance
        signer = None if governance is None else governance.request_signer
        return None if signer is None else signer.agent_did

    async def dispatch(self, command: GovernedCommand) -> DispatchResult:
        """Evaluate an unadmitted command with Core, then dispatch its verdict."""
        profile_failure = await self._admit(command)
        if profile_failure is not None:
            return profile_failure
        now = self._clock().astimezone(UTC)
        event = _activity_started(command, now)
        try:
            if self._governance is None:
                raise GovernanceProtocolError()
            decision = await self._governance.evaluate(event)
            if not isinstance(decision, GovernanceDecision):
                decision = GovernanceDecision.parse(decision)
        except GovernanceTransportError:
            return await self._terminal(
                command,
                None,
                Disposition.NOT_EXECUTED,
                Directive.CONTINUE,
                None,
                DispatchErrorCode.GOVERNANCE_TRANSPORT,
            )
        except (GovernanceProtocolError, TypeError, ValueError):
            return await self._terminal(
                command,
                None,
                Disposition.NOT_EXECUTED,
                Directive.CONTINUE,
                None,
                DispatchErrorCode.GOVERNANCE_PROTOCOL,
            )
        await self._emit(command, decision, "governance_decision_received")
        return await self._dispatch_decision(command, decision, report_core=True)

    async def dispatch_with_decision(
        self, command: GovernedCommand, decision: GovernanceDecision
    ) -> DispatchResult:
        """Dispatch an already-evaluated operation under its governance decision.

        The caller (an application agent that evaluated the operation with a
        governance Core) owns the evaluation; this entry admits the profile,
        validates the decision shape, and executes the verdict: CONSTRAIN runs
        the command in a sandbox under the policy the decision names (resolved
        through the sandbox policy resolver), ALLOW runs it on the host, and
        any other verdict terminates without execution. No Core client is
        constructed or called.
        """
        profile_failure = await self._admit(command)
        if profile_failure is not None:
            return profile_failure
        if not isinstance(decision, GovernanceDecision):
            raise TypeError("dispatch_with_decision accepts GovernanceDecision only")
        if decision.fallback_used:
            return await self._terminal(
                command,
                decision,
                Disposition.NOT_EXECUTED,
                Directive.CONTINUE,
                None,
                DispatchErrorCode.GOVERNANCE_FALLBACK,
            )
        await self._emit(command, decision, "governance_decision_received")
        return await self._dispatch_decision(command, decision, report_core=False)

    async def dispatch_trusted_constrain(self, command: GovernedCommand) -> DispatchResult:
        """Dispatch CONSTRAIN input from an owned application agent.

        This is an explicit same-trust-domain handoff, not an authorization
        mechanism. It performs independent profile admission, can only select
        sandbox execution, and never constructs or calls a Core client.
        """
        profile_failure = await self._admit(command)
        if profile_failure is not None:
            return profile_failure
        reference = "trusted-application:" + ":".join(
            (command.workflow_id, command.run_id, command.activity_id)
        )
        decision = GovernanceDecision.parse(
            {
                "governance_event_id": str(uuid.uuid5(uuid.NAMESPACE_URL, reference)),
                "verdict": "constrain",
                "risk_score": 0.0,
                "action": "constrain",
                "fallback_used": False,
                "constraints": ["run_in_sandbox"],
            }
        )
        await self._emit(command, decision, "trusted_application_input_accepted")
        return await self._dispatch_decision(command, decision, report_core=False)

    async def dispatch_authorized_constrain(
        self, command: GovernedCommand, *, authorization_id: str
    ) -> DispatchResult:
        """Dispatch a caller-authenticated CONSTRAIN without another Core call.

        The caller owns cryptographic authorization validation. This narrow entry
        point admits only a non-fallback sandbox constraint and never permits host
        execution. The authorization identifier is metadata only.
        """
        profile_failure = await self._admit(command)
        if profile_failure is not None:
            return profile_failure
        if not isinstance(authorization_id, str) or not authorization_id:
            raise TypeError("authorization id rejected")
        decision = GovernanceDecision.parse(
            {
                "governance_event_id": str(uuid.uuid5(uuid.NAMESPACE_URL, authorization_id)),
                "verdict": "constrain",
                "risk_score": 0.0,
                "action": "constrain",
                "fallback_used": False,
                "constraints": ["run_in_sandbox"],
            }
        )
        await self._emit(command, decision, "authorization_receipt_accepted")
        return await self._dispatch_decision(command, decision, report_core=False)

    async def _admit(self, command: GovernedCommand) -> DispatchResult | None:
        if not isinstance(command, GovernedCommand):
            raise TypeError("dispatch accepts GovernedCommand only")
        now = self._clock().astimezone(UTC)
        if self._config.profiles.admits(command.profile_id, command.argv, now=now):
            return None
        return await self._terminal(
            command,
            None,
            Disposition.NOT_EXECUTED,
            Directive.CONTINUE,
            None,
            DispatchErrorCode.PROFILE_REJECTED,
        )

    async def _dispatch_decision(
        self,
        command: GovernedCommand,
        decision: GovernanceDecision,
        *,
        report_core: bool,
    ) -> DispatchResult:
        if decision.fallback_used:
            return await self._terminal(
                command,
                decision,
                Disposition.NOT_EXECUTED,
                Directive.CONTINUE,
                None,
                DispatchErrorCode.GOVERNANCE_FALLBACK,
            )
        if decision.verdict == "allow":
            return await self._dispatch_host(command, decision)
        if decision.verdict == "constrain":
            constraints = decision.constraints
            if constraints != ("run_in_sandbox",):
                return await self._terminal(
                    command,
                    decision,
                    Disposition.NOT_EXECUTED,
                    Directive.CONTINUE,
                    None,
                    DispatchErrorCode.UNSUPPORTED_CONSTRAINT,
                )
            if decision.has_guardrails_result:
                return await self._terminal(
                    command,
                    decision,
                    Disposition.NOT_EXECUTED,
                    Directive.CONTINUE,
                    None,
                    DispatchErrorCode.REMEDIATION_UNSUPPORTED,
                )
            if not self._config.sandbox.enabled:
                return await self._terminal(
                    command,
                    decision,
                    Disposition.NOT_EXECUTED,
                    Directive.CONTINUE,
                    None,
                    DispatchErrorCode.SANDBOX_DISABLED,
                )
            return await self._dispatch_sandbox(command, decision, report_core=report_core)
        if decision.verdict == "require_approval":
            return await self._terminal(
                command,
                decision,
                Disposition.NOT_EXECUTED,
                Directive.CONTINUE,
                None,
                DispatchErrorCode.APPROVAL_REQUIRED,
            )
        if decision.verdict == "block":
            return await self._terminal(
                command,
                decision,
                Disposition.NOT_EXECUTED,
                Directive.CONTINUE,
                None,
                DispatchErrorCode.BLOCKED,
            )
        return await self._terminal(
            command,
            decision,
            Disposition.NOT_EXECUTED,
            Directive.HALT,
            None,
            DispatchErrorCode.HALTED,
        )

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

    async def _dispatch_host(
        self, command: GovernedCommand, decision: GovernanceDecision
    ) -> DispatchResult:
        started = self._monotonic()
        try:
            outcome = await self._host.execute(command.argv, command.timeout_seconds)
        except _HostFailure as failure:
            return await self._terminal(
                command,
                decision,
                Disposition.EXECUTION_INDETERMINATE,
                Directive.CONTINUE,
                ExecutionMetadata(
                    sandbox_id=None,
                    exit_code=None,
                    stdout=b"",
                    stderr=b"",
                    timeout_status=TimeoutStatus.UNKNOWN,
                    cleanup_status=CleanupStatus.NOT_NEEDED,
                ),
                failure.code,
            )
        execution = ExecutionMetadata(
            sandbox_id=None,
            exit_code=outcome.exit_code,
            stdout=outcome.stdout,
            stderr=outcome.stderr,
            timeout_status=outcome.timeout_status,
            cleanup_status=CleanupStatus.NOT_NEEDED,
        )
        await self._emit(
            command,
            decision,
            "host_exec_finished",
            disposition=Disposition.EXECUTED_ON_HOST.value,
            execution=execution,
            duration_ms=_duration_ms(started, self._monotonic()),
        )
        return await self._terminal(
            command,
            decision,
            Disposition.EXECUTED_ON_HOST,
            Directive.CONTINUE,
            execution,
            None,
        )

    async def _policy_for(self, decision: GovernanceDecision) -> PolicyDocument:
        """Resolve the policy the decision names; pinned fallback without a resolver."""
        resolver = self._config.sandbox.policy_resolver
        named = decision.raw.get("policy_id")
        if resolver is not None:
            if not isinstance(named, str) or not named:
                raise GovernanceProtocolError("decision omitted a policy id")
            resolved = resolver(named)
            if not isinstance(resolved, PolicyDocument):
                raise GovernanceProtocolError("policy resolution failed")
            return resolved
        return self._config.sandbox.policy_document

    async def _dispatch_sandbox(
        self,
        command: GovernedCommand,
        decision: GovernanceDecision,
        *,
        report_core: bool,
    ) -> DispatchResult:
        sandbox_id = self._sandbox_id()
        ownership = [False]
        started_ns = _epoch_ns(self._clock())
        try:
            result = await self._dispatch_sandbox_lifecycle(
                command, decision, sandbox_id, ownership
            )
            if report_core:
                return await self._report_sandbox_result(
                    command, decision, result, started_ns=started_ns
                )
            return result
        except asyncio.CancelledError:
            cleanup = CleanupStatus.NOT_NEEDED
            if ownership[0]:
                cleanup_task = asyncio.create_task(self._cleanup(command, decision, sandbox_id))
                try:
                    cleanup = await asyncio.shield(cleanup_task)
                except asyncio.CancelledError:
                    cleanup = await cleanup_task
            if report_core:
                cancelled_result = DispatchResult(
                    disposition=Disposition.EXECUTION_INDETERMINATE,
                    directive=Directive.CONTINUE,
                    execution=ExecutionMetadata(
                        sandbox_id=sandbox_id,
                        exit_code=None,
                        stdout=b"",
                        stderr=b"",
                        timeout_status=TimeoutStatus.UNKNOWN,
                        cleanup_status=cleanup,
                    ),
                    error=NormalizedDispatchError(DispatchErrorCode.CANCELLED),
                    _governance=decision.raw,
                )
                await self._report_sandbox_result(
                    command, decision, cancelled_result, started_ns=started_ns
                )
            raise

    async def _dispatch_sandbox_lifecycle(
        self,
        command: GovernedCommand,
        decision: GovernanceDecision,
        sandbox_id: str,
        ownership: list[bool],
    ) -> DispatchResult:
        cleanup_required = False
        lifecycle_token: str | None = None
        await self._emit(
            command,
            decision,
            "sandbox_create_started",
            sandbox_id=sandbox_id,
            lifecycle_phase="create",
        )
        try:
            response = await self._sandbox.create(
                CreateRequest(
                    request_id=sandbox_id,
                    template=self._config.sandbox.asset_bundle.template,
                    policy_document=await self._policy_for(decision),
                    expected_policy=self._config.sandbox.asset_bundle.policy,
                ),
                self._config.sandbox.create_deadline_ms,
            )
        except SandboxServiceTransportError as error:
            cleanup_required = error.submission_state is SubmissionState.POSSIBLY_SUBMITTED
            ownership[0] = cleanup_required
            detail = f"{error.code}: {error.message}" if getattr(error, 'message', None) else str(error.code)
            return await self._sandbox_terminal(
                command,
                decision,
                sandbox_id,
                cleanup_required,
                Disposition.NOT_EXECUTED,
                DispatchErrorCode.SANDBOX_CREATE,
                None,
                detail=detail,
            )
        except (ProtocolValidationError, ValueError, TypeError):
            return await self._sandbox_terminal(
                command,
                decision,
                sandbox_id,
                False,
                Disposition.NOT_EXECUTED,
                DispatchErrorCode.SANDBOX_PROTOCOL,
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
                    decision,
                    sandbox_id,
                    True,
                    Disposition.NOT_EXECUTED,
                    DispatchErrorCode.SANDBOX_PROTOCOL,
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
            detail = failure.get("detail") if isinstance(failure, dict) else None
            return await self._sandbox_terminal(
                command,
                decision,
                sandbox_id,
                cleanup_required,
                Disposition.NOT_EXECUTED,
                DispatchErrorCode.SANDBOX_CREATE,
                None,
                detail=detail,
            )
        elif response.response == "boundary_failed":
            failure = response.fields.get("failure")
            cleanup_required = (
                isinstance(failure, dict) and failure.get("cleanup_target") is not None
            )
            ownership[0] = cleanup_required
            detail = failure.get("detail") if isinstance(failure, dict) else None
            return await self._sandbox_terminal(
                command,
                decision,
                sandbox_id,
                cleanup_required,
                Disposition.NOT_EXECUTED,
                DispatchErrorCode.SANDBOX_CREATE,
                None,
                detail=detail,
            )
        else:
            ownership[0] = True
            return await self._sandbox_terminal(
                command,
                decision,
                sandbox_id,
                True,
                Disposition.NOT_EXECUTED,
                DispatchErrorCode.SANDBOX_PROTOCOL,
                None,
            )
        await self._emit(
            command,
            decision,
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
                decision,
                sandbox_id,
                cleanup_required,
                Disposition.NOT_EXECUTED,
                DispatchErrorCode.SANDBOX_READINESS,
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
                decision,
                sandbox_id,
                cleanup_required,
                Disposition.NOT_EXECUTED,
                DispatchErrorCode.SANDBOX_READINESS,
                None,
            )
        lifecycle_token = ready_token
        await self._emit(
            command,
            decision,
            "sandbox_ready",
            sandbox_id=sandbox_id,
            lifecycle_phase="ready",
        )
        await self._emit(
            command,
            decision,
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
                DispatchErrorCode.SANDBOX_EXEC_NOT_DISPATCHED
                if disposition is Disposition.NOT_EXECUTED
                else DispatchErrorCode.SANDBOX_EXEC_INDETERMINATE
            )
            return await self._sandbox_terminal(
                command,
                decision,
                sandbox_id,
                cleanup_required,
                disposition,
                code,
                None,
            )
        except (ProtocolValidationError, ValueError, TypeError):
            return await self._sandbox_terminal(
                command,
                decision,
                sandbox_id,
                cleanup_required,
                Disposition.EXECUTION_INDETERMINATE,
                DispatchErrorCode.SANDBOX_PROTOCOL,
                None,
            )
        if executed.response == "executed":
            try:
                completed = ExecCompleted.from_wire(executed.fields.get("result"))
            except (ProtocolValidationError, TypeError):
                return await self._sandbox_terminal(
                    command,
                    decision,
                    sandbox_id,
                    cleanup_required,
                    Disposition.EXECUTION_INDETERMINATE,
                    DispatchErrorCode.SANDBOX_PROTOCOL,
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
                decision,
                "sandbox_exec_finished",
                sandbox_id=sandbox_id,
                lifecycle_phase="exec",
                disposition=Disposition.EXECUTED_IN_SANDBOX.value,
                execution=execution,
            )
            return await self._sandbox_terminal(
                command,
                decision,
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
                DispatchErrorCode.SANDBOX_EXEC_NOT_DISPATCHED
                if disposition is Disposition.NOT_EXECUTED
                else DispatchErrorCode.SANDBOX_EXEC_INDETERMINATE
            )
            return await self._sandbox_terminal(
                command,
                decision,
                sandbox_id,
                cleanup_required,
                disposition,
                code,
                None,
            )
        return await self._sandbox_terminal(
            command,
            decision,
            sandbox_id,
            cleanup_required,
            Disposition.EXECUTION_INDETERMINATE,
            DispatchErrorCode.SANDBOX_PROTOCOL,
            None,
        )

    async def _sandbox_terminal(
        self,
        command: GovernedCommand,
        decision: GovernanceDecision,
        sandbox_id: str,
        cleanup_required: bool,
        disposition: Disposition,
        error_code: DispatchErrorCode | None,
        execution: ExecutionMetadata | None,
        error_detail: str | None = None,
    ) -> DispatchResult:
        cleanup = (
            await self._cleanup(command, decision, sandbox_id)
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
            decision,
            disposition,
            Directive.CONTINUE,
            execution,
            error_code,
        )

    async def _report_sandbox_result(
        self,
        command: GovernedCommand,
        initial_decision: GovernanceDecision,
        result: DispatchResult,
        *,
        started_ns: int,
    ) -> DispatchResult:
        """Attach bounded sandbox evidence, then govern normal completion.

        The completed hook is best-effort and can never undo execution. A
        BLOCK/HALT response is nevertheless surfaced as terminal/future control,
        matching completed-hook semantics in the shared SDK. ActivityCompleted
        is a separate, span-free lifecycle evaluation and remains fail-closed.
        """
        if self._governance is None:
            return result
        completed_ns = max(started_ns + 1, _epoch_ns(self._clock()))
        hook_decision: GovernanceDecision | None = None
        try:
            raw_hook_decision = await self._governance.evaluate(
                _sandbox_completed_hook(
                    command,
                    result,
                    self._config,
                    started_ns=started_ns,
                    completed_ns=completed_ns,
                )
            )
            hook_decision = (
                raw_hook_decision
                if isinstance(raw_hook_decision, GovernanceDecision)
                else GovernanceDecision.parse(raw_hook_decision)
            )
        except (
            GovernanceTransportError,
            GovernanceProtocolError,
            TypeError,
            ValueError,
        ):
            # Completed telemetry is explicitly best-effort. Execution and
            # cleanup have already happened and are never reclassified here.
            hook_decision = None

        if hook_decision is not None and hook_decision.verdict in {"block", "halt"}:
            return _completed_stop_result(result, initial_decision, hook_decision)

        if not _is_normal_sandbox_completion(result):
            return result

        try:
            raw_completed_decision = await self._governance.evaluate(
                _activity_completed(
                    command,
                    result,
                    self._clock(),
                    duration_ns=completed_ns - started_ns,
                )
            )
            completed_decision = (
                raw_completed_decision
                if isinstance(raw_completed_decision, GovernanceDecision)
                else GovernanceDecision.parse(raw_completed_decision)
            )
        except GovernanceTransportError:
            return _completion_failure_result(
                result, initial_decision, DispatchErrorCode.GOVERNANCE_TRANSPORT
            )
        except (GovernanceProtocolError, TypeError, ValueError):
            return _completion_failure_result(
                result, initial_decision, DispatchErrorCode.GOVERNANCE_PROTOCOL
            )

        if completed_decision.fallback_used:
            return _completion_failure_result(
                result, initial_decision, DispatchErrorCode.GOVERNANCE_FALLBACK
            )
        if completed_decision.verdict == "halt":
            return _completion_failure_result(
                result,
                initial_decision,
                DispatchErrorCode.HALTED,
                directive=Directive.HALT,
            )
        if completed_decision.verdict == "block":
            return _completion_failure_result(result, initial_decision, DispatchErrorCode.BLOCKED)
        if completed_decision.verdict == "require_approval":
            return _completion_failure_result(
                result, initial_decision, DispatchErrorCode.APPROVAL_REQUIRED
            )
        if completed_decision.has_guardrails_result:
            return _completion_failure_result(
                result, initial_decision, DispatchErrorCode.REMEDIATION_UNSUPPORTED
            )
        return result

    async def _cleanup(
        self, command: GovernedCommand, decision: GovernanceDecision, sandbox_id: str
    ) -> CleanupStatus:
        await self._emit(
            command,
            decision,
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
                decision,
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
                decision,
                "sandbox_execution_failed",
                sandbox_id=sandbox_id,
                lifecycle_phase="delete",
                cleanup_status=status.value,
            )
        return status

    async def _terminal(
        self,
        command: GovernedCommand,
        decision: GovernanceDecision | None,
        disposition: Disposition,
        directive: Directive,
        execution: ExecutionMetadata | None,
        error_code: DispatchErrorCode | None,
    ) -> DispatchResult:
        result = DispatchResult(
            disposition=disposition,
            directive=directive,
            execution=execution,
            error=None if error_code is None else NormalizedDispatchError(error_code, detail=error_detail),
            _governance=None if decision is None else decision.raw,
        )
        await self._emit(
            command,
            decision,
            "dispatch_terminal",
            disposition=disposition.value,
            directive=directive.value,
            execution=execution,
            error_code=None if error_code is None else error_code.value,
        )
        return result

    async def _emit(
        self,
        command: GovernedCommand,
        decision: GovernanceDecision | None,
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
        raw = None if decision is None else decision.raw
        bundle = self._config.sandbox.asset_bundle
        value = TelemetryEvent(
            event=event,
            workflow_id=command.workflow_id,
            run_id=command.run_id,
            activity_id=command.activity_id,
            attempt=command.attempt,
            governance_event_id=None if raw is None else raw["governance_event_id"],
            governance_policy_id=(
                None
                if raw is None or not isinstance(raw.get("policy_id"), str)
                else raw["policy_id"]
            ),
            verdict=None if decision is None else decision.verdict,
            action=None if decision is None else decision.action,
            fallback_used=None if decision is None else decision.fallback_used,
            constraints=None if decision is None else decision.constraints,
            disposition=disposition,
            directive=directive,
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


def _activity_started(command: GovernedCommand, now: datetime) -> dict[str, Any]:
    """Build the real pre-execution governed-Activity event evaluated by Core."""
    return {
        "source": "governed-dispatcher",
        "event_type": "ActivityStarted",
        "workflow_id": command.workflow_id,
        "run_id": command.run_id,
        "workflow_type": command.workflow_type,
        "task_queue": command.task_queue,
        "timestamp": _iso8601(now),
        "activity_id": command.activity_id,
        "activity_type": "openbox_governed_command",
        "attempt": command.attempt,
        "profile_id": command.profile_id,
        "activity_input": [{"argv": list(command.argv)}],
        "operation": {
            "profile_id": command.profile_id,
            "arguments": dict(command.arguments),
        },
    }


def _sandbox_completed_hook(
    command: GovernedCommand,
    result: DispatchResult,
    config: DispatcherConfig,
    *,
    started_ns: int,
    completed_ns: int,
) -> dict[str, Any]:
    execution = result.execution
    stdout = b"" if execution is None else execution.stdout
    stderr = b"" if execution is None else execution.stderr
    error_code = "none" if result.error is None else result.error.code.value
    disposition = result.disposition.value
    timeout_status = "unknown" if execution is None else execution.timeout_status.value
    cleanup_status = "not_needed" if execution is None else execution.cleanup_status.value
    exit_code = None if execution is None else execution.exit_code
    if timeout_status in {
        TimeoutStatus.CONFIRMED_TIMEOUT.value,
        TimeoutStatus.POSSIBLE_TIMEOUT.value,
    }:
        outcome = "timeout"
    elif disposition == Disposition.EXECUTED_IN_SANDBOX.value:
        outcome = "success" if exit_code == 0 else "nonzero"
    elif disposition == Disposition.EXECUTION_INDETERMINATE.value:
        outcome = "indeterminate"
    else:
        outcome = "not_executed"

    bundle = config.sandbox.asset_bundle
    span_id, trace_id = _sandbox_span_ids(
        workflow_id=command.workflow_id,
        run_id=command.run_id,
        activity_id=command.activity_id,
        attempt=command.attempt,
    )
    attributes: dict[str, str | int | bool] = {
        "sandbox.provider": "openshell",
        "openbox.sandbox.profile_id": _safe_evidence_identity(command.profile_id),
        "openbox.sandbox.runtime_contract_version": bundle.runtime_contract_version,
        "openbox.sandbox.adapter_build_sha256": bundle.adapter_build_sha256,
        "openbox.sandbox.compatibility_id": _safe_evidence_identity(bundle.compatibility_id),
        "openbox.sandbox.image_digest": _image_digest(bundle.template),
        "openbox.sandbox.template_sha256": hashlib.sha256(
            bundle.template.encode("utf-8")
        ).hexdigest(),
        "openbox.sandbox.policy_id": _safe_evidence_identity(bundle.policy.id),
        "openbox.sandbox.policy_version": bundle.policy.version,
        "openbox.sandbox.policy_sha256": bundle.policy.sha256,
        "openbox.sandbox.profile_bundle_version": _safe_evidence_identity(
            config.profiles.bundle_version
        ),
        "openbox.sandbox.outcome": outcome,
        "openbox.sandbox.disposition": disposition,
        "openbox.sandbox.timeout_status": timeout_status,
        "openbox.sandbox.cleanup_status": cleanup_status,
        "openbox.sandbox.directive": result.directive.value,
        "openbox.sandbox.error_code": error_code,
        "openbox.sandbox.stdout_bytes": len(stdout),
        "openbox.sandbox.stderr_bytes": len(stderr),
        "openbox.sandbox.stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "openbox.sandbox.stderr_sha256": hashlib.sha256(stderr).hexdigest(),
    }
    if execution is not None and execution.sandbox_id is not None:
        attributes["openbox.sandbox.id"] = _safe_evidence_identity(execution.sandbox_id)
    if exit_code is not None:
        attributes["openbox.sandbox.exit_code"] = exit_code

    span: dict[str, Any] = {
        "span_id": span_id,
        "trace_id": trace_id,
        "parent_span_id": None,
        "name": "openbox.sandbox_execution",
        "kind": "INTERNAL",
        "stage": "completed",
        "start_time": started_ns,
        "end_time": completed_ns,
        "duration_ns": completed_ns - started_ns,
        "attributes": attributes,
        "status": {
            "code": "UNSET" if outcome == "success" else "ERROR",
            "description": None,
        },
        "events": [],
        "hook_type": "sandbox_execution",
        "error": None,
    }
    return {
        "source": "workflow-telemetry",
        "event_type": "ActivityStarted",
        "workflow_id": command.workflow_id,
        "run_id": command.run_id,
        "workflow_type": command.workflow_type,
        "task_queue": command.task_queue,
        "timestamp": _iso8601_ns(completed_ns),
        "activity_id": command.activity_id,
        "activity_type": "openbox_governed_command",
        "attempt": command.attempt,
        "profile_id": command.profile_id,
        "hook_trigger": True,
        "span_count": 1,
        "spans": [span],
    }


def _activity_completed(
    command: GovernedCommand,
    result: DispatchResult,
    now: datetime,
    *,
    duration_ns: int,
) -> dict[str, Any]:
    return {
        "source": "workflow-telemetry",
        "event_type": "ActivityCompleted",
        "workflow_id": command.workflow_id,
        "run_id": command.run_id,
        "workflow_type": command.workflow_type,
        "task_queue": command.task_queue,
        "timestamp": _iso8601(now),
        "activity_id": command.activity_id,
        "activity_type": "openbox_governed_command",
        "attempt": command.attempt,
        "profile_id": command.profile_id,
        "status": "completed",
        "duration_ms": duration_ns / 1_000_000,
        "activity_output": {
            "disposition": result.disposition.value,
            "cleanup_status": result.execution.cleanup_status.value
            if result.execution is not None
            else CleanupStatus.NOT_NEEDED.value,
        },
    }


def _is_normal_sandbox_completion(result: DispatchResult) -> bool:
    return (
        result.disposition is Disposition.EXECUTED_IN_SANDBOX
        and result.error is None
        and result.execution is not None
        and result.execution.cleanup_status is CleanupStatus.DELETED
    )


def _completion_failure_result(
    result: DispatchResult,
    initial_decision: GovernanceDecision,
    error_code: DispatchErrorCode,
    *,
    directive: Directive = Directive.CONTINUE,
) -> DispatchResult:
    return DispatchResult(
        disposition=result.disposition,
        directive=directive,
        execution=result.execution,
        error=NormalizedDispatchError(error_code),
        _governance=initial_decision.raw,
    )


def _completed_stop_result(
    result: DispatchResult,
    initial_decision: GovernanceDecision,
    completed_decision: GovernanceDecision,
) -> DispatchResult:
    if completed_decision.verdict == "halt":
        return _completion_failure_result(
            result,
            initial_decision,
            DispatchErrorCode.HALTED,
            directive=Directive.HALT,
        )
    return _completion_failure_result(result, initial_decision, DispatchErrorCode.BLOCKED)


def _sandbox_span_ids(
    *,
    workflow_id: str,
    run_id: str,
    activity_id: str,
    attempt: int,
) -> tuple[str, str]:
    """Derive resend-stable sandbox span identity without relaxing dispatch admission."""
    identity = "|".join(
        (workflow_id, run_id, activity_id, str(attempt), "sandbox_execution")
    ).encode("utf-8")
    return (
        hashlib.sha256(identity).hexdigest()[:16],
        hashlib.sha256(b"trace|" + identity).hexdigest()[:32],
    )


def _safe_evidence_identity(value: str) -> str:
    """Keep identity metadata bounded and incapable of carrying arbitrary bodies."""
    return value if _SAFE_EVIDENCE_IDENTITY.fullmatch(value) is not None else "unknown"


def _image_digest(template: str) -> str:
    marker = "@sha256:"
    before, separator, digest = template.rpartition(marker)
    if (
        not before
        or separator != marker
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise GovernanceProtocolError()
    return "sha256:" + digest


def _epoch_ns(value: datetime) -> int:
    return int(value.astimezone(UTC).timestamp() * 1_000_000_000)


def _iso8601_ns(value: int) -> str:
    return _iso8601(datetime.fromtimestamp(value / 1_000_000_000, UTC))


def _iso8601(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _duration_ms(started: float, finished: float) -> int:
    return max(0, int((finished - started) * 1000))


def _timeout_status(value: str) -> TimeoutStatus:
    return {
        "not_observed": TimeoutStatus.NOT_OBSERVED,
        "confirmed": TimeoutStatus.CONFIRMED_TIMEOUT,
        "possible": TimeoutStatus.POSSIBLE_TIMEOUT,
    }[value]
