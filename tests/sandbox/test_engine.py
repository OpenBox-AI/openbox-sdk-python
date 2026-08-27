from __future__ import annotations

import asyncio
import base64
import tempfile
import unittest
from pathlib import Path

from openbox_core.contracts.context import ActivityContext
from openbox_sandbox import (
    CleanupBacklog,
    CleanupStatus,
    Disposition,
    InMemoryTelemetrySink,
    SandboxAuthorization,
    SandboxEngineConfig,
    SandboxErrorCode,
    SandboxValidationError,
)
from openbox_sandbox.runtime import (
    SandboxServiceTransportError,
    ServiceResponse,
    SubmissionState,
    TransportFailureCode,
)

from .helpers import SANDBOX_ID, authorization, command, config, engine


class SandboxExecutionEngineTests(unittest.IsolatedAsyncioTestCase):
    async def test_authorized_constrain_owns_complete_sandbox_lifecycle(self) -> None:
        telemetry = InMemoryTelemetrySink()
        value, sandbox = engine(configuration=config(telemetry=telemetry))

        result = await value.execute(command(), authorization())

        self.assertEqual(result.disposition, Disposition.EXECUTED_IN_SANDBOX)
        self.assertEqual(
            [name for name, _ in sandbox.calls],
            ["create", "wait_ready", "exec", "delete", "wait_deleted"],
        )
        assert result.execution is not None
        self.assertEqual(result.execution.exit_code, 7)
        self.assertEqual(result.execution.stdout, b"sandbox-out\x00")
        self.assertEqual(result.execution.stderr, b"sandbox-err\xff")
        self.assertEqual(result.execution.cleanup_status, CleanupStatus.DELETED)
        self.assertEqual(result.authorization["verdict"], "constrain")
        self.assertEqual(
            [event.event for event in telemetry.events],
            [
                "authorization_accepted",
                "sandbox_create_started",
                "sandbox_create_finished",
                "sandbox_ready",
                "sandbox_exec_started",
                "sandbox_exec_finished",
                "sandbox_delete_started",
                "sandbox_deleted",
                "dispatch_terminal",
            ],
        )

    async def test_profile_rejection_and_kill_switch_never_create(self) -> None:
        value, sandbox = engine()
        result = await value.execute(command(profile_id="unknown"), authorization())
        assert result.error is not None
        self.assertEqual(result.error.code, SandboxErrorCode.PROFILE_REJECTED)
        self.assertEqual(sandbox.calls, [])

        value, sandbox = engine(configuration=config(enabled=False))
        result = await value.execute(command(), authorization())
        assert result.error is not None
        self.assertEqual(result.error.code, SandboxErrorCode.SANDBOX_DISABLED)
        self.assertEqual(sandbox.calls, [])

    async def test_oversized_success_response_is_protocol_indeterminate(self) -> None:
        value, sandbox = engine()
        sandbox.values["exec"] = ServiceResponse(
            "executed",
            {
                "result": {
                    "exit_code": 0,
                    "stdout_base64": base64.b64encode(b"x" * 1025).decode(),
                    "stderr_base64": "",
                    "timeout": "not_observed",
                }
            },
        )

        result = await value.execute(command(), authorization())

        self.assertEqual(result.disposition, Disposition.EXECUTION_INDETERMINATE)
        assert result.error is not None
        self.assertEqual(result.error.code, SandboxErrorCode.SANDBOX_PROTOCOL)
        assert result.execution is not None
        self.assertEqual(result.execution.stdout, b"")
        self.assertEqual(result.execution.cleanup_status, CleanupStatus.DELETED)

    async def test_uncertain_exec_is_indeterminate_and_cleanup_owned(self) -> None:
        value, sandbox = engine()
        sandbox.values["exec"] = SandboxServiceTransportError(
            SubmissionState.POSSIBLY_SUBMITTED,
            TransportFailureCode.DEADLINE,
        )

        result = await value.execute(command(), authorization())

        self.assertEqual(result.disposition, Disposition.EXECUTION_INDETERMINATE)
        assert result.error is not None
        self.assertEqual(result.error.code, SandboxErrorCode.SANDBOX_EXEC_INDETERMINATE)
        self.assertEqual(
            [name for name, _ in sandbox.calls],
            ["create", "wait_ready", "exec", "delete", "wait_deleted"],
        )

    async def test_cancellation_waits_for_owned_cleanup(self) -> None:
        value, sandbox = engine()
        started = asyncio.Event()
        release = asyncio.Event()

        async def wait_ready(*args):
            sandbox.calls.append(("wait_ready", args))
            started.set()
            await release.wait()

        sandbox.wait_ready = wait_ready
        task = asyncio.create_task(value.execute(command(), authorization()))
        await started.wait()
        task.cancel()
        release.set()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual([name for name, _ in sandbox.calls][-2:], ["delete", "wait_deleted"])

    async def test_failed_cleanup_is_reconciled_from_backlog(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            backlog = CleanupBacklog(Path(directory), "linux-arm64-v1")
            value, sandbox = engine(configuration=config(cleanup_backlog=backlog))
            sandbox.values["wait_deleted"] = SandboxServiceTransportError(
                SubmissionState.POSSIBLY_SUBMITTED,
                TransportFailureCode.TRANSPORT,
            )
            result = await value.execute(command(), authorization())
            assert result.execution is not None
            self.assertEqual(result.execution.cleanup_status, CleanupStatus.FAILED)
            self.assertEqual(await backlog.request_ids(), (SANDBOX_ID,))

            from openbox_sandbox.runtime import ServiceResponse

            sandbox.values["wait_deleted"] = ServiceResponse("terminally_absent", {})
            reconciled = await value.reconcile_cleanup()
            self.assertEqual(reconciled.attempted, 1)
            self.assertEqual(reconciled.deleted, 1)
            self.assertEqual(reconciled.remaining, 0)

    async def test_configuration_and_command_attempt_fail_closed(self) -> None:
        configuration = config()
        with self.assertRaises(ValueError):
            SandboxEngineConfig(
                profiles=object(),  # type: ignore[arg-type]
                sandbox=configuration.sandbox,
            )
        with self.assertRaises(SandboxValidationError):
            command(
                context=ActivityContext(
                    workflow_id="wf-123",
                    run_id="run-456",
                    activity_id="act-789",
                    metadata={"attempt": True},
                )
            )
        with self.assertRaises(TypeError):
            SandboxAuthorization.verified_receipt(
                "receipt-1",
                metadata={"unbounded": "value"},  # type: ignore[call-arg]
            )

    async def test_engine_exposes_only_immutable_wrapper_bindings(self) -> None:
        telemetry = InMemoryTelemetrySink()
        configuration = config(telemetry=telemetry)
        value, _ = engine(configuration=configuration)
        self.assertIs(value.profiles, configuration.profiles)
        self.assertIs(value.asset_bundle, configuration.sandbox.asset_bundle)
        self.assertIs(value.telemetry_sink, configuration.telemetry)

    async def test_engine_has_no_core_or_host_execution_surface(self) -> None:
        value, _ = engine()
        for name in ("dispatch", "dispatch_trusted_constrain", "_dispatch_host"):
            self.assertFalse(hasattr(value, name))
