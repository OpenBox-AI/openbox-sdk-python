"""Adapter/context-binding conformance pieces: recording adapter + env builder."""

from __future__ import annotations

from typing import Any

from ..config import InstrumentationConfig, OpenBoxConfig
from ..context import ContextStore
from ..contracts.context import ActivityContext
from ..contracts.results import EvaluationResult, Verdict
from ..errors import ApprovalRejectedError, GovernanceBlockedError, GovernanceHaltError
from ..runtime import OpenBoxRuntime
from .fake_core import FakeCore, fake_client

__all__ = ["CONFORMANCE_CONTEXT", "RecordingHookAdapter", "build_conformance_runtime"]

# The reference activity context every conformance case binds.
CONFORMANCE_CONTEXT = ActivityContext(
    workflow_id="wf-conformance",
    run_id="run-conformance",
    workflow_type="ConformanceWorkflow",
    task_queue="conformance-queue",
    activity_id="act-conformance",
    activity_type="conformance_activity",
)


class RecordingHookAdapter:
    """Reference FrameworkAdapter: records every delegation, raises core errors.

    ``approve_next`` drives the async approval outcome (True ⇒ approved).
    """

    name = "conformance"

    def __init__(self) -> None:
        self.hook_blocked: list[EvaluationResult] = []
        self.lifecycle_blocked: list[EvaluationResult] = []
        self.completed_results: list[EvaluationResult] = []
        self.completed_contexts: list[ActivityContext | None] = []
        self.approvals: list[EvaluationResult] = []
        self.approval_contexts: list[ActivityContext | None] = []
        self.approve_next = True

    async def handle_approval(
        self, result: EvaluationResult, context: ActivityContext | None = None
    ) -> None:
        self.approvals.append(result)
        self.approval_contexts.append(context)
        if not self.approve_next:
            raise ApprovalRejectedError("rejected by conformance adapter")

    def raise_lifecycle_blocked(self, result: EvaluationResult) -> None:
        self.lifecycle_blocked.append(result)
        self._raise(result)

    def raise_hook_blocked(self, result: EvaluationResult) -> None:
        self.hook_blocked.append(result)
        self._raise(result)

    def on_completed_hook_result(
        self, result: EvaluationResult, context: ActivityContext | None = None
    ) -> None:
        self.completed_results.append(result)
        self.completed_contexts.append(context)

    @staticmethod
    def _raise(result: EvaluationResult) -> None:
        if result.verdict is Verdict.HALT:
            raise GovernanceHaltError(result.reason or "halted")
        raise GovernanceBlockedError(result.verdict, result.reason or "blocked")


def build_conformance_runtime(
    fake_core: FakeCore,
    adapter: Any | None = None,
    store: ContextStore | None = None,
    **instrumentation_overrides: Any,
) -> OpenBoxRuntime:
    """OpenBoxRuntime wired to the fake Core with an isolated ContextStore."""
    config = OpenBoxConfig(
        api_url="https://core.test",
        api_key="obx_test_conformance",
        instrumentation=InstrumentationConfig(**instrumentation_overrides),
    )
    return OpenBoxRuntime(
        config,
        adapter if adapter is not None else RecordingHookAdapter(),
        client=fake_client(fake_core),
        context_store=store if store is not None else ContextStore(),
    )
