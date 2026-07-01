"""OpenBoxRuntime delegation tests — block/halt/approval route to the adapter."""

import httpx
import pytest

from openbox_core.adapters.base import CoreAdapter, FrameworkAdapter
from openbox_core.client import EvaluationClient
from openbox_core.config import OpenBoxConfig
from openbox_core.contracts.events import workflow_started
from openbox_core.contracts.results import EvaluationResult, Verdict
from openbox_core.errors import (
    ApprovalRejectedError,
    GovernanceBlockedError,
    GovernanceHaltError,
    GuardrailsValidationError,
)
from openbox_core.runtime import OpenBoxRuntime

WF = dict(workflow_id="wf-1", run_id="r-1", workflow_type="W")


class RecordingAdapter:
    """Fake FrameworkAdapter recording every delegation."""

    name = "recording"

    def __init__(self):
        self.lifecycle_blocked: list[EvaluationResult] = []
        self.hook_blocked: list[EvaluationResult] = []
        self.approvals: list[EvaluationResult] = []
        self.completed: list[EvaluationResult] = []

    async def handle_approval(self, result):
        self.approvals.append(result)

    def raise_lifecycle_blocked(self, result):
        self.lifecycle_blocked.append(result)
        raise GovernanceBlockedError(result.verdict, result.reason or "blocked")

    def raise_hook_blocked(self, result):
        self.hook_blocked.append(result)
        raise GovernanceBlockedError(result.verdict, result.reason or "blocked")

    def on_completed_hook_result(self, result):
        self.completed.append(result)


def make_runtime(response_json, adapter=None):
    transport = httpx.MockTransport(lambda r: httpx.Response(200, json=response_json))
    client = EvaluationClient(
        "https://core.test", "obx_test_x", transport=transport, async_transport=transport
    )
    config = OpenBoxConfig(api_url="https://core.test", api_key="obx_test_x")
    return OpenBoxRuntime(config, adapter, client=client)


class TestLifecycleDelegation:
    def test_allow_returns_result(self):
        runtime = make_runtime({"verdict": "allow"}, RecordingAdapter())
        result = runtime.evaluate_lifecycle(workflow_started(**WF))
        assert result.verdict is Verdict.ALLOW

    def test_block_delegates_to_adapter(self):
        adapter = RecordingAdapter()
        runtime = make_runtime({"verdict": "block", "reason": "no"}, adapter)
        with pytest.raises(GovernanceBlockedError):
            runtime.evaluate_lifecycle(workflow_started(**WF))
        assert len(adapter.lifecycle_blocked) == 1
        assert adapter.lifecycle_blocked[0].verdict is Verdict.BLOCK

    def test_halt_delegates_and_sets_halt_flag(self):
        adapter = RecordingAdapter()
        runtime = make_runtime({"verdict": "halt", "reason": "kill"}, adapter)
        with pytest.raises(GovernanceBlockedError):  # adapter's chosen error
            runtime.evaluate_lifecycle(workflow_started(**WF))
        assert runtime.context_store.halt_requested is True

    def test_guardrails_failure_raises(self):
        response = {
            "verdict": "allow",
            "guardrails_result": {"validation_passed": False, "reasons": [{"reason": "pii"}]},
        }
        runtime = make_runtime(response, RecordingAdapter())
        with pytest.raises(GuardrailsValidationError, match="pii"):
            runtime.evaluate_lifecycle(workflow_started(**WF))

    async def test_require_approval_drives_adapter_async(self):
        adapter = RecordingAdapter()
        runtime = make_runtime({"verdict": "require_approval", "approval_id": "app-1"}, adapter)
        result = await runtime.aevaluate_lifecycle(workflow_started(**WF))
        assert result.verdict is Verdict.REQUIRE_APPROVAL
        assert len(adapter.approvals) == 1

    def test_sync_require_approval_returned_to_caller(self):
        adapter = RecordingAdapter()
        runtime = make_runtime({"verdict": "require_approval"}, adapter)
        result = runtime.evaluate_lifecycle(workflow_started(**WF))
        assert result.verdict is Verdict.REQUIRE_APPROVAL
        assert adapter.approvals == []  # sync path never drives async approval


class TestCoreAdapterDefaults:
    def test_core_adapter_raises_block(self):
        adapter = CoreAdapter()
        with pytest.raises(GovernanceBlockedError):
            adapter.raise_hook_blocked(EvaluationResult(verdict=Verdict.BLOCK, reason="x"))

    def test_core_adapter_raises_halt(self):
        adapter = CoreAdapter()
        with pytest.raises(GovernanceHaltError):
            adapter.raise_lifecycle_blocked(EvaluationResult(verdict=Verdict.HALT))

    async def test_core_adapter_approval_fails_safe_without_poller(self):
        adapter = CoreAdapter()
        with pytest.raises(ApprovalRejectedError, match="failing safe"):
            await adapter.handle_approval(
                EvaluationResult(verdict=Verdict.REQUIRE_APPROVAL, approval_id="a")
            )

    def test_protocol_conformance(self):
        assert isinstance(CoreAdapter(), FrameworkAdapter)
        assert isinstance(RecordingAdapter(), FrameworkAdapter)


class TestRuntimeLifecycleManagement:
    def test_close_clears_context_and_transport(self):
        from openbox_core.context import ContextStore
        from openbox_core.contracts.context import ActivityContext

        store = ContextStore()
        runtime = make_runtime({"verdict": "allow"})
        runtime.context_store = store
        store.register_trace(1, ActivityContext(workflow_id="wf"))
        runtime.close()
        assert store.trace_map_size() == 0

    async def test_aclose(self):
        runtime = make_runtime({"verdict": "allow"})
        await runtime.aclose()

    def test_uninstall_without_install_is_noop(self):
        make_runtime({"verdict": "allow"}).uninstall_instrumentation()
