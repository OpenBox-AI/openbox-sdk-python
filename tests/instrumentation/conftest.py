"""Shared fixtures: fake Core transport, recording adapter, wired runtime."""

import httpx
import pytest

from openbox_core.client import EvaluationClient
from openbox_core.config import InstrumentationConfig, OpenBoxConfig
from openbox_core.context import ContextStore
from openbox_core.contracts.context import ActivityContext
from openbox_core.contracts.results import EvaluationResult
from openbox_core.errors import GovernanceBlockedError, GovernanceHaltError
from openbox_core.hooks.preflight import HookRuntime
from openbox_core.runtime import OpenBoxRuntime

ACTIVITY_CTX = ActivityContext(
    workflow_id="wf-1",
    run_id="run-1",
    workflow_type="W",
    task_queue="q",
    activity_id="act-1",
    activity_type="charge",
)


class FakeCore:
    """Programmable fake Core: queue verdict responses, capture payloads."""

    def __init__(self, *verdicts):
        self.queue = list(verdicts)
        self.payloads: list[dict] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        import json

        if request.url.path.endswith("/governance/evaluate"):
            self.payloads.append(json.loads(request.content))
            response = self.queue.pop(0) if self.queue else {"verdict": "allow"}
            return httpx.Response(200, json=response)
        if request.url.path.endswith("/governance/approval"):
            response = self.queue.pop(0) if self.queue else {"action": "allow"}
            return httpx.Response(200, json=response)
        return httpx.Response(200, json={})

    @property
    def started_payloads(self):
        return [p for p in self.payloads if p.get("spans") and p["spans"][0].get("stage") == "started"]

    @property
    def completed_payloads(self):
        return [p for p in self.payloads if p.get("spans") and p["spans"][0].get("stage") == "completed"]


class RaisingHookAdapter:
    """Adapter recording hook delegations and raising core errors."""

    name = "test-hook-adapter"

    def __init__(self):
        self.hook_blocked: list[EvaluationResult] = []
        self.completed_results: list[EvaluationResult] = []
        self.approvals: list[EvaluationResult] = []
        self.approve_next = True

    async def handle_approval(self, result):
        self.approvals.append(result)
        if not self.approve_next:
            from openbox_core.errors import ApprovalRejectedError

            raise ApprovalRejectedError("rejected by test adapter")

    def raise_lifecycle_blocked(self, result):
        raise GovernanceBlockedError(result.verdict, result.reason or "blocked")

    def raise_hook_blocked(self, result):
        self.hook_blocked.append(result)
        from openbox_core.contracts.results import Verdict

        if result.verdict is Verdict.HALT:
            raise GovernanceHaltError(result.reason or "halted")
        raise GovernanceBlockedError(result.verdict, result.reason or "blocked")

    def on_completed_hook_result(self, result):
        self.completed_results.append(result)


def build_runtime(fake_core: FakeCore, adapter=None, store=None, **instrumentation_overrides):
    transport = httpx.MockTransport(fake_core.handler)
    client = EvaluationClient(
        "https://core.test", "obx_test_x", transport=transport, async_transport=transport
    )
    config = OpenBoxConfig(
        api_url="https://core.test",
        api_key="obx_test_x",
        instrumentation=InstrumentationConfig(**instrumentation_overrides),
    )
    return OpenBoxRuntime(
        config,
        adapter or RaisingHookAdapter(),
        client=client,
        context_store=store or ContextStore(),
    )


@pytest.fixture
def fake_core():
    return FakeCore()


@pytest.fixture
def adapter():
    return RaisingHookAdapter()


@pytest.fixture
def store():
    return ContextStore()


@pytest.fixture
def runtime(fake_core, adapter, store):
    return build_runtime(fake_core, adapter, store)


@pytest.fixture
def hook_runtime(runtime):
    return HookRuntime(runtime)
