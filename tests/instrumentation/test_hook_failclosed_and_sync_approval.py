"""Started-hook fail-closed mapping + the sync adapter-approval seam.

A fail-closed evaluation failure must become a framework-native HALT through
the adapter (raw ``GovernanceAPIError`` reads as a generic retryable failure
to frameworks like Temporal), and adapters exposing ``handle_approval_sync``
own sync HITL instead of the inline core poller.
"""

import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "wire"))
from span_fixtures import TRACE_ID, FakeSpan  # noqa: E402

from openbox_core.client import EvaluationClient
from openbox_core.config import OpenBoxConfig
from openbox_core.conformance.fake_core import FakeCore, fake_client
from openbox_core.conformance.hook_preflight import (
    CONFORMANCE_CONTEXT,
    RecordingHookAdapter,
)
from openbox_core.context import ContextStore
from openbox_core.contracts.otel_spans import HookType
from openbox_core.errors import ContractError, GovernanceHaltError
from openbox_core.hooks.preflight import HookRuntime
from openbox_core.runtime import OpenBoxRuntime


def _down_client(on_api_error: str) -> EvaluationClient:
    def handler(request):
        raise httpx.ConnectError("core is down")

    transport = httpx.MockTransport(handler)
    return EvaluationClient(
        "https://core.test",
        "obx_test_conformance",
        on_api_error=on_api_error,
        transport=transport,
        async_transport=transport,
    )


def _runtime(client: EvaluationClient, adapter, store) -> OpenBoxRuntime:
    config = OpenBoxConfig(api_url="https://core.test", api_key="obx_test_conformance")
    return OpenBoxRuntime(config, adapter, client=client, context_store=store)


def _bound_span(store: ContextStore) -> FakeSpan:
    store.register_trace(TRACE_ID, CONFORMANCE_CONTEXT)
    return FakeSpan()


HTTP_FIELDS = {"http_method": "GET", "http_url": "https://governed.example/x"}


class TestStartedFailClosed:
    def test_fail_closed_api_error_maps_to_adapter_halt(self):
        adapter, store = RecordingHookAdapter(), ContextStore()
        hooks = HookRuntime(_runtime(_down_client("fail_closed"), adapter, store))
        span = _bound_span(store)

        with pytest.raises(GovernanceHaltError):
            hooks.preflight(span, hook_type=HookType.HTTP_REQUEST, fields=HTTP_FIELDS)

        assert len(adapter.hook_blocked) == 1
        halt = adapter.hook_blocked[0]
        assert halt.verdict.value == "halt"
        assert halt.fallback_used is True
        assert "fail_closed_error" in halt.raw
        # The failure also aborts the activity for subsequent hooks.
        assert store.is_activity_aborted(
            CONFORMANCE_CONTEXT.workflow_id, CONFORMANCE_CONTEXT.activity_id
        )

    def test_fail_open_api_error_proceeds(self):
        adapter, store = RecordingHookAdapter(), ContextStore()
        hooks = HookRuntime(_runtime(_down_client("fail_open"), adapter, store))
        span = _bound_span(store)

        assert hooks.preflight(span, hook_type=HookType.HTTP_REQUEST, fields=HTTP_FIELDS) is True
        assert adapter.hook_blocked == []

    def test_contract_error_fails_closed_even_when_fail_open(self, monkeypatch):
        adapter, store = RecordingHookAdapter(), ContextStore()
        hooks = HookRuntime(_runtime(_down_client("fail_open"), adapter, store))
        span = _bound_span(store)
        monkeypatch.setattr(
            hooks._gate,
            "preflight",
            lambda event: (_ for _ in ()).throw(ContractError("bad payload")),
        )

        with pytest.raises(GovernanceHaltError):
            hooks.preflight(span, hook_type=HookType.HTTP_REQUEST, fields=HTTP_FIELDS)
        assert adapter.hook_blocked[0].verdict.value == "halt"

    async def test_async_fail_closed_maps_to_adapter_halt(self):
        adapter, store = RecordingHookAdapter(), ContextStore()
        hooks = HookRuntime(_runtime(_down_client("fail_closed"), adapter, store))
        span = _bound_span(store)

        with pytest.raises(GovernanceHaltError):
            await hooks.apreflight(span, hook_type=HookType.HTTP_REQUEST, fields=HTTP_FIELDS)
        assert adapter.hook_blocked[0].fallback_used is True


class _RetryStyleAdapter(RecordingHookAdapter):
    """Adapter owning sync HITL natively (Temporal-style retryable pending)."""

    class Pending(Exception):
        pass

    def __init__(self):
        super().__init__()
        self.sync_approvals = []
        self.approve_sync = False

    def handle_approval_sync(self, result):
        self.sync_approvals.append(result)
        if not self.approve_sync:
            raise self.Pending("approval pending — retry")


class TestSyncApprovalAdapterSeam:
    def _hooks(self, adapter):
        store = ContextStore()
        fake = FakeCore({"verdict": "require_approval", "approval_id": "appr-1"})
        runtime = OpenBoxRuntime(
            OpenBoxConfig(api_url="https://core.test", api_key="obx_test_conformance"),
            adapter,
            client=fake_client(fake),
            context_store=store,
        )
        return HookRuntime(runtime), store, fake

    def test_adapter_seam_owns_sync_approval(self):
        adapter = _RetryStyleAdapter()
        hooks, store, fake = self._hooks(adapter)
        span = _bound_span(store)

        with pytest.raises(_RetryStyleAdapter.Pending):
            hooks.preflight(span, hook_type=HookType.HTTP_REQUEST, fields=HTTP_FIELDS)

        assert len(adapter.sync_approvals) == 1
        # The inline core poller must NOT have been driven.
        assert fake.approval_requests == []

    def test_adapter_seam_return_means_approved(self):
        adapter = _RetryStyleAdapter()
        adapter.approve_sync = True
        hooks, store, fake = self._hooks(adapter)
        span = _bound_span(store)

        assert hooks.preflight(span, hook_type=HookType.HTTP_REQUEST, fields=HTTP_FIELDS) is True
        assert fake.approval_requests == []

    def test_without_seam_core_poller_still_drives(self):
        adapter = RecordingHookAdapter()  # no handle_approval_sync
        hooks, store, fake = self._hooks(adapter)
        fake.queue.append({"action": "allow"})  # poller decision
        span = _bound_span(store)

        assert hooks.preflight(span, hook_type=HookType.HTTP_REQUEST, fields=HTTP_FIELDS) is True
        assert len(fake.approval_requests) == 1
