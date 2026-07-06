"""The full required-case conformance matrix.

Every case asserts BEHAVIOR — the real operation ran or did not run — plus
re-asserts the wire shape (hex ids, flat SpanData, no nested otel envelope).
This file exercises the packaged kit exactly the way a framework SDK would.
"""

import pytest
import requests

from openbox_core.conformance.fake_core import FakeCore, assert_hook_wire_shape
from openbox_core.conformance.hook_preflight import (
    CONFORMANCE_CONTEXT,
    RecordingHookAdapter,
)
from openbox_core.conformance.instrumentation import (
    LocalCountingServer,
    bound_conformance_activity,
    installed_conformance_runtime,
)
from openbox_core.context import ContextStore, activity_scope
from openbox_core.errors import (
    GovernanceBlockedError,
    GovernanceHaltError,
)
from openbox_core.instrumentation.function import governed


@pytest.fixture(scope="module")
def server():
    server = LocalCountingServer()
    yield server
    server.stop()


class TestHttpCases:
    def test_http_started_block_request_not_sent(self, server):
        fake_core = FakeCore({"verdict": "block", "reason": "policy"})
        store = ContextStore()
        with installed_conformance_runtime(fake_core, store=store), bound_conformance_activity(store):
            before = server.hits
            with pytest.raises(GovernanceBlockedError):
                requests.get(server.url, timeout=5)
            assert server.hits == before
        assert_hook_wire_shape(fake_core.started_payloads[0])

    def test_http_started_halt_not_sent_and_halt_shaped_error(self, server):
        fake_core = FakeCore({"verdict": "halt", "reason": "emergency"})
        adapter, store = RecordingHookAdapter(), ContextStore()
        with installed_conformance_runtime(fake_core, adapter, store), bound_conformance_activity(store):
            before = server.hits
            with pytest.raises(GovernanceHaltError):  # halt-SHAPED error
                requests.get(server.url, timeout=5)
            assert server.hits == before
            assert store.halt_requested
        assert adapter.hook_blocked[0].verdict.value == "halt"

    def test_http_require_approval_rejected_not_sent(self, server):
        fake_core = FakeCore(
            {"verdict": "require_approval", "approval_id": "app-1"},
            {"action": "block", "reason": "human rejected"},  # approval poll
        )
        store = ContextStore()
        with installed_conformance_runtime(fake_core, store=store) as runtime, bound_conformance_activity(store):
            runtime.config.hitl.poll_interval_ms = 0
            before = server.hits
            with pytest.raises(GovernanceBlockedError):
                requests.get(server.url, timeout=5)
            assert server.hits == before  # rejected ⇒ never sent

    def test_http_require_approval_allowed_sent_after_approval(self, server):
        fake_core = FakeCore(
            {"verdict": "require_approval", "approval_id": "app-1"},
            {"action": "allow"},        # approval poll grants
            {"verdict": "allow"},       # completed telemetry
        )
        store = ContextStore()
        with installed_conformance_runtime(fake_core, store=store) as runtime, bound_conformance_activity(store):
            runtime.config.hitl.poll_interval_ms = 0
            before = server.hits
            response = requests.get(server.url, timeout=5)
            assert response.status_code == 200
            assert server.hits == before + 1  # sent AFTER approval
        assert len(fake_core.approval_requests) == 1


class TestDbFileFunctionCases:
    def test_db_started_block_query_not_called(self):
        import sqlalchemy
        from sqlalchemy import text

        engine = sqlalchemy.create_engine("sqlite:///:memory:")
        fake_core = FakeCore({"verdict": "block", "reason": "no db"})
        store = ContextStore()
        try:
            with installed_conformance_runtime(fake_core, store=store), bound_conformance_activity(store):
                with engine.connect() as conn:
                    with pytest.raises(GovernanceBlockedError):
                        conn.execute(text("SELECT 1"))
            assert_hook_wire_shape(fake_core.started_payloads[0])
        finally:
            engine.dispose()

    def test_file_open_started_block_handle_not_opened(self, tmp_path):
        fake_core = FakeCore({"verdict": "block", "reason": "no files"})
        store = ContextStore()
        blocked_path = tmp_path / "never.txt"
        with installed_conformance_runtime(fake_core, store=store, file_enabled=True), bound_conformance_activity(store):
            with pytest.raises(GovernanceBlockedError):
                open(blocked_path, "w")
        assert not blocked_path.exists()

    def test_function_started_block_not_called(self):
        fake_core = FakeCore({"verdict": "block", "reason": "no calls"})
        store = ContextStore()
        calls = []

        @governed
        def wrapped():
            calls.append(1)

        with installed_conformance_runtime(fake_core, store=store), bound_conformance_activity(store):
            with pytest.raises(GovernanceBlockedError):
                wrapped()
        assert calls == []

    def test_completed_block_marks_future_blocked_op_already_ran(self):
        fake_core = FakeCore(
            {"verdict": "allow"},                        # started: proceed
            {"verdict": "block", "reason": "post-hoc"},  # completed: block future
        )
        adapter, store = RecordingHookAdapter(), ContextStore()
        calls = []

        @governed
        def wrapped():
            calls.append(1)
            return "ran"

        with installed_conformance_runtime(fake_core, adapter, store), bound_conformance_activity(store):
            assert wrapped() == "ran"  # op already ran; NOT undone, NO raise
        assert calls == [1]
        assert adapter.completed_results[-1].verdict.value == "block"
        assert store.is_activity_aborted(
            CONFORMANCE_CONTEXT.workflow_id, CONFORMANCE_CONTEXT.activity_id
        )  # FUTURE execution blocked


class TestContextCases:
    def test_context_bound_before_hooks_and_reset_after(self):
        store = ContextStore()
        with activity_scope(CONFORMANCE_CONTEXT, store=store):
            assert store.current_activity_context() is CONFORMANCE_CONTEXT
        assert store.current_activity_context() is None

    def test_context_reset_on_exception(self):
        store = ContextStore()
        with pytest.raises(RuntimeError):
            with activity_scope(CONFORMANCE_CONTEXT, store=store):
                raise RuntimeError("activity failed")
        assert store.current_activity_context() is None

    def test_trace_lookup_uses_canonical_key(self):
        import sys
        from pathlib import Path

        sys.path.insert(0, str(Path(__file__).parent.parent / "wire"))
        from span_fixtures import TRACE_ID, FakeSpan

        from openbox_core.hooks.events import resolve_context

        store = ContextStore()
        # Register with the raw OTel INTEGER trace id...
        store.register_trace(TRACE_ID, CONFORMANCE_CONTEXT)
        # ...and look up from a child span carrying the same integer id.
        assert resolve_context(store, FakeSpan()) is CONFORMANCE_CONTEXT

    async def test_executor_thread_hook_resolves_context(self):
        import asyncio

        from openbox_core.otel.propagation import install_context_propagating_executor

        assert install_context_propagating_executor() is True
        store = ContextStore()

        def in_thread():
            return store.current_activity_context()

        with activity_scope(CONFORMANCE_CONTEXT, store=store):
            loop = asyncio.get_running_loop()
            seen = await loop.run_in_executor(None, in_thread)
        assert seen is CONFORMANCE_CONTEXT


class TestWireShapeReasserted:
    def test_started_and_completed_wire_shape(self, server):
        fake_core = FakeCore({"verdict": "allow"}, {"verdict": "allow"})
        store = ContextStore()
        with installed_conformance_runtime(fake_core, store=store), bound_conformance_activity(store):
            requests.get(server.url, timeout=5)
        for payload in fake_core.payloads:
            assert_hook_wire_shape(payload)
