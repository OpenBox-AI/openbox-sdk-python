"""Context bind/reset tests — reset is GUARANTEED, including on exceptions."""

import pytest

from openbox_core.context import ContextStore, activity_scope
from openbox_core.contracts.context import ActivityContext

CTX = ActivityContext(workflow_id="wf-1", run_id="r-1", activity_id="a-1", activity_type="t")


class TestBindReset:
    def test_bind_current_reset(self):
        store = ContextStore()
        assert store.current_activity_context() is None
        token = store.bind(CTX)
        assert store.current_activity_context() is CTX
        store.reset(token)
        assert store.current_activity_context() is None

    def test_nested_binding_restores_outer(self):
        store = ContextStore()
        outer = ActivityContext(activity_id="outer")
        inner = ActivityContext(activity_id="inner")
        outer_token = store.bind(outer)
        inner_token = store.bind(inner)
        assert store.current_activity_context() is inner
        store.reset(inner_token)
        assert store.current_activity_context() is outer
        store.reset(outer_token)


class TestActivityScope:
    def test_scope_binds_and_resets(self):
        store = ContextStore()
        with activity_scope(CTX, store=store) as bound:
            assert bound is CTX
            assert store.current_activity_context() is CTX
        assert store.current_activity_context() is None

    def test_scope_resets_on_exception(self):
        # The Temporal leak fix: reset lives in finally, not the happy path.
        store = ContextStore()
        with pytest.raises(RuntimeError):
            with activity_scope(CTX, store=store):
                raise RuntimeError("operation failed")
        assert store.current_activity_context() is None

    def test_scope_registers_and_unregisters_trace(self):
        store = ContextStore()
        trace_id = 0x4BF92F3577B34DA6A3CE929D0E0E4736
        with activity_scope(CTX, trace_id=trace_id, store=store):
            assert store.context_for_trace(trace_id) is CTX
        assert store.context_for_trace(trace_id) is None

    def test_scope_unregisters_trace_on_exception(self):
        store = ContextStore()
        with pytest.raises(ValueError):
            with activity_scope(CTX, trace_id=7, store=store):
                raise ValueError("boom")
        assert store.context_for_trace(7) is None
        assert store.trace_map_size() == 0


class TestGovernanceFlags:
    def test_abort_flags(self):
        store = ContextStore()
        assert not store.is_activity_aborted("wf", "a")
        store.mark_activity_aborted("wf", "a")
        assert store.is_activity_aborted("wf", "a")
        store.clear_activity_aborted("wf", "a")
        assert not store.is_activity_aborted("wf", "a")

    def test_halt_flag_and_clear(self):
        store = ContextStore()
        assert store.halt_requested is False
        store.request_halt()
        assert store.halt_requested is True
        store.clear()
        assert store.halt_requested is False
