"""Canonical trace-key tests — int keying on BOTH register and lookup sides."""

import pytest

from openbox_core.context import ContextStore, canonical_trace_key
from openbox_core.contracts.context import ActivityContext

CTX = ActivityContext(workflow_id="wf-1", activity_id="a-1")
TRACE_INT = 0x4BF92F3577B34DA6A3CE929D0E0E4736
TRACE_HEX = "4bf92f3577b34da6a3ce929d0e0e4736"


class TestCanonicalTraceKey:
    def test_int_passthrough(self):
        assert canonical_trace_key(TRACE_INT) == TRACE_INT

    def test_hex_string_converts_to_same_key(self):
        assert canonical_trace_key(TRACE_HEX) == TRACE_INT

    def test_non_hex_string_rejected(self):
        with pytest.raises(ValueError, match="not hex"):
            canonical_trace_key("not-a-trace")

    def test_bool_and_other_types_rejected(self):
        with pytest.raises(TypeError):
            canonical_trace_key(True)
        with pytest.raises(TypeError):
            canonical_trace_key(3.14)


class TestRegisterLookupSymmetry:
    def test_register_int_lookup_int(self):
        store = ContextStore()
        store.register_trace(TRACE_INT, CTX)
        assert store.context_for_trace(TRACE_INT) is CTX

    def test_register_int_lookup_wire_hex(self):
        # The wire hex is only a representation — same canonical key.
        store = ContextStore()
        store.register_trace(TRACE_INT, CTX)
        assert store.context_for_trace(TRACE_HEX) is CTX

    def test_register_hex_lookup_int(self):
        store = ContextStore()
        store.register_trace(TRACE_HEX, CTX)
        assert store.context_for_trace(TRACE_INT) is CTX

    def test_unknown_trace_returns_none(self):
        assert ContextStore().context_for_trace(12345) is None


class TestLeakSafety:
    def test_unregister_removes_entry(self):
        store = ContextStore()
        store.register_trace(1, CTX)
        store.unregister_trace(1)
        assert store.context_for_trace(1) is None
        assert store.trace_map_size() == 0

    def test_map_does_not_grow_unbounded_with_cleanup(self):
        store = ContextStore()
        for i in range(1000):
            store.register_trace(i, CTX)
            store.unregister_trace(i)
        assert store.trace_map_size() == 0

    def test_clear_empties_everything(self):
        store = ContextStore()
        for i in range(10):
            store.register_trace(i, CTX)
        store.mark_activity_aborted("wf", "a")
        store.clear()
        assert store.trace_map_size() == 0
        assert store.context_for_trace(3) is None
        assert not store.is_activity_aborted("wf", "a")

    def test_stale_lookup_after_completion_returns_none(self):
        store = ContextStore()
        store.register_trace(TRACE_INT, CTX)
        store.unregister_trace(TRACE_INT)  # activity completed
        assert store.context_for_trace(TRACE_HEX) is None
