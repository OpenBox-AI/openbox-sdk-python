"""Hex-id format tests — regex assertions, not truthiness."""

import re

from span_fixtures import TRACE_ID, FakeSpan

from openbox_core.contracts.otel_spans import HookType, Stage, from_otel_span
from openbox_core.otel.trace_context import (
    extract_span_context,
    format_span_id,
    format_trace_id,
    raw_trace_id,
)
from openbox_core.wire.core_span import to_core_span_data

SPAN_HEX = re.compile(r"^[0-9a-f]{16}$")
TRACE_HEX = re.compile(r"^[0-9a-f]{32}$")


class TestWireIds:
    def test_ids_match_hex_regexes(self):
        span_data = from_otel_span(FakeSpan(), stage=Stage.STARTED, hook_type=HookType.HTTP_REQUEST)
        wire, _ = to_core_span_data(span_data)
        assert SPAN_HEX.fullmatch(wire["span_id"])
        assert TRACE_HEX.fullmatch(wire["trace_id"])
        assert SPAN_HEX.fullmatch(wire["parent_span_id"])
        assert "otel" not in wire

    def test_no_raw_integer_ids_anywhere_in_wire_payload(self):
        span_data = from_otel_span(
            FakeSpan(), stage=Stage.COMPLETED, hook_type=HookType.HTTP_REQUEST
        )
        wire, _ = to_core_span_data(span_data)

        def walk(node, path=""):
            if isinstance(node, dict):
                for key, value in node.items():
                    child = f"{path}.{key}" if path else key
                    if key in ("span_id", "trace_id", "parent_span_id"):
                        assert isinstance(value, (str, type(None))), (
                            f"raw integer id leaked at {child}"
                        )
                    walk(value, child)
            elif isinstance(node, list):
                for i, value in enumerate(node):
                    walk(value, f"{path}[{i}]")

        walk(wire)

    def test_padding_small_ids(self):
        assert format_span_id(1) == "0" * 15 + "1"
        assert format_trace_id(0xAB) == "0" * 30 + "ab"


class TestExtractSpanContext:
    def test_full_extraction(self):
        span_id, trace_id, parent_id = extract_span_context(FakeSpan())
        assert SPAN_HEX.fullmatch(span_id)
        assert TRACE_HEX.fullmatch(trace_id)
        assert SPAN_HEX.fullmatch(parent_id)

    def test_degrades_to_zero_hex_on_junk(self):
        span_id, trace_id, parent_id = extract_span_context(object())
        assert span_id == "0" * 16
        assert trace_id == "0" * 32
        assert parent_id is None

    def test_raw_trace_id_for_context_lookup(self):
        assert raw_trace_id(FakeSpan()) == TRACE_ID
        assert raw_trace_id(object()) is None
