"""Span-context extraction and hex-id formatting for wire payloads.

Two representations, never confused:
- INTERNAL: raw OTel integers (trace correlation keys — see context.py).
- WIRE: lowercase hex strings — ``span_id`` 16 chars, ``trace_id`` 32 chars,
  ``parent_span_id`` 16 chars. Raw integers must NEVER reach the wire.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "format_span_id",
    "format_trace_id",
    "extract_span_context",
    "raw_trace_id",
]


def format_span_id(span_id: int) -> str:
    """16-char lowercase hex."""
    return format(span_id, "016x")


def format_trace_id(trace_id: int) -> str:
    """32-char lowercase hex."""
    return format(trace_id, "032x")


def _span_context_of(span: Any) -> Any:
    if hasattr(span, "get_span_context"):
        try:
            return span.get_span_context()
        except Exception:
            return None
    return getattr(span, "context", None)


def extract_span_context(span: Any) -> tuple[str, str, str | None]:
    """(span_id_hex16, trace_id_hex32, parent_span_id_hex16 | None).

    Handles NonRecordingSpan, mocks, and missing attributes safely — degraded
    ids become all-zero hex, never an exception.
    """
    span_context = _span_context_of(span)
    try:
        span_id_value = getattr(span_context, "span_id", None)
        span_id = format_span_id(span_id_value) if isinstance(span_id_value, int) else "0" * 16
    except (AttributeError, TypeError):
        span_id = "0" * 16
    try:
        trace_id_value = getattr(span_context, "trace_id", None)
        trace_id = format_trace_id(trace_id_value) if isinstance(trace_id_value, int) else "0" * 32
    except (AttributeError, TypeError):
        trace_id = "0" * 32

    parent_span_id = None
    parent = getattr(span, "parent", None)
    parent_id_value = getattr(parent, "span_id", None) if parent is not None else None
    if isinstance(parent_id_value, int):
        parent_span_id = format_span_id(parent_id_value)

    return span_id, trace_id, parent_span_id


def raw_trace_id(span: Any) -> int | None:
    """The raw integer trace id for context-store lookups (or None)."""
    span_context = _span_context_of(span)
    trace_id = getattr(span_context, "trace_id", None)
    return trace_id if isinstance(trace_id, int) else None
