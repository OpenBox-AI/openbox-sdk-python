"""Span contracts — Stage, HookType, and the internal OpenBox span envelope.

OTel spans are the INTERNAL source of truth (there are no fixed
HttpSpan/DbSpan/... dataclasses). The internal envelope is::

    {
        "otel": serialize_readable_span(span),   # preserved OTel surface
        "openbox": {
            "hook_type": ..., "stage": ..., "activity_context": ...,
            "fields": {...},        # wrapper-supplied wire root fields
            "diagnostics": [...],
        },
    }

This nested shape is INTERNAL ONLY — it must never be sent as ``spans[]``
(Core would ignore the unknown keys and deserialize an empty SpanData,
breaking OPA input, dedup, storage, and approval fingerprints). The wire
projection lives in ``wire/core_span.py``.

Pure module: span access is DUCK-TYPED (plain getattr) so importing this never
pulls in opentelemetry — the import-safety harness holds.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import Enum
from typing import Any

__all__ = [
    "Stage",
    "HookType",
    "serialize_readable_span",
    "from_otel_span",
    "OpenBoxSpanAdapter",
]


class Stage(str, Enum):
    """Hook evaluation stage."""

    STARTED = "started"
    COMPLETED = "completed"


class HookType(str, Enum):
    """Operation category of a hook span (Core root field ``hook_type``)."""

    HTTP_REQUEST = "http_request"
    DB_QUERY = "db_query"
    FILE_OPERATION = "file_operation"
    FUNCTION_CALL = "function_call"
    LLM_CALL = "llm_call"  # reserved; LLM instrumentation lands when scoped


def _span_context_of(span: Any) -> Any:
    if hasattr(span, "get_span_context"):
        try:
            return span.get_span_context()
        except Exception:
            return None
    return getattr(span, "context", None)


def _enum_name(value: Any) -> str | None:
    """'SpanKind.CLIENT' -> 'CLIENT'; plain strings pass through."""
    if value is None:
        return None
    name = getattr(value, "name", None)
    if isinstance(name, str):
        return name
    text = str(value)
    return text.split(".")[-1] if text else None


def _attributes_of(obj: Any) -> dict[str, Any]:
    attributes = getattr(obj, "attributes", None)
    if attributes is None:
        return {}
    try:
        return dict(attributes)
    except Exception:
        return {}


def serialize_readable_span(span: Any) -> dict[str, Any]:
    """Preserve the OTel surface the SDK exposes, via duck-typed access.

    Ids stay RAW INTEGERS here (internal representation; the wire projection
    formats hex strings). Missing pieces degrade to None/empty — a span is
    never rejected during serialization.
    """
    span_context = _span_context_of(span)
    context_part = None
    if span_context is not None:
        span_id = getattr(span_context, "span_id", None)
        trace_id = getattr(span_context, "trace_id", None)
        context_part = {
            "span_id": span_id if isinstance(span_id, int) else None,
            "trace_id": trace_id if isinstance(trace_id, int) else None,
        }

    parent = getattr(span, "parent", None)
    parent_part = None
    if parent is not None:
        parent_span_id = getattr(parent, "span_id", None)
        if isinstance(parent_span_id, int):
            parent_part = {"span_id": parent_span_id}

    status = getattr(span, "status", None)
    status_part = None
    if status is not None:
        status_part = {
            "code": _enum_name(getattr(status, "status_code", None)) or "UNSET",
            "description": getattr(status, "description", None),
        }

    events = []
    for event in getattr(span, "events", None) or ():
        events.append(
            {
                "name": getattr(event, "name", None),
                "timestamp": getattr(event, "timestamp", None),
                "attributes": _attributes_of(event),
            }
        )

    links = []
    for link in getattr(span, "links", None) or ():
        link_context = getattr(link, "context", None)
        links.append(
            {
                "context": {
                    "span_id": getattr(link_context, "span_id", None),
                    "trace_id": getattr(link_context, "trace_id", None),
                },
                "attributes": _attributes_of(link),
            }
        )

    resource = getattr(span, "resource", None)
    resource_part = _attributes_of(resource) if resource is not None else None

    scope = getattr(span, "instrumentation_scope", None)
    scope_part = None
    if scope is not None:
        scope_part = {
            "name": getattr(scope, "name", None),
            "version": getattr(scope, "version", None),
        }

    start_time = getattr(span, "start_time", None)
    end_time = getattr(span, "end_time", None)
    return {
        "context": context_part,
        "parent": parent_part,
        "name": getattr(span, "name", None),
        "kind": _enum_name(getattr(span, "kind", None)),
        "start_time": start_time if isinstance(start_time, int) else None,
        "end_time": end_time if isinstance(end_time, int) else None,
        "attributes": _attributes_of(span),
        "events": events,
        "links": links,
        "status": status_part,
        "resource": resource_part,
        "instrumentation_scope": scope_part,
    }


def from_otel_span(
    span: Any,
    *,
    stage: Stage | str,
    hook_type: HookType | str | None = None,
    activity_context: Any = None,
    fields: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the internal ``{"otel": ..., "openbox": ...}`` span envelope.

    Args:
        span: OTel span (Span/ReadableSpan/NonRecordingSpan — duck-typed).
        stage: started/completed.
        hook_type: Operation category (None for non-hook telemetry spans).
        activity_context: The bound ActivityContext (or None).
        fields: Wrapper-supplied Core root fields (request_body, rowcount,
            args, ...) that the wire projection merges at the span root —
            these carry data OTel attributes don't (bodies, results).
    """
    stage_value = stage.value if isinstance(stage, Stage) else str(stage)
    hook_value = hook_type.value if isinstance(hook_type, HookType) else hook_type
    return {
        "otel": serialize_readable_span(span),
        "openbox": {
            "hook_type": hook_value,
            "stage": stage_value,
            "activity_context": activity_context,
            "fields": dict(fields) if fields else {},
            "diagnostics": [],
        },
    }


class OpenBoxSpanAdapter:
    """Adapter object form of :func:`from_otel_span` (protocol-compatible)."""

    @staticmethod
    def from_otel_span(
        span: Any,
        *,
        stage: Stage | str,
        hook_type: HookType | str | None = None,
        activity_context: Any = None,
        fields: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        return from_otel_span(
            span,
            stage=stage,
            hook_type=hook_type,
            activity_context=activity_context,
            fields=fields,
        )
