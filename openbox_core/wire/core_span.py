"""to_core_span_data — project the internal span envelope to Core's flat
``SpanData`` wire shape (openbox-core ``internal/content/governance.go``).

Wire rules (verified against the Go struct + the payloads Temporal emits):

- Ids are HEX STRINGS: span_id 16, trace_id 32, parent_span_id 16 chars.
  Raw integer OTel ids must never be sent.
- Timestamps are epoch NANOSECONDS.
- started-stage spans emit EXPLICIT ``end_time: null`` and
  ``duration_ns: null`` (never omitted, never ``end_time == start_time``);
  Core's non-pointer ``EndTime int64`` unmarshals null -> 0.
- Semantic HTTP/DB/file/function fields are best-effort from OTel attributes
  (new-convention key first, legacy fallback); absence is a diagnostic,
  NEVER a rejection.
- Full OTel preservation goes under ``data`` ONLY (no span-level ``metadata``
  field exists on the backend); ids inside ``data`` are hex-ified too.
- The nested ``{"otel", "openbox"}`` envelope itself must never appear in
  the output.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..config import PrivacyConfig
from ..contracts.otel_spans import serialize_readable_span
from ..otel.trace_context import format_span_id, format_trace_id
from ..serialization import apply_redaction, truncate_string
from ..validation.diagnostics import Diagnostic
from ..validation.span_normalization import (
    redaction_diagnostics,
    semantic_gap_diagnostics,
    truncation_diagnostic,
)

__all__ = ["to_core_span_data"]

# Structural fields present on EVERY wire span even when null (exclude_none
# must not drop them — Core relies on explicit started-stage nulls).
_ALWAYS_PRESENT = ("span_id", "trace_id", "name", "stage", "start_time", "end_time", "duration_ns")

# Best-effort semantic attribute mapping: wire field -> OTel keys (new, legacy).
_SEMANTIC_ATTR_MAP: dict[str, tuple[str, ...]] = {
    "http_url": ("url.full", "http.url"),
    "http_method": ("http.request.method", "http.method"),
    "http_status_code": ("http.response.status_code", "http.status_code"),
    "db_system": ("db.system.name", "db.system"),
    "db_name": ("db.namespace", "db.name"),
    "db_operation": ("db.operation.name", "db.operation"),
    "db_statement": ("db.query.text", "db.statement"),
    "server_address": ("server.address", "net.peer.name"),
    "server_port": ("server.port", "net.peer.port"),
    "file_path": ("file.path",),
    "file_mode": ("file.mode",),
    "file_operation": ("file.operation",),
    "function": ("code.function.name", "code.function"),
    "module": ("code.namespace", "code.module"),
}

# Wrapper-supplied fields eligible for body truncation.
_TRUNCATABLE_FIELDS = ("request_body", "response_body")


def _attr(attributes: Mapping[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        value = attributes.get(key)
        if value is not None:
            return value
    return None


def _hexify_data_blob(otel: dict[str, Any]) -> dict[str, Any]:
    """Copy of the preserved OTel payload with ids as hex strings (raw ints
    must not reach the wire, even inside ``data``)."""
    blob = dict(otel)
    context = blob.get("context")
    if isinstance(context, dict):
        blob["context"] = {
            "span_id": format_span_id(context["span_id"]) if isinstance(context.get("span_id"), int) else None,
            "trace_id": format_trace_id(context["trace_id"]) if isinstance(context.get("trace_id"), int) else None,
        }
    parent = blob.get("parent")
    if isinstance(parent, dict) and isinstance(parent.get("span_id"), int):
        blob["parent"] = {"span_id": format_span_id(parent["span_id"])}
    links = blob.get("links")
    if isinstance(links, list):
        hexed_links = []
        for link in links:
            link_context = link.get("context", {}) if isinstance(link, dict) else {}
            hexed_links.append(
                {
                    **link,
                    "context": {
                        "span_id": format_span_id(link_context["span_id"])
                        if isinstance(link_context.get("span_id"), int)
                        else None,
                        "trace_id": format_trace_id(link_context["trace_id"])
                        if isinstance(link_context.get("trace_id"), int)
                        else None,
                    },
                }
            )
        blob["links"] = hexed_links
    return blob


def to_core_span_data(
    envelope: dict[str, Any],
    *,
    privacy: PrivacyConfig | None = None,
    include_otel_data: bool = True,
) -> tuple[dict[str, Any], list[Diagnostic]]:
    """Project one internal span envelope to a flat Core ``SpanData`` dict.

    Returns ``(wire_span, diagnostics)``. Missing semantic attributes are
    diagnostics, never failures; redaction/truncation is recorded.
    """
    otel = envelope.get("otel") or serialize_readable_span(None)
    openbox = envelope.get("openbox") or {}
    stage: str = openbox.get("stage") or "completed"
    hook_type: str | None = openbox.get("hook_type")
    fields: dict[str, Any] = dict(openbox.get("fields") or {})
    diagnostics: list[Diagnostic] = []

    context = otel.get("context") or {}
    span_id_int = context.get("span_id")
    trace_id_int = context.get("trace_id")
    parent = otel.get("parent") or {}
    parent_id_int = parent.get("span_id")

    attributes = dict(otel.get("attributes") or {})
    if privacy and privacy.redact_keys:
        attributes, changed = apply_redaction(attributes, privacy.redact_keys)
        diagnostics.extend(redaction_diagnostics([f"attributes.{p}" for p in changed]))

    start_time = otel.get("start_time")
    end_time = otel.get("end_time")
    if stage == "started":
        # Explicit structural nulls — Core unmarshals EndTime=0 (non-pointer).
        end_time = None
        duration_ns = None
    else:
        duration_ns = (
            end_time - start_time
            if isinstance(end_time, int) and isinstance(start_time, int)
            else None
        )

    status = otel.get("status") or {"code": "UNSET", "description": None}

    wire: dict[str, Any] = {
        "span_id": format_span_id(span_id_int) if isinstance(span_id_int, int) else "0" * 16,
        "trace_id": format_trace_id(trace_id_int) if isinstance(trace_id_int, int) else "0" * 32,
        "name": otel.get("name") or (hook_type or "span"),
        "stage": stage,
        "start_time": start_time,
        "end_time": end_time,
        "duration_ns": duration_ns,
    }
    if isinstance(parent_id_int, int):
        wire["parent_span_id"] = format_span_id(parent_id_int)
    if otel.get("kind"):
        wire["kind"] = otel["kind"]
    if attributes:
        wire["attributes"] = attributes
    wire["status"] = status
    wire["events"] = otel.get("events") or []
    if hook_type:
        wire["hook_type"] = hook_type

    # Best-effort semantic enrichment from OTel attributes.
    for wire_field, attr_keys in _SEMANTIC_ATTR_MAP.items():
        value = _attr(attributes, attr_keys)
        if value is not None:
            wire[wire_field] = value

    # Wrapper-supplied root fields override attribute-derived values (they
    # carry data OTel attributes don't: bodies, results, rowcounts).
    for field_name, value in fields.items():
        if value is None:
            continue
        if privacy and field_name in _TRUNCATABLE_FIELDS and isinstance(value, str):
            truncated, was_truncated = truncate_string(value, privacy.max_body_size)
            if was_truncated:
                diagnostics.append(
                    truncation_diagnostic(field_name, len(value), privacy.max_body_size)
                )
            value = truncated
        wire[field_name] = value

    # Full OTel preservation — ONLY under data (no span-level metadata field).
    if include_otel_data:
        wire["data"] = {"otel": _hexify_data_blob(otel)}

    diagnostics.extend(semantic_gap_diagnostics(wire, hook_type))
    return wire, diagnostics
