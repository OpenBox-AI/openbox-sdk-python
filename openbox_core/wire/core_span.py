"""to_core_span_data — project the internal span envelope to Core's flat
``SpanData`` wire shape (openbox-core ``internal/content/governance.go``).

Wire rules (verified against the Go struct + the payloads the Temporal SDK's
legacy flat hooks emit — this projection is the shared source of truth every
framework SDK relies on):

- Ids are HEX STRINGS: span_id 16, trace_id 32, parent_span_id 16 chars.
  Raw integer OTel ids must never be sent.
- Timestamps are epoch NANOSECONDS.
- started-stage spans emit EXPLICIT ``end_time: null`` and
  ``duration_ns: null`` (never omitted, never ``end_time == start_time``);
  Core's non-pointer ``EndTime int64`` unmarshals null -> 0.
- The COMMON root fields (span_id, trace_id, parent_span_id, name, kind,
  stage, start_time, end_time, duration_ns, attributes, status, events,
  hook_type, error) are ALWAYS present — null-valued when absent, never
  omitted — matching the legacy flat contract.
- Each hook family's own root fields (http_*/db_*/file_*/function) are ALSO
  always present for that family (null when the wrapper/attributes did not
  supply them). ``attributes`` carries OTel-native attributes ONLY.
- Semantic HTTP/DB/file/function fields are best-effort from OTel attributes
  (new-convention key first, legacy fallback); absence is a diagnostic,
  NEVER a rejection.
- ``semantic_type`` is NEVER set here — Core computes it.
- Hook spans are FLAT: no ``data`` blob, no nested ``{"otel", "openbox"}``
  envelope. Full OTel preservation under ``data`` is an OPT-IN debug facility
  (``include_otel_data=True``), OFF by default so the emitted hook wire matches
  Temporal exactly; ids inside ``data`` are hex-ified when it is requested.
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

# Kind fallback per hook type. The Temporal legacy hooks hardcode a kind; the
# base derives it from the OTel span but must still guarantee a non-null value.
_DEFAULT_KIND_BY_HOOK: dict[str, str] = {
    "http_request": "CLIENT",
    "db_query": "CLIENT",
    "file_operation": "INTERNAL",
    "function_call": "INTERNAL",
    "llm_call": "CLIENT",
}

# Family-specific root fields that MUST exist (explicit null if unsupplied) so
# the flat SpanData carries the exact key set the Temporal legacy hooks emit.
# Common fields (parent_span_id/kind/attributes/status/events/error/…) are
# guaranteed separately in the wire dict below.
_ROOT_FIELDS_BY_HOOK_TYPE: dict[str, tuple[str, ...]] = {
    "http_request": (
        "http_method",
        "http_url",
        "http_status_code",
        "request_headers",
        "response_headers",
        "request_body",
        "response_body",
    ),
    "db_query": (
        "db_system",
        "db_name",
        "db_operation",
        "db_statement",
        "server_address",
        "server_port",
        "rowcount",
    ),
    "file_operation": (
        "file_path",
        "file_mode",
        "file_operation",
        "bytes_read",
        "bytes_written",
    ),
    "function_call": ("function", "module", "args", "result"),
}


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
    include_otel_data: bool = False,
) -> tuple[dict[str, Any], list[Diagnostic]]:
    """Project one internal span envelope to a flat Core ``SpanData`` dict.

    Returns ``(wire_span, diagnostics)``. Missing semantic attributes are
    diagnostics, never failures; redaction/truncation is recorded.

    ``include_otel_data`` defaults to ``False``: the hook wire contract is flat
    (Temporal parity). Pass ``True`` only for debug/diagnostic captures that
    want the preserved OTel surface under ``data`` — never on the send path.
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

    # Common root fields — ALWAYS present (null when absent), matching the
    # Temporal legacy flat contract. parent_span_id/kind/attributes/error are
    # never omitted; kind falls back to a per-family default when the OTel span
    # carries none so the wire always has a concrete SpanKind.
    wire: dict[str, Any] = {
        "span_id": format_span_id(span_id_int) if isinstance(span_id_int, int) else "0" * 16,
        "trace_id": format_trace_id(trace_id_int) if isinstance(trace_id_int, int) else "0" * 32,
        "parent_span_id": format_span_id(parent_id_int) if isinstance(parent_id_int, int) else None,
        "name": otel.get("name") or (hook_type or "span"),
        "kind": otel.get("kind") or _DEFAULT_KIND_BY_HOOK.get(hook_type or "", "INTERNAL"),
        "stage": stage,
        "start_time": start_time,
        "end_time": end_time,
        "duration_ns": duration_ns,
        "attributes": attributes,
        "status": status,
        "events": otel.get("events") or [],
        "error": None,
    }
    if hook_type:
        wire["hook_type"] = hook_type

    # Best-effort semantic enrichment from OTel attributes.
    for wire_field, attr_keys in _SEMANTIC_ATTR_MAP.items():
        value = _attr(attributes, attr_keys)
        if value is not None:
            wire[wire_field] = value

    # Wrapper-supplied root fields override attribute-derived values (they
    # carry data OTel attributes don't: bodies, results, rowcounts, error).
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

    # Guarantee every family-specific root key exists (explicit null if neither
    # attributes nor the wrapper supplied it) — the legacy flat hooks always
    # emit the full family key set; Core's ``omitempty`` tolerates the nulls.
    for field_name in _ROOT_FIELDS_BY_HOOK_TYPE.get(hook_type or "", ()):
        wire.setdefault(field_name, None)

    # Completed-stage timing parity: OTel-owned spans (httpx/requests) are not
    # ended when the response hook fires, so ``end_time`` is null even though a
    # duration was measured. Reconstruct it from start_time + duration so a
    # completed span always carries a real end_time (Temporal sets now_ns).
    if stage != "started" and wire.get("end_time") is None:
        measured = wire.get("duration_ns")
        if isinstance(start_time, int) and isinstance(measured, int):
            wire["end_time"] = start_time + measured

    # Hook spans are flat: the OTel ``data`` blob is opt-in debug only and must
    # never appear on the send path (Temporal's legacy hooks emit no data).
    if include_otel_data:
        wire["data"] = {"otel": _hexify_data_blob(otel)}

    diagnostics.extend(semantic_gap_diagnostics(wire, hook_type))
    return wire, diagnostics
