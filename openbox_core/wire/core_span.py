"""to_core_span_data — normalize flat Core ``SpanData`` wire spans.

Wire rules (verified against the Go struct + the payloads the Temporal SDK's
legacy flat hooks emit):

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
  during ``contracts.otel_spans.from_otel_span``; absence is a diagnostic,
  NEVER a rejection.
- ``semantic_type`` is NEVER set here — Core computes it.
- Hook spans are FLAT in memory and on the wire: no ``data`` blob and no nested
  ``{"otel", "openbox"}`` envelope.
"""

from __future__ import annotations

from typing import Any

from ..config import PrivacyConfig
from ..contracts.otel_spans import _ROOT_FIELDS_BY_HOOK_TYPE
from ..serialization import apply_redaction, truncate_string
from ..validation.diagnostics import Diagnostic
from ..validation.span_normalization import (
    redaction_diagnostics,
    semantic_gap_diagnostics,
    truncation_diagnostic,
)

__all__ = ["to_core_span_data"]

# Wrapper-supplied fields eligible for body truncation.
_TRUNCATABLE_FIELDS = ("request_body", "response_body")

_COMMON_DEFAULTS: dict[str, Any] = {
    "span_id": "0" * 16,
    "trace_id": "0" * 32,
    "parent_span_id": None,
    "name": "span",
    "kind": "INTERNAL",
    "start_time": None,
    "end_time": None,
    "duration_ns": None,
    "attributes": {},
    "status": {"code": "UNSET", "description": None},
    "events": [],
    "error": None,
}


def to_core_span_data(
    span: dict[str, Any],
    *,
    privacy: PrivacyConfig | None = None,
    include_otel_data: bool = False,
) -> tuple[dict[str, Any], list[Diagnostic]]:
    """Normalize one flat Core ``SpanData`` dict.

    Returns ``(wire_span, diagnostics)``. Missing semantic attributes are
    diagnostics, never failures; redaction/truncation is recorded.

    ``include_otel_data`` is retained as a compatibility parameter but is now a
    no-op: spans stay flat everywhere.
    """
    _ = include_otel_data
    diagnostics: list[Diagnostic] = []
    wire = dict(span)
    # Never let old nested/debug shapes leak forward, even if a migration caller
    # hands them to this normalizer.
    wire.pop("otel", None)
    wire.pop("openbox", None)
    wire.pop("data", None)
    wire.pop("metadata", None)

    hook_type = wire.get("hook_type")
    attributes = dict(wire.get("attributes") or {})
    if privacy and privacy.redact_keys:
        attributes, changed = apply_redaction(attributes, privacy.redact_keys)
        diagnostics.extend(redaction_diagnostics([f"attributes.{p}" for p in changed]))
    wire["attributes"] = attributes

    for field_name in _TRUNCATABLE_FIELDS:
        if field_name not in wire:
            continue
        value = wire.get(field_name)
        if privacy and field_name in _TRUNCATABLE_FIELDS and isinstance(value, str):
            truncated, was_truncated = truncate_string(value, privacy.max_body_size)
            if was_truncated:
                diagnostics.append(
                    truncation_diagnostic(field_name, len(value), privacy.max_body_size)
                )
            value = truncated
        wire[field_name] = value

    for field_name, value in _COMMON_DEFAULTS.items():
        if field_name in wire:
            continue
        if isinstance(value, dict):
            wire[field_name] = dict(value)
        elif isinstance(value, list):
            wire[field_name] = list(value)
        else:
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
    if wire.get("stage") != "started" and wire.get("end_time") is None:
        start_time = wire.get("start_time")
        measured = wire.get("duration_ns")
        if isinstance(start_time, int) and isinstance(measured, int):
            wire["end_time"] = start_time + measured

    diagnostics.extend(semantic_gap_diagnostics(wire, hook_type))
    return wire, diagnostics
