"""build_evaluate_payload — the SINGLE owner of the evaluate request body.

Assembles the exact ``/api/v1/governance/evaluate`` body for hook events:
the ``EventEnvelope`` fields at the top level (``event_type=ActivityStarted``,
``hook_trigger=true``, ``activity_id``/``activity_type``, ``timestamp``),
``spans`` as a list of flat Core ``SpanData`` dicts, and ``span_count``.

The strict gate injects this as its ``payload_builder`` — the gate never
reimplements body assembly, and ``serialization.serialize_body`` (byte-only)
then produces the signed bytes.
"""

from __future__ import annotations

from typing import Any

from ..config import PrivacyConfig
from ..contracts.events import EventEnvelope
from ..validation.diagnostics import Diagnostic
from ..validation.span_normalization import semantic_gap_diagnostics
from .core_span import to_core_span_data

__all__ = ["build_evaluate_payload", "make_payload_builder"]


def build_evaluate_payload(
    event: EventEnvelope,
    *,
    privacy: PrivacyConfig | None = None,
) -> tuple[dict[str, Any], list[Diagnostic]]:
    """Assemble the hook evaluate body from a validated hook envelope.

    Spans may be internal ``{"otel", "openbox"}`` envelopes (projected here)
    or already-flat wire dicts (passed through with gap diagnostics only —
    supports migration call sites that pre-build flat spans).
    """
    diagnostics: list[Diagnostic] = []
    wire_spans: list[dict[str, Any]] = []
    for span in event.spans:
        if isinstance(span, dict) and "otel" in span:
            wire_span, span_diagnostics = to_core_span_data(span, privacy=privacy)
            diagnostics.extend(span_diagnostics)
        else:
            wire_span = dict(span)
            diagnostics.extend(
                semantic_gap_diagnostics(wire_span, wire_span.get("hook_type"))
            )
        wire_spans.append(wire_span)

    payload = event.to_payload_dict()
    payload["spans"] = wire_spans
    payload["span_count"] = len(wire_spans)
    return payload, diagnostics


def make_payload_builder(privacy: PrivacyConfig | None = None):
    """Bind a privacy config into the gate's single-argument builder seam."""

    def _builder(event: EventEnvelope) -> tuple[dict[str, Any], list[Diagnostic]]:
        return build_evaluate_payload(event, privacy=privacy)

    return _builder
