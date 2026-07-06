"""Non-fail span diagnostics — best-effort degradations that never reject.

Missing semantic attributes, compatibility noise, and privacy transforms are
DIAGNOSTICS, not failures. Only malformed envelopes/stages/bindings are strict
(see event_rules.py). Semantic gaps never reject or drop a span.
"""

from __future__ import annotations

from typing import Any

from .diagnostics import (
    ATTR_REDACTED,
    ATTR_TRUNCATED,
    COMPAT_NOISE_REMOVED,
    SPAN_ATTR_MISSING,
    Diagnostic,
    DiagnosticLevel,
)

__all__ = [
    "strip_compat_noise",
    "semantic_gap_diagnostics",
    "redaction_diagnostics",
    "truncation_diagnostic",
    "SEMANTIC_FIELDS_BY_HOOK_TYPE",
]

# Best-effort semantic fields per hook type — absence is an INFO diagnostic.
SEMANTIC_FIELDS_BY_HOOK_TYPE: dict[str, tuple[str, ...]] = {
    "http_request": ("http_method", "http_url"),
    "db_query": ("db_system", "db_statement"),
    "file_operation": ("file_path", "file_operation"),
    "function_call": ("function", "module"),
}


def strip_compat_noise(payload: dict[str, Any]) -> tuple[dict[str, Any], list[Diagnostic]]:
    """Remove ``spans=[]``/``span_count=0`` from a lifecycle wire payload.

    Core ignores these empty fields, but they are contract noise. Removal is
    recorded as a diagnostic — it is NOT a configurable mode. Non-empty spans
    are not touched here (they are a strict failure upstream).
    """
    diagnostics: list[Diagnostic] = []
    removed: list[str] = []
    cleaned = dict(payload)
    if "spans" in cleaned and cleaned["spans"] == []:
        del cleaned["spans"]
        removed.append("spans")
    if "span_count" in cleaned and cleaned["span_count"] == 0:
        del cleaned["span_count"]
        removed.append("span_count")
    if removed:
        diagnostics.append(
            Diagnostic(
                level=DiagnosticLevel.INFO,
                code=COMPAT_NOISE_REMOVED,
                message=f"Removed compatibility noise before send: {removed}",
                detail={"removed": removed},
            )
        )
    return cleaned, diagnostics


def semantic_gap_diagnostics(
    span_wire: dict[str, Any], hook_type: str | None
) -> list[Diagnostic]:
    """INFO diagnostics for missing best-effort semantic fields.

    The span is still sent — semantic gaps NEVER reject a span.
    """
    fields = SEMANTIC_FIELDS_BY_HOOK_TYPE.get(hook_type or "", ())
    return [
        Diagnostic(
            level=DiagnosticLevel.INFO,
            code=SPAN_ATTR_MISSING,
            message=f"Best-effort semantic attribute missing: {field_name}",
            detail={"hook_type": hook_type, "field": field_name},
        )
        for field_name in fields
        if span_wire.get(field_name) is None
    ]


def redaction_diagnostics(changed_paths: list[str]) -> list[Diagnostic]:
    """Diagnostics identifying exactly what redaction changed."""
    if not changed_paths:
        return []
    return [
        Diagnostic(
            level=DiagnosticLevel.INFO,
            code=ATTR_REDACTED,
            message=f"Redacted {len(changed_paths)} value(s) before send",
            detail={"paths": list(changed_paths)},
        )
    ]


def truncation_diagnostic(field_name: str, original_size: int, max_size: int) -> Diagnostic:
    """Diagnostic identifying a truncated value."""
    return Diagnostic(
        level=DiagnosticLevel.INFO,
        code=ATTR_TRUNCATED,
        message=f"Truncated {field_name} from {original_size} to {max_size} chars",
        detail={"field": field_name, "original_size": original_size, "max_size": max_size},
    )
