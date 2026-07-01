"""Structured diagnostic records attached to evaluation results.

Diagnostics are the NON-FAIL half of validation: they record best-effort
degradations (missing semantic attributes, compat-noise removal, redaction)
without rejecting anything. Strict failures raise ContractError instead —
there is no diagnostic for a contract violation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

__all__ = [
    "DiagnosticLevel",
    "Diagnostic",
    "SPAN_ATTR_MISSING",
    "COMPAT_NOISE_REMOVED",
    "ATTR_REDACTED",
    "ATTR_TRUNCATED",
    "HOOK_SKIPPED_NO_CONTEXT",
]

# Diagnostic codes (stable machine identifiers)
SPAN_ATTR_MISSING = "SPAN_ATTR_MISSING"
COMPAT_NOISE_REMOVED = "COMPAT_NOISE_REMOVED"
ATTR_REDACTED = "ATTR_REDACTED"
ATTR_TRUNCATED = "ATTR_TRUNCATED"
HOOK_SKIPPED_NO_CONTEXT = "HOOK_SKIPPED_NO_CONTEXT"


class DiagnosticLevel(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"


@dataclass(frozen=True)
class Diagnostic:
    """One structured diagnostic record.

    Attributes:
        level: Severity (INFO/WARNING) — never an error (errors raise).
        code: Stable machine code (e.g. ``SPAN_ATTR_MISSING``).
        message: Human-readable summary.
        detail: Structured context (what changed, which key, which span).
    """

    level: DiagnosticLevel
    code: str
    message: str
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level.value,
            "code": self.code,
            "message": self.message,
            "detail": dict(self.detail),
        }
