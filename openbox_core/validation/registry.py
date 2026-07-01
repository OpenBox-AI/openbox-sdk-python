"""Validation dispatch — route an envelope to its rule set, aggregate diagnostics.

Strict failures raise ContractError (before any send); the return value is the
list of non-fail diagnostics collected along the way.
"""

from __future__ import annotations

from ..contracts.events import EventEnvelope
from .diagnostics import Diagnostic
from .event_rules import check_hook_envelope, check_lifecycle_envelope, check_stage

__all__ = ["validate_lifecycle", "validate_hook"]


def validate_lifecycle(event: EventEnvelope) -> list[Diagnostic]:
    """Validate a lifecycle/signal/handoff envelope. Raises ContractError on
    violation; returns diagnostics (none today — reserved for future rules)."""
    check_lifecycle_envelope(event)
    return []


def validate_hook(event: EventEnvelope, expected_stage: str) -> list[Diagnostic]:
    """Validate a hook envelope for the given stage ("started"/"completed").

    ``check_hook_envelope``'s first rule rejects ``hook_trigger=false``, which
    also covers non-HOOK envelopes routed here by mistake.
    """
    check_hook_envelope(event)
    check_stage(event, expected_stage)
    return []
