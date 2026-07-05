"""Strict contract failures — raise ContractError BEFORE any network send.

The gate is ALWAYS strict for OpenBox event contracts and runtime invariants;
there is no OBSERVE/SANITIZE/STRICT mode and no way to downgrade these to
diagnostics. Fail-open applies only to network errors, never here.

Strict failure list (proposal §Phase 2):
- malformed lifecycle event envelope
- hook event has ``hook_trigger=false`` (span-bearing but not marked hook)
- hook event uses the wrong wire event type
- ``preflight()`` receives completed-stage spans
- ``completed()`` receives started-stage spans
- ``ActivityCompleted`` contains non-empty hook span payloads
- instrumentation produced an impossible/malformed hook event
"""

from __future__ import annotations

from typing import Any

from ..contracts.events import EventEnvelope, EventKind, EventType, classify_event
from ..errors import ContractError

__all__ = [
    "span_stage",
    "check_lifecycle_envelope",
    "check_hook_envelope",
    "check_stage",
]

# Payload fields every workflow-scoped lifecycle event must carry.
_REQUIRED_WORKFLOW_FIELDS = ("workflow_id", "run_id", "workflow_type")
_REQUIRED_HANDOFF_FIELDS = ("from_agent_did", "multi_agent_session_id")


def span_stage(span: Any) -> str | None:
    """Extract the stage from a span payload.

    Spans are flat-only: the stage lives at the top level. Enum values normalize
    via ``.value``.
    """
    if isinstance(span, dict):
        stage: Any = span.get("stage")
    else:
        stage = getattr(span, "stage", None)
    value = getattr(stage, "value", stage)
    return value if isinstance(value, str) else None


def _require_fields(event: EventEnvelope, fields: tuple[str, ...], what: str) -> None:
    missing = [f for f in fields if not event.payload.get(f)]
    if missing:
        raise ContractError(
            f"Malformed {what} envelope: missing required fields {missing}",
            code="ENVELOPE_MISSING_FIELDS",
            detail={"missing": missing, "event_type": event.event_type.value},
        )


def check_lifecycle_envelope(event: EventEnvelope) -> None:
    """Strict checks for non-hook envelopes (lifecycle/signal/handoff)."""
    if not isinstance(event.event_type, EventType):
        raise ContractError(
            f"Malformed envelope: event_type must be an EventType, got {type(event.event_type).__name__}",
            code="ENVELOPE_BAD_EVENT_TYPE",
        )

    kind = classify_event(event)
    if kind is EventKind.HOOK:
        raise ContractError(
            "check_lifecycle_envelope received a hook event — route hook events "
            "through preflight()/completed()",
            code="HOOK_ON_LIFECYCLE_PATH",
        )

    # A span-bearing envelope that is not marked as a hook is malformed:
    # either it IS a hook (then hook_trigger must be true) or spans are noise.
    if event.spans:
        if event.event_type is EventType.ACTIVITY_COMPLETED:
            raise ContractError(
                "ActivityCompleted must not carry non-empty hook spans — completed "
                "telemetry routes through completed() with completed-stage spans",
                code="ACTIVITY_COMPLETED_WITH_SPANS",
                detail={"span_count": len(event.spans)},
            )
        raise ContractError(
            f"{event.event_type.value} carries spans but hook_trigger=false — "
            "span-bearing evaluations must be hook events",
            code="HOOK_TRIGGER_FALSE",
            detail={"span_count": len(event.spans)},
        )

    if kind is EventKind.HANDOFF:
        _require_fields(event, _REQUIRED_HANDOFF_FIELDS, "handoff")
        return
    _require_fields(event, _REQUIRED_WORKFLOW_FIELDS, "lifecycle")
    if kind is EventKind.SIGNAL and not event.payload.get("signal_name"):
        raise ContractError(
            "Malformed signal envelope: missing signal_name",
            code="ENVELOPE_MISSING_FIELDS",
            detail={"missing": ["signal_name"]},
        )


def check_hook_envelope(event: EventEnvelope) -> None:
    """Strict checks for hook (span-bearing) envelopes."""
    if not event.hook_trigger:
        raise ContractError(
            "Hook evaluation requires hook_trigger=true",
            code="HOOK_TRIGGER_FALSE",
        )
    if event.event_type is not EventType.ACTIVITY_STARTED:
        raise ContractError(
            f"Hook events must use wire event type ActivityStarted, got "
            f"{event.event_type.value}",
            code="HOOK_WRONG_WIRE_TYPE",
            detail={"event_type": event.event_type.value},
        )
    if not event.spans:
        raise ContractError(
            "Hook event carries no spans — instrumentation produced an impossible "
            "hook event",
            code="HOOK_EMPTY_SPANS",
        )
    if not event.activity_id or not event.activity_type:
        raise ContractError(
            "Hook event is not attached to a bound activity (activity_id and "
            "activity_type are required)",
            code="HOOK_UNBOUND_ACTIVITY",
            detail={
                "activity_id": event.activity_id,
                "activity_type": event.activity_type,
            },
        )
    for index, span in enumerate(event.spans):
        if isinstance(span, dict):
            forbidden = sorted({"otel", "openbox", "data"} & set(span))
            if forbidden:
                raise ContractError(
                    "Hook spans must be flat Core SpanData dicts — nested/debug "
                    f"keys are not allowed at spans[{index}]: {forbidden}",
                    code="HOOK_SPAN_NOT_FLAT",
                    detail={"index": index, "forbidden": forbidden},
                )


def check_stage(event: EventEnvelope, expected_stage: str) -> None:
    """Reject stage-mismatched spans (preflight=started, completed=completed)."""
    for index, span in enumerate(event.spans):
        stage = span_stage(span)
        if stage is None:
            raise ContractError(
                f"Hook span[{index}] has no stage — instrumentation produced a "
                "malformed hook span",
                code="HOOK_SPAN_NO_STAGE",
                detail={"index": index},
            )
        if stage != expected_stage:
            raise ContractError(
                f"{expected_stage}-stage evaluation received a {stage}-stage span "
                f"at spans[{index}]",
                code="HOOK_STAGE_MISMATCH",
                detail={"index": index, "expected": expected_stage, "actual": stage},
            )
