"""Event contracts — EventType, EventKind, EventEnvelope, classification, factories.

Pure, import-safe module: no network, crypto, OTel, logging, wall-clock, or
random. Timestamps are RFC3339 strings *passed in* by callers — never generated
here (``datetime.now`` is forbidden in contracts; the sending layer stamps
missing timestamps).

Wire rules (mirror the Temporal SDK payloads Core receives today):

- ``EventEnvelope.event_type`` stores the **backend wire type**.
- Hook evaluations are internally ``EventKind.HOOK`` but serialize as
  ``ActivityStarted`` + ``hook_trigger=true`` + non-empty ``spans``.
- ``ActivityCompleted`` must not carry non-empty hook spans (validated by the
  strict gate; factories make invalid states hard to build).
- Handoff payloads require ``from_agent_did`` + ``multi_agent_session_id``
  (both non-empty); ``to_agent_did`` is deliberately omitted — the receiver is
  derived server-side from the authenticated signed identity.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

__all__ = [
    "SOURCE_WORKFLOW_TELEMETRY",
    "EventType",
    "EventKind",
    "EventEnvelope",
    "classify_event",
    "wire_event_type",
    "rfc3339_from_datetime",
    "workflow_started",
    "workflow_completed",
    "workflow_failed",
    "activity_started",
    "activity_completed",
    "signal_received",
    "handoff",
    "hook",
]

# ``source`` field Core receives on every governance event.
SOURCE_WORKFLOW_TELEMETRY = "workflow-telemetry"


class EventType(str, Enum):
    """Backend wire event types (Core's accepted ``event_type`` values)."""

    WORKFLOW_STARTED = "WorkflowStarted"
    WORKFLOW_COMPLETED = "WorkflowCompleted"
    WORKFLOW_FAILED = "WorkflowFailed"
    SIGNAL_RECEIVED = "SignalReceived"
    ACTIVITY_STARTED = "ActivityStarted"
    ACTIVITY_COMPLETED = "ActivityCompleted"
    HANDOFF = "Handoff"


class EventKind(Enum):
    """Internal event classification. Not a wire concept."""

    LIFECYCLE = "lifecycle"
    HOOK = "hook"
    SIGNAL = "signal"
    HANDOFF = "handoff"


def rfc3339_from_datetime(ts: datetime) -> str:
    """Format a datetime as RFC3339 (UTC, millisecond precision, trailing ``Z``).

    Pure formatter — the caller supplies the datetime; naive datetimes are
    assumed UTC. This is the *event-payload* timestamp format. It is distinct
    from the request-*signing* timestamp, which keeps ``+00:00`` (never ``Z``).
    """
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@dataclass(frozen=True)
class EventEnvelope:
    """A governance event addressed to OpenBox Core.

    Attributes:
        event_type: Backend **wire** event type (hook events store
            ``ACTIVITY_STARTED`` — the wire type Core accepts).
        payload: Flat wire fields (``workflow_id``, ``run_id``, ...). Serialized
            at the top level of the request body, not nested.
        spans: Hook span payloads (internal span envelopes until wire
            projection). Empty for lifecycle events.
        hook_trigger: True only for hook evaluations.
        activity_id / activity_type: The bound activity for activity-scoped and
            hook events.
        timestamp: RFC3339 ``Z`` string, passed in. ``None`` means the sending
            layer stamps it (``setdefault`` semantics — an explicit value is
            preserved).
        source: Constant event source tag Core expects.
    """

    event_type: EventType
    payload: Mapping[str, Any] = field(default_factory=dict)
    spans: tuple[Any, ...] = ()
    hook_trigger: bool = False
    activity_id: str | None = None
    activity_type: str | None = None
    timestamp: str | None = None
    source: str = SOURCE_WORKFLOW_TELEMETRY

    def to_payload_dict(self) -> dict[str, Any]:
        """Flat lifecycle wire dict (omit-when-absent; never null keys).

        Spans and ``span_count`` are deliberately NOT emitted here — hook body
        assembly is owned by ``wire/evaluate_payload.py``, the single owner of
        the evaluate body shape.
        """
        body: dict[str, Any] = {
            "source": self.source,
            "event_type": wire_event_type(self).value,
            **dict(self.payload),
        }
        if self.activity_id is not None:
            body["activity_id"] = self.activity_id
        if self.activity_type is not None:
            body["activity_type"] = self.activity_type
        if self.hook_trigger:
            body["hook_trigger"] = True
        if self.timestamp is not None:
            body["timestamp"] = self.timestamp
        return body


def classify_event(event: EventEnvelope) -> EventKind:
    """Classify an envelope. Derived from stored fields — never trust callers
    to pass a separate, possibly-inconsistent kind."""
    if event.hook_trigger:
        return EventKind.HOOK
    if event.event_type is EventType.HANDOFF:
        return EventKind.HANDOFF
    if event.event_type is EventType.SIGNAL_RECEIVED:
        return EventKind.SIGNAL
    return EventKind.LIFECYCLE


def wire_event_type(event: EventEnvelope) -> EventType:
    """Backend wire event type. A HOOK-kind event is always ``ActivityStarted``
    on the wire regardless of what the envelope stores."""
    if event.hook_trigger:
        return EventType.ACTIVITY_STARTED
    return event.event_type


# ─── Factories ───────────────────────────────────────────────────────────────
#
# Factories build wire-consistent envelopes. They raise ValueError on
# programmer misuse (missing required identity fields); *runtime* contract
# violations on arbitrary envelopes are the strict gate's job (ContractError).


def _base_workflow_payload(
    workflow_id: str,
    run_id: str,
    workflow_type: str,
    task_queue: str | None,
    multi_agent_session_id: str | None,
    extra: Mapping[str, Any] | None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "workflow_id": workflow_id,
        "run_id": run_id,
        "workflow_type": workflow_type,
    }
    if task_queue is not None:
        payload["task_queue"] = task_queue
    # Omitted entirely when absent (never a null key) — Temporal parity.
    if multi_agent_session_id:
        payload["multi_agent_session_id"] = multi_agent_session_id
    if extra:
        payload.update(extra)
    return payload


def workflow_started(
    *,
    workflow_id: str,
    run_id: str,
    workflow_type: str,
    task_queue: str | None = None,
    multi_agent_session_id: str | None = None,
    timestamp: str | None = None,
    extra: Mapping[str, Any] | None = None,
) -> EventEnvelope:
    """WorkflowStarted lifecycle event."""
    return EventEnvelope(
        event_type=EventType.WORKFLOW_STARTED,
        payload=_base_workflow_payload(
            workflow_id, run_id, workflow_type, task_queue, multi_agent_session_id, extra
        ),
        timestamp=timestamp,
    )


def workflow_completed(
    *,
    workflow_id: str,
    run_id: str,
    workflow_type: str,
    task_queue: str | None = None,
    multi_agent_session_id: str | None = None,
    timestamp: str | None = None,
    extra: Mapping[str, Any] | None = None,
) -> EventEnvelope:
    """WorkflowCompleted lifecycle event."""
    return EventEnvelope(
        event_type=EventType.WORKFLOW_COMPLETED,
        payload=_base_workflow_payload(
            workflow_id, run_id, workflow_type, task_queue, multi_agent_session_id, extra
        ),
        timestamp=timestamp,
    )


def workflow_failed(
    *,
    workflow_id: str,
    run_id: str,
    workflow_type: str,
    error: str | None = None,
    task_queue: str | None = None,
    multi_agent_session_id: str | None = None,
    timestamp: str | None = None,
    extra: Mapping[str, Any] | None = None,
) -> EventEnvelope:
    """WorkflowFailed lifecycle event."""
    payload = _base_workflow_payload(
        workflow_id, run_id, workflow_type, task_queue, multi_agent_session_id, extra
    )
    if error is not None:
        payload["error"] = error
    return EventEnvelope(
        event_type=EventType.WORKFLOW_FAILED, payload=payload, timestamp=timestamp
    )


def activity_started(
    *,
    workflow_id: str,
    run_id: str,
    workflow_type: str,
    activity_id: str,
    activity_type: str,
    task_queue: str | None = None,
    activity_input: Any = None,
    attempt: int | None = None,
    multi_agent_session_id: str | None = None,
    timestamp: str | None = None,
    extra: Mapping[str, Any] | None = None,
) -> EventEnvelope:
    """ActivityStarted lifecycle event (NOT a hook — ``hook_trigger`` stays false)."""
    payload = _base_workflow_payload(
        workflow_id, run_id, workflow_type, task_queue, multi_agent_session_id, extra
    )
    if activity_input is not None:
        payload["activity_input"] = activity_input
    if attempt is not None:
        payload["attempt"] = attempt
    return EventEnvelope(
        event_type=EventType.ACTIVITY_STARTED,
        payload=payload,
        activity_id=activity_id,
        activity_type=activity_type,
        timestamp=timestamp,
    )


def activity_completed(
    *,
    workflow_id: str,
    run_id: str,
    workflow_type: str,
    activity_id: str,
    activity_type: str,
    task_queue: str | None = None,
    result: Any = None,
    error: str | None = None,
    attempt: int | None = None,
    multi_agent_session_id: str | None = None,
    timestamp: str | None = None,
    extra: Mapping[str, Any] | None = None,
) -> EventEnvelope:
    """ActivityCompleted lifecycle event.

    Never carries hook spans. Legacy ``spans=[]``/``span_count=0`` compat noise
    is not produced here at all; the wire assembler additionally strips it from
    hand-built payloads (recorded as a diagnostic).
    """
    payload = _base_workflow_payload(
        workflow_id, run_id, workflow_type, task_queue, multi_agent_session_id, extra
    )
    if result is not None:
        payload["result"] = result
    if error is not None:
        payload["error"] = error
    if attempt is not None:
        payload["attempt"] = attempt
    return EventEnvelope(
        event_type=EventType.ACTIVITY_COMPLETED,
        payload=payload,
        activity_id=activity_id,
        activity_type=activity_type,
        timestamp=timestamp,
    )


def signal_received(
    *,
    workflow_id: str,
    run_id: str,
    workflow_type: str,
    signal_name: str,
    task_queue: str | None = None,
    multi_agent_session_id: str | None = None,
    timestamp: str | None = None,
    extra: Mapping[str, Any] | None = None,
) -> EventEnvelope:
    """SignalReceived event."""
    payload = _base_workflow_payload(
        workflow_id, run_id, workflow_type, task_queue, multi_agent_session_id, extra
    )
    payload["signal_name"] = signal_name
    return EventEnvelope(
        event_type=EventType.SIGNAL_RECEIVED, payload=payload, timestamp=timestamp
    )


def handoff(
    *,
    from_agent_did: str,
    multi_agent_session_id: str,
    timestamp: str | None = None,
) -> EventEnvelope:
    """Multi-agent Handoff event.

    Both fields are required and non-empty (raises ValueError before any
    network call). ``to_agent_did`` is deliberately NOT included — the receiver
    is derived server-side from the authenticated signed identity.
    """
    if not from_agent_did or not from_agent_did.strip():
        raise ValueError("handoff: from_agent_did is required and must be non-empty")
    if not multi_agent_session_id or not multi_agent_session_id.strip():
        raise ValueError(
            "handoff: multi_agent_session_id is required and must be non-empty"
        )
    return EventEnvelope(
        event_type=EventType.HANDOFF,
        payload={
            "from_agent_did": from_agent_did,
            "multi_agent_session_id": multi_agent_session_id,
        },
        timestamp=timestamp,
    )


def hook(
    *,
    activity_context: Mapping[str, Any],
    activity_id: str,
    activity_type: str,
    spans: tuple[Any, ...] | list[Any],
    timestamp: str | None = None,
) -> EventEnvelope:
    """Hook (span-bearing) evaluation event.

    Internally ``EventKind.HOOK``; serializes as wire ``ActivityStarted`` +
    ``hook_trigger=true`` + non-empty ``spans``. Must be attached to a bound
    activity — callers resolve ``activity_context`` from the ContextStore
    first (no bound context ⇒ skip the hook entirely; don't call this).

    Args:
        activity_context: Flat context payload fields (workflow_id, run_id, ...)
            merged at the top level of the wire body.
        activity_id / activity_type: The bound activity identity (required).
        spans: Non-empty span payloads (internal envelopes; projected to Core
            ``SpanData`` wire dicts at body assembly).
    """
    if not activity_id or not activity_type:
        raise ValueError(
            "hook: activity_id and activity_type are required — hook events must "
            "be attached to a bound activity"
        )
    if not spans:
        raise ValueError("hook: spans must be non-empty for a hook evaluation")
    return EventEnvelope(
        event_type=EventType.ACTIVITY_STARTED,
        payload=dict(activity_context),
        spans=tuple(spans),
        hook_trigger=True,
        activity_id=activity_id,
        activity_type=activity_type,
        timestamp=timestamp,
    )
