"""Event classification, wire serialization, and factory contract tests."""

from datetime import UTC, datetime

import pytest

from openbox_core.contracts.events import (
    SOURCE_WORKFLOW_TELEMETRY,
    EventEnvelope,
    EventKind,
    EventType,
    activity_completed,
    activity_started,
    classify_event,
    handoff,
    hook,
    rfc3339_from_datetime,
    signal_received,
    wire_event_type,
    workflow_completed,
    workflow_failed,
    workflow_started,
)

WF = dict(workflow_id="wf-1", run_id="run-1", workflow_type="OrderWorkflow")


def make_hook(**overrides):
    kwargs = dict(
        activity_context={**WF, "task_queue": "q"},
        activity_id="act-1",
        activity_type="charge_card",
        spans=[{"span_id": "aa" * 8}],
    )
    kwargs.update(overrides)
    return hook(**kwargs)


class TestClassification:
    def test_hook_classifies_hook_but_wire_activity_started(self):
        event = make_hook()
        assert classify_event(event) is EventKind.HOOK
        assert wire_event_type(event) is EventType.ACTIVITY_STARTED
        assert event.hook_trigger is True
        assert len(event.spans) == 1

    def test_lifecycle_classification(self):
        assert classify_event(workflow_started(**WF)) is EventKind.LIFECYCLE
        assert classify_event(workflow_completed(**WF)) is EventKind.LIFECYCLE
        assert classify_event(workflow_failed(**WF)) is EventKind.LIFECYCLE
        started = activity_started(**WF, activity_id="a", activity_type="t")
        assert classify_event(started) is EventKind.LIFECYCLE

    def test_signal_and_handoff_classification(self):
        sig = signal_received(**WF, signal_name="approve")
        assert classify_event(sig) is EventKind.SIGNAL
        ho = handoff(from_agent_did="did:aip:x", multi_agent_session_id="s-1")
        assert classify_event(ho) is EventKind.HANDOFF

    def test_wire_event_type_passthrough_for_lifecycle(self):
        completed = activity_completed(**WF, activity_id="a", activity_type="t")
        assert wire_event_type(completed) is EventType.ACTIVITY_COMPLETED

    def test_hand_built_hook_envelope_still_wires_activity_started(self):
        # hook_trigger alone drives wire type, even if a caller stored the wrong one
        event = EventEnvelope(
            event_type=EventType.ACTIVITY_COMPLETED, hook_trigger=True
        )
        assert classify_event(event) is EventKind.HOOK
        assert wire_event_type(event) is EventType.ACTIVITY_STARTED


class TestPayloadDict:
    def test_lifecycle_payload_shape(self):
        event = workflow_started(
            **WF, task_queue="q", multi_agent_session_id="sess-9", timestamp="2026-01-01T00:00:00.000Z"
        )
        body = event.to_payload_dict()
        assert body == {
            "source": SOURCE_WORKFLOW_TELEMETRY,
            "event_type": "WorkflowStarted",
            "workflow_id": "wf-1",
            "run_id": "run-1",
            "workflow_type": "OrderWorkflow",
            "task_queue": "q",
            "multi_agent_session_id": "sess-9",
            "timestamp": "2026-01-01T00:00:00.000Z",
        }

    def test_absent_fields_are_omitted_not_null(self):
        body = workflow_started(**WF).to_payload_dict()
        assert "multi_agent_session_id" not in body
        assert "task_queue" not in body
        assert "timestamp" not in body
        assert "hook_trigger" not in body
        assert None not in body.values()

    def test_activity_event_carries_ids(self):
        event = activity_started(
            **WF, activity_id="act-1", activity_type="charge", attempt=2, activity_input=[1]
        )
        body = event.to_payload_dict()
        assert body["activity_id"] == "act-1"
        assert body["activity_type"] == "charge"
        assert body["attempt"] == 2
        assert body["activity_input"] == [1]

    def test_hook_payload_dict_sets_hook_trigger_but_no_spans(self):
        body = make_hook().to_payload_dict()
        assert body["hook_trigger"] is True
        assert body["event_type"] == "ActivityStarted"
        # span attachment is owned by wire/evaluate_payload.py, not the envelope
        assert "spans" not in body
        assert "span_count" not in body

    def test_activity_completed_never_produces_compat_noise(self):
        body = activity_completed(**WF, activity_id="a", activity_type="t").to_payload_dict()
        assert "spans" not in body
        assert "span_count" not in body


class TestFactoriesValidation:
    def test_handoff_requires_both_fields(self):
        with pytest.raises(ValueError, match="from_agent_did"):
            handoff(from_agent_did="  ", multi_agent_session_id="s")
        with pytest.raises(ValueError, match="multi_agent_session_id"):
            handoff(from_agent_did="did:aip:x", multi_agent_session_id="")

    def test_handoff_omits_to_agent_did(self):
        body = handoff(from_agent_did="did:aip:x", multi_agent_session_id="s").to_payload_dict()
        assert "to_agent_did" not in body
        assert body["from_agent_did"] == "did:aip:x"
        assert body["multi_agent_session_id"] == "s"

    def test_hook_requires_bound_activity(self):
        with pytest.raises(ValueError, match="bound activity"):
            make_hook(activity_id="")

    def test_hook_requires_nonempty_spans(self):
        with pytest.raises(ValueError, match="spans"):
            make_hook(spans=[])

    def test_workflow_failed_carries_error(self):
        body = workflow_failed(**WF, error="boom").to_payload_dict()
        assert body["error"] == "boom"


class TestRfc3339:
    def test_formats_utc_millis_z(self):
        ts = datetime(2026, 7, 2, 3, 4, 5, 678901, tzinfo=UTC)
        assert rfc3339_from_datetime(ts) == "2026-07-02T03:04:05.678Z"

    def test_naive_datetime_assumed_utc(self):
        ts = datetime(2026, 7, 2, 3, 4, 5, 678901)
        assert rfc3339_from_datetime(ts) == "2026-07-02T03:04:05.678Z"
