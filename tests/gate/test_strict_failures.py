"""Strict gate tests — every contract violation raises BEFORE any send."""

import httpx
import pytest

from openbox_core.client import EvaluationClient
from openbox_core.contracts.events import (
    EventEnvelope,
    EventType,
    handoff,
    hook,
    signal_received,
    workflow_started,
)
from openbox_core.errors import ContractError, OpenBoxConfigError
from openbox_core.gate import GovernanceGate

WF = dict(workflow_id="wf-1", run_id="run-1", workflow_type="W")


class CountingClient(EvaluationClient):
    """Real client over MockTransport that counts evaluate sends."""

    def __init__(self, response_json=None):
        self.sends = 0

        def handler(request):
            self.sends += 1
            return httpx.Response(200, json=response_json or {"verdict": "allow"})

        transport = httpx.MockTransport(handler)
        super().__init__(
            "https://core.test", "obx_test_x", transport=transport, async_transport=transport
        )


def started_span(**extra):
    return {"stage": "started", "span_id": "aa" * 8, **extra}


def completed_span(**extra):
    return {"stage": "completed", "span_id": "aa" * 8, **extra}


def make_hook(spans):
    return hook(
        activity_context=WF, activity_id="a-1", activity_type="charge", spans=spans
    )


def make_gate(client=None, payload_builder=None, config=None):
    return GovernanceGate(
        client or CountingClient(),
        config,
        payload_builder=payload_builder or (lambda event: (event.to_payload_dict(), [])),
    )


class TestStrictLifecycleFailures:
    def test_missing_workflow_fields_raise_before_send(self):
        client = CountingClient()
        gate = make_gate(client)
        bad = EventEnvelope(event_type=EventType.WORKFLOW_STARTED, payload={"workflow_id": "wf"})
        with pytest.raises(ContractError, match="missing required fields"):
            gate.evaluate(bad)
        assert client.sends == 0

    def test_signal_requires_signal_name(self):
        client = CountingClient()
        bad = EventEnvelope(event_type=EventType.SIGNAL_RECEIVED, payload=WF)
        with pytest.raises(ContractError, match="signal_name"):
            make_gate(client).evaluate(bad)
        assert client.sends == 0

    def test_handoff_requires_identity_fields(self):
        client = CountingClient()
        bad = EventEnvelope(event_type=EventType.HANDOFF, payload={"from_agent_did": "d"})
        with pytest.raises(ContractError, match="multi_agent_session_id"):
            make_gate(client).evaluate(bad)
        assert client.sends == 0

    def test_hook_event_on_lifecycle_path_rejected(self):
        client = CountingClient()
        with pytest.raises(ContractError, match="HOOK_ON_LIFECYCLE_PATH|hook"):
            make_gate(client).evaluate(make_hook([started_span()]))
        assert client.sends == 0

    def test_activity_completed_with_nonempty_spans_rejected(self):
        client = CountingClient()
        bad = EventEnvelope(
            event_type=EventType.ACTIVITY_COMPLETED,
            payload=WF,
            spans=(completed_span(),),
        )
        with pytest.raises(ContractError, match="ActivityCompleted must not carry"):
            make_gate(client).evaluate(bad)
        assert client.sends == 0

    def test_span_bearing_non_hook_rejected(self):
        client = CountingClient()
        bad = EventEnvelope(
            event_type=EventType.WORKFLOW_STARTED, payload=WF, spans=(started_span(),)
        )
        with pytest.raises(ContractError, match="hook_trigger=false"):
            make_gate(client).evaluate(bad)
        assert client.sends == 0


class TestStrictHookFailures:
    def test_hook_trigger_false_rejected(self):
        client = CountingClient()
        bad = EventEnvelope(
            event_type=EventType.ACTIVITY_STARTED,
            payload=WF,
            spans=(started_span(),),
            hook_trigger=False,
            activity_id="a",
            activity_type="t",
        )
        with pytest.raises(ContractError, match="hook_trigger=true"):
            make_gate(client).preflight(bad)
        assert client.sends == 0

    def test_wrong_wire_type_rejected(self):
        client = CountingClient()
        bad = EventEnvelope(
            event_type=EventType.ACTIVITY_COMPLETED,
            payload=WF,
            spans=(started_span(),),
            hook_trigger=True,
            activity_id="a",
            activity_type="t",
        )
        with pytest.raises(ContractError, match="wire event type ActivityStarted"):
            make_gate(client).preflight(bad)
        assert client.sends == 0

    def test_unbound_activity_rejected(self):
        client = CountingClient()
        bad = EventEnvelope(
            event_type=EventType.ACTIVITY_STARTED,
            payload=WF,
            spans=(started_span(),),
            hook_trigger=True,
        )
        with pytest.raises(ContractError, match="bound activity"):
            make_gate(client).preflight(bad)
        assert client.sends == 0

    def test_empty_spans_rejected(self):
        client = CountingClient()
        bad = EventEnvelope(
            event_type=EventType.ACTIVITY_STARTED,
            payload=WF,
            hook_trigger=True,
            activity_id="a",
            activity_type="t",
        )
        with pytest.raises(ContractError, match="no spans"):
            make_gate(client).preflight(bad)
        assert client.sends == 0

    def test_missing_payload_builder_raises_config_error(self):
        client = CountingClient()
        gate = GovernanceGate(client)  # no payload_builder
        with pytest.raises(OpenBoxConfigError, match="payload_builder"):
            gate.preflight(make_hook([started_span()]))
        assert client.sends == 0


class TestStageMismatch:
    def test_preflight_rejects_completed_stage_spans(self):
        client = CountingClient()
        with pytest.raises(ContractError, match="started-stage evaluation received a completed"):
            make_gate(client).preflight(make_hook([completed_span()]))
        assert client.sends == 0

    def test_completed_rejects_started_stage_spans(self):
        client = CountingClient()
        with pytest.raises(ContractError, match="completed-stage evaluation received a started"):
            make_gate(client).completed(make_hook([started_span()]))
        assert client.sends == 0

    def test_stageless_span_rejected(self):
        client = CountingClient()
        with pytest.raises(ContractError, match="no stage"):
            make_gate(client).preflight(make_hook([{"span_id": "aa" * 8}]))
        assert client.sends == 0

    def test_nested_span_shape_rejected(self):
        client = CountingClient()
        internal = {"otel": {"name": "GET"}, "openbox": {"stage": "started"}}
        with pytest.raises(ContractError, match="flat Core SpanData"):
            make_gate(client).preflight(make_hook([internal]))
        assert client.sends == 0


class TestHappyPathsAndAsync:
    def test_lifecycle_evaluate_sends_and_stamps_timestamp(self):
        client = CountingClient()
        captured = {}

        def handler(request):
            import json

            captured.update(json.loads(request.content))
            client.sends += 1
            return httpx.Response(200, json={"verdict": "allow"})

        client._transport = httpx.MockTransport(handler)
        client._sync_client = None  # force rebuild with new transport
        result = make_gate(client).evaluate(workflow_started(**WF))
        assert result.verdict.value == "allow"
        assert captured["event_type"] == "WorkflowStarted"
        assert captured["timestamp"].endswith("Z")  # event-payload format

    def test_explicit_timestamp_preserved(self):
        captured = {}

        def handler(request):
            import json

            captured.update(json.loads(request.content))
            return httpx.Response(200, json={"verdict": "allow"})

        transport = httpx.MockTransport(handler)
        client = EvaluationClient(
            "https://core.test", "obx_test_x", transport=transport, async_transport=transport
        )
        event = workflow_started(**WF, timestamp="2026-01-01T00:00:00.000Z")
        make_gate(client).evaluate(event)
        assert captured["timestamp"] == "2026-01-01T00:00:00.000Z"

    async def test_async_paths(self):
        client = CountingClient()
        gate = make_gate(client)
        result = await gate.aevaluate(workflow_started(**WF))
        assert result.verdict.value == "allow"
        result = await gate.apreflight(make_hook([started_span()]))
        assert result.verdict.value == "allow"
        result = await gate.acompleted(make_hook([completed_span()]))
        assert result.verdict.value == "allow"
        assert client.sends == 3

    def test_signal_and_handoff_happy_path(self):
        client = CountingClient()
        gate = make_gate(client)
        gate.evaluate(signal_received(**WF, signal_name="go"))
        gate.evaluate(handoff(from_agent_did="did:aip:x", multi_agent_session_id="s"))
        assert client.sends == 2


class TestNoPublicModeToggle:
    def test_no_mode_parameter_in_any_public_gate_api(self):
        # The gate is ALWAYS strict — no mode kwarg on any public callable.
        # (Docstrings may MENTION the forbidden modes; signatures may not.)
        import inspect

        from openbox_core import gate as gate_module

        callables = [GovernanceGate.__init__] + [
            member
            for name, member in inspect.getmembers(GovernanceGate, inspect.isfunction)
            if not name.startswith("_")
        ]
        for func in callables:
            parameters = inspect.signature(func).parameters
            assert not any("mode" in p.lower() for p in parameters), (
                f"{func.__qualname__} exposes a mode-like parameter"
            )
        module_names = {n for n in vars(gate_module) if not n.startswith("_")}
        assert not {"OBSERVE", "SANITIZE", "STRICT", "GateMode"} & module_names
        # Config carries no gate-mode field either.
        from openbox_core.config import GateConfig

        assert not any("mode" in f.lower() for f in GateConfig.__dataclass_fields__)
