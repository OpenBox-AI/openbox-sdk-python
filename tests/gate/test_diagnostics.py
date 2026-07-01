"""Diagnostic-path tests — degradations send + record, never reject."""

import json

import httpx

from openbox_core.client import EvaluationClient
from openbox_core.config import OpenBoxConfig, PrivacyConfig
from openbox_core.contracts.events import activity_completed
from openbox_core.gate import GovernanceGate
from openbox_core.validation.diagnostics import (
    ATTR_REDACTED,
    COMPAT_NOISE_REMOVED,
    SPAN_ATTR_MISSING,
    Diagnostic,
    DiagnosticLevel,
)
from openbox_core.validation.span_normalization import (
    semantic_gap_diagnostics,
    strip_compat_noise,
)

WF = dict(workflow_id="wf-1", run_id="run-1", workflow_type="W")


def capture_gate(config=None):
    captured = {}

    def handler(request):
        captured.update(json.loads(request.content))
        return httpx.Response(200, json={"verdict": "allow"})

    transport = httpx.MockTransport(handler)
    client = EvaluationClient(
        "https://core.test", "obx_test_x", transport=transport, async_transport=transport
    )
    return GovernanceGate(client, config), captured


class TestCompatNoiseRemoval:
    def test_activity_completed_empty_spans_removed_and_diagnosed(self):
        # Hand-built legacy payload dict with compat noise:
        event = activity_completed(
            **WF, activity_id="a", activity_type="t", extra={"spans": [], "span_count": 0}
        )
        gate, captured = capture_gate()
        result = gate.evaluate(event)
        assert "spans" not in captured
        assert "span_count" not in captured
        codes = [d["code"] for d in result.diagnostics]
        assert COMPAT_NOISE_REMOVED in codes

    def test_nonzero_span_count_untouched(self):
        cleaned, diagnostics = strip_compat_noise({"span_count": 3, "spans": ["x"]})
        assert cleaned["span_count"] == 3
        assert diagnostics == []


class TestSemanticGaps:
    def test_missing_http_fields_are_info_not_failure(self):
        diagnostics = semantic_gap_diagnostics({"span_id": "x"}, "http_request")
        codes = {(d.code, d.detail["field"]) for d in diagnostics}
        assert (SPAN_ATTR_MISSING, "http_url") in codes
        assert (SPAN_ATTR_MISSING, "http_method") in codes
        assert all(d.level is DiagnosticLevel.INFO for d in diagnostics)

    def test_present_fields_produce_no_diagnostics(self):
        span = {"http_url": "https://x", "http_method": "GET"}
        assert semantic_gap_diagnostics(span, "http_request") == []

    def test_unknown_hook_type_produces_no_diagnostics(self):
        assert semantic_gap_diagnostics({}, "llm_call") == []
        assert semantic_gap_diagnostics({}, None) == []


class TestRedaction:
    def test_redaction_applied_and_diagnosed(self):
        config = OpenBoxConfig(privacy=PrivacyConfig(redact_keys={"password"}))
        event = activity_completed(
            **WF, activity_id="a", activity_type="t",
            extra={"activity_input": {"password": "hunter2", "user": "bob"}},
        )
        gate, captured = capture_gate(config)
        result = gate.evaluate(event)
        assert captured["activity_input"]["password"] == "[REDACTED]"
        assert captured["activity_input"]["user"] == "bob"
        redacted = [d for d in result.diagnostics if d["code"] == ATTR_REDACTED]
        assert redacted and "activity_input.password" in redacted[0]["detail"]["paths"]

    def test_no_redact_keys_no_diagnostics(self):
        gate, captured = capture_gate()
        result = gate.evaluate(
            activity_completed(**WF, activity_id="a", activity_type="t",
                               extra={"activity_input": {"password": "x"}})
        )
        assert captured["activity_input"]["password"] == "x"
        assert all(d["code"] != ATTR_REDACTED for d in result.diagnostics)


class TestDiagnosticRecord:
    def test_to_dict_shape(self):
        d = Diagnostic(DiagnosticLevel.INFO, "X_CODE", "msg", {"k": 1})
        assert d.to_dict() == {"level": "INFO", "code": "X_CODE", "message": "msg", "detail": {"k": 1}}
