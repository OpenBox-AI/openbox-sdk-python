"""EvaluationResult / GuardrailsResult / Verdict parsing tests."""

from openbox_core.contracts.results import (
    EvaluationResult,
    GuardrailsResult,
    Verdict,
)


class TestVerdict:
    def test_v10_compat_mappings(self):
        assert Verdict.from_string("continue") is Verdict.ALLOW
        assert Verdict.from_string("stop") is Verdict.HALT
        assert Verdict.from_string("require-approval") is Verdict.REQUIRE_APPROVAL
        assert Verdict.from_string("request_approval") is Verdict.REQUIRE_APPROVAL

    def test_none_and_unknown_default_allow(self):
        assert Verdict.from_string(None) is Verdict.ALLOW
        assert Verdict.from_string("banana") is Verdict.ALLOW

    def test_priority_order(self):
        order = [Verdict.ALLOW, Verdict.CONSTRAIN, Verdict.REQUIRE_APPROVAL, Verdict.BLOCK, Verdict.HALT]
        assert [v.priority for v in order] == [1, 2, 3, 4, 5]
        assert Verdict.highest_priority([Verdict.ALLOW, Verdict.BLOCK]) is Verdict.BLOCK
        assert Verdict.highest_priority([]) is Verdict.ALLOW

    def test_predicates(self):
        assert Verdict.BLOCK.should_stop() and Verdict.HALT.should_stop()
        assert not Verdict.ALLOW.should_stop()
        assert Verdict.REQUIRE_APPROVAL.requires_approval()


FULL_RESPONSE = {
    "verdict": "block",
    "reason": "policy denied",
    "policy_id": "pol-7",
    "risk_score": 0.83,
    "metadata": {"k": "v"},
    "governance_event_id": "evt-42",
    "guardrails_result": {
        "redacted_input": {"card": "****"},
        "input_type": "activity_input",
        "raw_logs": {"x": 1},
        "validation_passed": False,
        "reasons": [{"type": "pii", "field": "card", "reason": "card number"}],
    },
    "approval_id": "app-1",
    "approval_expiration_time": "2026-07-02T00:00:00Z",
    "trust_tier": "silver",
    "alignment_score": 0.5,
    "behavioral_violations": ["v1"],
    "constraints": [{"c": 1}],
    "fallback_used": False,
    "diagnostics": [{"level": "INFO", "code": "X"}],
    "unknown_future_field": {"keep": "me"},
}


class TestEvaluationResult:
    def test_full_field_preservation(self):
        result = EvaluationResult.from_dict(FULL_RESPONSE)
        assert result.verdict is Verdict.BLOCK
        assert result.reason == "policy denied"
        assert result.policy_id == "pol-7"
        assert result.risk_score == 0.83
        assert result.metadata == {"k": "v"}
        assert result.governance_event_id == "evt-42"
        assert result.approval_id == "app-1"
        assert result.approval_expiration_time == "2026-07-02T00:00:00Z"
        assert result.trust_tier == "silver"
        assert result.alignment_score == 0.5
        assert result.behavioral_violations == ["v1"]
        assert result.constraints == [{"c": 1}]
        assert result.fallback_used is False
        assert result.diagnostics == [{"level": "INFO", "code": "X"}]
        # raw preserves EVERYTHING, including unknown keys
        assert result.raw["unknown_future_field"] == {"keep": "me"}

    def test_guardrails_is_guardrails_result_same_object(self):
        result = EvaluationResult.from_dict(FULL_RESPONSE)
        assert result.guardrails is result.guardrails_result
        assert result.guardrails.validation_passed is False
        assert result.guardrails.get_reason_strings() == ["card number"]

    def test_three_new_fields_default(self):
        result = EvaluationResult.from_dict({"verdict": "allow"})
        assert result.fallback_used is False
        assert result.diagnostics == []
        assert result.raw == {"verdict": "allow"}

    def test_v10_action_fallback(self):
        assert EvaluationResult.from_dict({"action": "stop"}).verdict is Verdict.HALT
        assert EvaluationResult.from_dict({}).verdict is Verdict.ALLOW

    def test_verdict_precedes_action_for_evaluation(self):
        # EvaluationResult keeps Temporal's verdict-first order (the
        # action-precedence change applies to ApprovalResult only).
        result = EvaluationResult.from_dict({"verdict": "block", "action": "continue"})
        assert result.verdict is Verdict.BLOCK

    def test_guardrails_key_alias(self):
        result = EvaluationResult.from_dict(
            {"verdict": "allow", "guardrails": {"input_type": "activity_input"}}
        )
        assert result.guardrails is not None
        assert result.guardrails.input_type == "activity_input"

    def test_action_backcompat_property(self):
        assert EvaluationResult(verdict=Verdict.ALLOW).action == "continue"
        assert EvaluationResult(verdict=Verdict.HALT).action == "stop"
        assert EvaluationResult(verdict=Verdict.REQUIRE_APPROVAL).action == "require-approval"
        assert EvaluationResult(verdict=Verdict.BLOCK).action == "block"

    def test_fallback_allow_shape(self):
        result = EvaluationResult.fallback_allow("network unreachable")
        assert result.verdict is Verdict.ALLOW
        assert result.fallback_used is True
        assert result.reason == "network unreachable"


class TestGuardrailsResult:
    def test_from_dict_defaults(self):
        gr = GuardrailsResult.from_dict({})
        assert gr.validation_passed is True
        assert gr.reasons == []
        assert gr.get_reason_strings() == []
