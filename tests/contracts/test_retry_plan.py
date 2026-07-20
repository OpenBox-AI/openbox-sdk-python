"""retry_plan parsing + handle_retryable_block tests (frozen wire contract).

Covers: present-null vs absent, falsy-value preservation, boolean rejection, the finite/
safe-integer numeric rule (incl. nested), action="block" approvals, HALT/expired -> None,
the EvaluationResult path not raising AttributeError, and default BLOCK enforcement unchanged.
"""

import pytest

from openbox_core.contracts.results import (
    ApprovalResult,
    EvaluationResult,
    RetryDirective,
    RetryPlan,
    Verdict,
    handle_retryable_block,
)
from openbox_core.errors import GovernanceBlockedError
from openbox_core.gate import raise_for_verdict

SAFE_MAX = 2**53 - 1


def _block(**extra):
    return {"verdict": "block", **extra}


class TestRetryPlanParsing:
    def test_valid_plan_parses_on_evaluation(self):
        r = EvaluationResult.from_dict(_block(retry_plan={"new_input": "x"}))
        assert isinstance(r.retry_plan, RetryPlan)
        assert r.retry_plan.new_input == "x"

    def test_valid_plan_parses_on_approval_block_action(self):
        r = ApprovalResult.from_dict(
            {"action": "block", "retry_plan": {"new_input": [1, 2]}}
        )
        assert r.verdict is Verdict.BLOCK
        assert isinstance(r.retry_plan, RetryPlan)
        assert r.retry_plan.new_input == [1, 2]

    def test_present_null_is_distinct_from_absent(self):
        present = EvaluationResult.from_dict(_block(retry_plan={"new_input": None}))
        assert present.retry_plan is not None
        assert present.retry_plan.new_input is None

        absent = EvaluationResult.from_dict(_block())
        assert absent.retry_plan is None

    def test_json_null_field_is_treated_as_absent(self):
        assert EvaluationResult.from_dict(_block(retry_plan=None)).retry_plan is None

    def test_falsy_values_preserved(self):
        for val in (None, "", 0, [], {}):
            r = EvaluationResult.from_dict(_block(retry_plan={"new_input": val}))
            assert r.retry_plan is not None, val
            assert r.retry_plan.new_input == val

    def test_boolean_new_input_rejected(self):
        for val in (True, False):
            r = EvaluationResult.from_dict(_block(retry_plan={"new_input": val}))
            assert r.retry_plan is None

    def test_extra_key_rejected(self):
        r = EvaluationResult.from_dict(
            _block(retry_plan={"new_input": None, "x": 1})
        )
        assert r.retry_plan is None

    def test_missing_new_input_rejected(self):
        r = EvaluationResult.from_dict(_block(retry_plan={"other": 1}))
        assert r.retry_plan is None

    def test_non_dict_plan_rejected(self):
        for bad in ("str", 5, [1], True):
            r = EvaluationResult.from_dict(_block(retry_plan=bad))
            assert r.retry_plan is None

    def test_numeric_safe_boundary(self):
        assert (
            EvaluationResult.from_dict(
                _block(retry_plan={"new_input": SAFE_MAX})
            ).retry_plan
            is not None
        )
        assert (
            EvaluationResult.from_dict(
                _block(retry_plan={"new_input": SAFE_MAX + 1})
            ).retry_plan
            is None
        )

    def test_non_finite_and_nested_unsafe_rejected(self):
        assert (
            EvaluationResult.from_dict(
                _block(retry_plan={"new_input": float("inf")})
            ).retry_plan
            is None
        )
        assert (
            EvaluationResult.from_dict(
                _block(retry_plan={"new_input": float("nan")})
            ).retry_plan
            is None
        )
        assert (
            EvaluationResult.from_dict(
                _block(retry_plan={"new_input": {"a": [SAFE_MAX + 1]}})
            ).retry_plan
            is None
        )
        assert (
            EvaluationResult.from_dict(
                _block(retry_plan={"new_input": {"a": [SAFE_MAX]}})
            ).retry_plan
            is not None
        )

    def test_raw_preserved(self):
        data = _block(retry_plan={"new_input": "x"}, extra="keep")
        r = EvaluationResult.from_dict(data)
        assert r.raw["extra"] == "keep"
        assert r.raw["retry_plan"] == {"new_input": "x"}


class TestHandleRetryableBlock:
    def test_directive_from_evaluation_block(self):
        r = EvaluationResult.from_dict(
            _block(
                retry_plan={"new_input": "x"},
                governance_event_id="ev-1",
                reason="blocked",
            )
        )
        d = handle_retryable_block(r)
        assert isinstance(d, RetryDirective)
        assert d.new_input == "x"
        assert d.governance_event_id == "ev-1"
        assert d.reason == "blocked"

    def test_directive_from_approval_reads_event_id_from_raw(self):
        r = ApprovalResult.from_dict(
            {
                "action": "block",
                "retry_plan": {"new_input": None},
                "governance_event_id": "ev-2",
                "reason": "retry",
            }
        )
        d = handle_retryable_block(r)
        assert d is not None
        assert d.new_input is None
        assert d.governance_event_id == "ev-2"

    def test_approval_event_id_falls_back_to_id(self):
        r = ApprovalResult.from_dict(
            {"action": "block", "retry_plan": {"new_input": 1}, "id": "ev-3"}
        )
        d = handle_retryable_block(r)
        assert d is not None
        assert d.governance_event_id == "ev-3"

    def test_plain_block_returns_none(self):
        assert handle_retryable_block(EvaluationResult.from_dict(_block())) is None

    def test_non_block_verdicts_return_none(self):
        for verdict in ("allow", "constrain", "require_approval", "halt"):
            r = EvaluationResult.from_dict(
                {"verdict": verdict, "retry_plan": {"new_input": "x"}}
            )
            assert handle_retryable_block(r) is None, verdict

    def test_halt_approval_returns_none_even_with_plan(self):
        r = ApprovalResult.from_dict(
            {"action": "halt", "retry_plan": {"new_input": "x"}}
        )
        assert handle_retryable_block(r) is None

    def test_expired_approval_returns_none_even_if_block(self):
        r = ApprovalResult.from_dict(
            {"action": "block", "retry_plan": {"new_input": "x"}, "expired": True}
        )
        assert r.verdict is Verdict.BLOCK
        assert handle_retryable_block(r) is None

    def test_pending_approval_returns_none(self):
        r = ApprovalResult.from_dict({"retry_plan": {"new_input": "x"}})
        assert r.verdict is None
        assert handle_retryable_block(r) is None

    def test_evaluation_result_never_raises_attributeerror(self):
        # EvaluationResult has no is_blocking()/expired; the gate must not touch them.
        r = EvaluationResult.from_dict(_block(retry_plan={"new_input": "x"}))
        assert handle_retryable_block(r) is not None

    def test_block_without_plan_returns_none(self):
        assert handle_retryable_block(EvaluationResult.from_dict(_block())) is None


class TestEnforcementUnchanged:
    def test_block_still_raises_even_with_retry_plan(self):
        # Adding retry_plan support must NOT suppress the default block; the helper is opt-in only.
        r = EvaluationResult.from_dict(
            _block(retry_plan={"new_input": "x"}, reason="nope")
        )
        with pytest.raises(GovernanceBlockedError):
            raise_for_verdict(r)
