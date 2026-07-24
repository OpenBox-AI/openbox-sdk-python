"""patch parsing + handle_patch tests (frozen wire contract).

Covers: present-null vs absent, falsy-value preservation, boolean rejection, the finite/
safe-integer numeric rule (incl. nested), action="block" approvals, HALT/expired -> None,
the EvaluationResult path not raising AttributeError, and default BLOCK enforcement unchanged.
"""

import pytest

from openbox_core.contracts.results import (
    ApprovalResult,
    EvaluationResult,
    Patch,
    PatchDirective,
    Verdict,
    handle_patch,
)
from openbox_core.errors import GovernanceBlockedError
from openbox_core.gate import raise_for_verdict

SAFE_MAX = 2**53 - 1


def _block(**extra):
    return {"verdict": "block", **extra}


class TestPatchParsing:
    def test_valid_patch_parses_on_evaluation(self):
        r = EvaluationResult.from_dict(_block(patch={"new_input": "x"}))
        assert isinstance(r.patch, Patch)
        assert r.patch.new_input == "x"

    def test_valid_patch_parses_on_approval_block_action(self):
        r = ApprovalResult.from_dict(
            {"action": "block", "patch": {"new_input": [1, 2]}}
        )
        assert r.verdict is Verdict.BLOCK
        assert isinstance(r.patch, Patch)
        assert r.patch.new_input == [1, 2]

    def test_present_null_is_distinct_from_absent(self):
        present = EvaluationResult.from_dict(_block(patch={"new_input": None}))
        assert present.patch is not None
        assert present.patch.new_input is None

        absent = EvaluationResult.from_dict(_block())
        assert absent.patch is None

    def test_json_null_field_is_treated_as_absent(self):
        assert EvaluationResult.from_dict(_block(patch=None)).patch is None

    def test_falsy_values_preserved(self):
        for val in (None, "", 0, [], {}):
            r = EvaluationResult.from_dict(_block(patch={"new_input": val}))
            assert r.patch is not None, val
            assert r.patch.new_input == val

    def test_boolean_new_input_rejected(self):
        for val in (True, False):
            r = EvaluationResult.from_dict(_block(patch={"new_input": val}))
            assert r.patch is None

    def test_extra_key_rejected(self):
        r = EvaluationResult.from_dict(
            _block(patch={"new_input": None, "x": 1})
        )
        assert r.patch is None

    def test_missing_new_input_rejected(self):
        r = EvaluationResult.from_dict(_block(patch={"other": 1}))
        assert r.patch is None

    def test_non_dict_patch_rejected(self):
        for bad in ("str", 5, [1], True):
            r = EvaluationResult.from_dict(_block(patch=bad))
            assert r.patch is None

    def test_numeric_safe_boundary(self):
        assert (
            EvaluationResult.from_dict(
                _block(patch={"new_input": SAFE_MAX})
            ).patch
            is not None
        )
        assert (
            EvaluationResult.from_dict(
                _block(patch={"new_input": SAFE_MAX + 1})
            ).patch
            is None
        )

    def test_non_finite_and_nested_unsafe_rejected(self):
        assert (
            EvaluationResult.from_dict(
                _block(patch={"new_input": float("inf")})
            ).patch
            is None
        )
        assert (
            EvaluationResult.from_dict(
                _block(patch={"new_input": float("nan")})
            ).patch
            is None
        )
        assert (
            EvaluationResult.from_dict(
                _block(patch={"new_input": {"a": [SAFE_MAX + 1]}})
            ).patch
            is None
        )
        assert (
            EvaluationResult.from_dict(
                _block(patch={"new_input": {"a": [SAFE_MAX]}})
            ).patch
            is not None
        )

    def test_raw_preserved(self):
        data = _block(patch={"new_input": "x"}, extra="keep")
        r = EvaluationResult.from_dict(data)
        assert r.raw["extra"] == "keep"
        assert r.raw["patch"] == {"new_input": "x"}


class TestHandlePatch:
    def test_directive_from_evaluation_block(self):
        r = EvaluationResult.from_dict(
            _block(
                patch={"new_input": "x"},
                governance_event_id="ev-1",
                reason="blocked",
            )
        )
        d = handle_patch(r)
        assert isinstance(d, PatchDirective)
        assert d.new_input == "x"
        assert d.governance_event_id == "ev-1"
        assert d.reason == "blocked"

    def test_directive_from_approval_reads_event_id_from_raw(self):
        r = ApprovalResult.from_dict(
            {
                "action": "block",
                "patch": {"new_input": None},
                "governance_event_id": "ev-2",
                "reason": "patch",
            }
        )
        d = handle_patch(r)
        assert d is not None
        assert d.new_input is None
        assert d.governance_event_id == "ev-2"

    def test_approval_event_id_falls_back_to_id(self):
        r = ApprovalResult.from_dict(
            {"action": "block", "patch": {"new_input": 1}, "id": "ev-3"}
        )
        d = handle_patch(r)
        assert d is not None
        assert d.governance_event_id == "ev-3"

    def test_plain_block_returns_none(self):
        assert handle_patch(EvaluationResult.from_dict(_block())) is None

    def test_non_block_verdicts_return_none(self):
        for verdict in ("allow", "constrain", "require_approval", "halt"):
            r = EvaluationResult.from_dict(
                {"verdict": verdict, "patch": {"new_input": "x"}}
            )
            assert handle_patch(r) is None, verdict

    def test_halt_approval_returns_none_even_with_patch(self):
        r = ApprovalResult.from_dict(
            {"action": "halt", "patch": {"new_input": "x"}}
        )
        assert handle_patch(r) is None

    def test_expired_approval_returns_none_even_if_block(self):
        r = ApprovalResult.from_dict(
            {"action": "block", "patch": {"new_input": "x"}, "expired": True}
        )
        assert r.verdict is Verdict.BLOCK
        assert handle_patch(r) is None

    def test_pending_approval_returns_none(self):
        r = ApprovalResult.from_dict({"patch": {"new_input": "x"}})
        assert r.verdict is None
        assert handle_patch(r) is None

    def test_evaluation_result_never_raises_attributeerror(self):
        # EvaluationResult has no is_blocking()/expired; the gate must not touch them.
        r = EvaluationResult.from_dict(_block(patch={"new_input": "x"}))
        assert handle_patch(r) is not None

    def test_block_without_patch_returns_none(self):
        assert handle_patch(EvaluationResult.from_dict(_block())) is None


class TestEnforcementUnchanged:
    def test_block_still_raises_even_with_patch(self):
        # Adding patch support must NOT suppress the default block; the helper is opt-in only.
        r = EvaluationResult.from_dict(
            _block(patch={"new_input": "x"}, reason="nope")
        )
        with pytest.raises(GovernanceBlockedError):
            raise_for_verdict(r)
