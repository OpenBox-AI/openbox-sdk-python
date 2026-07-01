"""ApprovalResult normalization tests — action-precedence, id aliasing, expiry."""

from openbox_core.contracts.results import ApprovalResult, Verdict


class TestDecisionPrecedence:
    def test_action_wins_over_verdict(self):
        # Deliberate behavior change vs Temporal (verdict-first there);
        # regression-gated before the Temporal SDK adopts this parser.
        result = ApprovalResult.from_dict({"verdict": "block", "action": "continue"})
        assert result.verdict is Verdict.ALLOW
        assert result.action == "continue"

    def test_verdict_used_when_no_action(self):
        result = ApprovalResult.from_dict({"verdict": "halt"})
        assert result.verdict is Verdict.HALT

    def test_absent_both_is_pending_never_auto_allow(self):
        result = ApprovalResult.from_dict({})
        assert result.verdict is None
        assert result.is_pending()
        assert not result.is_blocking()
        assert not result.allow_shaped


class TestIdNormalization:
    def test_id_normalized_to_approval_id(self):
        assert ApprovalResult.from_dict({"id": "legacy-9"}).approval_id == "legacy-9"

    def test_approval_id_preferred_over_id(self):
        result = ApprovalResult.from_dict({"approval_id": "new-1", "id": "legacy-9"})
        assert result.approval_id == "new-1"


class TestExpiry:
    def test_expired_blocks_by_default(self):
        result = ApprovalResult.from_dict({"expired": True})
        assert result.expired is True
        assert result.is_blocking()
        assert not result.is_pending()

    def test_expired_with_explicit_allow_does_not_block(self):
        result = ApprovalResult.from_dict({"expired": True, "action": "allow"})
        assert not result.is_blocking()

    def test_expired_with_block_verdict_blocks(self):
        result = ApprovalResult.from_dict({"expired": True, "verdict": "block"})
        assert result.is_blocking()


class TestPendingAndRaw:
    def test_require_approval_and_constrain_stay_pending(self):
        assert ApprovalResult.from_dict({"verdict": "require_approval"}).is_pending()
        assert ApprovalResult.from_dict({"verdict": "constrain"}).is_pending()

    def test_block_is_blocking_not_pending(self):
        result = ApprovalResult.from_dict({"action": "block", "reason": "nope"})
        assert result.is_blocking()
        assert not result.is_pending()
        assert result.reason == "nope"

    def test_raw_preserved(self):
        data = {"action": "allow", "surprise": [1, 2]}
        assert ApprovalResult.from_dict(data).raw == data
