"""FrameworkAdapter protocol + the core default adapter.

The adapter is the ONE seam where governance verdicts become framework-native
effects. There is exactly one path: wrapper -> hook runtime -> adapter.
Framework SDKs override the callbacks (e.g. Temporal maps block/halt to
ApplicationError types and drives its HITL retry loop); the default
``CoreAdapter`` raises the core error types directly.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from ..contracts.results import EvaluationResult
from ..errors import (
    ApprovalExpiredError,
    ApprovalRejectedError,
    GovernanceBlockedError,
    GovernanceHaltError,
)

if TYPE_CHECKING:
    from typing import NoReturn

    from ..approvals import ApprovalPoller

__all__ = ["FrameworkAdapter", "CoreAdapter"]


@runtime_checkable
class FrameworkAdapter(Protocol):
    """Native-enforcement callbacks implemented by framework SDKs."""

    name: str

    async def handle_approval(self, result: EvaluationResult) -> None:
        """Drive the framework's approval flow for REQUIRE_APPROVAL.

        Return normally when approved; raise the framework's native rejection/
        expiry error otherwise. Called BEFORE the real operation runs.

        Adapters may ALSO define a plain-sync ``handle_approval_sync(result)``
        (not part of the required protocol): when present, sync hook paths
        delegate to it instead of driving the core inline poller — frameworks
        whose HITL is retry-based (e.g. Temporal) raise their native retryable
        pending error there.
        """
        ...

    def raise_lifecycle_blocked(self, result: EvaluationResult) -> NoReturn:
        """Produce the framework-native effect for a BLOCK/HALT lifecycle verdict."""
        ...

    def raise_hook_blocked(self, result: EvaluationResult) -> NoReturn:
        """Produce the framework-native effect for a BLOCK/HALT started-hook
        verdict. The real operation has NOT run."""
        ...

    def on_completed_hook_result(self, result: EvaluationResult) -> None:
        """React to a completed-hook verdict. The operation ALREADY ran —
        implementations may only affect FUTURE execution (e.g. mark the
        activity/session blocked); they must never pretend to undo work."""
        ...


class CoreAdapter:
    """Default adapter — raises core error types (framework-agnostic).

    Args:
        approval_poller: Optional ApprovalPoller enabling a real HITL wait.
            Without one, REQUIRE_APPROVAL is fail-safe: rejected (the operation
            does not run) rather than silently allowed.
    """

    name = "core"

    def __init__(self, approval_poller: ApprovalPoller | None = None):
        self._poller = approval_poller

    async def handle_approval(self, result: EvaluationResult) -> None:
        if self._poller is None or not result.approval_id:
            raise ApprovalRejectedError(
                "REQUIRE_APPROVAL verdict but no approval flow is configured — "
                "failing safe (operation not run)"
            )
        approval = await self._poller.await_decision(
            result.raw.get("workflow_id", ""),
            result.raw.get("run_id", ""),
            result.raw.get("activity_id", ""),
        )
        if approval.allow_shaped:
            return
        if approval.expired:
            raise ApprovalExpiredError(approval.reason or "Approval window expired")
        raise ApprovalRejectedError(approval.reason or "Approval rejected")

    def raise_lifecycle_blocked(self, result: EvaluationResult) -> NoReturn:
        self._raise_stop(result)

    def raise_hook_blocked(self, result: EvaluationResult) -> NoReturn:
        self._raise_stop(result)

    def on_completed_hook_result(self, result: EvaluationResult) -> None:
        # Completed telemetry never undoes the operation; the runtime records
        # abort/halt flags for FUTURE execution — nothing to do here.
        return None

    @staticmethod
    def _raise_stop(result: EvaluationResult) -> NoReturn:
        from ..contracts.results import Verdict

        if result.verdict is Verdict.HALT:
            raise GovernanceHaltError(result.reason or "Halted by governance policy")
        raise GovernanceBlockedError(
            result.verdict, result.reason or "Blocked by governance policy"
        )
