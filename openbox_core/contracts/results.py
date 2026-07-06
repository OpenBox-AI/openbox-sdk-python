"""Result contracts — Verdict, GuardrailsResult, EvaluationResult, ApprovalResult.

Pure, import-safe module: no network, crypto, OTel, logging, wall-clock, or
random. Strict dataclass constructors AND loose ``from_dict()`` parsers are
both public so callers can work with typed values or raw backend dicts.

Parsing preserves ``raw`` so nothing the backend sent is ever lost, and stays
tolerant of unknown keys (field-shape drift from Core must not crash SDKs).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

__all__ = [
    "Verdict",
    "GuardrailsResult",
    "EvaluationResult",
    "ApprovalResult",
]


class Verdict(str, Enum):
    """5-tier graduated response. Priority: HALT > BLOCK > REQUIRE_APPROVAL > CONSTRAIN > ALLOW."""

    ALLOW = "allow"
    CONSTRAIN = "constrain"
    REQUIRE_APPROVAL = "require_approval"
    BLOCK = "block"
    HALT = "halt"

    @classmethod
    def from_string(cls, value: str | None) -> Verdict:
        """Parse with v1.0 compat: 'continue'→ALLOW, 'stop'→HALT, 'require-approval'→REQUIRE_APPROVAL."""
        if value is None:
            return cls.ALLOW
        normalized = value.lower().replace("-", "_")
        if normalized == "continue":
            return cls.ALLOW
        if normalized == "stop":
            return cls.HALT
        if normalized in ("require_approval", "request_approval"):
            return cls.REQUIRE_APPROVAL
        try:
            return cls(normalized)
        except ValueError:
            return cls.ALLOW

    @property
    def priority(self) -> int:
        """Priority for aggregation: HALT=5, BLOCK=4, REQUIRE_APPROVAL=3, CONSTRAIN=2, ALLOW=1."""
        return {
            Verdict.ALLOW: 1,
            Verdict.CONSTRAIN: 2,
            Verdict.REQUIRE_APPROVAL: 3,
            Verdict.BLOCK: 4,
            Verdict.HALT: 5,
        }[self]

    @classmethod
    def highest_priority(cls, verdicts: list[Verdict]) -> Verdict:
        """Get highest priority verdict from list. Returns ALLOW if empty."""
        return max(verdicts, key=lambda v: v.priority) if verdicts else cls.ALLOW

    def should_stop(self) -> bool:
        """True if BLOCK or HALT."""
        return self in (Verdict.BLOCK, Verdict.HALT)

    def requires_approval(self) -> bool:
        """True if REQUIRE_APPROVAL."""
        return self == Verdict.REQUIRE_APPROVAL


@dataclass
class GuardrailsResult:
    """Guardrails check result from the governance API.

    Contains redacted input/output that should replace the original activity
    data, plus validation results that can block execution.
    """

    redacted_input: Any = None  # Redacted activity_input/activity_output (JSON-decoded)
    input_type: str = ""  # "activity_input" or "activity_output"
    raw_logs: dict[str, Any] | None = None  # Raw logs from guardrails evaluation
    validation_passed: bool = True  # If False, execution should be stopped
    reasons: list[dict[str, str]] = field(default_factory=list)  # [{type, field, reason}]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GuardrailsResult:
        return cls(
            redacted_input=data.get("redacted_input"),
            input_type=data.get("input_type", ""),
            raw_logs=data.get("raw_logs"),
            validation_passed=data.get("validation_passed", True),
            reasons=data.get("reasons") or [],
        )

    def get_reason_strings(self) -> list[str]:
        """Extract just the 'reason' field from each reason object."""
        return [r.get("reason", "") for r in self.reasons if r.get("reason")]


@dataclass
class EvaluationResult:
    """Response from a governance evaluation.

    ``guardrails`` and ``guardrails_result`` are the SAME object —
    ``guardrails_result`` is a read-only compatibility alias; there is no way
    for the two to diverge.

    Optional transport/diagnostic fields default to falsy values so strict
    construction stays terse.
    """

    verdict: Verdict
    reason: str | None = None
    policy_id: str | None = None
    risk_score: float = 0.0
    metadata: dict[str, Any] | None = None
    governance_event_id: str | None = None
    guardrails: GuardrailsResult | None = None
    approval_id: str | None = None
    approval_expiration_time: str | None = None
    trust_tier: str | None = None
    alignment_score: float | None = None
    behavioral_violations: list[str] | None = None
    constraints: list[dict[str, Any]] | None = None
    fallback_used: bool = False  # True when fail-open produced this result
    diagnostics: list[Any] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def guardrails_result(self) -> GuardrailsResult | None:
        """Alias of ``guardrails`` (same object)."""
        return self.guardrails

    @property
    def action(self) -> str:
        """Backward compat: return the v1.0 action string derived from verdict."""
        if self.verdict == Verdict.ALLOW:
            return "continue"
        if self.verdict == Verdict.HALT:
            return "stop"
        if self.verdict == Verdict.REQUIRE_APPROVAL:
            return "require-approval"
        return self.verdict.value

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvaluationResult:
        """Parse a governance response dict (v1.0 and v1.1 compatible).

        Verdict-first with v1.0 ``action`` fallback — the approval
        *action-precedence* change applies to :class:`ApprovalResult` only.
        Unknown keys are preserved in ``raw``, never an error.
        """
        guardrails = None
        if data.get("guardrails_result"):
            guardrails = GuardrailsResult.from_dict(data["guardrails_result"])
        elif data.get("guardrails"):
            guardrails = GuardrailsResult.from_dict(data["guardrails"])

        verdict = Verdict.from_string(data.get("verdict") or data.get("action", "continue"))

        return cls(
            verdict=verdict,
            reason=data.get("reason"),
            policy_id=data.get("policy_id"),
            risk_score=data.get("risk_score", 0.0),
            metadata=data.get("metadata"),
            governance_event_id=data.get("governance_event_id"),
            guardrails=guardrails,
            approval_id=data.get("approval_id"),
            approval_expiration_time=data.get("approval_expiration_time"),
            trust_tier=data.get("trust_tier"),
            alignment_score=data.get("alignment_score"),
            behavioral_violations=data.get("behavioral_violations"),
            constraints=data.get("constraints"),
            fallback_used=bool(data.get("fallback_used", False)),
            diagnostics=data.get("diagnostics") or [],
            raw=dict(data),
        )

    @classmethod
    def fallback_allow(cls, reason: str) -> EvaluationResult:
        """Allow-shaped result for fail-open network-error paths.

        ``fallback_used=True`` marks it as a fallback so callers can tell a
        policy ALLOW from an unreachable-Core ALLOW. A network error must never
        silently flip BLOCK→ALLOW without this marker.
        """
        return cls(verdict=Verdict.ALLOW, reason=reason, fallback_used=True)


@dataclass
class ApprovalResult:
    """Normalized HITL approval-poll response.

    Decision-source precedence: **``action`` wins over ``verdict``** when both
    are present.

    When NEITHER field is present, ``verdict`` is ``None`` (pending-unknown) —
    never auto-ALLOW. Expired approvals block unless the backend explicitly
    returned an allow-shaped verdict/action.
    """

    verdict: Verdict | None = None
    action: str | None = None
    reason: str | None = None
    approval_id: str | None = None
    approval_expiration_time: str | None = None
    expired: bool = False
    raw: dict[str, Any] = field(default_factory=dict)

    # Known decision vocabulary for approvals (current values + accepted aliases).
    # Anything OUTSIDE this set parses to None (pending) — the evaluate-path
    # leniency of Verdict.from_string (unknown -> ALLOW) is too loose at the
    # human-approval trust boundary and is not used here.
    _DECISION_VOCABULARY = frozenset(
        {
            "allow",
            "constrain",
            "require_approval",
            "request_approval",
            "block",
            "halt",
            "continue",
            "stop",
        }
    )

    @staticmethod
    def _parse_decision(value: Any) -> Verdict | None:
        """Strict, fail-safe decision parsing: empty/unknown -> None (pending)."""
        if not isinstance(value, str) or not value.strip():
            return None
        normalized = value.strip().lower().replace("-", "_")
        if normalized not in ApprovalResult._DECISION_VOCABULARY:
            return None
        return Verdict.from_string(normalized)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ApprovalResult:
        action = data.get("action")
        # Empty/whitespace action is absent; it must not shadow ``verdict``.
        if not isinstance(action, str) or not action.strip():
            action = None
        verdict_source = action if action is not None else data.get("verdict")
        verdict = cls._parse_decision(verdict_source)
        return cls(
            verdict=verdict,
            action=action,
            reason=data.get("reason"),
            # Normalize ``id`` → ``approval_id``.
            approval_id=data.get("approval_id") or data.get("id"),
            approval_expiration_time=data.get("approval_expiration_time"),
            expired=bool(data.get("expired", False)),
            raw=dict(data),
        )

    @property
    def allow_shaped(self) -> bool:
        """True when the backend explicitly returned an allow verdict/action."""
        return self.verdict == Verdict.ALLOW

    def is_blocking(self) -> bool:
        """True when this response must stop the operation.

        Expired approvals are blocking unless explicitly allow-shaped; an
        explicit BLOCK/HALT verdict is blocking regardless of expiry.
        """
        if self.expired:
            return not self.allow_shaped
        return self.verdict is not None and self.verdict.should_stop()

    def is_pending(self) -> bool:
        """True while the approval decision is still outstanding.

        Absent verdict/action (``None``) is pending — never auto-ALLOW.
        REQUIRE_APPROVAL and CONSTRAIN keep polling.
        """
        if self.expired:
            return False
        if self.verdict is None:
            return True
        return self.verdict in (Verdict.REQUIRE_APPROVAL, Verdict.CONSTRAIN)
