"""GovernanceGate — always-strict validation orchestrating evaluate calls.

The gate is ALWAYS STRICT for OpenBox event contracts and runtime invariants:
malformed contracts raise ``ContractError`` BEFORE any network send. There is
deliberately NO ``mode``/``OBSERVE``/``SANITIZE``/``STRICT`` toggle anywhere in
this API — fail-open policy applies only to network errors inside the client,
never to contract violations.

Paths:
- ``evaluate``/``aevaluate``   — lifecycle events (no spans); the gate
  serializes the envelope dict directly.
- ``preflight``/``apreflight`` — hook STARTED-stage evaluation. Enforced by
  the hook runtime/adapter (BLOCK/HALT/REQUIRE_APPROVAL stop the operation).
- ``completed``/``acompleted`` — hook COMPLETED-stage telemetry. Influences
  *future* execution only; it never undoes the operation.

Hook body assembly is delegated to the injected ``payload_builder`` —
``wire/evaluate_payload.build_evaluate_payload`` is the single owner of the
evaluate body shape. The gate never reimplements it.

Enforcement priority (for adapters interpreting results):
HALT > BLOCK > guardrails-fail > REQUIRE_APPROVAL > CONSTRAIN > ALLOW.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .client import EvaluationClient
from .config import OpenBoxConfig
from .contracts.events import EventEnvelope
from .contracts.results import EvaluationResult, Verdict
from .errors import (
    GovernanceBlockedError,
    GovernanceHaltError,
    GuardrailsValidationError,
    OpenBoxConfigError,
)
from .serialization import apply_redaction, rfc3339_now, to_json_safe
from .validation.diagnostics import Diagnostic
from .validation.registry import validate_hook, validate_lifecycle
from .validation.span_normalization import redaction_diagnostics, strip_compat_noise

__all__ = ["GovernanceGate", "STAGE_STARTED", "STAGE_COMPLETED", "raise_for_verdict"]

STAGE_STARTED = "started"
STAGE_COMPLETED = "completed"

# payload_builder(event) -> (payload_dict, diagnostics)
PayloadBuilder = Callable[[EventEnvelope], tuple[dict[str, Any], list[Diagnostic]]]


class GovernanceGate:
    """Validate → serialize → evaluate → parse, strictly.

    Args:
        client: The EvaluationClient used for network calls.
        config: Resolved OpenBoxConfig (privacy settings are read here).
        payload_builder: Hook evaluate-body assembler. Wired to
            ``wire/evaluate_payload.build_evaluate_payload`` by the runtime;
            hook paths raise until one is provided (lifecycle paths work
            without it).
    """

    def __init__(
        self,
        client: EvaluationClient,
        config: OpenBoxConfig | None = None,
        *,
        payload_builder: PayloadBuilder | None = None,
    ):
        self._client = client
        self._config = config or OpenBoxConfig()
        self._payload_builder = payload_builder

    # ── Lifecycle events ──────────────────────────────────────────────────

    def evaluate(self, event: EventEnvelope) -> EvaluationResult:
        """Evaluate a lifecycle/signal/handoff event (strictly validated)."""
        payload, diagnostics = self._prepare_lifecycle(event)
        result = self._client.evaluate(payload)
        result.diagnostics.extend(d.to_dict() for d in diagnostics)
        return result

    async def aevaluate(self, event: EventEnvelope) -> EvaluationResult:
        """Async :meth:`evaluate`."""
        payload, diagnostics = self._prepare_lifecycle(event)
        result = await self._client.aevaluate(payload)
        result.diagnostics.extend(d.to_dict() for d in diagnostics)
        return result

    def _prepare_lifecycle(self, event: EventEnvelope) -> tuple[dict, list[Diagnostic]]:
        diagnostics = validate_lifecycle(event)
        payload = event.to_payload_dict()
        payload.setdefault("timestamp", rfc3339_now())
        # Legacy compat noise (spans=[] / span_count=0) never reaches the wire.
        payload, noise_diagnostics = strip_compat_noise(payload)
        diagnostics.extend(noise_diagnostics)
        return self._finalize_payload(payload, diagnostics)

    # ── Hook events ───────────────────────────────────────────────────────

    def preflight(self, event: EventEnvelope) -> EvaluationResult:
        """Started-stage hook evaluation (validated; body via payload_builder)."""
        payload, diagnostics = self._prepare_hook(event, STAGE_STARTED)
        result = self._client.evaluate(payload)
        result.diagnostics.extend(d.to_dict() for d in diagnostics)
        return result

    async def apreflight(self, event: EventEnvelope) -> EvaluationResult:
        """Async :meth:`preflight`."""
        payload, diagnostics = self._prepare_hook(event, STAGE_STARTED)
        result = await self._client.aevaluate(payload)
        result.diagnostics.extend(d.to_dict() for d in diagnostics)
        return result

    def completed(self, event: EventEnvelope) -> EvaluationResult:
        """Completed-stage hook telemetry. Never undoes the operation — the
        result may only influence FUTURE execution (adapter decides)."""
        payload, diagnostics = self._prepare_hook(event, STAGE_COMPLETED)
        result = self._client.evaluate(payload)
        result.diagnostics.extend(d.to_dict() for d in diagnostics)
        return result

    async def acompleted(self, event: EventEnvelope) -> EvaluationResult:
        """Async :meth:`completed`."""
        payload, diagnostics = self._prepare_hook(event, STAGE_COMPLETED)
        result = await self._client.aevaluate(payload)
        result.diagnostics.extend(d.to_dict() for d in diagnostics)
        return result

    def _prepare_hook(self, event: EventEnvelope, stage: str) -> tuple[dict, list[Diagnostic]]:
        diagnostics = validate_hook(event, stage)
        if self._payload_builder is None:
            raise OpenBoxConfigError(
                "GovernanceGate has no payload_builder — hook evaluation requires "
                "wire/evaluate_payload.build_evaluate_payload (wired by OpenBoxRuntime)"
            )
        payload, builder_diagnostics = self._payload_builder(event)
        diagnostics.extend(builder_diagnostics)
        payload.setdefault("timestamp", rfc3339_now())
        return self._finalize_payload(payload, diagnostics)

    # ── Shared payload finishing ──────────────────────────────────────────

    def _finalize_payload(
        self, payload: dict, diagnostics: list[Diagnostic]
    ) -> tuple[dict, list[Diagnostic]]:
        """JSON-safety + privacy redaction, applied BEFORE signing/sending."""
        payload = to_json_safe(payload)
        redact_keys = self._config.privacy.redact_keys
        if redact_keys:
            payload, changed = apply_redaction(payload, redact_keys)
            diagnostics.extend(redaction_diagnostics(changed))
        return payload, diagnostics


def raise_for_verdict(result: EvaluationResult) -> EvaluationResult | None:
    """Default enforcement helper implementing the verdict priority order.

    HALT > BLOCK > guardrails-fail > REQUIRE_APPROVAL > CONSTRAIN > ALLOW.

    Raises the core error types for stop-shaped results; returns the result
    for REQUIRE_APPROVAL (caller drives approval) and for ALLOW/CONSTRAIN
    (caller proceeds). Framework adapters typically translate these into
    native errors instead of calling this helper.
    """
    verdict = result.verdict
    if verdict == Verdict.HALT:
        raise GovernanceHaltError(result.reason or "Halted by governance policy")
    if verdict == Verdict.BLOCK:
        raise GovernanceBlockedError(verdict, result.reason or "Blocked by governance policy")
    # Guardrails failure outranks approval so it is never swallowed by a HITL flow.
    if result.guardrails and not result.guardrails.validation_passed:
        reasons = result.guardrails.get_reason_strings()
        raise GuardrailsValidationError(reasons or ["Guardrails validation failed"])
    return result
