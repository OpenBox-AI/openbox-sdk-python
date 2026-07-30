"""OpenBox base SDK — unified exception hierarchy.

Pure module: no network, crypto, OTel, logging, or wall-clock imports. Safe to
import from constrained framework paths.

Hierarchy:
    OpenBoxError (base)
    ├── ContractError               # strict-gate event/runtime contract violation
    ├── OpenBoxConfigError
    │   ├── OpenBoxAuthError
    │   │   └── OpenBoxSigningError # Core rejected a signed request (v1 DID or v2 Okta)
    │   ├── OpenBoxNetworkError
    │   └── OpenBoxInsecureURLError
    ├── GovernanceBlockedError      # hook/activity verdict BLOCK
    ├── GovernanceHaltError         # verdict HALT (framework-level termination)
    ├── GovernanceAPIError          # governance API failure (fail_closed)
    ├── GuardrailsValidationError   # guardrails validation_passed=False
    ├── ApprovalExpiredError        # HITL approval window expired
    ├── ApprovalRejectedError       # HITL approval explicitly rejected
    └── ApprovalTimeoutError        # HITL polling exceeded max wait
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .contracts.results import Verdict

__all__ = [
    "OpenBoxError",
    "ContractError",
    "OpenBoxConfigError",
    "OpenBoxAuthError",
    "OpenBoxNetworkError",
    "OpenBoxInsecureURLError",
    "OpenBoxSigningError",
    "map_signing_error",
    "GovernanceBlockedError",
    "GovernanceHaltError",
    "GovernanceAPIError",
    "GuardrailsValidationError",
    "ApprovalExpiredError",
    "ApprovalRejectedError",
    "ApprovalTimeoutError",
    "extract_governance_error",
]


# ═══════════════════════════════════════════════════════════════════
# Base
# ═══════════════════════════════════════════════════════════════════


class OpenBoxError(Exception):
    """Base class for all OpenBox SDK errors."""


# ═══════════════════════════════════════════════════════════════════
# Strict-gate contract violations
# ═══════════════════════════════════════════════════════════════════


class ContractError(OpenBoxError):
    """Raised by the always-strict gate on a malformed event/runtime contract.

    Contract violations raise *before* any network send, regardless of the
    ``on_api_error`` fail-open/fail-closed setting — fail-open applies only to
    network errors, never to contract violations.

    Attributes:
        code: Machine-readable violation code (e.g. ``HOOK_TRIGGER_FALSE``).
        detail: Optional structured context about the violation.
    """

    def __init__(self, message: str, code: str = "", detail: dict | None = None):
        self.code = code
        self.detail = detail or {}
        super().__init__(message)


# ═══════════════════════════════════════════════════════════════════
# Configuration errors
# ═══════════════════════════════════════════════════════════════════


class OpenBoxConfigError(OpenBoxError):
    """Raised when OpenBox configuration fails."""


class OpenBoxAuthError(OpenBoxConfigError):
    """Raised when API key validation fails."""


class OpenBoxNetworkError(OpenBoxConfigError):
    """Raised when network connectivity fails."""


class OpenBoxInsecureURLError(OpenBoxConfigError):
    """Raised when HTTP is used for non-localhost URLs."""


class OpenBoxSigningError(OpenBoxAuthError):
    """Raised when Core rejects a signed request — v1 OpenBox DID (AIP) or
    v2 Okta AI Agent assertion.

    Attributes:
        reason_code: Core's machine reason code (e.g. ``signature_invalid``
            for v1, ``assertion_signature_invalid`` for v2).
    """

    def __init__(self, message: str, reason_code: str | None = None):
        self.reason_code = reason_code
        super().__init__(message)


# Core signed-request rejection reason codes → actionable SDK guidance.
# Forward-compatible: Core today often collapses identity failures into a
# generic "invalid token" body with no machine code; these richer messages
# activate once Core emits a machine reason code ("reason_code"/"code"/"reason").
#
# v1 (OpenBox DID / AIP) codes and v2 (Okta AI Agent, contract §7) codes are
# both covered here — they are disjoint strings, so one map is unambiguous
# for both signing contracts.
_SIGNING_REASON_MESSAGES: dict[str, str] = {
    # ── v1 (OpenBox DID / AIP) ──────────────────────────────────────────
    "signature_invalid": (
        "Request signature rejected (signature_invalid). The signed bytes did not "
        "match — usually a body-hash mismatch (send content= bytes, never json=) or "
        "a wrong/rotated private key."
    ),
    "nonce_replayed": (
        "Request nonce was already used (nonce_replayed). Each request must carry a "
        "fresh nonce; do not retry a fully-prepared request verbatim."
    ),
    "did_agent_mismatch": (
        "DID does not match the authenticated agent (did_agent_mismatch). Check that "
        "agent_did matches the agent the API key/private key were provisioned for."
    ),
    "verifier_not_configured": (
        "Core has no verifier for this agent (verifier_not_configured). The agent's "
        "public key may not be imported to KMS yet — re-provision the agent."
    ),
    # Core's code is "timestamp_outside_window"; "timestamp_skew" kept as an alias.
    "timestamp_outside_window": (
        "Request timestamp outside the allowed window (timestamp_outside_window). Sync "
        "the host clock (NTP); signatures are valid only within ±300s."
    ),
    "timestamp_skew": (
        "Request timestamp outside the allowed window (timestamp_skew). Sync the host "
        "clock (NTP); signatures are valid only within ±300s."
    ),
    # ── v2 (Okta AI Agent) — docs/agent-identity-v2-contract.md §7 ──────
    "assertion_missing": (
        "No agent assertion was sent (assertion_missing). okta_ai_agent identity "
        "requires a signed X-OpenBox-Agent-Assertion header on every v2 request."
    ),
    "assertion_malformed": (
        "The agent assertion could not be parsed (assertion_malformed). Check that a "
        "compact JWT — not JSON or a bare token — is sent."
    ),
    "assertion_typ_mismatch": (
        "Assertion 'typ' did not equal 'openbox-agent-proof+jwt' (assertion_typ_mismatch)."
    ),
    "assertion_alg_rejected": (
        "Assertion algorithm is not allowed (assertion_alg_rejected). Only RS256 is "
        "supported at launch."
    ),
    "assertion_embedded_key_rejected": (
        "Assertion carried an embedded jwk/jku/x5u header, which Core always rejects "
        "(assertion_embedded_key_rejected)."
    ),
    "assertion_key_too_small": (
        "Assertion signed with an RSA key below the 2048-bit minimum "
        "(assertion_key_too_small)."
    ),
    "assertion_signature_invalid": (
        "Assertion signature did not verify (assertion_signature_invalid). Usually a "
        "body-hash mismatch (send content= bytes, never json=) or the wrong/rotated "
        "Okta private key."
    ),
    "method_endpoint_mismatch": (
        "This agent's configured verification method does not match the endpoint "
        "version called (method_endpoint_mismatch). An okta_ai_agent identity must "
        "call /api/v2/*; an openbox_did/legacy_unsigned identity must call /api/v1/*."
    ),
    "binding_invalid": (
        "The assertion's organization/agent/credential binding did not match "
        "(binding_invalid)."
    ),
    "transition_proof_invalid": (
        "The transition intent is unknown, expired, consumed, or does not match this "
        "agent/organization (transition_proof_invalid)."
    ),
    "proof_expired": (
        "The assertion or proof-of-possession expired before Core received it "
        "(proof_expired). Check clock sync and retry with a fresh assertion."
    ),
    "proof_replayed": (
        "Assertion 'jti' was already used (proof_replayed). Each request must carry a "
        "fresh jti; do not retry a fully-prepared request verbatim."
    ),
    "identity_ineligible": (
        "The linked Okta identity or credential is not currently eligible to verify "
        "(identity_ineligible) — inactive, unlinked, or a stale credential projection."
    ),
}


def map_signing_error(reason_code: str | None, fallback: str = "") -> OpenBoxSigningError:
    """Map a Core signing reason code to an actionable OpenBoxSigningError.

    Unknown/empty codes fall back to a generic message (optionally augmented with
    ``fallback`` context). Never raises — always returns an exception to raise.
    """
    if reason_code and reason_code in _SIGNING_REASON_MESSAGES:
        return OpenBoxSigningError(_SIGNING_REASON_MESSAGES[reason_code], reason_code)
    msg = fallback or (
        "Signed request rejected by OpenBox Core"
        + (f" ({reason_code})" if reason_code else "")
        + "."
    )
    return OpenBoxSigningError(msg, reason_code)


# ═══════════════════════════════════════════════════════════════════
# Governance verdict errors
# ═══════════════════════════════════════════════════════════════════


class GovernanceBlockedError(OpenBoxError):
    """Raised when governance blocks an operation (default adapter behavior).

    Framework adapters typically translate this into a native error type; the
    base adapter raises it directly.

    Attributes:
        verdict: The Verdict enum value (normalized from string if needed).
        reason: Human-readable explanation from the policy engine.
        url: The URL or resource identifier that was blocked (optional).
    """

    def __init__(self, verdict: str | Verdict, reason: str, url: str = ""):
        # Lazy import avoids a hard module-level dependency on contracts.
        if isinstance(verdict, str):
            from .contracts.results import Verdict

            self.verdict = Verdict.from_string(verdict)
        else:
            self.verdict = verdict
        self.reason = reason
        self.url = url
        super().__init__(f"Governance {self.verdict.value}: {reason}")


class GovernanceHaltError(OpenBoxError):
    """Raised when governance halts execution (HALT verdict).

    HALT is the nuclear option — the framework adapter decides how to stop
    future work.
    """

    def __init__(self, message: str):
        super().__init__(message)


class GovernanceAPIError(OpenBoxError):
    """Raised when the governance API fails and policy is fail_closed."""


# ═══════════════════════════════════════════════════════════════════
# Guardrails errors
# ═══════════════════════════════════════════════════════════════════


class GuardrailsValidationError(OpenBoxError):
    """Raised when guardrails validation_passed is False.

    Attributes:
        reasons: List of reason strings from the guardrails evaluation.
    """

    def __init__(self, reasons: list[str] | None = None):
        self.reasons = reasons or []
        reason_str = (
            "; ".join(self.reasons) if self.reasons else "Guardrails validation failed"
        )
        super().__init__(reason_str)


# ═══════════════════════════════════════════════════════════════════
# HITL approval errors
# ═══════════════════════════════════════════════════════════════════


class ApprovalExpiredError(OpenBoxError):
    """Raised when the HITL approval window expires (server-side deadline)."""


class ApprovalRejectedError(OpenBoxError):
    """Raised when a HITL approval is explicitly rejected by a human."""


class ApprovalTimeoutError(OpenBoxError):
    """Raised when HITL polling exceeds the configured max wait time."""

    def __init__(self, max_wait_ms: int | None = None):
        self.max_wait_ms = max_wait_ms
        msg = (
            f"Approval polling timed out after {max_wait_ms}ms"
            if max_wait_ms
            else "Approval polling timed out"
        )
        super().__init__(msg)


# ═══════════════════════════════════════════════════════════════════
# Utility: exception chain walker
# ═══════════════════════════════════════════════════════════════════


def extract_governance_error(exc: BaseException) -> GovernanceBlockedError | None:
    """Walk an exception chain to find a wrapped GovernanceBlockedError.

    Frameworks and client libraries often wrap errors. This utility recovers
    the original GovernanceBlockedError for verdict inspection.

    Args:
        exc: Any exception, potentially wrapping a GovernanceBlockedError.

    Returns:
        The GovernanceBlockedError if found in the chain, None otherwise.
    """
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, GovernanceBlockedError):
            return current
        # Walk both explicit (__cause__) and implicit (__context__) chains
        next_exc = getattr(current, "__cause__", None) or getattr(
            current, "__context__", None
        )
        # Also check framework .cause properties.
        if next_exc is None:
            next_exc = getattr(current, "cause", None)
        current = next_exc
    return None
