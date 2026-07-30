"""Sync + async EvaluationClient for OpenBox Core.

v1 (OpenBox DID / inferred legacy_unsigned) endpoints:
    POST /api/v1/governance/evaluate   — lifecycle + hook evaluations
    POST /api/v1/governance/approval   — HITL approval polling
    GET  /api/v1/auth/validate         — API key / signing validation
    POST /api/v1/handoffs              — source-authenticated handoff

v2 (Okta AI Agent) endpoints — selected automatically when the client is
constructed with an ``OktaAgentIdentity`` (proposal §13.3; contract §2.2):
    POST /api/v2/governance/evaluate
    POST /api/v2/governance/approval
    GET  /api/v2/auth/validate
    POST /api/v2/handoffs

There is no cross-version retry: the identity type picks the route once per
call, and a v2 auth failure is never retried against v1 (or vice versa).

Transport rules:
- Signed requests send ``content=body_bytes`` — NEVER ``json=`` (client-side
  re-serialization breaks Core's body-hash verification).
- ``httpx`` is imported lazily so this module never taints pure import paths.
- Fail modes apply to NETWORK errors only — contract violations raise before
  any send (see gate.py) and are never converted to fail-open ALLOWs:
    * fail_open (default): return allow-shaped ``EvaluationResult`` with
      ``fallback_used=True`` (callers can tell it apart from a policy ALLOW).
    * fail_closed: raise ``GovernanceAPIError`` (adapters map to native
      halt/block behavior).
- 401/403 are AUTHENTICATION failures, never network errors (proposal
  §13.6): evaluate/approval/validate/handoff/transition-preflight all raise
  an actionable typed error regardless of ``on_api_error`` — they never
  produce a fallback ALLOW and never launder into "still pending".
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from .contracts.results import ApprovalResult, EvaluationResult
from .errors import (
    GovernanceAPIError,
    OpenBoxAuthError,
    OpenBoxConfigError,
    OpenBoxNetworkError,
    map_signing_error,
)
from .identity import AgentIdentity, prepare_signed_request
from .identity_okta import OktaAgentIdentity, prepare_okta_signed_request
from .identity_transitions import (
    TRANSITION_PROOF_PATH,
    TRANSITION_PROOF_PATH_V2,
    build_okta_transition_proof_request,
    build_openbox_did_transition_proof_request,
)
from .identity_types import OktaAiAgentIdentityConfig, OpenBoxDidIdentityConfig
from .sdk_version import DEFAULT_SDK_ENGINE, DEFAULT_SDK_LANGUAGE

__all__ = [
    "EVALUATE_PATH",
    "APPROVAL_PATH",
    "AUTH_VALIDATE_PATH",
    "HANDOFF_PATH",
    "TRANSITION_PROOF_PATH",
    "EVALUATE_PATH_V2",
    "APPROVAL_PATH_V2",
    "AUTH_VALIDATE_PATH_V2",
    "HANDOFF_PATH_V2",
    "TRANSITION_PROOF_PATH_V2",
    "EvaluationClient",
    "check_expiration",
]

logger = logging.getLogger(__name__)

# v1 (OpenBox DID / inferred legacy_unsigned) routes — byte-compatible, unchanged.
EVALUATE_PATH = "/api/v1/governance/evaluate"
APPROVAL_PATH = "/api/v1/governance/approval"
AUTH_VALIDATE_PATH = "/api/v1/auth/validate"
HANDOFF_PATH = "/api/v1/handoffs"

# v2 (Okta AI Agent) routes (contract §2.2).
EVALUATE_PATH_V2 = "/api/v2/governance/evaluate"
APPROVAL_PATH_V2 = "/api/v2/governance/approval"
AUTH_VALIDATE_PATH_V2 = "/api/v2/auth/validate"
HANDOFF_PATH_V2 = "/api/v2/handoffs"

# Re-exported from identity_transitions for callers importing path constants
# from this module (matches the existing v1/v2 constant convention above).
# TRANSITION_PROOF_PATH / TRANSITION_PROOF_PATH_V2 imported above.


def check_expiration(data: dict) -> dict:
    """Set ``expired=True`` if ``approval_expiration_time`` is past.

    Modifies ``data`` in place and returns it. Handles ISO ``Z``, ISO offset,
    and space-separated DB formats. Parse failures are logged, never raised.
    """
    expiration_time_str = data.get("approval_expiration_time")
    if not expiration_time_str:
        return data
    try:
        normalized = str(expiration_time_str).replace("Z", "+00:00").replace(" ", "T")
        expiration_time = datetime.fromisoformat(normalized)
        if expiration_time.tzinfo is None:
            expiration_time = expiration_time.replace(tzinfo=UTC)
        if datetime.now(UTC) > expiration_time:
            data["expired"] = True
    except (ValueError, TypeError) as e:
        logger.warning(
            f"Failed to parse approval_expiration_time '{expiration_time_str}': {e}"
        )
    return data


def _extract_reason_code(body: bytes | None) -> str | None:
    """Machine reason code from Core's JSON error body, if present."""
    import json

    if not body:
        return None
    try:
        data = json.loads(body.decode("utf-8", errors="replace"))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    code = data.get("reason_code") or data.get("code") or data.get("reason")
    return code if isinstance(code, str) else None


class EvaluationClient:
    """HTTP client for the OpenBox Core governance API (sync + async).

    Holds persistent ``httpx.Client``/``httpx.AsyncClient`` instances created
    lazily on first use; call :meth:`close`/:meth:`aclose` on shutdown.
    """

    def __init__(
        self,
        api_url: str,
        api_key: str,
        *,
        timeout_seconds: float = 30.0,
        on_api_error: str = "fail_open",
        identity: AgentIdentity | OktaAgentIdentity | None = None,
        sdk_version: str | None = None,
        sdk_engine: str = DEFAULT_SDK_ENGINE,
        sdk_language: str = DEFAULT_SDK_LANGUAGE,
        transport: Any = None,
        async_transport: Any = None,
    ):
        """Args:
            api_url: Core base URL (no trailing slash needed).
            api_key: Bearer API key.
            timeout_seconds: Per-request timeout.
            on_api_error: "fail_open" (default) or "fail_closed".
            identity: Loaded identity for signed requests — an
                ``AgentIdentity`` selects v1 OpenBox DID routes, an
                ``OktaAgentIdentity`` selects v2 Okta AI Agent routes, and
                ``None`` selects inferred v1 legacy_unsigned (API-key-only).
            sdk_version/sdk_engine/sdk_language: Values used to build
                X-OpenBox-SDK-Version as openbox-{engine}-{language}-v{version}.
            transport/async_transport: Optional httpx transports (tests inject
                ``httpx.MockTransport`` here; production leaves them None).
        """
        if on_api_error not in ("fail_open", "fail_closed"):
            raise ValueError(f"on_api_error must be 'fail_open' or 'fail_closed', got {on_api_error!r}")
        self._api_url = api_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout_seconds
        self._on_api_error = on_api_error
        self._identity = identity
        self._sdk_version = sdk_version
        self._sdk_engine = sdk_engine
        self._sdk_language = sdk_language
        self._transport = transport
        self._async_transport = async_transport
        self._sync_client: Any = None
        self._async_client: Any = None

    # ── Transport plumbing ────────────────────────────────────────────────

    def _sync(self) -> Any:
        if self._sync_client is None:
            import httpx

            self._sync_client = httpx.Client(timeout=self._timeout, transport=self._transport)
        return self._sync_client

    def _async(self) -> Any:
        if self._async_client is None:
            import httpx

            self._async_client = httpx.AsyncClient(
                timeout=self._timeout, transport=self._async_transport
            )
        return self._async_client

    def close(self) -> None:
        """Close the sync transport (idempotent)."""
        if self._sync_client is not None:
            self._sync_client.close()
            self._sync_client = None

    async def aclose(self) -> None:
        """Close both transports (idempotent)."""
        self.close()
        if self._async_client is not None:
            await self._async_client.aclose()
            self._async_client = None

    def _prepared(
        self, method: str, v1_path: str, v2_path: str, payload: dict | None
    ) -> tuple[str, dict, bytes]:
        """Build ``(url, headers, body)`` for the version selected by identity type.

        An ``OktaAgentIdentity`` routes to ``v2_path`` and signs a v2
        assertion; any other identity (``AgentIdentity`` or ``None``) routes
        to ``v1_path`` — this is the ONLY branch point for endpoint version,
        so there is no code path that can retry a v2 call against v1 or vice
        versa (proposal §13.3).
        """
        if isinstance(self._identity, OktaAgentIdentity):
            headers, body = prepare_okta_signed_request(
                method,
                v2_path,
                payload,
                api_key=self._api_key,
                identity=self._identity,
                sdk_version=self._sdk_version,
                sdk_engine=self._sdk_engine,
                sdk_language=self._sdk_language,
            )
            return f"{self._api_url}{v2_path}", headers, body

        headers, body = prepare_signed_request(
            method,
            v1_path,
            payload,
            api_key=self._api_key,
            identity=self._identity,
            sdk_version=self._sdk_version,
            sdk_engine=self._sdk_engine,
            sdk_language=self._sdk_language,
        )
        return f"{self._api_url}{v1_path}", headers, body

    def _classify_auth_failure(self, response: Any, *, signed: bool) -> Exception:
        """Build the exception for a 401/403 response.

        A machine reason code is only attributed to a SIGNED request (v1 DID
        or v2 Okta assertion) — an API-key-only request gets the generic
        message. ``signed`` is explicit (not read from ``self._identity``)
        because a transition-preflight call always signs with a candidate
        identity regardless of this client's own configured mode.
        """
        reason_code = _extract_reason_code(response.content) if signed else None
        if reason_code:
            return map_signing_error(reason_code)
        return OpenBoxAuthError(
            f"Authentication rejected (HTTP {response.status_code}). "
            "Check your API key at dashboard.openbox.ai"
        )

    # ── Evaluate ──────────────────────────────────────────────────────────

    def evaluate(self, payload: dict) -> EvaluationResult:
        """POST a governance event; parse the verdict.

        401/403 always raise (fails closed regardless of ``on_api_error`` —
        an authentication failure is never a network error). Other NETWORK
        errors never raise under fail_open — they return a
        ``fallback_used=True`` ALLOW."""
        url, headers, body = self._prepared("POST", EVALUATE_PATH, EVALUATE_PATH_V2, payload)
        try:
            response = self._sync().post(url, content=body, headers=headers)
        except Exception as e:  # network layer
            return self._network_failure(f"Governance API unreachable: {e}")
        return self._parse_evaluate_response(response)

    async def aevaluate(self, payload: dict) -> EvaluationResult:
        """Async :meth:`evaluate`."""
        url, headers, body = self._prepared("POST", EVALUATE_PATH, EVALUATE_PATH_V2, payload)
        try:
            response = await self._async().post(url, content=body, headers=headers)
        except Exception as e:
            return self._network_failure(f"Governance API unreachable: {e}")
        return self._parse_evaluate_response(response)

    def _parse_evaluate_response(self, response: Any) -> EvaluationResult:
        if response.status_code in (401, 403):
            raise self._classify_auth_failure(response, signed=self._identity is not None)
        if response.status_code >= 400:
            return self._network_failure(f"Governance API error: HTTP {response.status_code}")
        try:
            data = response.json()
        except Exception as e:
            return self._network_failure(f"Governance API returned unparseable body: {e}")
        result = EvaluationResult.from_dict(data)
        if result.verdict.should_stop():
            logger.info(f"Governance blocked: {result.reason} (policy: {result.policy_id})")
        return result

    def _network_failure(self, reason: str) -> EvaluationResult:
        """Apply the on_api_error policy to a NETWORK failure."""
        logger.warning(reason)
        if self._on_api_error == "fail_closed":
            raise GovernanceAPIError(reason)
        return EvaluationResult.fallback_allow(reason)

    # ── Approval polling ──────────────────────────────────────────────────

    def poll_approval(self, workflow_id: str, run_id: str, activity_id: str) -> ApprovalResult | None:
        """Poll HITL approval status once.

        401/403 always raise (fails closed — an authentication failure must
        never be laundered into "still pending"). A genuine network/transport
        failure or non-200 still returns ``None`` (callers treat that as
        still-pending and retry)."""
        payload = {"workflow_id": workflow_id, "run_id": run_id, "activity_id": activity_id}
        url, headers, body = self._prepared("POST", APPROVAL_PATH, APPROVAL_PATH_V2, payload)
        try:
            response = self._sync().post(url, content=body, headers=headers)
        except Exception as e:
            logger.warning(f"Failed to poll approval status: {e}")
            return None
        return self._parse_approval_response(response)

    async def apoll_approval(
        self, workflow_id: str, run_id: str, activity_id: str
    ) -> ApprovalResult | None:
        """Async :meth:`poll_approval`."""
        payload = {"workflow_id": workflow_id, "run_id": run_id, "activity_id": activity_id}
        url, headers, body = self._prepared("POST", APPROVAL_PATH, APPROVAL_PATH_V2, payload)
        try:
            response = await self._async().post(url, content=body, headers=headers)
        except Exception as e:
            logger.warning(f"Failed to poll approval status: {e}")
            return None
        return self._parse_approval_response(response)

    def _parse_approval_response(self, response: Any) -> ApprovalResult | None:
        if response.status_code in (401, 403):
            raise self._classify_auth_failure(response, signed=self._identity is not None)
        if response.status_code != 200:
            logger.warning(f"Failed to get approval status: HTTP {response.status_code}")
            return None
        try:
            data = response.json()
        except Exception as e:
            logger.warning(f"Failed to parse approval response: {e}")
            return None
        check_expiration(data)
        return ApprovalResult.from_dict(data)

    # ── Auth validation ───────────────────────────────────────────────────

    def validate_api_key(self) -> bool:
        """GET the version-appropriate auth-validate route (signed when
        identity is configured).

        Returns True on success. Raises OpenBoxAuthError / OpenBoxSigningError
        on 401/403, OpenBoxNetworkError on connectivity failure.
        """
        url, headers, _ = self._prepared("GET", AUTH_VALIDATE_PATH, AUTH_VALIDATE_PATH_V2, None)
        try:
            response = self._sync().get(url, headers=headers)
        except Exception as e:
            raise OpenBoxNetworkError(f"Cannot reach OpenBox Core at {self._api_url}: {e}") from e
        return self._parse_auth_response(response)

    async def avalidate_api_key(self) -> bool:
        """Async :meth:`validate_api_key`."""
        url, headers, _ = self._prepared("GET", AUTH_VALIDATE_PATH, AUTH_VALIDATE_PATH_V2, None)
        try:
            response = await self._async().get(url, headers=headers)
        except Exception as e:
            raise OpenBoxNetworkError(f"Cannot reach OpenBox Core at {self._api_url}: {e}") from e
        return self._parse_auth_response(response)

    def _parse_auth_response(self, response: Any) -> bool:
        if response.status_code == 200:
            return True
        if response.status_code in (401, 403):
            raise self._classify_auth_failure(response, signed=self._identity is not None)
        raise OpenBoxNetworkError(
            f"Cannot reach OpenBox Core at {self._api_url}: HTTP {response.status_code}"
        )

    # ── Source-authenticated handoff (proposal §13.2/§15.1) ────────────────

    def emit_handoff(self, target_agent_id: str, reason: str | None = None) -> dict[str, Any]:
        """POST a source-authenticated handoff.

        This client's configured identity is always ``from_agent``;
        ``target_agent_id`` names the receiving OpenBox agent. Routes to
        :data:`HANDOFF_PATH` (v1, OpenBox DID) or :data:`HANDOFF_PATH_V2`
        (v2, Okta AI Agent) by identity type, same as :meth:`evaluate`.

        Raises ``OpenBoxConfigError`` for inferred unsigned mode (no
        identity configured) — there is no source to prove, so this never
        silently falls back to the legacy receiver-authenticated governance
        handoff event; un-upgraded callers keep using that event directly.
        """
        payload = self._handoff_payload(target_agent_id, reason)
        url, headers, body = self._prepared("POST", HANDOFF_PATH, HANDOFF_PATH_V2, payload)
        try:
            response = self._sync().post(url, content=body, headers=headers)
        except Exception as e:
            raise OpenBoxNetworkError(f"Cannot reach OpenBox Core at {self._api_url}: {e}") from e
        return self._parse_handoff_response(response)

    async def aemit_handoff(self, target_agent_id: str, reason: str | None = None) -> dict[str, Any]:
        """Async :meth:`emit_handoff`."""
        payload = self._handoff_payload(target_agent_id, reason)
        url, headers, body = self._prepared("POST", HANDOFF_PATH, HANDOFF_PATH_V2, payload)
        try:
            response = await self._async().post(url, content=body, headers=headers)
        except Exception as e:
            raise OpenBoxNetworkError(f"Cannot reach OpenBox Core at {self._api_url}: {e}") from e
        return self._parse_handoff_response(response)

    def _handoff_payload(self, target_agent_id: str, reason: str | None) -> dict[str, Any]:
        if self._identity is None:
            raise OpenBoxConfigError(
                "Cannot emit a source-authenticated handoff without a configured "
                "identity (openbox_did or okta_ai_agent) — inferred unsigned mode "
                "has no source to prove. Provision an identity first; un-upgraded "
                "callers keep using the legacy receiver-authenticated governance "
                "handoff event."
            )
        payload: dict[str, Any] = {"target_agent_id": target_agent_id}
        if reason is not None:
            payload["reason"] = reason
        return payload

    def _parse_handoff_response(self, response: Any) -> dict[str, Any]:
        if response.status_code in (401, 403):
            raise self._classify_auth_failure(response, signed=self._identity is not None)
        if response.status_code >= 400:
            raise GovernanceAPIError(f"Handoff request failed: HTTP {response.status_code}")
        try:
            return response.json()
        except Exception as e:
            raise GovernanceAPIError(f"Handoff response unparseable: {e}") from e

    # ── Transition preflight (proposal §13.5; contract §4.1) ────────────────
    #
    # Both helpers sign with the EXPLICIT candidate_identity ONLY — never
    # this client's active identity — even when the client happens to be
    # configured with the same kind of identity. See identity_transitions.py.

    def validate_okta_identity_transition(
        self,
        transition_id: str,
        challenge: str,
        *,
        candidate_identity: OktaAiAgentIdentityConfig | None = None,
    ) -> dict[str, Any]:
        """Prove possession of a candidate Okta credential for a prepared
        method-transition intent (contract §4.1; proposal §13.5)."""
        path, headers, body = build_okta_transition_proof_request(
            transition_id,
            challenge,
            api_key=self._api_key,
            candidate_identity=candidate_identity,
            sdk_version=self._sdk_version,
            sdk_engine=self._sdk_engine,
            sdk_language=self._sdk_language,
        )
        return self._send_transition_proof(path, headers, body)

    async def avalidate_okta_identity_transition(
        self,
        transition_id: str,
        challenge: str,
        *,
        candidate_identity: OktaAiAgentIdentityConfig | None = None,
    ) -> dict[str, Any]:
        """Async :meth:`validate_okta_identity_transition`."""
        path, headers, body = build_okta_transition_proof_request(
            transition_id,
            challenge,
            api_key=self._api_key,
            candidate_identity=candidate_identity,
            sdk_version=self._sdk_version,
            sdk_engine=self._sdk_engine,
            sdk_language=self._sdk_language,
        )
        return await self._asend_transition_proof(path, headers, body)

    def validate_openbox_did_identity_transition(
        self,
        transition_id: str,
        challenge: str,
        *,
        candidate_identity: OpenBoxDidIdentityConfig | None = None,
    ) -> dict[str, Any]:
        """Prove possession of a fresh candidate OpenBox DID key for a
        reverse-transition intent (proposal §9.4/§13.5)."""
        path, headers, body = build_openbox_did_transition_proof_request(
            transition_id,
            challenge,
            api_key=self._api_key,
            candidate_identity=candidate_identity,
            sdk_version=self._sdk_version,
            sdk_engine=self._sdk_engine,
            sdk_language=self._sdk_language,
        )
        return self._send_transition_proof(path, headers, body)

    async def avalidate_openbox_did_identity_transition(
        self,
        transition_id: str,
        challenge: str,
        *,
        candidate_identity: OpenBoxDidIdentityConfig | None = None,
    ) -> dict[str, Any]:
        """Async :meth:`validate_openbox_did_identity_transition`."""
        path, headers, body = build_openbox_did_transition_proof_request(
            transition_id,
            challenge,
            api_key=self._api_key,
            candidate_identity=candidate_identity,
            sdk_version=self._sdk_version,
            sdk_engine=self._sdk_engine,
            sdk_language=self._sdk_language,
        )
        return await self._asend_transition_proof(path, headers, body)

    def _send_transition_proof(self, path: str, headers: dict, body: bytes) -> dict[str, Any]:
        url = f"{self._api_url}{path}"
        try:
            response = self._sync().post(url, content=body, headers=headers)
        except Exception as e:
            raise OpenBoxNetworkError(f"Cannot reach OpenBox Core at {self._api_url}: {e}") from e
        return self._parse_transition_proof_response(response)

    async def _asend_transition_proof(self, path: str, headers: dict, body: bytes) -> dict[str, Any]:
        url = f"{self._api_url}{path}"
        try:
            response = await self._async().post(url, content=body, headers=headers)
        except Exception as e:
            raise OpenBoxNetworkError(f"Cannot reach OpenBox Core at {self._api_url}: {e}") from e
        return self._parse_transition_proof_response(response)

    def _parse_transition_proof_response(self, response: Any) -> dict[str, Any]:
        # Preflight always signs with a candidate identity, regardless of
        # this client's own configured mode — so a reason code always
        # applies here (unlike evaluate/approval/validate, where signed=
        # tracks self._identity).
        if response.status_code in (401, 403):
            raise self._classify_auth_failure(response, signed=True)
        if response.status_code >= 400:
            raise GovernanceAPIError(f"Transition proof rejected: HTTP {response.status_code}")
        try:
            return response.json()
        except Exception as e:
            raise GovernanceAPIError(f"Transition proof response unparseable: {e}") from e
