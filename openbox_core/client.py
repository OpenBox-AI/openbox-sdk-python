"""Sync + async EvaluationClient for OpenBox Core.

Endpoints:
    POST /api/v1/governance/evaluate   — lifecycle + hook evaluations
    POST /api/v1/governance/approval   — HITL approval polling
    GET  /api/v1/auth/validate         — API key / signing validation

Transport rules:
- Signed requests send ``content=body_bytes`` — NEVER ``json=`` (client-side
  re-serialization breaks Core's body-hash verification).
- ``httpx`` is imported lazily so this module never taints pure import paths.
- Fail modes apply to NETWORK errors only — SDK input contract violations raise
  before send and malformed successful Core responses raise after receive; neither
  is converted to a fail-open ALLOW:
    * fail_open (default): return allow-shaped ``EvaluationResult`` with
      ``fallback_used=True`` (callers can tell it apart from a policy ALLOW).
    * fail_closed: raise ``GovernanceAPIError`` (adapters map to native
      halt/block behavior).
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from .contracts.results import ApprovalResult, EvaluationResult
from .errors import (
    GovernanceAPIError,
    OpenBoxAuthError,
    OpenBoxNetworkError,
    map_signing_error,
)
from .identity import AgentIdentity, prepare_signed_request
from .sdk_version import DEFAULT_SDK_ENGINE, DEFAULT_SDK_LANGUAGE

__all__ = [
    "EVALUATE_PATH",
    "APPROVAL_PATH",
    "AUTH_VALIDATE_PATH",
    "EvaluationClient",
    "check_expiration",
]

logger = logging.getLogger(__name__)

EVALUATE_PATH = "/api/v1/governance/evaluate"
APPROVAL_PATH = "/api/v1/governance/approval"
AUTH_VALIDATE_PATH = "/api/v1/auth/validate"


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
        identity: AgentIdentity | None = None,
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
            identity: Loaded AgentIdentity for signed requests (None = unsigned).
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

    def _prepared(self, method: str, path: str, payload: dict | None) -> tuple[str, dict, bytes]:
        headers, body = prepare_signed_request(
            method,
            path,
            payload,
            api_key=self._api_key,
            identity=self._identity,
            sdk_version=self._sdk_version,
            sdk_engine=self._sdk_engine,
            sdk_language=self._sdk_language,
        )
        return f"{self._api_url}{path}", headers, body

    # ── Evaluate ──────────────────────────────────────────────────────────

    def evaluate(self, payload: dict) -> EvaluationResult:
        """POST a governance event; parse the verdict. Never raises on network
        errors under fail_open — returns a ``fallback_used=True`` ALLOW."""
        url, headers, body = self._prepared("POST", EVALUATE_PATH, payload)
        try:
            response = self._sync().post(url, content=body, headers=headers)
        except Exception as e:  # network layer
            return self._network_failure(f"Governance API unreachable: {e}")
        return self._parse_evaluate_response(response)

    async def aevaluate(self, payload: dict) -> EvaluationResult:
        """Async :meth:`evaluate`."""
        url, headers, body = self._prepared("POST", EVALUATE_PATH, payload)
        try:
            response = await self._async().post(url, content=body, headers=headers)
        except Exception as e:
            return self._network_failure(f"Governance API unreachable: {e}")
        return self._parse_evaluate_response(response)

    def _parse_evaluate_response(self, response: Any) -> EvaluationResult:
        if not 200 <= response.status_code < 300:
            return self._network_failure(f"Governance API error: HTTP {response.status_code}")
        result = EvaluationResult.from_wire(response.content)
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
        """Poll HITL approval status once. Returns None on poll failure
        (callers treat None as still-pending and retry)."""
        payload = {"workflow_id": workflow_id, "run_id": run_id, "activity_id": activity_id}
        url, headers, body = self._prepared("POST", APPROVAL_PATH, payload)
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
        url, headers, body = self._prepared("POST", APPROVAL_PATH, payload)
        try:
            response = await self._async().post(url, content=body, headers=headers)
        except Exception as e:
            logger.warning(f"Failed to poll approval status: {e}")
            return None
        return self._parse_approval_response(response)

    def _parse_approval_response(self, response: Any) -> ApprovalResult | None:
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
        """GET /api/v1/auth/validate (signed when identity is configured).

        Returns True on success. Raises OpenBoxAuthError / OpenBoxSigningError
        on 401/403, OpenBoxNetworkError on connectivity failure.
        """
        url, headers, _ = self._prepared("GET", AUTH_VALIDATE_PATH, None)
        try:
            response = self._sync().get(url, headers=headers)
        except Exception as e:
            raise OpenBoxNetworkError(f"Cannot reach OpenBox Core at {self._api_url}: {e}") from e
        return self._parse_auth_response(response)

    async def avalidate_api_key(self) -> bool:
        """Async :meth:`validate_api_key`."""
        url, headers, _ = self._prepared("GET", AUTH_VALIDATE_PATH, None)
        try:
            response = await self._async().get(url, headers=headers)
        except Exception as e:
            raise OpenBoxNetworkError(f"Cannot reach OpenBox Core at {self._api_url}: {e}") from e
        return self._parse_auth_response(response)

    def _parse_auth_response(self, response: Any) -> bool:
        if response.status_code == 200:
            return True
        if response.status_code in (401, 403):
            # When signing is enabled, surface Core's machine reason code as an
            # actionable signing error (signature_invalid, nonce_replayed, ...).
            reason_code = (
                _extract_reason_code(response.content) if self._identity is not None else None
            )
            if reason_code:
                raise map_signing_error(reason_code)
            raise OpenBoxAuthError("Invalid API key. Check your API key at dashboard.openbox.ai")
        raise OpenBoxNetworkError(
            f"Cannot reach OpenBox Core at {self._api_url}: HTTP {response.status_code}"
        )
