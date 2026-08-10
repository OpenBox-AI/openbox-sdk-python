from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import json
import math
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Protocol

from .errors import GovernanceProtocolError, GovernanceTransportError

_MAX_REQUEST_BYTES = 2 * 1024 * 1024
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_ENDPOINT = "/api/v1/governance/evaluate"
_AIP_HEADERS = {
    "x-openbox-agent-did": "X-OpenBox-Agent-DID",
    "x-openbox-agent-timestamp": "X-OpenBox-Agent-Timestamp",
    "x-openbox-agent-nonce": "X-OpenBox-Agent-Nonce",
    "x-openbox-agent-signature": "X-OpenBox-Agent-Signature",
    "x-openbox-body-sha256": "X-OpenBox-Body-SHA256",
}
_NONCE = re.compile(r"[A-Za-z0-9_-]{16,128}\Z")
_VERDICT_ACTION = {
    "allow": "allow",
    "constrain": "constrain",
    "require_approval": "require_approval",
    "block": "block",
    "halt": "halt",
}
_ALLOWED_RESPONSE_FIELDS = {
    "governance_event_id",
    "verdict",
    "risk_score",
    "action",
    "fallback_used",
    "trust_tier",
    "behavioral_violations",
    "approval_id",
    "constraints",
    "approval_expiration_time",
    "reason",
    "policy_id",
    "metadata",
    "guardrails_result",
    "guardrail_findings",
    "age_result",
}
_REQUIRED_RESPONSE_FIELDS = {
    "governance_event_id",
    "verdict",
    "risk_score",
    "action",
    "fallback_used",
}


class GovernanceRequestSigner(Protocol):
    """Dependency-free signer seam for optional AIP-authenticated Core calls."""

    @property
    def agent_did(self) -> str: ...

    def sign_headers(self, method: str, path: str, body: bytes) -> Mapping[str, str]: ...


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise GovernanceProtocolError()
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise GovernanceProtocolError()


def _strict_loads(body: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            body,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, UnicodeDecodeError, GovernanceProtocolError) as error:
        raise GovernanceProtocolError() from error
    if not isinstance(value, dict):
        raise GovernanceProtocolError()
    return value


def _json_bytes(value: object) -> bytes:
    try:
        body = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise GovernanceProtocolError() from error
    if not body or len(body) > _MAX_REQUEST_BYTES:
        raise GovernanceProtocolError()
    return body


@dataclass(frozen=True, slots=True, repr=False)
class GovernanceClientConfig:
    base_url: str
    bearer_token: str
    sdk_version: str
    ca_path: Path | None = None
    timeout_seconds: float = 10.0
    request_signer: GovernanceRequestSigner | None = None

    def __post_init__(self) -> None:
        parsed = urllib.parse.urlsplit(self.base_url)
        local_http = parsed.scheme == "http" and parsed.hostname in {
            "127.0.0.1",
            "localhost",
        }
        if (
            (parsed.scheme != "https" and not local_http)
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
            or (local_http and self.ca_path is not None)
            or not self.bearer_token
            or "\r" in self.bearer_token
            or "\n" in self.bearer_token
            or not self.sdk_version
            or "\r" in self.sdk_version
            or "\n" in self.sdk_version
            or isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not 0 < self.timeout_seconds <= 30
            or (
                self.request_signer is not None
                and (
                    not isinstance(getattr(self.request_signer, "agent_did", None), str)
                    or not getattr(self.request_signer, "agent_did", "")
                    or not callable(getattr(self.request_signer, "sign_headers", None))
                )
            )
        ):
            raise GovernanceProtocolError()

    @property
    def endpoint(self) -> str:
        return self.base_url.rstrip("/") + _ENDPOINT

    def __repr__(self) -> str:
        return (
            f"GovernanceClientConfig(base_url={self.base_url!r}, "
            "bearer_token=<redacted>, ca_path=<redacted>, "
            f"sdk_version={self.sdk_version!r}, timeout_seconds={self.timeout_seconds}, "
            f"request_signer={'configured' if self.request_signer else 'disabled'})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class GovernanceDecision:
    verdict: str
    risk_score: float
    action: str
    fallback_used: bool
    constraints: tuple[str, ...] | None
    has_guardrails_result: bool
    _raw: Mapping[str, Any]

    @property
    def raw(self) -> dict[str, Any]:
        return copy.deepcopy(dict(self._raw))

    def __repr__(self) -> str:
        return (
            f"GovernanceDecision(verdict={self.verdict!r}, "
            f"risk_score={self.risk_score}, action={self.action!r}, "
            f"fallback_used={self.fallback_used}, response=<preserved>)"
        )

    @classmethod
    def parse(cls, value: Mapping[str, Any] | bytes) -> GovernanceDecision:
        if isinstance(value, bytes):
            raw = _strict_loads(value)
        else:
            raw = _strict_loads(_json_bytes(value))
        fields = set(raw)
        if not _REQUIRED_RESPONSE_FIELDS <= fields or not fields <= _ALLOWED_RESPONSE_FIELDS:
            raise GovernanceProtocolError()
        event_id = raw["governance_event_id"]
        verdict = raw["verdict"]
        risk = raw["risk_score"]
        action = raw["action"]
        fallback = raw["fallback_used"]
        try:
            parsed_uuid = uuid.UUID(event_id) if isinstance(event_id, str) else None
        except ValueError as error:
            raise GovernanceProtocolError() from error
        if (
            parsed_uuid is None
            or str(parsed_uuid) != event_id
            or not isinstance(verdict, str)
            or verdict not in _VERDICT_ACTION
            or not isinstance(action, str)
            or action != _VERDICT_ACTION[verdict]
            or isinstance(risk, bool)
            or not isinstance(risk, (int, float))
            or not math.isfinite(risk)
            or not 0 <= risk <= 1
            or type(fallback) is not bool
        ):
            raise GovernanceProtocolError()
        _validate_optional(raw)
        constraints = raw.get("constraints")
        return cls(
            verdict=verdict,
            risk_score=float(risk),
            action=action,
            fallback_used=fallback,
            constraints=None if constraints is None else tuple(constraints),
            has_guardrails_result="guardrails_result" in raw,
            _raw=copy.deepcopy(raw),
        )


def _validate_optional(raw: Mapping[str, Any]) -> None:
    if "trust_tier" in raw:
        value = raw["trust_tier"]
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 4:
            raise GovernanceProtocolError()
    if "behavioral_violations" in raw and (
        not isinstance(raw["behavioral_violations"], list)
        or not all(isinstance(item, str) for item in raw["behavioral_violations"])
    ):
        raise GovernanceProtocolError()
    for name in ("approval_id", "approval_expiration_time", "reason", "policy_id"):
        if name in raw and not isinstance(raw[name], str):
            raise GovernanceProtocolError()
    if "constraints" in raw and (
        not isinstance(raw["constraints"], list)
        or not all(isinstance(item, str) for item in raw["constraints"])
    ):
        raise GovernanceProtocolError()
    if "metadata" in raw and not isinstance(raw["metadata"], dict):
        raise GovernanceProtocolError()
    if "guardrails_result" in raw:
        _validate_guardrails_result(raw["guardrails_result"])
    if "age_result" in raw:
        _validate_age_result(raw["age_result"])


def _exact_object(value: object, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise GovernanceProtocolError()
    return value


def _string(value: object) -> None:
    if not isinstance(value, str):
        raise GovernanceProtocolError()


def _integer(value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise GovernanceProtocolError()


def _finite_number(value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise GovernanceProtocolError()


def _validate_guardrails_result(value: object) -> None:
    result = _exact_object(
        value,
        {"input_type", "redacted_input", "raw_logs", "validation_passed", "reasons", "results"},
    )
    _string(result["input_type"])
    if not isinstance(result["raw_logs"], dict) or type(result["validation_passed"]) is not bool:
        raise GovernanceProtocolError()
    reasons = result["reasons"]
    if not isinstance(reasons, list):
        raise GovernanceProtocolError()
    for raw_reason in reasons:
        reason = _exact_object(raw_reason, {"type", "field", "reason"})
        for item in reason.values():
            _string(item)
    results = result["results"]
    if not isinstance(results, list):
        raise GovernanceProtocolError()
    for raw_result in results:
        guardrail = _exact_object(raw_result, {"guardrail_type", "results"})
        _string(guardrail["guardrail_type"])
        if not isinstance(guardrail["results"], list):
            raise GovernanceProtocolError()
        for raw_field in guardrail["results"]:
            field = _exact_object(raw_field, {"field", "order", "status", "reason"})
            _string(field["field"])
            _integer(field["order"])
            _string(field["status"])
            if field["reason"] is not None:
                _string(field["reason"])


def _validate_age_result(value: object) -> None:
    result = _exact_object(
        value,
        {
            "allowed",
            "verdict",
            "goal_alignment_checked",
            "goal_drifted",
            "fallback_used",
            "final_trust_score",
            "span_results",
            "total_spans",
            "violations_count",
            "response_time_ms",
        }
        | ({"reason"} if isinstance(value, dict) and "reason" in value else set()),
    )
    if (
        type(result["allowed"]) is not bool
        or result["verdict"] not in _VERDICT_ACTION
        or type(result["goal_alignment_checked"]) is not bool
        or type(result["goal_drifted"]) is not bool
        or type(result["fallback_used"]) is not bool
    ):
        raise GovernanceProtocolError()
    if "reason" in result:
        _string(result["reason"])
    if result["final_trust_score"] is not None:
        _validate_trust_score(result["final_trust_score"])
    spans = result["span_results"]
    if spans is not None and not isinstance(spans, list):
        raise GovernanceProtocolError()
    for raw_span in spans or []:
        span = _exact_object(
            raw_span,
            {
                "span_id",
                "semantic_type",
                "behavioral_result",
                "alignment_result",
                "trust_score_after",
                "timestamp",
            },
        )
        for name in ("span_id", "semantic_type", "timestamp"):
            _string(span[name])
        if span["alignment_result"] is not None:
            alignment = _exact_object(span["alignment_result"], {"is_aligned", "score"})
            if type(alignment["is_aligned"]) is not bool:
                raise GovernanceProtocolError()
            _finite_number(alignment["score"])
        if span["trust_score_after"] is not None:
            _validate_trust_score(span["trust_score_after"])
    for name in ("total_spans", "violations_count", "response_time_ms"):
        _integer(result[name])


def _validate_trust_score(value: object) -> None:
    score = _exact_object(
        value,
        {
            "trust_score",
            "trust_tier",
            "behavioral_compliance",
            "alignment_consistency",
            "aivss_baseline",
        },
    )
    for name in (
        "trust_score",
        "behavioral_compliance",
        "alignment_consistency",
        "aivss_baseline",
    ):
        _finite_number(score[name])
    _integer(score["trust_tier"])


def _validated_signer_headers(signer: GovernanceRequestSigner, body: bytes) -> dict[str, str]:
    try:
        supplied = signer.sign_headers("POST", _ENDPOINT, body)
        values = dict(supplied)
    except Exception as error:
        raise GovernanceProtocolError() from error
    if any(not isinstance(name, str) for name in values) or any(
        not isinstance(value, str) or not value for value in values.values()
    ):
        raise GovernanceProtocolError()
    normalized = {name.lower(): value for name, value in values.items()}
    if len(normalized) != len(values) or set(normalized) != set(_AIP_HEADERS):
        raise GovernanceProtocolError()
    for value in normalized.values():
        try:
            encoded = value.encode("ascii")
        except UnicodeEncodeError as error:
            raise GovernanceProtocolError() from error
        if len(encoded) > 8192 or "\r" in value or "\n" in value:
            raise GovernanceProtocolError()
    did = normalized["x-openbox-agent-did"]
    if did != signer.agent_did or not did.startswith("did:aip:"):
        raise GovernanceProtocolError()
    try:
        parsed_did = uuid.UUID(did[len("did:aip:") :])
    except ValueError as error:
        raise GovernanceProtocolError() from error
    if str(parsed_did) != did[len("did:aip:") :]:
        raise GovernanceProtocolError()
    timestamp = normalized["x-openbox-agent-timestamp"]
    try:
        parsed_timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as error:
        raise GovernanceProtocolError() from error
    if parsed_timestamp.tzinfo is None:
        raise GovernanceProtocolError()
    if _NONCE.fullmatch(normalized["x-openbox-agent-nonce"]) is None:
        raise GovernanceProtocolError()
    expected_hash = hashlib.sha256(body).hexdigest()
    if normalized["x-openbox-body-sha256"] != expected_hash:
        raise GovernanceProtocolError()
    try:
        signature = base64.b64decode(normalized["x-openbox-agent-signature"], validate=True)
    except ValueError as error:
        raise GovernanceProtocolError() from error
    if len(signature) != 64:
        raise GovernanceProtocolError()
    return {canonical: normalized[lowered] for lowered, canonical in _AIP_HEADERS.items()}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, request: Any, file: Any, code: int, message: str, headers: Any, new_url: str
    ) -> None:
        return None


class GovernanceClient:
    def __init__(self, config: GovernanceClientConfig) -> None:
        self._config = config
        self._ssl = ssl.create_default_context(
            cafile=str(config.ca_path) if config.ca_path else None
        )
        self._ssl.minimum_version = ssl.TLSVersion.TLSv1_2
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=self._ssl),
            _NoRedirect(),
        )

    async def evaluate(self, event: Mapping[str, Any]) -> GovernanceDecision:
        body = _json_bytes(event)
        response = await asyncio.to_thread(self._post, body)
        return GovernanceDecision.parse(response)

    def _post(self, body: bytes) -> bytes:
        headers = {
            "Authorization": "Bearer " + self._config.bearer_token,
            "Content-Type": "application/json",
            "X-OpenBox-SDK-Version": self._config.sdk_version,
        }
        if self._config.request_signer is not None:
            headers.update(_validated_signer_headers(self._config.request_signer, body))
        request = urllib.request.Request(
            self._config.endpoint,
            data=body,
            method="POST",
            headers=headers,
        )
        try:
            with self._opener.open(request, timeout=self._config.timeout_seconds) as response:
                if response.status != 200:
                    raise GovernanceTransportError()
                content_length = response.headers.get("Content-Length")
                if content_length is not None:
                    try:
                        length = int(content_length)
                    except ValueError as error:
                        raise GovernanceProtocolError() from error
                    if not 1 <= length <= _MAX_RESPONSE_BYTES:
                        raise GovernanceProtocolError()
                body = response.read(_MAX_RESPONSE_BYTES + 1)
        except GovernanceProtocolError:
            raise
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as error:
            raise GovernanceTransportError() from error
        if not body or len(body) > _MAX_RESPONSE_BYTES:
            raise GovernanceProtocolError()
        return body
