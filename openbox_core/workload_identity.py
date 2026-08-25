"""Keycloak service-account bootstrap and private-key JWT primitives.

This module owns the provider-neutral v3 workload-authentication wire contract.
It performs no network I/O and stores no private key material. The client keeps
the OpenBox API key in ``Authorization`` and carries the short-lived Keycloak
access token in :data:`WORKLOAD_TOKEN_HEADER`.
"""

from __future__ import annotations

import base64
import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse
from uuid import UUID

from .errors import OpenBoxAuthError, OpenBoxConfigError, OpenBoxNetworkError

__all__ = [
    "AUTH_BOOTSTRAP_PATH_V3",
    "WORKLOAD_TRANSITION_BOOTSTRAP_PATH_V3",
    "WORKLOAD_TRANSITION_PROOF_PATH_V3",
    "WORKLOAD_TOKEN_HEADER",
    "WorkloadBootstrapDocument",
    "WorkloadTransitionBootstrapDocument",
    "WorkloadAccessToken",
    "build_private_key_jwt",
    "parse_workload_bootstrap_document",
    "parse_workload_bootstrap_response",
    "parse_workload_transition_bootstrap_response",
    "parse_workload_token_response",
]

AUTH_BOOTSTRAP_PATH_V3 = "/api/v3/auth/bootstrap"
WORKLOAD_TRANSITION_BOOTSTRAP_PATH_V3 = "/api/v3/auth/workload-transition/bootstrap"
WORKLOAD_TRANSITION_PROOF_PATH_V3 = "/api/v3/auth/workload-transition/proof"
WORKLOAD_TOKEN_HEADER = "X-OpenBox-Workload-Token"
SUPPORTED_BOOTSTRAP_VERSION = 3
SUPPORTED_CONTRACT_VERSION = 3
CLIENT_ASSERTION_LIFETIME_SECONDS = 60
ACCESS_TOKEN_REFRESH_SKEW_SECONDS = 30
MAX_ACCESS_TOKEN_CACHE_SECONDS = 300
SUPPORTED_IDENTITY_SOURCES = frozenset({"openbox", "okta", "entra"})


@dataclass(frozen=True)
class WorkloadBootstrapDocument:
    """Validated non-secret metadata for one active Keycloak service account."""

    bootstrap_version: int
    contract_version: int
    token_endpoint: str
    issuer: str
    audience: str
    client_id: str
    service_account_id: str
    activation_version: str
    identity_source: str
    kid: str


@dataclass(frozen=True)
class WorkloadTransitionBootstrapDocument:
    """Validated metadata for one prepared, non-active workload candidate."""

    bootstrap_version: int
    contract_version: int
    transition_id: str
    token_endpoint: str
    client_id: str
    kid: str
    identity_source: str
    expires_at: datetime


@dataclass(frozen=True, repr=False)
class WorkloadAccessToken:
    """Short-lived token cache entry; the bearer value is never represented."""

    value: str
    expires_at: datetime

    def is_fresh(self, now: datetime | None = None) -> bool:
        current = now or datetime.now(UTC)
        return current + timedelta(seconds=ACCESS_TOKEN_REFRESH_SKEW_SECONDS) < self.expires_at

    def __repr__(self) -> str:
        return f"WorkloadAccessToken(value=<redacted>, expires_at={self.expires_at!r})"


def _require_string(source: dict[str, Any], field: str) -> str:
    value = source.get(field)
    if not isinstance(value, str) or not value.strip():
        raise OpenBoxConfigError(
            f"Workload bootstrap response is invalid: {field!r} must be a non-empty string."
        )
    return value.strip()


def _require_uuid(source: dict[str, Any], field: str) -> str:
    value = _require_string(source, field)
    try:
        parsed = UUID(value)
    except ValueError:
        raise OpenBoxConfigError(
            f"Workload bootstrap response is invalid: {field!r} must be a UUID."
        ) from None
    if str(parsed) != value.lower():
        raise OpenBoxConfigError(
            f"Workload bootstrap response is invalid: {field!r} must be a canonical UUID."
        )
    return str(parsed)


def _validate_endpoint_pair(issuer: str, token_endpoint: str) -> None:
    issuer_url = urlparse(issuer)
    token_url = urlparse(token_endpoint)
    for name, parsed in (("issuer", issuer_url), ("token_endpoint", token_url)):
        if not parsed.scheme or not parsed.hostname or parsed.username or parsed.password:
            raise OpenBoxConfigError(
                f"Workload bootstrap response is invalid: {name!r} must be an absolute URL."
            )
        is_local = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme != "https" and not (parsed.scheme == "http" and is_local):
            raise OpenBoxConfigError(
                f"Workload bootstrap response is invalid: {name!r} must use HTTPS."
            )
        if parsed.query or parsed.fragment:
            raise OpenBoxConfigError(
                f"Workload bootstrap response is invalid: {name!r} cannot contain query or fragment data."
            )

    expected = issuer.rstrip("/") + "/protocol/openid-connect/token"
    if token_endpoint != expected:
        raise OpenBoxConfigError(
            "Workload bootstrap response is invalid: 'token_endpoint' must belong "
            "to the exact advertised issuer."
        )


def parse_workload_bootstrap_document(raw: Any) -> WorkloadBootstrapDocument:
    """Strictly validate Core's v3 workload bootstrap response."""

    if not isinstance(raw, dict):
        raise OpenBoxConfigError("Workload bootstrap response is invalid: expected a JSON object.")
    if raw.get("bootstrap_version") != SUPPORTED_BOOTSTRAP_VERSION:
        raise OpenBoxConfigError(
            "Unsupported workload bootstrap version; upgrade the OpenBox SDK "
            "to match the Core deployment."
        )
    if raw.get("contract_version") != SUPPORTED_CONTRACT_VERSION:
        raise OpenBoxConfigError(
            "Unsupported workload contract version; upgrade the OpenBox SDK "
            "to match the Core deployment."
        )

    issuer = _require_string(raw, "issuer").rstrip("/")
    token_endpoint = _require_string(raw, "token_endpoint")
    _validate_endpoint_pair(issuer, token_endpoint)
    identity_source = _require_string(raw, "identity_source").lower()
    if identity_source not in SUPPORTED_IDENTITY_SOURCES:
        raise OpenBoxConfigError(
            "Workload bootstrap response is invalid: 'identity_source' is unsupported."
        )

    return WorkloadBootstrapDocument(
        bootstrap_version=SUPPORTED_BOOTSTRAP_VERSION,
        contract_version=SUPPORTED_CONTRACT_VERSION,
        token_endpoint=token_endpoint,
        issuer=issuer,
        audience=_require_string(raw, "audience"),
        client_id=_require_string(raw, "client_id"),
        service_account_id=_require_uuid(raw, "service_account_id"),
        activation_version=_require_uuid(raw, "activation_version"),
        identity_source=identity_source,
        kid=_require_string(raw, "kid"),
    )


def _reason_code(body: bytes | None) -> str | None:
    if not body:
        return None
    try:
        payload = json.loads(body.decode("utf-8", errors="replace"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    value = payload.get("reason_code") or payload.get("code")
    return value if isinstance(value, str) else None


def parse_workload_bootstrap_response(
    status_code: int, body: bytes
) -> WorkloadBootstrapDocument | None:
    """Parse bootstrap or return ``None`` only for explicit no-v3 authority.

    A missing route supports rolling upgrades. Every other outage or malformed
    response fails closed so an advertised workload authority is never silently
    downgraded to a legacy verifier.
    """

    if status_code == 404:
        return None
    if status_code == 409 and _reason_code(body) == "workload_identity_unavailable":
        return None
    if status_code in (401, 403):
        raise OpenBoxAuthError(f"Workload identity bootstrap was rejected (HTTP {status_code}).")
    if status_code != 200:
        raise OpenBoxNetworkError(
            f"OpenBox workload identity bootstrap failed (HTTP {status_code})."
        )
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OpenBoxConfigError("Workload bootstrap response is invalid: expected JSON.") from exc
    return parse_workload_bootstrap_document(payload)


def parse_workload_transition_bootstrap_response(
    status_code: int, body: bytes
) -> WorkloadTransitionBootstrapDocument:
    """Validate candidate metadata; this operation never downgrades."""

    if status_code in (401, 403):
        raise OpenBoxAuthError(f"Workload transition bootstrap was rejected (HTTP {status_code}).")
    if status_code == 409:
        raise OpenBoxConfigError(
            "The workload identity transition is unavailable, expired, or no longer awaiting proof."
        )
    if status_code != 200:
        raise OpenBoxNetworkError(
            f"OpenBox workload transition bootstrap failed (HTTP {status_code})."
        )
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OpenBoxConfigError(
            "Workload transition bootstrap response is invalid: expected JSON."
        ) from exc
    if not isinstance(payload, dict):
        raise OpenBoxConfigError(
            "Workload transition bootstrap response is invalid: expected an object."
        )
    if (
        payload.get("bootstrap_version") != SUPPORTED_BOOTSTRAP_VERSION
        or payload.get("contract_version") != SUPPORTED_CONTRACT_VERSION
    ):
        raise OpenBoxConfigError(
            "Unsupported workload transition contract; upgrade the OpenBox SDK."
        )
    token_endpoint = _require_string(payload, "token_endpoint")
    parsed_token = urlparse(token_endpoint)
    issuer = token_endpoint.removesuffix("/protocol/openid-connect/token")
    if (
        issuer == token_endpoint
        or not parsed_token.hostname
        or parsed_token.query
        or parsed_token.fragment
    ):
        raise OpenBoxConfigError(
            "Workload transition bootstrap response is invalid: token_endpoint is invalid."
        )
    _validate_endpoint_pair(issuer, token_endpoint)
    source = _require_string(payload, "identity_source").lower()
    if source not in SUPPORTED_IDENTITY_SOURCES:
        raise OpenBoxConfigError(
            "Workload transition bootstrap response is invalid: identity_source is unsupported."
        )
    raw_expiry = _require_string(payload, "expires_at")
    try:
        expires_at = datetime.fromisoformat(raw_expiry.replace("Z", "+00:00"))
    except ValueError:
        raise OpenBoxConfigError(
            "Workload transition bootstrap response is invalid: expires_at must be ISO-8601."
        ) from None
    if expires_at.tzinfo is None:
        raise OpenBoxConfigError(
            "Workload transition bootstrap response is invalid: expires_at must include a timezone."
        )
    return WorkloadTransitionBootstrapDocument(
        bootstrap_version=SUPPORTED_BOOTSTRAP_VERSION,
        contract_version=SUPPORTED_CONTRACT_VERSION,
        transition_id=_require_uuid(payload, "transition_id"),
        token_endpoint=token_endpoint,
        client_id=_require_string(payload, "client_id"),
        kid=_require_string(payload, "kid"),
        identity_source=source,
        expires_at=expires_at.astimezone(UTC),
    )


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def build_private_key_jwt(
    private_key_pem: str,
    document: WorkloadBootstrapDocument | WorkloadTransitionBootstrapDocument,
    *,
    issued_at: int | None = None,
    jti: str | None = None,
) -> str:
    """Create the RFC 7523 client assertion for Keycloak token exchange."""

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    from .identity_okta import load_rsa_pkcs8_private_key

    signer = load_rsa_pkcs8_private_key(private_key_pem)
    iat = issued_at if issued_at is not None else int(datetime.now(UTC).timestamp())
    header = {"alg": "RS256", "kid": document.kid, "typ": "JWT"}
    claims = {
        "aud": document.token_endpoint,
        "exp": iat + CLIENT_ASSERTION_LIFETIME_SECONDS,
        "iat": iat,
        "iss": document.client_id,
        "jti": jti or secrets.token_urlsafe(24),
        "sub": document.client_id,
    }
    protected = _b64url(_canonical_json(header))
    payload = _b64url(_canonical_json(claims))
    signing_input = f"{protected}.{payload}".encode("ascii")
    signature = signer.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{protected}.{payload}.{_b64url(signature)}"


def parse_workload_token_response(
    status_code: int,
    body: bytes,
    *,
    now: datetime | None = None,
) -> WorkloadAccessToken:
    """Validate and bound a Keycloak client-credentials response."""

    if status_code in (400, 401, 403):
        raise OpenBoxAuthError(
            f"Keycloak workload token exchange was rejected (HTTP {status_code})."
        )
    if status_code != 200:
        raise OpenBoxNetworkError(f"Keycloak workload token exchange failed (HTTP {status_code}).")
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OpenBoxConfigError(
            "Keycloak workload token response is invalid: expected JSON."
        ) from exc
    if not isinstance(payload, dict):
        raise OpenBoxConfigError("Keycloak workload token response is invalid: expected an object.")
    access_token = payload.get("access_token")
    token_type = payload.get("token_type")
    expires_in = payload.get("expires_in")
    if not isinstance(access_token, str) or not access_token:
        raise OpenBoxConfigError(
            "Keycloak workload token response is invalid: 'access_token' is required."
        )
    if not isinstance(token_type, str) or token_type.lower() != "bearer":
        raise OpenBoxConfigError(
            "Keycloak workload token response is invalid: token_type must be Bearer."
        )
    if (
        not isinstance(expires_in, (int, float))
        or isinstance(expires_in, bool)
        or expires_in <= ACCESS_TOKEN_REFRESH_SKEW_SECONDS
    ):
        raise OpenBoxConfigError(
            "Keycloak workload token response is invalid: expires_in is too short."
        )
    cache_seconds = min(float(expires_in), MAX_ACCESS_TOKEN_CACHE_SECONDS)
    issued = now or datetime.now(UTC)
    return WorkloadAccessToken(
        value=access_token,
        expires_at=issued + timedelta(seconds=cache_seconds),
    )
