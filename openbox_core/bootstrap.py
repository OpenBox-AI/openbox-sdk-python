"""Identity bootstrap: fetch the non-secret metadata needed to construct a v2
assertion from ``GET /api/v2/auth/bootstrap``, and prove the local private key
belongs to the credential Core actually selected.

Why this exists: signing a v2 assertion requires seven values (agent id,
organization id, deployment id, audience, external Okta agent id, credential
``kid``, algorithm) that Core already owns. Requiring an operator to copy them
into the runtime invites drift — a stale ``kid`` after rotation, an audience
pointing at the wrong deployment, an agent id copied from the wrong agent. Core is
the authority that validates them, so Core supplies them.

Fetching them does NOT make them trusted. Core independently re-derives and
re-compares every value when the signed assertion arrives; bootstrap only removes
the copying step.

Import safety: ``httpx`` and ``cryptography`` are imported lazily by the callers
this module delegates to, so importing this module stays cheap.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .errors import OpenBoxConfigError

__all__ = [
    "AUTH_BOOTSTRAP_PATH_V2",
    "SUPPORTED_BOOTSTRAP_VERSION",
    "PRIVATE_KEY_MISMATCH_MESSAGE",
    "IdentityBootstrapAuthority",
    "IdentityBootstrapDocument",
    "IdentityBootstrapOkta",
    "parse_bootstrap_document",
    "assert_private_key_matches_document",
    "bootstrap_guidance_for",
    "raise_for_bootstrap_status",
    "parse_bootstrap_response",
]

AUTH_BOOTSTRAP_PATH_V2 = "/api/v2/auth/bootstrap"

# The only bootstrap wire version this SDK understands. An unknown version fails
# closed with upgrade guidance rather than being interpreted optimistically.
SUPPORTED_BOOTSTRAP_VERSION = 1

# The fatal key-mismatch message. Actionable on purpose: this is the one bootstrap
# failure an operator can only fix by changing which key the runtime holds, or
# which credential the agent has selected. Kept byte-identical to the TypeScript
# SDK's message so operators see one wording across languages.
PRIVATE_KEY_MISMATCH_MESSAGE = (
    "The configured private key does not match the selected Okta credential for "
    "this OpenBox agent. Export the private key associated with the selected "
    "credential, or rotate the agent credential."
)


@dataclass(frozen=True)
class IdentityBootstrapAuthority:
    """Provider-neutral, non-secret active-authority metadata from Core."""

    assignment_id: str
    provider_generation_id: str
    generation_number: int
    activation_version: str
    identity_id: str
    credential_id: str
    projection_version: str


@dataclass(frozen=True)
class IdentityBootstrapOkta:
    """The okta_ai_agent half of the bootstrap document."""

    external_agent_id: str
    credential_kid: str
    algorithm: str
    public_jwk_thumbprint: str


@dataclass(frozen=True)
class IdentityBootstrapDocument:
    """A validated bootstrap document. Contains no secret material."""

    bootstrap_version: int
    identity_method: str
    openbox_agent_id: str
    organization_id: str
    deployment_id: str
    assertion_audience: str
    authority: IdentityBootstrapAuthority
    okta: IdentityBootstrapOkta


def _require_string(source: dict, key: str, path: str) -> str:
    value = source.get(key)
    if not isinstance(value, str) or not value:
        raise OpenBoxConfigError(
            f"Identity bootstrap response is invalid: {path!r} must be a non-empty string."
        )
    return value


def _parse_authority(raw: Any) -> IdentityBootstrapAuthority:
    if not isinstance(raw, dict):
        raise OpenBoxConfigError(
            "Identity bootstrap response is invalid: 'authority' must be an object."
        )

    generation_number = raw.get("generation_number")
    if (
        not isinstance(generation_number, int)
        or isinstance(generation_number, bool)
        or generation_number < 1
    ):
        raise OpenBoxConfigError(
            "Identity bootstrap response is invalid: "
            "'authority.generation_number' must be a positive integer."
        )

    return IdentityBootstrapAuthority(
        assignment_id=_require_string(raw, "assignment_id", "authority.assignment_id"),
        provider_generation_id=_require_string(
            raw, "provider_generation_id", "authority.provider_generation_id"
        ),
        generation_number=generation_number,
        activation_version=_require_string(
            raw, "activation_version", "authority.activation_version"
        ),
        identity_id=_require_string(raw, "identity_id", "authority.identity_id"),
        credential_id=_require_string(raw, "credential_id", "authority.credential_id"),
        projection_version=_require_string(
            raw, "projection_version", "authority.projection_version"
        ),
    )


def parse_bootstrap_document(raw: Any) -> IdentityBootstrapDocument:
    """Parse and strictly validate a bootstrap response body.

    Every check fails closed. A response that is merely *plausible* is not good
    enough: the values here determine what this runtime signs, and a silently
    accepted wrong value produces assertions Core will reject with no local
    explanation.
    """
    if not isinstance(raw, dict):
        raise OpenBoxConfigError("Identity bootstrap response is invalid: expected a JSON object.")

    version = raw.get("bootstrap_version")
    if version != SUPPORTED_BOOTSTRAP_VERSION:
        raise OpenBoxConfigError(
            f"Unsupported identity bootstrap version {version!r}; this SDK supports "
            f"version {SUPPORTED_BOOTSTRAP_VERSION}. Upgrade the OpenBox SDK to match "
            "your Core deployment."
        )

    identity_method = _require_string(raw, "identity_method", "identity_method")
    if identity_method != "okta_ai_agent":
        raise OpenBoxConfigError(
            f"This OpenBox agent's identity method is {identity_method!r}, not "
            "'okta_ai_agent'. Configure the matching identity for this agent, or "
            "select an Okta credential for it in OpenBox."
        )

    okta_raw = raw.get("okta")
    if not isinstance(okta_raw, dict):
        raise OpenBoxConfigError(
            "Identity bootstrap response is invalid: 'okta' must be an object."
        )

    algorithm = _require_string(okta_raw, "algorithm", "okta.algorithm")
    if algorithm.upper() != "RS256":
        raise OpenBoxConfigError(
            f"Unsupported Okta credential algorithm {algorithm!r}; only 'RS256' is allowlisted."
        )

    return IdentityBootstrapDocument(
        bootstrap_version=SUPPORTED_BOOTSTRAP_VERSION,
        identity_method=identity_method,
        openbox_agent_id=_require_string(raw, "openbox_agent_id", "openbox_agent_id"),
        organization_id=_require_string(raw, "organization_id", "organization_id"),
        deployment_id=_require_string(raw, "deployment_id", "deployment_id"),
        assertion_audience=_require_string(raw, "assertion_audience", "assertion_audience"),
        authority=_parse_authority(raw.get("authority")),
        okta=IdentityBootstrapOkta(
            external_agent_id=_require_string(
                okta_raw, "external_agent_id", "okta.external_agent_id"
            ),
            credential_kid=_require_string(okta_raw, "credential_kid", "okta.credential_kid"),
            algorithm="RS256",
            public_jwk_thumbprint=_require_string(
                okta_raw, "public_jwk_thumbprint", "okta.public_jwk_thumbprint"
            ),
        ),
    )


def assert_private_key_matches_document(
    private_key_pem: str, document: IdentityBootstrapDocument
) -> None:
    """Verify the local private key corresponds to the selected public credential.

    Runs BEFORE any governed request. Sending one after a mismatch could only
    produce a signature Core rejects, with a far less diagnosable error.
    """
    from .identity_okta import load_rsa_pkcs8_private_key
    from .jwk_thumbprint import jwk_thumbprint_sha256, thumbprints_match

    local = jwk_thumbprint_sha256(load_rsa_pkcs8_private_key(private_key_pem))
    if not thumbprints_match(local, document.okta.public_jwk_thumbprint):
        raise OpenBoxConfigError(PRIVATE_KEY_MISMATCH_MESSAGE)


def _reason_code_of(body: bytes | None) -> str | None:
    """Machine reason code from Core's error body, mirroring the client's helper."""
    if not body:
        return None
    try:
        parsed = json.loads(body.decode("utf-8", errors="replace"))
    except Exception:
        return None
    if not isinstance(parsed, dict):
        return None
    # `is not None`, not `or`: an empty-string reason_code must not fall through
    # to `reason`, matching the TypeScript SDK's `??`.
    code = parsed.get("reason_code")
    if code is None:
        code = parsed.get("reason")
    return code if isinstance(code, str) else None


def bootstrap_guidance_for(code: str | None, status: int) -> str:
    """Operator-facing guidance per Core reason code.

    Codes come from Core's stable bootstrap set; an unrecognized code falls back
    to a generic hint rather than being treated as success.
    """
    guidance = {
        "invalid_api_key": "the OPENBOX_API_KEY is absent, invalid, or revoked.",
        "agent_inactive": "this agent is not active in OpenBox.",
        "identity_method_mismatch": (
            "this agent is not configured for Okta identity verification."
        ),
        "selected_credential_missing": (
            "select or register an Okta credential for this agent in OpenBox."
        ),
        "selected_credential_inactive": (
            "the agent's selected Okta credential or its provider link is not active."
        ),
        "credential_algorithm_unsupported": (
            "the selected Okta credential uses an algorithm this contract does not allow."
        ),
        "provider_metadata_stale": (
            "OpenBox has not recently synchronized this credential from Okta; retry shortly."
        ),
        "identity_configuration_invalid": (
            "the OpenBox Core deployment's identity configuration is incomplete."
        ),
        "verifier_unavailable": (
            "OpenBox Core is temporarily unable to resolve identity metadata; retry shortly."
        ),
    }
    if code in guidance:
        return guidance[code]
    if status >= 500:
        return "OpenBox Core reported a server-side problem; retry shortly."
    return "check the API key and this agent's identity configuration in OpenBox."


def raise_for_bootstrap_status(status: int, body: bytes | None) -> None:
    """Raise for a non-2xx bootstrap response; return normally on success."""
    if status == 404:
        raise OpenBoxConfigError(
            "This Core version does not support Okta identity bootstrap. Upgrade Core "
            "or provide the complete legacy Okta identity configuration."
        )
    if status < 200 or status >= 300:
        code = _reason_code_of(body)
        suffix = f" ({code})" if code else ""
        raise OpenBoxConfigError(
            f"Identity bootstrap failed with HTTP {status}{suffix}: "
            f"{bootstrap_guidance_for(code, status)}"
        )


def parse_bootstrap_response(status: int, body: bytes | None) -> IdentityBootstrapDocument:
    """Validate an HTTP status then parse the body into a document."""
    raise_for_bootstrap_status(status, body)
    try:
        parsed = json.loads((body or b"").decode("utf-8"))
    except Exception as exc:
        raise OpenBoxConfigError(
            "Identity bootstrap response is invalid: body is not valid JSON."
        ) from exc
    return parse_bootstrap_document(parsed)
