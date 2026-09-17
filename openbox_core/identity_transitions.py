"""Transition-preflight request builders (contract §4.1 / proposal §13.5).

Pure request-assembly functions for the two ``.../auth/transition-proof``
preflight routes — kept separate from ``client.py`` (which only sends the
request and parses the response) so the "explicit candidate, never the
client's active signer" rule lives in one small, easily-audited place, per
proposal §17.28:

    the transition helper must take an EXPLICIT candidate identity; falling
    back to the client's active signer would let a runtime "prove
    possession" of a key it does not have.

Neither function ever reads a client's active identity — they only see
whatever ``candidate_identity`` the caller passes in, and omitting it is a
local configuration error (never inferred, never defaulted).
"""

from __future__ import annotations

from typing import Any

from .errors import OpenBoxConfigError
from .identity import AgentIdentity, prepare_signed_request
from .identity_okta import OktaAgentIdentity, prepare_okta_signed_request
from .identity_types import OktaAiAgentIdentityConfig, OpenBoxDidIdentityConfig
from .sdk_version import DEFAULT_SDK_ENGINE, DEFAULT_SDK_LANGUAGE

__all__ = [
    "TRANSITION_PROOF_PATH",
    "TRANSITION_PROOF_PATH_V2",
    "build_okta_transition_proof_request",
    "build_openbox_did_transition_proof_request",
]

TRANSITION_PROOF_PATH = "/api/v1/auth/transition-proof"
TRANSITION_PROOF_PATH_V2 = "/api/v2/auth/transition-proof"


def build_okta_transition_proof_request(
    transition_id: str,
    challenge: str,
    *,
    api_key: str,
    candidate_identity: OktaAiAgentIdentityConfig | None,
    sdk_version: str | None = None,
    sdk_engine: str = DEFAULT_SDK_ENGINE,
    sdk_language: str = DEFAULT_SDK_LANGUAGE,
) -> tuple[str, dict[str, str], bytes]:
    """Build the signed ``POST /api/v2/auth/transition-proof`` request.

    Signs with ``candidate_identity`` ONLY. Raises ``OpenBoxConfigError`` if
    it is omitted — this is a local configuration error, never inferred from
    an active client identity.

    Returns ``(path, headers, body_bytes)``; the caller prefixes the base
    URL and sends the bytes verbatim.
    """
    if candidate_identity is None:
        raise OpenBoxConfigError(
            "validate_okta_identity_transition requires an explicit "
            "candidate_identity for the target Okta credential — it never "
            "falls back to the client's active identity signer. A runtime "
            "must prove possession of the key it is transitioning TO, not "
            "the key it already uses."
        )
    candidate = OktaAgentIdentity.from_config(candidate_identity)
    payload = {"transition_id": transition_id}
    extra_claims = {
        "obx_transition_purpose": "okta_ai_agent",
        "obx_transition_id": transition_id,
        "obx_transition_challenge": challenge,
    }
    headers, body = prepare_okta_signed_request(
        "POST",
        TRANSITION_PROOF_PATH_V2,
        payload,
        api_key=api_key,
        identity=candidate,
        sdk_version=sdk_version,
        sdk_engine=sdk_engine,
        sdk_language=sdk_language,
        extra_claims=extra_claims,
    )
    return TRANSITION_PROOF_PATH_V2, headers, body


def build_openbox_did_transition_proof_request(
    transition_id: str,
    challenge: str,
    *,
    api_key: str,
    candidate_identity: OpenBoxDidIdentityConfig | None,
    sdk_version: str | None = None,
    sdk_engine: str = DEFAULT_SDK_ENGINE,
    sdk_language: str = DEFAULT_SDK_LANGUAGE,
) -> tuple[str, dict[str, str], bytes]:
    """Build the signed ``POST /api/v1/auth/transition-proof`` request.

    Signs with ``candidate_identity`` ONLY (the fresh reverse-prepare DID
    key) — never this client's currently active identity. Raises
    ``OpenBoxConfigError`` if omitted.

    v1 has no JWT claims channel, so both ``transition_id`` and ``challenge``
    travel in the signed request body (unlike the v2 assertion, which carries
    the challenge as a claim — contract §4.1). This does not touch v1's
    canonical-string construction; it is an ordinary signed POST at a new
    path, reusing ``identity.prepare_signed_request`` unchanged.

    Returns ``(path, headers, body_bytes)``; the caller prefixes the base
    URL and sends the bytes verbatim.
    """
    if candidate_identity is None:
        raise OpenBoxConfigError(
            "validate_openbox_did_identity_transition requires an explicit "
            "candidate_identity for the freshly provisioned DID key — it "
            "never falls back to the client's active identity signer. A "
            "runtime must prove possession of the key it is transitioning "
            "TO, not the key it already uses."
        )
    candidate = AgentIdentity.from_private_key(
        candidate_identity.did, candidate_identity.private_key
    )
    payload: dict[str, Any] = {"transition_id": transition_id, "challenge": challenge}
    headers, body = prepare_signed_request(
        "POST",
        TRANSITION_PROOF_PATH,
        payload,
        api_key=api_key,
        identity=candidate,
        sdk_version=sdk_version,
        sdk_engine=sdk_engine,
        sdk_language=sdk_language,
    )
    return TRANSITION_PROOF_PATH, headers, body
