"""OktaAgentIdentity — RS256 JWT assertion signing for the v2 (Okta AI Agent) contract.

Implements the assertion-generation order from proposal §13.4 and the wire
shape frozen in ``docs/agent-identity-v2-contract.md`` §§2-4:

    serialize body once -> hash transmitted bytes -> random jti -> short
    iat/exp -> deployment/org/agent/okta-agent/audience claims ->
    obx_api_key_sha256 from the exact bearer key -> exact htm/htu -> sign
    RS256 -> send the same bytes that were hashed

Contract invariants:

- Only PKCS8 PEM private keys are accepted this release (decision §13.1
  rule 8; private JWK input is deferred).
- ``alg`` is always the identity's configured algorithm, which
  :meth:`OktaAgentIdentity.from_config` already restricted to
  :data:`SUPPORTED_ALGORITHMS`. Core independently allowlists ``RS256`` only
  (contract §3) — this module never introduces a second place a caller could
  smuggle a different value through.
- ``typ`` is always ``openbox-agent-proof+jwt``; ``jwk``/``jku``/``x5u`` are
  never emitted.
- Header and claims are serialized with sorted keys and compact separators —
  this matches Core's Go ``encoding/json`` map marshaling byte-for-byte
  (verified against the golden fixtures in ``tests/signing/identity_v2/``),
  which is what makes the SDK's own assertions byte-reproducible from the
  same inputs across languages.
- Minimum RSA modulus size is 2048 bits; smaller keys are rejected locally,
  never echoing key bytes in errors.
- ``exp - iat`` is fixed at :data:`ASSERTION_LIFETIME_SECONDS` (60s, the
  contract ceiling — see contract §4).

SANDBOX SAFETY: ``cryptography`` is imported lazily inside functions,
mirroring ``identity.py``. This module must never be imported from
constrained framework paths; signing happens only in client/runtime code.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .errors import OpenBoxConfigError
from .identity import build_auth_headers
from .identity_types import OktaAiAgentIdentityConfig
from .sdk_version import DEFAULT_SDK_ENGINE, DEFAULT_SDK_LANGUAGE
from .serialization import serialize_body

__all__ = [
    "HEADER_ASSERTION",
    "JWT_TYP",
    "MIN_RSA_KEY_BITS",
    "ASSERTION_LIFETIME_SECONDS",
    "SUPPORTED_ALGORITHMS",
    "load_rsa_pkcs8_private_key",
    "OktaAgentIdentity",
    "build_assertion_claims",
    "sign_assertion",
    "prepare_okta_signed_request",
]

# v2 assertion header — the ONLY identity header v2 ever sends (contract §2.1).
HEADER_ASSERTION = "X-OpenBox-Agent-Assertion"
JWT_TYP = "openbox-agent-proof+jwt"
MIN_RSA_KEY_BITS = 2048
ASSERTION_LIFETIME_SECONDS = 60  # exp - iat; contract §4 requires <= 60s
# RS256 only at launch (proposal decision 24.2 / contract §3). ES256 is
# deferred behind the same contract once cross-language fixtures exist.
SUPPORTED_ALGORITHMS = ("RS256",)


def load_rsa_pkcs8_private_key(pem: str) -> Any:
    """Load a PKCS8 PEM RSA private key, rejecting <2048-bit keys locally.

    Never echoes key bytes in error messages — the PEM is non-repudiation
    material.

    Raises OpenBoxConfigError on any failure (bad PEM, wrong key type, or an
    undersized modulus).
    """
    # cryptography imported lazily — keeps it off any eager import path.
    from cryptography.hazmat.primitives import serialization as crypto_serialization
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

    try:
        key = crypto_serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
    except Exception:
        raise OpenBoxConfigError(
            "Invalid Okta agent private key: could not load a PKCS8 PEM RSA "
            "private key (key bytes not shown)."
        ) from None

    if not isinstance(key, RSAPrivateKey):
        raise OpenBoxConfigError(
            "Invalid Okta agent private key: expected an RSA private key "
            "(key bytes not shown)."
        )
    if key.key_size < MIN_RSA_KEY_BITS:
        raise OpenBoxConfigError(
            f"Invalid Okta agent private key: RSA modulus is {key.key_size} "
            f"bits, minimum is {MIN_RSA_KEY_BITS} bits (key bytes not shown)."
        )
    return key


@dataclass
class OktaAgentIdentity:
    """A validated Okta AI Agent identity plus its loaded RSA signer.

    Stores the loaded key OBJECT — never raw PEM bytes/strings after init.
    Construct via :meth:`from_config` for validation.
    """

    openbox_agent_id: str
    organization_id: str
    deployment_id: str
    external_agent_id: str
    key_id: str
    audience: str
    algorithm: str
    signer: Any = field(repr=False)  # RSAPrivateKey; excluded from repr

    @classmethod
    def from_config(cls, config: OktaAiAgentIdentityConfig) -> OktaAgentIdentity:
        """Validate the algorithm, decode + load the PEM, return a ready identity."""
        if config.algorithm not in SUPPORTED_ALGORITHMS:
            raise OpenBoxConfigError(
                f"Unsupported Okta agent algorithm {config.algorithm!r}; only "
                f"{SUPPORTED_ALGORITHMS!r} is supported at launch."
            )
        return cls(
            openbox_agent_id=config.openbox_agent_id,
            organization_id=config.organization_id,
            deployment_id=config.deployment_id,
            external_agent_id=config.external_agent_id,
            key_id=config.key_id,
            audience=config.audience,
            algorithm=config.algorithm,
            signer=load_rsa_pkcs8_private_key(config.private_key),
        )

    def sign(self, signing_input: bytes) -> bytes:
        """RS256-sign the exact JWT signing input (``b64url(header).b64url(payload)``)."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        return self.signer.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())

    def __repr__(self) -> str:  # never leak key material
        return (
            f"OktaAgentIdentity(external_agent_id={self.external_agent_id!r}, "
            f"key_id={self.key_id!r}, signer=<loaded>)"
        )


def _b64url(data: bytes) -> str:
    """Base64url, unpadded — the JWT segment encoding (RFC 7515 §2)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _canonical_json(obj: dict[str, Any]) -> bytes:
    """Sorted-key, compact-separator JSON.

    Matches Core's Go ``encoding/json`` map marshaling byte-for-byte
    (verified against the golden fixtures). Explicit sorting — not
    incidental dict insertion order — is what keeps assertion bytes
    reproducible across languages for the same claim values.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_assertion_claims(
    *,
    identity: OktaAgentIdentity,
    api_key: str,
    method: str,
    path: str,
    body_sha256: str,
    jti: str,
    iat: int,
    exp: int,
    extra_claims: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the 12 required v2 claims (contract §4), plus any extras.

    ``extra_claims`` carries the three transition-proof claims (contract
    §4.1) for ``/api/v2/auth/transition-proof`` only; pass ``None`` for
    every other route.
    """
    claims: dict[str, Any] = {
        "iss": identity.external_agent_id,
        "sub": identity.external_agent_id,
        "aud": identity.audience,
        "obx_deployment_id": identity.deployment_id,
        "obx_organization_id": identity.organization_id,
        "obx_agent_id": identity.openbox_agent_id,
        "obx_api_key_sha256": hashlib.sha256(api_key.encode("utf-8")).hexdigest(),
        "iat": iat,
        "exp": exp,
        "jti": jti,
        "htm": method.upper(),
        "htu": path,
        "body_sha256": body_sha256,
    }
    if extra_claims:
        claims.update(extra_claims)
    return claims


def sign_assertion(identity: OktaAgentIdentity, claims: dict[str, Any]) -> str:
    """Build the protected header, sign, and return the compact JWT.

    Header and claims are both sorted-key/compact JSON (see
    :func:`_canonical_json`), so the same inputs always produce
    byte-identical assertions.
    """
    header = {"alg": identity.algorithm, "kid": identity.key_id, "typ": JWT_TYP}
    header_b64 = _b64url(_canonical_json(header))
    payload_b64 = _b64url(_canonical_json(claims))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature_b64 = _b64url(identity.sign(signing_input))
    return f"{header_b64}.{payload_b64}.{signature_b64}"


def prepare_okta_signed_request(
    method: str,
    path: str,
    payload: dict | None,
    *,
    api_key: str,
    identity: OktaAgentIdentity,
    sdk_version: str | None = None,
    sdk_engine: str = DEFAULT_SDK_ENGINE,
    sdk_language: str = DEFAULT_SDK_LANGUAGE,
    extra_claims: dict[str, Any] | None = None,
    _jti: str | None = None,
    _iat: int | None = None,
) -> tuple[dict[str, str], bytes]:
    """Build v2 request headers + exact body bytes — the v2 counterpart of
    ``identity.prepare_signed_request``.

    Follows proposal §13.4's ten-step order:

    1. serialize the body exactly once (:func:`serialization.serialize_body`)
    2. hash the transmitted bytes
    3. random ``jti``
    4. short ``iat``/``exp``
    5. deployment/org/agent/okta-agent/audience claims
    6. ``obx_api_key_sha256`` from the exact bearer key
    7. exact ``htm``/``htu``
    8. sign RS256 with the configured private key
    9. send the same bytes that were hashed
    10. only :data:`HEADER_ASSERTION` + the existing base auth headers for
        v2 — this function has no code path that can add a v1 DID header.

    Args:
        method: HTTP method (case-insensitive; upper-cased into ``htm``).
        path: URL path only, no host/query — INCLUDES the ``/api/v2`` prefix.
        payload: JSON-serializable body, or ``None`` for empty-body (GET)
            requests.
        api_key: Bearer API key for the base auth headers and
            ``obx_api_key_sha256``.
        identity: Loaded OktaAgentIdentity.
        extra_claims: The three transition-proof claims (contract §4.1) for
            the transition-proof route only.
        _jti/_iat: Deterministic injection points for golden-fixture tests
            ONLY. Production callers must not pass them — a reused jti is
            rejected by Core (proof_replayed).

    Returns:
        ``(headers, body_bytes)``. Callers MUST send ``content=body_bytes`` —
        never ``json=`` — so the transmitted bytes match the hashed bytes.
    """
    body_bytes = serialize_body(payload)
    body_sha256 = hashlib.sha256(body_bytes).hexdigest()

    jti = _jti if _jti is not None else secrets.token_urlsafe(24)
    iat = _iat if _iat is not None else int(datetime.now(UTC).timestamp())
    exp = iat + ASSERTION_LIFETIME_SECONDS

    claims = build_assertion_claims(
        identity=identity,
        api_key=api_key,
        method=method,
        path=path,
        body_sha256=body_sha256,
        jti=jti,
        iat=iat,
        exp=exp,
        extra_claims=extra_claims,
    )
    assertion = sign_assertion(identity, claims)

    headers = build_auth_headers(
        api_key, sdk_version, sdk_engine=sdk_engine, sdk_language=sdk_language
    )
    headers[HEADER_ASSERTION] = assertion
    return headers, body_bytes
