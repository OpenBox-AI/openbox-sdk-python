"""AgentIdentity — AIP DID validation and Ed25519 request signing.

Reproduces the Temporal SDK signing contract BYTE-FOR-BYTE. The canonical
string (must match Core ``agent.go:93``)::

    UPPER(METHOD)\nPATH\nTIMESTAMP\nNONCE\nBODY_SHA256_HEX

Contract invariants (verified against the live Temporal signer):

- The signing TIMESTAMP is ``datetime.now(timezone.utc).isoformat()`` —
  it KEEPS ``+00:00`` and never uses ``Z``. (The event-payload timestamp is a
  different field with a different format.) NOTE: the CrewAI SDK diverges here
  (``Z`` + ``uuid4`` nonce); the base SDK matches Temporal — the divergence is
  documented by a cross-check test, not unified.
- NONCE is ``secrets.token_urlsafe(24)``.
- Signature is standard padded base64 of the Ed25519 signature over the
  canonical string, ASCII-decoded.
- PATH includes the ``/api/v1`` prefix; no host, no query.
- Body bytes are produced ONCE by ``serialization.serialize_body`` and sent
  verbatim via ``content=body_bytes`` — NEVER ``json=``.

SANDBOX SAFETY: ``cryptography`` is imported lazily inside functions. This
module must never be imported from constrained framework paths; signing
happens only in client/runtime code.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .errors import OpenBoxConfigError
from .serialization import serialize_body

__all__ = [
    "AGENT_DID_PREFIX",
    "EMPTY_BODY_SHA256",
    "HEADER_DID",
    "HEADER_TIMESTAMP",
    "HEADER_NONCE",
    "HEADER_SIGNATURE",
    "HEADER_BODY_SHA256",
    "validate_agent_did",
    "load_ed25519_seed",
    "AgentIdentity",
    "build_canonical_string",
    "build_auth_headers",
    "prepare_signed_request",
]

# Agent DID prefix; the suffix must be a parseable UUID (validated via
# uuid.UUID, matching Core's UUID parser rather than a loose regex).
AGENT_DID_PREFIX = "did:aip:"

# SHA-256 of empty bytes — body hash for GET / empty-body requests.
EMPTY_BODY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# AIP signed-request header names (Core agent.go:26-30).
HEADER_DID = "X-OpenBox-Agent-DID"
HEADER_TIMESTAMP = "X-OpenBox-Agent-Timestamp"
HEADER_NONCE = "X-OpenBox-Agent-Nonce"
HEADER_SIGNATURE = "X-OpenBox-Agent-Signature"
HEADER_BODY_SHA256 = "X-OpenBox-Body-SHA256"


def validate_agent_did(agent_did: str) -> None:
    """Validate agent DID format (``did:aip:<uuid>``).

    Parses the suffix with uuid.UUID so malformed UUID layouts fail locally at
    init (matching Core's parser) rather than slipping through to a Core 4xx.

    Raises OpenBoxConfigError on mismatch.
    """
    if not isinstance(agent_did, str) or not agent_did.startswith(AGENT_DID_PREFIX):
        raise OpenBoxConfigError(
            f"Invalid agent DID format. Expected 'did:aip:<uuid>', "
            f"got: '{str(agent_did)[:24]}...' (showing first 24 chars)"
        )
    suffix = agent_did[len(AGENT_DID_PREFIX):]
    try:
        uuid.UUID(suffix)
    except (ValueError, AttributeError):
        raise OpenBoxConfigError(
            f"Invalid agent DID: '{agent_did[:24]}...' — the part after "
            f"'{AGENT_DID_PREFIX}' is not a valid UUID."
        ) from None


def load_ed25519_seed(agent_private_key: str) -> Any:
    """Decode a base64 raw 32-byte Ed25519 seed and load a private key object.

    The provisioned key is a raw 32-byte seed (base64), NOT PKCS8. Returns a
    cryptography Ed25519PrivateKey. Never echoes key bytes in error messages —
    the seed is non-repudiation material.

    Raises OpenBoxConfigError on any failure (bad base64, wrong length, load error).
    """
    # cryptography imported lazily — keeps it off any eager import path.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    try:
        seed = base64.b64decode(agent_private_key, validate=True)
    except Exception:
        raise OpenBoxConfigError(
            "Invalid agent private key: not valid base64 (key bytes not shown)."
        ) from None

    if len(seed) != 32:
        raise OpenBoxConfigError(
            f"Invalid agent private key: expected a 32-byte Ed25519 seed, "
            f"got {len(seed)} bytes (key bytes not shown)."
        )

    try:
        return Ed25519PrivateKey.from_private_bytes(seed)
    except Exception:
        raise OpenBoxConfigError(
            "Invalid agent private key: could not load Ed25519 key (key bytes not shown)."
        ) from None


@dataclass
class AgentIdentity:
    """A validated agent DID plus its loaded Ed25519 signer.

    Stores the loaded key OBJECT — never raw seed bytes/strings after init.
    Construct via :meth:`from_private_key` for validation.
    """

    agent_did: str
    signer: Any = field(repr=False)  # Ed25519PrivateKey; excluded from repr

    @classmethod
    def from_private_key(cls, agent_did: str, agent_private_key: str) -> AgentIdentity:
        """Validate the DID, decode + load the seed, return a ready identity."""
        validate_agent_did(agent_did)
        return cls(agent_did=agent_did, signer=load_ed25519_seed(agent_private_key))

    def sign(self, canonical: str) -> str:
        """Sign a canonical string; return standard padded base64 (ASCII)."""
        return base64.b64encode(self.signer.sign(canonical.encode("utf-8"))).decode("ascii")

    def __repr__(self) -> str:  # never leak key material
        return f"AgentIdentity(agent_did={self.agent_did!r}, signer=<loaded>)"


def build_canonical_string(
    method: str, path: str, timestamp: str, nonce: str, body_sha256: str
) -> str:
    """The exact canonical string Core verifies (``agent.go:93``)."""
    return "\n".join([method.upper(), path, timestamp, nonce, body_sha256])


def build_auth_headers(api_key: str, sdk_version: str | None = None) -> dict[str, str]:
    """Standard bearer auth headers for governance API calls."""
    if sdk_version is None:
        from . import __version__ as sdk_version
    return {
        "Authorization": f"Bearer {api_key}",
        "User-Agent": f"OpenBox-SDK/{sdk_version}",
        "X-OpenBox-SDK-Version": sdk_version,
    }


def prepare_signed_request(
    method: str,
    path: str,
    payload: dict | None,
    *,
    api_key: str,
    identity: AgentIdentity | None,
    sdk_version: str | None = None,
    _timestamp: str | None = None,
    _nonce: str | None = None,
) -> tuple[dict[str, str], bytes]:
    """Build request headers + exact body bytes — the single source of truth.

    Args:
        method: HTTP method (case-insensitive; upper-cased into the canonical string).
        path: URL path only, no host/query — INCLUDES the ``/api/v1`` prefix.
        payload: JSON-serializable body, or ``None`` for empty-body (GET) requests.
        api_key: Bearer API key for the base auth headers.
        identity: Loaded AgentIdentity, or ``None`` for unsigned mode.
        _timestamp/_nonce: Deterministic injection points for golden-fixture
            tests ONLY. Production callers must not pass them — a reused nonce
            is rejected by Core (nonce_replayed).

    Returns:
        ``(headers, body_bytes)``. Callers MUST send ``content=body_bytes`` —
        never ``json=`` — so the transmitted bytes match the hashed bytes.
    """
    body_bytes = serialize_body(payload)
    headers = build_auth_headers(api_key, sdk_version)

    if identity is not None:
        body_sha256 = hashlib.sha256(body_bytes).hexdigest()
        # Signing timestamp KEEPS +00:00 (never Z) — Core verifies these bytes.
        timestamp = _timestamp if _timestamp is not None else datetime.now(UTC).isoformat()
        nonce = _nonce if _nonce is not None else secrets.token_urlsafe(24)
        canonical = build_canonical_string(method, path, timestamp, nonce, body_sha256)
        headers[HEADER_DID] = identity.agent_did
        headers[HEADER_TIMESTAMP] = timestamp
        headers[HEADER_NONCE] = nonce
        headers[HEADER_SIGNATURE] = identity.sign(canonical)
        headers[HEADER_BODY_SHA256] = body_sha256

    return headers, body_bytes
