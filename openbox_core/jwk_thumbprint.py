"""RFC 7638 JWK thumbprint derivation for the identity-bootstrap flow.

The SDK derives its LOCAL private key's public thumbprint and compares it against
the one Core returns for the agent's selected credential. A match proves the
runtime holds the right key before a single governed request is sent; a mismatch
is fatal and must never be retried past.

Import safety: ``cryptography`` is imported lazily inside the function, matching
this package's convention (see ``tests/test_import_safety.py``) so importing this
module never pulls in a heavy dependency.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any

from .errors import OpenBoxConfigError

__all__ = ["jwk_thumbprint_sha256", "thumbprints_match"]


def _b64url_uint(value: int) -> str:
    """Encode a non-negative integer as base64url, unpadded — RFC 7518 §2."""
    length = max(1, (value.bit_length() + 7) // 8)
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode("ascii")


def jwk_thumbprint_sha256(key: Any) -> str:
    """RFC 7638 SHA-256 thumbprint of ``key``'s PUBLIC half.

    Returned base64url without padding.

    Only the three required RSA members (``e``, ``kty``, ``n``) participate, in
    lexicographic order with no whitespace. ``kid``/``alg``/``use`` are excluded
    deliberately: an SDK deriving a JWK from a private key does not know Core's
    stored ``kid`` or ``alg``, so including any of them would make the two sides'
    digests disagree by construction.

    Accepts an RSA private OR public key, matching the TypeScript SDK's helper. A
    private key is reduced to its public numbers first, so no private parameter
    ever reaches the digest input or an error message. Accepting a public key is
    what lets the RFC 7638 §3.1 reference vector — which publishes only a public
    key — be verified through this function rather than around it.
    """
    from cryptography.hazmat.primitives.asymmetric import rsa

    if isinstance(key, rsa.RSAPrivateKey):
        public_key = key.public_key()
    elif isinstance(key, rsa.RSAPublicKey):
        public_key = key
    else:
        raise OpenBoxConfigError(
            "Cannot derive a JWK thumbprint: expected an RSA key (key bytes not shown)."
        )

    numbers = public_key.public_numbers()
    # sort_keys + the compact separators ARE the RFC 7638 canonical form.
    canonical = json.dumps(
        {"e": _b64url_uint(numbers.e), "kty": "RSA", "n": _b64url_uint(numbers.n)},
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def thumbprints_match(left: str, right: str) -> bool:
    """Constant-time thumbprint comparison.

    Constant-time is specified for this step even though a thumbprint is public,
    so the routine cannot become a side channel if it is ever reused for
    something that is not. ``compare_digest`` handles unequal lengths itself.
    """
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))
