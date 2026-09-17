"""Shared test-only identity fixtures for the v2 client test suite.

Uses freshly generated real keys (not the vendored golden-fixture keypair,
which is exercised separately for byte-parity in
``tests/signing/test_identity_v2_signing.py``) so these tests are
self-contained and never risk depending on / mutating vendored fixture
bytes.

Bare top-level module (no package `__init__.py` in `tests/`) — imported as
``from identity_fixtures import ...``, mirroring the existing
``tests/wire/span_fixtures.py`` convention.
"""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from openbox_core.identity import AgentIdentity
from openbox_core.identity_okta import OktaAgentIdentity
from openbox_core.identity_types import OktaAiAgentIdentityConfig, OpenBoxDidIdentityConfig

DID = "did:aip:12345678-1234-5678-1234-567812345678"
SEED_B64 = base64.b64encode(bytes(range(32))).decode()

OTHER_DID = "did:aip:87654321-4321-8765-4321-876543218765"
OTHER_SEED_B64 = base64.b64encode(bytes(range(32))[::-1]).decode()


def generate_pkcs8_pem(key_size: int = 2048) -> str:
    """Generate a fresh RSA private key, PKCS8 PEM-encoded."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return key.private_bytes(
        encoding=crypto_serialization.Encoding.PEM,
        format=crypto_serialization.PrivateFormat.PKCS8,
        encryption_algorithm=crypto_serialization.NoEncryption(),
    ).decode("ascii")


def make_okta_identity_config(**overrides: object) -> OktaAiAgentIdentityConfig:
    fields: dict[str, object] = dict(
        openbox_agent_id="agent-1",
        organization_id="org-1",
        deployment_id="dep-1",
        external_agent_id="wlp-1",
        key_id="kid-1",
        audience="urn:openbox:dep-1:core",
        private_key=generate_pkcs8_pem(),
    )
    fields.update(overrides)
    return OktaAiAgentIdentityConfig(**fields)  # type: ignore[arg-type]


def make_okta_identity(**overrides: object) -> OktaAgentIdentity:
    return OktaAgentIdentity.from_config(make_okta_identity_config(**overrides))


def make_did_identity() -> AgentIdentity:
    return AgentIdentity.from_private_key(DID, SEED_B64)


def make_other_did_identity() -> AgentIdentity:
    return AgentIdentity.from_private_key(OTHER_DID, OTHER_SEED_B64)


def make_did_identity_config(**overrides: object) -> OpenBoxDidIdentityConfig:
    fields: dict[str, object] = dict(did=OTHER_DID, private_key=OTHER_SEED_B64)
    fields.update(overrides)
    return OpenBoxDidIdentityConfig(**fields)  # type: ignore[arg-type]
