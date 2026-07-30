"""Byte-parity tests between this SDK's v2 assertion signing and the vendored
golden fixtures (contract §2-4; proposal §13.4/§13.9).

Mirrors ``test_golden_signing.py``'s role for v1: proves this SDK reproduces
the vendored fixtures byte-for-byte when fed the exact same inputs
(deterministic jti/iat injection), rather than merely checking decoded claim
shape (that weaker, fixture-only check already lives in
``test_identity_v2_fixtures.py``, which is vendored and must not be edited).

Does NOT touch anything under ``tests/signing/identity_v2/`` — only reads it.
"""

from __future__ import annotations

import base64
import json
import pathlib

import pytest
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from openbox_core.errors import OpenBoxConfigError
from openbox_core.identity_okta import (
    ASSERTION_LIFETIME_SECONDS,
    OktaAgentIdentity,
    load_rsa_pkcs8_private_key,
    prepare_okta_signed_request,
)
from openbox_core.identity_types import OktaAiAgentIdentityConfig

FIXTURE_DIR = pathlib.Path(__file__).parent / "identity_v2"

POSITIVE_CASES = [
    "evaluate.json",
    "approval.json",
    "auth-validate.json",
    "handoff.json",
]


def _read_fixture(*segments: str) -> dict:
    return json.loads(FIXTURE_DIR.joinpath(*segments).read_text())


def _b64url_to_int(segment: str) -> int:
    padding = "=" * (-len(segment) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(segment + padding), "big")


def _jwk_to_pkcs8_pem(jwk: dict) -> str:
    """Fixture-only JWK -> PKCS8 PEM conversion.

    Production code never parses a JWK private key — the canonical encoding
    is PEM (proposal §13.1 rule 8) — this exists purely so the test can feed
    the vendored fixture's private JWK into ``OktaAiAgentIdentityConfig``.
    """
    numbers = rsa.RSAPrivateNumbers(
        p=_b64url_to_int(jwk["p"]),
        q=_b64url_to_int(jwk["q"]),
        d=_b64url_to_int(jwk["d"]),
        dmp1=_b64url_to_int(jwk["dp"]),
        dmq1=_b64url_to_int(jwk["dq"]),
        iqmp=_b64url_to_int(jwk["qi"]),
        public_numbers=rsa.RSAPublicNumbers(
            e=_b64url_to_int(jwk["e"]), n=_b64url_to_int(jwk["n"])
        ),
    )
    private_key = numbers.private_key()
    return private_key.private_bytes(
        encoding=crypto_serialization.Encoding.PEM,
        format=crypto_serialization.PrivateFormat.PKCS8,
        encryption_algorithm=crypto_serialization.NoEncryption(),
    ).decode("ascii")


def _decode_segment(segment: str) -> dict:
    padding = "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment + padding))


def _fixture_identity(fixture: dict) -> OktaAgentIdentity:
    keypair = _read_fixture("keypair.json")
    claims = fixture["claims"]
    config = OktaAiAgentIdentityConfig(
        openbox_agent_id=claims["obx_agent_id"],
        organization_id=claims["obx_organization_id"],
        deployment_id=claims["obx_deployment_id"],
        external_agent_id=claims["iss"],
        key_id=fixture["header"]["kid"],
        audience=claims["aud"],
        private_key=_jwk_to_pkcs8_pem(keypair["private_jwk"]),
        algorithm=fixture["header"]["alg"],
    )
    return OktaAgentIdentity.from_config(config)


@pytest.mark.parametrize("filename", POSITIVE_CASES)
def test_prepare_okta_signed_request_matches_fixture_byte_for_byte(filename: str) -> None:
    fixture = _read_fixture(filename)
    identity = _fixture_identity(fixture)
    payload = json.loads(base64.b64decode(fixture["body_base64"])) if fixture["body_base64"] else None
    claims = fixture["claims"]

    headers, body = prepare_okta_signed_request(
        fixture["method"],
        fixture["path"],
        payload,
        api_key=fixture["api_key"],
        identity=identity,
        _jti=claims["jti"],
        _iat=claims["iat"],
    )

    assert body == base64.b64decode(fixture["body_base64"])
    assert headers["X-OpenBox-Agent-Assertion"] == fixture["assertion"]
    assert "X-OpenBox-Agent-DID" not in headers

    header_seg, payload_seg, _ = headers["X-OpenBox-Agent-Assertion"].split(".")
    assert _decode_segment(header_seg) == fixture["header"]
    assert _decode_segment(payload_seg) == claims


def test_transition_proof_assertion_matches_fixture_byte_for_byte() -> None:
    fixture = _read_fixture("transition-proof.json")
    identity = _fixture_identity(fixture)
    payload = json.loads(base64.b64decode(fixture["body_base64"]))
    claims = fixture["claims"]

    headers, body = prepare_okta_signed_request(
        fixture["method"],
        fixture["path"],
        payload,
        api_key=fixture["api_key"],
        identity=identity,
        extra_claims={
            "obx_transition_purpose": claims["obx_transition_purpose"],
            "obx_transition_id": claims["obx_transition_id"],
            "obx_transition_challenge": claims["obx_transition_challenge"],
        },
        _jti=claims["jti"],
        _iat=claims["iat"],
    )

    assert body == base64.b64decode(fixture["body_base64"])
    assert headers["X-OpenBox-Agent-Assertion"] == fixture["assertion"]


class TestAssertionLifetimeAndKeySize:
    def test_assertion_lifetime_is_60_seconds(self):
        assert ASSERTION_LIFETIME_SECONDS == 60

    def test_undersized_rsa_key_rejected_locally(self):
        keypair = _read_fixture("keypair.json")
        undersized_pem = _jwk_to_pkcs8_pem(
            keypair["undersized_key_for_negative_test"]["private_jwk"]
        )
        with pytest.raises(OpenBoxConfigError, match="2048") as exc_info:
            load_rsa_pkcs8_private_key(undersized_pem)
        assert "bytes not shown" in str(exc_info.value)
