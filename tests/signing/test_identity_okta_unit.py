"""Unit tests for openbox_core.identity_okta — key loading, claim building,
assertion signing, and OpenBoxConfig.load_okta_identity() end-to-end.

Uses a freshly generated RSA-2048 test key (NOT the vendored fixture
keypair, which ``test_identity_v2_signing.py`` already exercises for byte
parity against Core's own golden fixtures) so these tests are self-contained.
"""

from __future__ import annotations

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from openbox_core.config import OpenBoxConfig
from openbox_core.errors import OpenBoxConfigError
from openbox_core.identity_okta import (
    HEADER_ASSERTION,
    MIN_RSA_KEY_BITS,
    OktaAgentIdentity,
    load_rsa_pkcs8_private_key,
    prepare_okta_signed_request,
)
from openbox_core.identity_types import OktaAiAgentIdentityConfig


def _generate_pkcs8_pem(key_size: int = 2048) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return key.private_bytes(
        encoding=crypto_serialization.Encoding.PEM,
        format=crypto_serialization.PrivateFormat.PKCS8,
        encryption_algorithm=crypto_serialization.NoEncryption(),
    ).decode("ascii")


def _decode_segment(segment: str) -> dict:
    padding = "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment + padding))


REAL_PEM = _generate_pkcs8_pem()

CONFIG_KWARGS = dict(
    openbox_agent_id="agent-1",
    organization_id="org-1",
    deployment_id="dep-1",
    external_agent_id="wlp-external-1",
    key_id="kid-1",
    audience="urn:openbox:dep-1:core",
)


class TestLoadRsaPkcs8PrivateKey:
    def test_loads_valid_key(self):
        key = load_rsa_pkcs8_private_key(REAL_PEM)
        assert key.key_size == 2048

    def test_rejects_undersized_key(self):
        small_pem = _generate_pkcs8_pem(1024)
        with pytest.raises(OpenBoxConfigError, match=str(MIN_RSA_KEY_BITS)):
            load_rsa_pkcs8_private_key(small_pem)

    def test_rejects_malformed_pem_without_echoing_bytes(self):
        with pytest.raises(OpenBoxConfigError, match="key bytes not shown"):
            load_rsa_pkcs8_private_key("not a pem")

    def test_rejects_non_rsa_key(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        ed_key = Ed25519PrivateKey.generate()
        pem = ed_key.private_bytes(
            encoding=crypto_serialization.Encoding.PEM,
            format=crypto_serialization.PrivateFormat.PKCS8,
            encryption_algorithm=crypto_serialization.NoEncryption(),
        ).decode("ascii")
        with pytest.raises(OpenBoxConfigError, match="RSA"):
            load_rsa_pkcs8_private_key(pem)


class TestOktaAgentIdentity:
    def test_from_config_loads_and_validates(self):
        config = OktaAiAgentIdentityConfig(private_key=REAL_PEM, **CONFIG_KWARGS)
        identity = OktaAgentIdentity.from_config(config)
        assert identity.key_id == "kid-1"
        assert identity.algorithm == "RS256"

    def test_rejects_unsupported_algorithm(self):
        config = OktaAiAgentIdentityConfig(
            private_key=REAL_PEM, algorithm="HS256", **CONFIG_KWARGS
        )
        with pytest.raises(OpenBoxConfigError, match="RS256"):
            OktaAgentIdentity.from_config(config)

    def test_repr_never_leaks_private_key(self):
        config = OktaAiAgentIdentityConfig(private_key=REAL_PEM, **CONFIG_KWARGS)
        identity = OktaAgentIdentity.from_config(config)
        assert "BEGIN PRIVATE KEY" not in repr(identity)
        assert "kid-1" in repr(identity)


class TestPrepareOktaSignedRequest:
    def _identity(self) -> OktaAgentIdentity:
        return OktaAgentIdentity.from_config(
            OktaAiAgentIdentityConfig(private_key=REAL_PEM, **CONFIG_KWARGS)
        )

    def test_claims_cover_all_twelve_required_fields(self):
        identity = self._identity()
        headers, body = prepare_okta_signed_request(
            "POST",
            "/api/v2/governance/evaluate",
            {"a": 1},
            api_key="obx_test_abc",
            identity=identity,
        )
        assert body == b'{"a":1}'
        assertion = headers[HEADER_ASSERTION]
        header_b64, payload_b64, _ = assertion.split(".")

        header = _decode_segment(header_b64)
        claims = _decode_segment(payload_b64)
        assert header == {"alg": "RS256", "kid": "kid-1", "typ": "openbox-agent-proof+jwt"}
        for claim in (
            "iss",
            "sub",
            "aud",
            "obx_deployment_id",
            "obx_organization_id",
            "obx_agent_id",
            "obx_api_key_sha256",
            "iat",
            "exp",
            "jti",
            "htm",
            "htu",
            "body_sha256",
        ):
            assert claim in claims
        assert claims["iss"] == claims["sub"] == "wlp-external-1"
        assert claims["aud"] == "urn:openbox:dep-1:core"
        assert claims["obx_api_key_sha256"] == hashlib.sha256(b"obx_test_abc").hexdigest()
        assert claims["exp"] - claims["iat"] == 60
        assert claims["htm"] == "POST"
        assert claims["htu"] == "/api/v2/governance/evaluate"
        assert claims["body_sha256"] == hashlib.sha256(b'{"a":1}').hexdigest()

    def test_empty_body_hashes_to_well_known_constant(self):
        identity = self._identity()
        headers, body = prepare_okta_signed_request(
            "GET",
            "/api/v2/auth/validate",
            None,
            api_key="obx_test_abc",
            identity=identity,
        )
        assert body == b""
        claims = _decode_segment(headers[HEADER_ASSERTION].split(".")[1])
        assert claims["body_sha256"] == hashlib.sha256(b"").hexdigest()

    def test_only_assertion_and_base_headers_are_sent(self):
        identity = self._identity()
        headers, _ = prepare_okta_signed_request(
            "POST",
            "/api/v2/governance/evaluate",
            {"x": 1},
            api_key="obx_test_abc",
            identity=identity,
        )
        assert set(headers) == {
            "Authorization",
            "User-Agent",
            "X-OpenBox-SDK-Version",
            HEADER_ASSERTION,
        }

    def test_jti_and_iat_injection_are_deterministic(self):
        identity = self._identity()
        headers, _ = prepare_okta_signed_request(
            "POST",
            "/api/v2/governance/evaluate",
            {"x": 1},
            api_key="obx_test_abc",
            identity=identity,
            _jti="fixed-jti",
            _iat=1000,
        )
        claims = _decode_segment(headers[HEADER_ASSERTION].split(".")[1])
        assert claims["jti"] == "fixed-jti"
        assert claims["iat"] == 1000
        assert claims["exp"] == 1060


class TestConfigLoadOktaIdentity:
    def test_load_okta_identity_end_to_end(self):
        config = OpenBoxConfig.resolve(
            environ={},
            api_url="https://api.openbox.ai",
            api_key="obx_test_abc",
            okta_agent_id="wlp-external-1",
            okta_agent_key_id="kid-1",
            okta_agent_private_key=REAL_PEM,
            openbox_agent_id="agent-1",
            organization_id="org-1",
            deployment_id="dep-1",
            agent_proof_audience="urn:openbox:dep-1:core",
        )
        identity = config.load_okta_identity()
        assert identity is not None
        assert identity.key_id == "kid-1"
        assert config.load_identity() is None
