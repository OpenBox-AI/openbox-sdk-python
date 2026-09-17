"""Okta config-mode resolution: bootstrap / legacy explicit / invalid mixed.

Mirrors openbox-sdk-ts's test/config-bootstrap-mode.test.ts case for case — the
two SDKs must behave identically (addendum §8).
"""

from __future__ import annotations

import base64
import json
import pathlib

import pytest
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from openbox_core.config import OpenBoxConfig
from openbox_core.errors import OpenBoxConfigError

FIXTURE_DIR = pathlib.Path(__file__).parent.parent / "signing" / "identity_v2"


def _b64url_to_int(segment: str) -> int:
    padding = "=" * (-len(segment) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(segment + padding), "big")


def _fixture_okta_pem() -> str:
    jwk = json.loads((FIXTURE_DIR / "keypair.json").read_text())["private_jwk"]
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
    return (
        numbers.private_key()
        .private_bytes(
            encoding=crypto_serialization.Encoding.PEM,
            format=crypto_serialization.PrivateFormat.PKCS8,
            encryption_algorithm=crypto_serialization.NoEncryption(),
        )
        .decode("ascii")
    )


OKTA_PEM = _fixture_okta_pem()
BASE = {"api_url": "https://core.example.com", "api_key": "obx_test_k"}

# The 6 metadata fields Core supplies in bootstrap mode.
MANAGED_FIELDS = {
    "openbox_agent_id": "00000000-0000-4000-8000-000000000002",
    "organization_id": "00000000-0000-4000-8000-000000000001",
    "deployment_id": "fixture-deployment",
    "agent_proof_audience": "urn:openbox:fixture-deployment:core",
    "okta_agent_id": "fixture-okta-ai-agent-0001",
    "okta_agent_key_id": "fixture-okta-credential-kid-0001",
}


def resolve(**overrides) -> OpenBoxConfig:
    """``environ={}`` isolates every case from the real process environment."""
    return OpenBoxConfig.resolve(environ={}, **{**BASE, **overrides})


class TestBootstrapMode:
    def test_accepts_minimal_three_value_configuration(self):
        config = resolve(okta_agent_private_key=OKTA_PEM)

        assert config.identity_method == "okta_ai_agent"
        assert config.okta_config_mode() == "bootstrap"
        assert config.okta_bootstrap_private_key() == OKTA_PEM
        # The identity cannot exist yet — Core has not supplied its metadata.
        assert config.load_okta_identity() is None

    def test_infers_okta_from_private_key_alone(self):
        # The private key is one of the method-inference trigger fields, so a
        # three-value config still resolves to v2 rather than legacy_unsigned.
        assert resolve(okta_agent_private_key=OKTA_PEM).identity_method == "okta_ai_agent"

    def test_resolves_from_environment_variables(self):
        config = OpenBoxConfig.resolve(
            environ={
                "OPENBOX_API_URL": "https://core.example.com",
                "OPENBOX_API_KEY": "obx_live_envkey",
                "OPENBOX_OKTA_AGENT_PRIVATE_KEY": OKTA_PEM,
            }
        )
        assert config.okta_config_mode() == "bootstrap"
        assert config.okta_bootstrap_private_key() == OKTA_PEM

    def test_does_not_require_deployment_id(self):
        # The operator no longer sets this, which is what prevents a runtime from
        # signing for one deployment while calling another.
        config = resolve(okta_agent_private_key=OKTA_PEM)
        assert config.deployment_id is None
        assert config.agent_proof_audience is None

    def test_tolerates_explicit_rs256_algorithm(self):
        config = resolve(okta_agent_private_key=OKTA_PEM, okta_agent_algorithm="RS256")
        assert config.okta_config_mode() == "bootstrap"

    def test_rejects_stale_non_rs256_algorithm(self):
        with pytest.raises(OpenBoxConfigError, match="RS256"):
            resolve(okta_agent_private_key=OKTA_PEM, okta_agent_algorithm="RS512")

    def test_does_not_parse_private_key_during_offline_resolution(self):
        # normalized() must stay pure and offline — key parsing and the thumbprint
        # check belong to the bootstrap step. A garbage key resolves fine here and
        # fails later, at bootstrap.
        config = resolve(
            okta_agent_private_key="-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----"
        )
        assert config.okta_config_mode() == "bootstrap"

    def test_private_key_stays_out_of_repr(self):
        config = resolve(okta_agent_private_key=OKTA_PEM)
        assert "BEGIN PRIVATE KEY" not in repr(config)


class TestLegacyExplicitMode:
    def test_still_works_with_every_field_configured(self):
        config = resolve(**MANAGED_FIELDS, okta_agent_private_key=OKTA_PEM)

        assert config.okta_config_mode() == "legacy"
        # No bootstrap will be attempted.
        assert config.okta_bootstrap_private_key() is None

        identity = config.load_okta_identity()
        assert identity is not None
        assert identity.key_id == MANAGED_FIELDS["okta_agent_key_id"]
        assert identity.audience == MANAGED_FIELDS["agent_proof_audience"]
        assert identity.external_agent_id == MANAGED_FIELDS["okta_agent_id"]

    def test_still_requires_the_algorithm_field(self):
        # Pre-existing behaviour: legacy mode's completeness check is unchanged.
        # okta_agent_algorithm carries a "RS256" default, so this asserts an
        # explicitly blanked value is still rejected rather than defaulted.
        with pytest.raises(OpenBoxConfigError, match="okta_agent_algorithm"):
            resolve(**MANAGED_FIELDS, okta_agent_private_key=OKTA_PEM, okta_agent_algorithm="")

    def test_mixed_mode_error_names_the_env_vars(self):
        # Parity with the TypeScript SDK: an operator needs the env var to unset,
        # not just the internal field name.
        with pytest.raises(OpenBoxConfigError) as excinfo:
            resolve(
                okta_agent_private_key=OKTA_PEM,
                okta_agent_key_id=MANAGED_FIELDS["okta_agent_key_id"],
            )
        message = str(excinfo.value)
        assert "OPENBOX_OKTA_AGENT_KEY_ID" in message
        assert "OPENBOX_AGENT_ID" in message
        assert "OPENBOX_DEPLOYMENT_ID" in message

    def test_explicit_okta_method_wins_over_did_field_presence(self):
        # Parity with the TypeScript SDK's resolveIdentityMethod: an explicit
        # method must not be discarded by field presence. Direct construction
        # skips validation, which load_okta_identity documents as supported.
        config = OpenBoxConfig(
            api_url="https://core.example.com",
            api_key="obx_test_k",
            identity_method="okta_ai_agent",
            okta_agent_private_key=OKTA_PEM,
            agent_did="did:aip:12345678-1234-5678-1234-567812345678",
        )
        # Must NOT report "not Okta mode" and hand back a v1 DID identity.
        assert config.okta_config_mode() == "bootstrap"
        assert config.okta_bootstrap_private_key() == OKTA_PEM


class TestInvalidMixedMode:
    @pytest.mark.parametrize("field,value", list(MANAGED_FIELDS.items()))
    def test_rejects_partial_configuration(self, field, value):
        # A leftover field from before a rotation would otherwise silently win
        # over the correct value from Core.
        with pytest.raises(OpenBoxConfigError):
            resolve(okta_agent_private_key=OKTA_PEM, **{field: value})

    def test_names_configured_and_missing_fields(self):
        with pytest.raises(OpenBoxConfigError) as excinfo:
            resolve(
                okta_agent_private_key=OKTA_PEM,
                okta_agent_key_id=MANAGED_FIELDS["okta_agent_key_id"],
            )
        message = str(excinfo.value)

        assert "okta_agent_key_id" in message
        # The missing ones are listed too, so the operator can choose a direction.
        assert "openbox_agent_id" in message
        assert "organization_id" in message
        # And both remedies are stated.
        assert "bootstrap mode" in message

    def test_rejects_configuration_missing_exactly_one_managed_field(self):
        all_but_one = {k: v for k, v in MANAGED_FIELDS.items() if k != "okta_agent_key_id"}
        with pytest.raises(OpenBoxConfigError):
            resolve(**all_but_one, okta_agent_private_key=OKTA_PEM)


class TestIdentityMethodBoundaries:
    def test_requires_private_key_in_every_okta_mode(self):
        # Core can never supply this value, so its absence is fatal regardless of mode.
        with pytest.raises(OpenBoxConfigError, match="okta_agent_private_key"):
            resolve(identity_method="okta_ai_agent")

    def test_rejects_did_configuration_with_okta_private_key(self):
        # Must be an explicit error, never a silent guess about which method wins.
        with pytest.raises(OpenBoxConfigError, match="mutually exclusive"):
            resolve(
                agent_did="did:aip:12345678-1234-5678-1234-567812345678",
                agent_private_key="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
                okta_agent_private_key=OKTA_PEM,
            )

    def test_leaves_did_only_configuration_untouched(self):
        config = resolve(
            agent_did="did:aip:12345678-1234-5678-1234-567812345678",
            agent_private_key="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        )

        assert config.identity_method == "openbox_did"
        assert config.okta_config_mode() is None
        assert config.okta_bootstrap_private_key() is None
        assert config.load_identity() is not None

    def test_leaves_unsigned_configuration_untouched(self):
        config = resolve()
        assert config.identity_method == "legacy_unsigned"
        assert config.okta_config_mode() is None
        assert config.okta_bootstrap_private_key() is None
