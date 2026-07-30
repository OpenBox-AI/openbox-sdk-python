"""Tagged identity-verification-method resolution + validation (proposal §13.1).

Extends ``test_resolution_order.py``'s DID-only coverage with the v2 Okta AI
Agent tagged config: explicit-method precedence, mutual exclusion, required
fields, env-var layering, and secret redaction.
"""

from __future__ import annotations

import pytest

from openbox_core.config import OpenBoxConfig
from openbox_core.errors import OpenBoxConfigError
from openbox_core.identity_types import OktaAiAgentIdentityConfig

VALID = dict(api_url="https://api.openbox.ai", api_key="obx_test_abc123")
DID_FIELDS = dict(
    agent_did="did:aip:12345678-1234-5678-1234-567812345678",
    agent_private_key="c2VjcmV0LXNlZWQtc2VjcmV0LXNlZWQtc2VjcmV0ISE=",
)
# A syntactically-plausible (but not cryptographically loaded) PEM string —
# config validation only checks field PRESENCE + algorithm, never key
# validity (mirrors how normalized() never calls load_ed25519_seed either).
OKTA_FIELDS = dict(
    okta_agent_id="wlp-fixture-agent",
    okta_agent_key_id="fixture-kid",
    okta_agent_private_key="-----BEGIN PRIVATE KEY-----\nMIIBogFAKE\n-----END PRIVATE KEY-----",
    openbox_agent_id="00000000-0000-4000-8000-000000000002",
    organization_id="00000000-0000-4000-8000-000000000001",
    deployment_id="fixture-deployment",
    agent_proof_audience="urn:openbox:fixture-deployment:core",
)


class TestInference:
    def test_neither_present_infers_legacy_unsigned(self):
        config = OpenBoxConfig.resolve(environ={}, **VALID)
        assert config.identity_method == "legacy_unsigned"

    def test_did_fields_infer_openbox_did(self):
        config = OpenBoxConfig.resolve(environ={}, **VALID, **DID_FIELDS)
        assert config.identity_method == "openbox_did"

    def test_okta_fields_infer_okta_ai_agent(self):
        config = OpenBoxConfig.resolve(environ={}, **VALID, **OKTA_FIELDS)
        assert config.identity_method == "okta_ai_agent"

    def test_explicit_method_wins_when_fields_also_present(self):
        config = OpenBoxConfig.resolve(
            environ={}, **VALID, **OKTA_FIELDS, identity_method="okta_ai_agent"
        )
        assert config.identity_method == "okta_ai_agent"


class TestMutualExclusion:
    def test_did_and_okta_fields_together_rejected(self):
        with pytest.raises(OpenBoxConfigError, match="mutually exclusive"):
            OpenBoxConfig.resolve(environ={}, **VALID, **OKTA_FIELDS, **DID_FIELDS)

    def test_legacy_unsigned_not_explicitly_selectable(self):
        with pytest.raises(OpenBoxConfigError, match="never selected"):
            OpenBoxConfig.resolve(environ={}, **VALID, identity_method="legacy_unsigned")

    def test_unknown_explicit_method_rejected(self):
        with pytest.raises(OpenBoxConfigError, match="openbox_did"):
            OpenBoxConfig.resolve(environ={}, **VALID, identity_method="bogus")

    def test_explicit_openbox_did_without_fields_rejected(self):
        with pytest.raises(OpenBoxConfigError, match="together"):
            OpenBoxConfig.resolve(environ={}, **VALID, identity_method="openbox_did")


class TestOktaRequiredFields:
    def test_missing_field_rejected_at_construction(self):
        incomplete = dict(OKTA_FIELDS)
        del incomplete["agent_proof_audience"]
        with pytest.raises(OpenBoxConfigError, match="agent_proof_audience"):
            OpenBoxConfig.resolve(environ={}, **VALID, **incomplete)

    def test_unsupported_algorithm_rejected(self):
        with pytest.raises(OpenBoxConfigError, match="RS256"):
            OpenBoxConfig.resolve(
                environ={}, **VALID, **OKTA_FIELDS, okta_agent_algorithm="HS256"
            )

    def test_env_var_layering(self):
        env = {
            "OPENBOX_API_URL": "https://api.openbox.ai",
            "OPENBOX_API_KEY": "obx_test_abc",
            "OPENBOX_OKTA_AGENT_ID": OKTA_FIELDS["okta_agent_id"],
            "OPENBOX_OKTA_AGENT_KEY_ID": OKTA_FIELDS["okta_agent_key_id"],
            "OPENBOX_OKTA_AGENT_PRIVATE_KEY": OKTA_FIELDS["okta_agent_private_key"],
            "OPENBOX_AGENT_ID": OKTA_FIELDS["openbox_agent_id"],
            "OPENBOX_ORGANIZATION_ID": OKTA_FIELDS["organization_id"],
            "OPENBOX_DEPLOYMENT_ID": OKTA_FIELDS["deployment_id"],
            "OPENBOX_AGENT_PROOF_AUDIENCE": OKTA_FIELDS["agent_proof_audience"],
        }
        config = OpenBoxConfig.resolve(environ=env)
        assert config.identity_method == "okta_ai_agent"
        assert config.okta_agent_algorithm == "RS256"

    def test_explicit_method_env_var(self):
        env = {
            "OPENBOX_API_URL": "https://api.openbox.ai",
            "OPENBOX_API_KEY": "obx_test_abc",
            "OPENBOX_AGENT_IDENTITY_METHOD": "okta_ai_agent",
            "OPENBOX_OKTA_AGENT_ID": OKTA_FIELDS["okta_agent_id"],
            "OPENBOX_OKTA_AGENT_KEY_ID": OKTA_FIELDS["okta_agent_key_id"],
            "OPENBOX_OKTA_AGENT_PRIVATE_KEY": OKTA_FIELDS["okta_agent_private_key"],
            "OPENBOX_AGENT_ID": OKTA_FIELDS["openbox_agent_id"],
            "OPENBOX_ORGANIZATION_ID": OKTA_FIELDS["organization_id"],
            "OPENBOX_DEPLOYMENT_ID": OKTA_FIELDS["deployment_id"],
            "OPENBOX_AGENT_PROOF_AUDIENCE": OKTA_FIELDS["agent_proof_audience"],
        }
        config = OpenBoxConfig.resolve(environ=env)
        assert config.identity_method == "okta_ai_agent"


class TestRedaction:
    def test_repr_never_leaks_okta_private_key(self):
        config = OpenBoxConfig.resolve(environ={}, **VALID, **OKTA_FIELDS)
        assert "MIIBogFAKE" not in repr(config)

    def test_okta_agent_identity_config_repr_hides_private_key(self):
        candidate = OktaAiAgentIdentityConfig(
            openbox_agent_id="a",
            organization_id="o",
            deployment_id="d",
            external_agent_id="e",
            key_id="k",
            audience="aud",
            private_key="super-secret-pem-material",
        )
        assert "super-secret-pem-material" not in repr(candidate)


class TestLoadOktaIdentity:
    def test_load_okta_identity_none_when_not_configured(self):
        config = OpenBoxConfig.resolve(environ={}, **VALID)
        assert config.load_okta_identity() is None

    def test_load_okta_identity_none_when_did_configured(self):
        config = OpenBoxConfig.resolve(environ={}, **VALID, **DID_FIELDS)
        assert config.load_okta_identity() is None
        assert config.load_identity() is not None
