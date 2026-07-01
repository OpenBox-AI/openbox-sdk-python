"""Config layered-resolution tests: explicit > env_prefix > OPENBOX_* > defaults."""

import pytest

from openbox_core.config import OpenBoxConfig
from openbox_core.errors import (
    OpenBoxAuthError,
    OpenBoxConfigError,
    OpenBoxInsecureURLError,
)

VALID = dict(api_url="https://api.openbox.ai", api_key="obx_test_abc123")


class TestResolutionOrder:
    def test_explicit_beats_env_prefix_and_global(self):
        env = {
            "OPENBOX_TEMPORAL_API_URL": "https://prefix.example",
            "OPENBOX_API_URL": "https://global.example",
            "OPENBOX_TEMPORAL_API_KEY": "obx_test_prefix",
            "OPENBOX_API_KEY": "obx_test_global",
        }
        config = OpenBoxConfig.resolve(
            env_prefix="OPENBOX_TEMPORAL",
            environ=env,
            api_url="https://explicit.example",
            api_key="obx_test_explicit",
        )
        assert config.api_url == "https://explicit.example"
        assert config.api_key == "obx_test_explicit"

    def test_env_prefix_beats_global(self):
        env = {
            "OPENBOX_TEMPORAL_API_URL": "https://prefix.example",
            "OPENBOX_API_URL": "https://global.example",
            "OPENBOX_API_KEY": "obx_test_global",
        }
        config = OpenBoxConfig.resolve(env_prefix="OPENBOX_TEMPORAL", environ=env)
        assert config.api_url == "https://prefix.example"
        assert config.api_key == "obx_test_global"  # falls through to global

    def test_global_beats_defaults(self):
        env = {
            "OPENBOX_API_URL": "https://global.example",
            "OPENBOX_API_KEY": "obx_test_global",
            "OPENBOX_TIMEOUT_SECONDS": "12.5",
        }
        config = OpenBoxConfig.resolve(environ=env)
        assert config.api_url == "https://global.example"
        assert config.timeout_seconds == 12.5

    def test_defaults_apply_last(self):
        config = OpenBoxConfig.resolve(environ={}, **VALID)
        assert config.timeout_seconds == 30.0
        assert config.on_api_error == "fail_open"
        assert config.instrumentation.http_enabled is True
        assert config.instrumentation.llm_enabled is False
        assert config.gate.skip_activity_types == {"send_governance_event"}
        assert config.privacy.max_body_size == 65536

    def test_no_prefix_ignores_prefixed_vars(self):
        env = {
            "OPENBOX_TEMPORAL_API_URL": "https://prefix.example",
            "OPENBOX_API_URL": "https://global.example",
            "OPENBOX_API_KEY": "obx_test_global",
        }
        config = OpenBoxConfig.resolve(environ=env)
        assert config.api_url == "https://global.example"


class TestValidation:
    def test_missing_required_fields(self):
        with pytest.raises(OpenBoxConfigError, match="api_url"):
            OpenBoxConfig.resolve(environ={})
        with pytest.raises(OpenBoxConfigError, match="api_key"):
            OpenBoxConfig.resolve(environ={}, api_url="https://api.openbox.ai")

    def test_api_key_format_enforced(self):
        with pytest.raises(OpenBoxAuthError, match="Invalid API key format"):
            OpenBoxConfig.resolve(environ={}, api_url="https://x.ai", api_key="sk-nope")

    def test_https_required_for_non_localhost(self):
        with pytest.raises(OpenBoxInsecureURLError):
            OpenBoxConfig.resolve(environ={}, api_url="http://api.openbox.ai", api_key="obx_test_a")

    def test_http_localhost_allowed_and_url_normalized(self):
        config = OpenBoxConfig.resolve(
            environ={}, api_url="http://localhost:8080/", api_key="obx_test_a"
        )
        assert config.api_url == "http://localhost:8080"

    def test_partial_identity_rejected_both_or_neither(self):
        with pytest.raises(OpenBoxConfigError, match="together"):
            OpenBoxConfig.resolve(environ={}, **VALID, agent_did="did:aip:12345678-1234-5678-1234-567812345678")

    def test_invalid_did_rejected(self):
        with pytest.raises(OpenBoxConfigError, match="DID"):
            OpenBoxConfig.resolve(environ={}, **VALID, agent_did="did:wrong:x", agent_private_key="AAAA")

    def test_on_api_error_validated(self):
        with pytest.raises(OpenBoxConfigError, match="on_api_error"):
            OpenBoxConfig.resolve(environ={}, **VALID, on_api_error="explode")

    def test_unknown_field_rejected(self):
        with pytest.raises(OpenBoxConfigError, match="Unknown config fields"):
            OpenBoxConfig.resolve(environ={}, **VALID, made_up_field=1)


class TestIdentityLoading:
    def test_load_identity_none_when_unsigned(self):
        assert OpenBoxConfig.resolve(environ={}, **VALID).load_identity() is None

    def test_load_identity_from_env(self):
        import base64

        env = {
            "OPENBOX_API_URL": "https://api.openbox.ai",
            "OPENBOX_API_KEY": "obx_test_abc",
            "OPENBOX_AGENT_DID": "did:aip:12345678-1234-5678-1234-567812345678",
            "OPENBOX_AGENT_PRIVATE_KEY": base64.b64encode(bytes(range(32))).decode(),
        }
        identity = OpenBoxConfig.resolve(environ=env).load_identity()
        assert identity is not None
        assert identity.agent_did.startswith("did:aip:")

    def test_bad_seed_rejected_without_echoing_bytes(self):
        with pytest.raises(OpenBoxConfigError, match="key bytes not shown"):
            OpenBoxConfig.resolve(
                environ={},
                **VALID,
                agent_did="did:aip:12345678-1234-5678-1234-567812345678",
                agent_private_key="dG9vc2hvcnQ=",  # valid b64, wrong length
            ).load_identity()

    def test_repr_never_leaks_private_key(self):
        config = OpenBoxConfig.resolve(
            environ={},
            **VALID,
            agent_did="did:aip:12345678-1234-5678-1234-567812345678",
            agent_private_key="c2VjcmV0LXNlZWQtc2VjcmV0LXNlZWQtc2VjcmV0ISE=",
        )
        assert "c2VjcmV0" not in repr(config)
