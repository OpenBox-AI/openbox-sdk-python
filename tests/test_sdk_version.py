from __future__ import annotations

import httpx

import openbox_core
from openbox_core.client import EvaluationClient
from openbox_core.config import OpenBoxConfig
from openbox_core.identity import build_auth_headers
from openbox_core.runtime import OpenBoxRuntime
from openbox_core.sdk_version import build_sdk_identifier, normalize_sdk_version


def test_build_sdk_identifier_defaults_to_base_python_package_version():
    assert (
        build_sdk_identifier()
        == f"openbox-base-python-v{openbox_core.__version__}"
    )


def test_build_sdk_identifier_accepts_framework_engine_and_minor_version():
    assert (
        build_sdk_identifier(engine="Framework", language="Python", version="v1.1")
        == "openbox-framework-python-v1.1"
    )


def test_build_sdk_identifier_preserves_valid_full_identifier():
    assert (
        build_sdk_identifier(version="openbox-custom-python-v1.2.3")
        == "openbox-custom-python-v1.2.3"
    )


def test_normalize_sdk_version_rejects_unversioned_values():
    try:
        normalize_sdk_version("latest")
    except ValueError as exc:
        assert "sdk version" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_build_auth_headers_sends_standard_sdk_identifier():
    headers = build_auth_headers(
        "obx_test_a",
        "1.2.3",
        sdk_engine="custom",
        sdk_language="python",
    )

    assert headers["X-OpenBox-SDK-Version"] == "openbox-custom-python-v1.2.3"
    assert headers["User-Agent"] == "OpenBox-SDK/openbox-custom-python-v1.2.3"


def test_evaluation_client_uses_configured_sdk_identifier():
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["sdk"] = request.headers["X-OpenBox-SDK-Version"]
        return httpx.Response(200, json={"verdict": "allow"})

    client = EvaluationClient(
        "https://core.test",
        "obx_test_a",
        sdk_version="1.2.3",
        sdk_engine="custom",
        transport=httpx.MockTransport(handler),
    )

    client.evaluate({"event_type": "WorkflowStarted"})

    assert seen["sdk"] == "openbox-custom-python-v1.2.3"


def test_runtime_passes_configured_sdk_identifier_to_default_client():
    runtime = OpenBoxRuntime(
        OpenBoxConfig(
            api_url="https://core.test",
            api_key="obx_test_a",
            sdk_version="1.1",
            sdk_engine="custom",
        )
    )

    assert runtime.client._sdk_version == "1.1"
    assert runtime.client._sdk_engine == "custom"
    assert runtime.client._sdk_language == "python"
