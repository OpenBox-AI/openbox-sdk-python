"""v2 endpoint selection + no-v1-fallback proof (proposal §13.3, contract §2.1/§2.2).

An okta_ai_agent-configured client must route to /api/v2/* and send ONLY
X-OpenBox-Agent-Assertion + the existing base auth headers — never any v1 DID
identity header, even as a "fallback". Also covers source-authenticated
handoff emission (proposal §13.2/§15.1).
"""

from __future__ import annotations

import httpx
import pytest
from identity_fixtures import make_did_identity, make_okta_identity

from openbox_core.client import (
    APPROVAL_PATH_V2,
    AUTH_VALIDATE_PATH_V2,
    EVALUATE_PATH,
    EVALUATE_PATH_V2,
    HANDOFF_PATH,
    HANDOFF_PATH_V2,
    EvaluationClient,
)
from openbox_core.errors import OpenBoxConfigError, OpenBoxSigningError
from openbox_core.identity_okta import HEADER_ASSERTION

V1_IDENTITY_HEADERS = (
    "x-openbox-agent-did",
    "x-openbox-agent-timestamp",
    "x-openbox-agent-nonce",
    "x-openbox-agent-signature",
    "x-openbox-body-sha256",
)


def _client(handler, *, identity=None) -> EvaluationClient:
    transport = httpx.MockTransport(handler)
    return EvaluationClient(
        "https://core.test",
        "obx_test_abc",
        identity=identity,
        transport=transport,
        async_transport=transport,
    )


class TestOktaRoutesToV2:
    def test_evaluate_uses_v2_path(self):
        captured = {}

        def handler(request):
            captured["path"] = request.url.path
            return httpx.Response(200, json={"verdict": "allow"})

        _client(handler, identity=make_okta_identity()).evaluate({"x": 1})
        assert captured["path"] == EVALUATE_PATH_V2
        assert captured["path"] != EVALUATE_PATH

    def test_approval_uses_v2_path(self):
        captured = {}

        def handler(request):
            captured["path"] = request.url.path
            return httpx.Response(200, json={"action": "allow"})

        _client(handler, identity=make_okta_identity()).poll_approval("wf", "run", "act")
        assert captured["path"] == APPROVAL_PATH_V2

    def test_validate_uses_v2_path(self):
        captured = {}

        def handler(request):
            captured["path"] = request.url.path
            captured["method"] = request.method
            return httpx.Response(200)

        _client(handler, identity=make_okta_identity()).validate_api_key()
        assert captured["path"] == AUTH_VALIDATE_PATH_V2
        assert captured["method"] == "GET"

    def test_no_v1_identity_header_leaks_onto_a_v2_request(self):
        captured = {}

        def handler(request):
            captured["headers"] = {k.lower(): v for k, v in request.headers.items()}
            return httpx.Response(200, json={"verdict": "allow"})

        _client(handler, identity=make_okta_identity()).evaluate({"x": 1})
        headers = captured["headers"]
        for v1_header in V1_IDENTITY_HEADERS:
            assert v1_header not in headers, f"v1 header {v1_header} leaked onto a v2 request"
        assert HEADER_ASSERTION.lower() in headers
        assert "authorization" in headers
        assert "x-openbox-sdk-version" in headers

    def test_no_cross_version_retry_on_v2_auth_failure(self):
        calls = []

        def handler(request):
            calls.append(request.url.path)
            return httpx.Response(401, json={"reason_code": "assertion_signature_invalid"})

        with pytest.raises(OpenBoxSigningError):
            _client(handler, identity=make_okta_identity()).evaluate({"x": 1})
        # Exactly one call — never falls back to v1 after the v2 rejection.
        assert calls == [EVALUATE_PATH_V2]


class TestDidAndLegacyStillRouteToV1:
    def test_did_identity_uses_v1_paths(self):
        captured = {}

        def handler(request):
            captured["path"] = request.url.path
            return httpx.Response(200, json={"verdict": "allow"})

        _client(handler, identity=make_did_identity()).evaluate({"x": 1})
        assert captured["path"] == EVALUATE_PATH

    def test_unsigned_mode_uses_v1_paths(self):
        captured = {}

        def handler(request):
            captured["path"] = request.url.path
            return httpx.Response(200, json={"verdict": "allow"})

        _client(handler).evaluate({"x": 1})
        assert captured["path"] == EVALUATE_PATH


class TestHandoffEmission:
    def test_okta_identity_emits_v2_handoff(self):
        captured = {}

        def handler(request):
            captured["path"] = request.url.path
            captured["body"] = request.content
            return httpx.Response(200, json={"id": "handoff-1"})

        result = _client(handler, identity=make_okta_identity()).emit_handoff(
            "00000000-0000-4000-8000-00000000000c", reason="delegation"
        )
        assert captured["path"] == HANDOFF_PATH_V2
        assert captured["body"] == (
            b'{"target_agent_id":"00000000-0000-4000-8000-00000000000c","reason":"delegation"}'
        )
        assert result == {"id": "handoff-1"}

    def test_did_identity_emits_v1_handoff(self):
        captured = {}

        def handler(request):
            captured["path"] = request.url.path
            return httpx.Response(200, json={"id": "handoff-1"})

        _client(handler, identity=make_did_identity()).emit_handoff("target-agent")
        assert captured["path"] == HANDOFF_PATH

    def test_handoff_without_reason_omits_the_key(self):
        captured = {}

        def handler(request):
            captured["body"] = request.content
            return httpx.Response(200, json={})

        _client(handler, identity=make_did_identity()).emit_handoff("target-agent")
        assert captured["body"] == b'{"target_agent_id":"target-agent"}'

    def test_unsigned_mode_cannot_emit_handoff(self):
        def handler(request):
            raise AssertionError("must not send a request without a source identity")

        with pytest.raises(OpenBoxConfigError, match="identity"):
            _client(handler).emit_handoff("target-agent")

    async def test_async_unsigned_mode_cannot_emit_handoff(self):
        def handler(request):
            raise AssertionError("must not send a request without a source identity")

        with pytest.raises(OpenBoxConfigError, match="identity"):
            await _client(handler).aemit_handoff("target-agent")

    async def test_async_okta_identity_emits_v2_handoff(self):
        captured = {}

        def handler(request):
            captured["path"] = request.url.path
            return httpx.Response(200, json={"id": "handoff-2"})

        result = await _client(handler, identity=make_okta_identity()).aemit_handoff(
            "target-agent"
        )
        assert captured["path"] == HANDOFF_PATH_V2
        assert result == {"id": "handoff-2"}
