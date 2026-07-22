"""EvaluationClient fail-open/fail-closed and auth-validation tests.

Uses httpx.MockTransport — requests never leave the process.
"""


import httpx
import pytest

from openbox_core.client import (
    AUTH_VALIDATE_PATH,
    EVALUATE_PATH,
    EvaluationClient,
)
from openbox_core.contracts.results import Verdict
from openbox_core.errors import (
    ContractError,
    GovernanceAPIError,
    OpenBoxAuthError,
    OpenBoxNetworkError,
    OpenBoxSigningError,
)
from openbox_core.identity import AgentIdentity

SEED_B64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="  # bytes(range(32))
DID = "did:aip:12345678-1234-5678-1234-567812345678"


def make_client(handler, *, on_api_error="fail_open", identity=None) -> EvaluationClient:
    transport = httpx.MockTransport(handler)
    return EvaluationClient(
        "https://core.test",
        "obx_test_abc",
        on_api_error=on_api_error,
        identity=identity,
        transport=transport,
        async_transport=transport,
    )


class TestEvaluateSuccess:
    def test_parses_result_and_sends_exact_bytes(self):
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["path"] = request.url.path
            captured["body"] = request.content
            captured["auth"] = request.headers.get("Authorization")
            return httpx.Response(200, json={"verdict": "block", "reason": "no"})

        client = make_client(handler)
        result = client.evaluate({"b": 1, "a": 2})
        assert result.verdict is Verdict.BLOCK
        assert result.fallback_used is False
        assert captured["path"] == EVALUATE_PATH
        # compact separators, single serialization pass, insertion order kept
        assert captured["body"] == b'{"b":1,"a":2}'
        assert captured["auth"] == "Bearer obx_test_abc"

    async def test_async_parses_result(self):
        def handler(request):
            return httpx.Response(200, json={"verdict": "allow"})

        result = await make_client(handler).aevaluate({"x": 1})
        assert result.verdict is Verdict.ALLOW

    def test_signed_request_carries_aip_headers(self):
        captured = {}

        def handler(request):
            captured["headers"] = dict(request.headers)
            return httpx.Response(200, json={"verdict": "allow"})

        identity = AgentIdentity.from_private_key(DID, SEED_B64)
        make_client(handler, identity=identity).evaluate({"x": 1})
        assert captured["headers"]["x-openbox-agent-did"] == DID
        assert "x-openbox-agent-signature" in captured["headers"]
        assert captured["headers"]["x-openbox-agent-timestamp"].endswith("+00:00")


class TestFailOpen:
    def test_network_error_returns_fallback_allow(self):
        def handler(request):
            raise httpx.ConnectError("boom")

        result = make_client(handler).evaluate({"x": 1})
        assert result.verdict is Verdict.ALLOW
        assert result.fallback_used is True
        assert "unreachable" in result.reason

    def test_http_500_returns_fallback_allow(self):
        def handler(request):
            return httpx.Response(500)

        result = make_client(handler).evaluate({"x": 1})
        assert result.fallback_used is True

    def test_redirect_is_not_parsed_as_success(self):
        def handler(request):
            return httpx.Response(302, json={"verdict": "allow"})

        result = make_client(handler).evaluate({"x": 1})
        assert result.fallback_used is True

    def test_unparseable_success_is_contract_failure(self):
        def handler(request):
            return httpx.Response(200, content=b"<html>not json</html>")

        with pytest.raises(ContractError, match="Malformed governance response"):
            make_client(handler).evaluate({"x": 1})

    def test_client_creation_failure_still_follows_fail_open(self, monkeypatch):
        client = make_client(lambda _: httpx.Response(200, json={}))

        def fail():
            raise RuntimeError("client setup failed")

        monkeypatch.setattr(client, "_sync", fail)
        result = client.evaluate({"x": 1})
        assert result.verdict is Verdict.ALLOW
        assert result.fallback_used is True

    async def test_async_network_error_fallback(self):
        def handler(request):
            raise httpx.ConnectError("boom")

        result = await make_client(handler).aevaluate({"x": 1})
        assert result.fallback_used is True


class TestFailClosed:
    def test_network_error_raises(self):
        def handler(request):
            raise httpx.ConnectError("boom")

        with pytest.raises(GovernanceAPIError, match="unreachable"):
            make_client(handler, on_api_error="fail_closed").evaluate({"x": 1})

    def test_http_error_raises(self):
        def handler(request):
            return httpx.Response(503)

        with pytest.raises(GovernanceAPIError, match="HTTP 503"):
            make_client(handler, on_api_error="fail_closed").evaluate({"x": 1})

    async def test_async_raises(self):
        def handler(request):
            raise httpx.ConnectError("boom")

        with pytest.raises(GovernanceAPIError):
            await make_client(handler, on_api_error="fail_closed").aevaluate({"x": 1})

    def test_invalid_mode_rejected(self):
        with pytest.raises(ValueError):
            EvaluationClient("https://x", "obx_test_a", on_api_error="explode")


class TestAuthValidate:
    def test_success(self):
        def handler(request):
            assert request.url.path == AUTH_VALIDATE_PATH
            assert request.method == "GET"
            return httpx.Response(200, json={"ok": True})

        assert make_client(handler).validate_api_key() is True

    def test_401_raises_auth_error(self):
        def handler(request):
            return httpx.Response(401, json={"error": "bad key"})

        with pytest.raises(OpenBoxAuthError):
            make_client(handler).validate_api_key()

    def test_signing_reason_code_surfaced_when_signed(self):
        def handler(request):
            return httpx.Response(403, json={"reason_code": "signature_invalid"})

        identity = AgentIdentity.from_private_key(DID, SEED_B64)
        with pytest.raises(OpenBoxSigningError, match="signature_invalid") as exc_info:
            make_client(handler, identity=identity).validate_api_key()
        assert exc_info.value.reason_code == "signature_invalid"

    def test_5xx_raises_network_error(self):
        def handler(request):
            return httpx.Response(502)

        with pytest.raises(OpenBoxNetworkError):
            make_client(handler).validate_api_key()

    async def test_async_success(self):
        def handler(request):
            return httpx.Response(200)

        assert await make_client(handler).avalidate_api_key() is True


class TestClose:
    def test_close_idempotent(self):
        client = make_client(lambda r: httpx.Response(200, json={"verdict": "allow"}))
        client.evaluate({"x": 1})
        client.close()
        client.close()

    async def test_aclose_idempotent(self):
        client = make_client(lambda r: httpx.Response(200, json={"verdict": "allow"}))
        await client.aevaluate({"x": 1})
        await client.aclose()
        await client.aclose()
