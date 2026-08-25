"""Keycloak service-account authentication for Core v3 routes."""

from __future__ import annotations

import base64
import json
from urllib.parse import parse_qs

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from openbox_core.client import EvaluationClient
from openbox_core.errors import OpenBoxAuthError, OpenBoxConfigError, OpenBoxNetworkError
from openbox_core.instrumentation.http import set_ignored_url_prefixes, should_ignore_url
from openbox_core.workload_identity import (
    AUTH_BOOTSTRAP_PATH_V3,
    WORKLOAD_TOKEN_HEADER,
    WORKLOAD_TRANSITION_BOOTSTRAP_PATH_V3,
    WORKLOAD_TRANSITION_PROOF_PATH_V3,
    build_private_key_jwt,
    parse_workload_bootstrap_document,
    parse_workload_transition_bootstrap_response,
)

API_URL = "https://core.example.test"
API_KEY = "obx_test_workload"
AGENT_ID = "11111111-1111-4111-8111-111111111111"
SERVICE_ACCOUNT_ID = "22222222-2222-4222-8222-222222222222"
ACTIVATION_VERSION = "33333333-3333-4333-8333-333333333333"
CLIENT_ID = "openbox-agent-11111111-22222222"
ISSUER = "https://id.example.test/realms/openbox"
TOKEN_ENDPOINT = f"{ISSUER}/protocol/openid-connect/token"
KID = "workload-key-1"
TRANSITION_ID = "44444444-4444-4444-8444-444444444444"


def _private_key() -> str:
    from cryptography.hazmat.primitives import serialization

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


PRIVATE_KEY = _private_key()


def bootstrap_body(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "bootstrap_version": 3,
        "contract_version": 3,
        "token_endpoint": TOKEN_ENDPOINT,
        "issuer": ISSUER,
        "audience": "openbox-core",
        "client_id": CLIENT_ID,
        "service_account_id": SERVICE_ACCOUNT_ID,
        "activation_version": ACTIVATION_VERSION,
        "identity_source": "okta",
        "kid": KID,
    }
    body.update(overrides)
    return body


def _jwt_segment(token: str, index: int) -> dict[str, object]:
    segment = token.split(".")[index]
    segment += "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment))


class WorkloadServer:
    def __init__(self, *, bootstrap_status: int = 200, token_status: int = 200):
        self.bootstrap_status = bootstrap_status
        self.token_status = token_status
        self.calls: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        if request.url.path == AUTH_BOOTSTRAP_PATH_V3:
            if self.bootstrap_status == 409:
                return httpx.Response(
                    409,
                    json={"reason_code": "workload_identity_unavailable"},
                )
            return httpx.Response(self.bootstrap_status, json=bootstrap_body())
        if str(request.url) == TOKEN_ENDPOINT:
            return httpx.Response(
                self.token_status,
                json={
                    "access_token": "keycloak-access-token",
                    "token_type": "Bearer",
                    "expires_in": 300,
                },
            )
        return httpx.Response(200, json={"allowed": True, "verdict": "ALLOW"})


def make_client(server: WorkloadServer) -> EvaluationClient:
    transport = httpx.MockTransport(server)
    return EvaluationClient(
        API_URL,
        API_KEY,
        workload_private_key=PRIVATE_KEY,
        transport=transport,
        async_transport=transport,
    )


class TestWorkloadBootstrap:
    def test_parses_strict_public_metadata(self):
        document = parse_workload_bootstrap_document(bootstrap_body())

        assert document.client_id == CLIENT_ID
        assert document.service_account_id == SERVICE_ACCOUNT_ID
        assert document.activation_version == ACTIVATION_VERSION
        assert document.identity_source == "okta"
        assert "PRIVATE KEY" not in repr(document)

    @pytest.mark.parametrize(
        ("overrides", "message"),
        [
            ({"bootstrap_version": 2}, "bootstrap version"),
            ({"contract_version": 2}, "contract version"),
            ({"identity_source": "unknown"}, "identity_source"),
            ({"service_account_id": "not-a-uuid"}, "service_account_id"),
            ({"token_endpoint": "https://other.test/token"}, "token_endpoint"),
        ],
    )
    def test_rejects_malformed_or_cross_origin_metadata(self, overrides, message):
        with pytest.raises(OpenBoxConfigError, match=message):
            parse_workload_bootstrap_document(bootstrap_body(**overrides))

    def test_builds_short_lived_exact_client_assertion(self):
        document = parse_workload_bootstrap_document(bootstrap_body())

        assertion = build_private_key_jwt(
            PRIVATE_KEY,
            document,
            issued_at=1_700_000_000,
            jti="assertion-1",
        )

        assert _jwt_segment(assertion, 0) == {
            "alg": "RS256",
            "kid": KID,
            "typ": "JWT",
        }
        assert _jwt_segment(assertion, 1) == {
            "aud": TOKEN_ENDPOINT,
            "exp": 1_700_000_060,
            "iat": 1_700_000_000,
            "iss": CLIENT_ID,
            "jti": "assertion-1",
            "sub": CLIENT_ID,
        }

    def test_parses_transition_candidate_metadata(self):
        document = parse_workload_transition_bootstrap_response(
            200,
            json.dumps(
                {
                    "bootstrap_version": 3,
                    "contract_version": 3,
                    "transition_id": TRANSITION_ID,
                    "token_endpoint": TOKEN_ENDPOINT,
                    "client_id": CLIENT_ID,
                    "kid": KID,
                    "identity_source": "okta",
                    "expires_at": "2026-08-16T12:00:00Z",
                }
            ).encode(),
        )

        assert document.transition_id == TRANSITION_ID
        assert document.client_id == CLIENT_ID
        assert document.expires_at.tzinfo is not None


class TestWorkloadRouting:
    def test_internal_token_exchange_is_not_governed(self, monkeypatch):
        server = WorkloadServer()
        client = make_client(server)
        original_send = httpx.Client.send
        governed_urls: list[str] = []

        def instrumented_send(client, request, *args, **kwargs):
            url = str(request.url)
            if not should_ignore_url(url):
                governed_urls.append(url)
            return original_send(client, request, *args, **kwargs)

        monkeypatch.setattr(httpx.Client, "send", instrumented_send)
        set_ignored_url_prefixes({API_URL})
        try:
            assert client.validate_api_key() is True
        finally:
            set_ignored_url_prefixes(set())

        assert governed_urls == []

    def test_composes_api_key_and_workload_token_on_v3(self):
        server = WorkloadServer()
        client = make_client(server)

        assert client.validate_api_key() is True

        bootstrap = server.calls[0]
        token = server.calls[1]
        governed = server.calls[2]
        assert bootstrap.url.path == "/api/v3/auth/bootstrap"
        assert bootstrap.headers["authorization"] == f"Bearer {API_KEY}"
        assert WORKLOAD_TOKEN_HEADER.lower() not in bootstrap.headers
        assert str(token.url) == TOKEN_ENDPOINT
        assert "authorization" not in token.headers
        form = parse_qs(token.content.decode())
        assert form["grant_type"] == ["client_credentials"]
        assert form["client_id"] == [CLIENT_ID]
        assert _jwt_segment(form["client_assertion"][0], 0)["kid"] == KID
        assert governed.url.path == "/api/v3/auth/validate"
        assert governed.headers["authorization"] == f"Bearer {API_KEY}"
        assert governed.headers[WORKLOAD_TOKEN_HEADER] == "keycloak-access-token"
        assert "x-openbox-agent-assertion" not in governed.headers

    def test_reuses_cached_bootstrap_and_access_token(self):
        server = WorkloadServer()
        client = make_client(server)

        client.validate_api_key()
        client.validate_api_key()

        assert [request.url.path for request in server.calls].count(AUTH_BOOTSTRAP_PATH_V3) == 1
        assert [str(request.url) for request in server.calls].count(TOKEN_ENDPOINT) == 1
        assert [request.url.path for request in server.calls].count("/api/v3/auth/validate") == 2

    def test_explicit_unavailable_response_preserves_v1(self):
        server = WorkloadServer(bootstrap_status=409)
        client = make_client(server)

        assert client.validate_api_key() is True

        assert server.calls[-1].url.path == "/api/v1/auth/validate"
        assert WORKLOAD_TOKEN_HEADER.lower() not in server.calls[-1].headers

    def test_older_core_without_v3_preserves_v1(self):
        server = WorkloadServer(bootstrap_status=404)
        client = make_client(server)

        assert client.validate_api_key() is True
        assert server.calls[-1].url.path == "/api/v1/auth/validate"

    def test_does_not_downgrade_when_active_token_exchange_fails(self):
        server = WorkloadServer(token_status=400)
        client = make_client(server)

        with pytest.raises(OpenBoxAuthError, match="token exchange"):
            client.validate_api_key()

        assert not any(request.url.path.startswith("/api/v1/") for request in server.calls)
        assert not any(request.url.path.startswith("/api/v2/") for request in server.calls)

    def test_bootstrap_outage_does_not_downgrade(self):
        server = WorkloadServer(bootstrap_status=503)
        client = make_client(server)

        with pytest.raises(OpenBoxNetworkError, match="workload identity bootstrap"):
            client.validate_api_key()

        assert not any(request.url.path.startswith("/api/v1/") for request in server.calls)

    @pytest.mark.asyncio
    async def test_async_requests_use_the_same_v3_contract(self):
        server = WorkloadServer()
        client = make_client(server)

        assert await client.avalidate_api_key() is True
        assert server.calls[-1].url.path == "/api/v3/auth/validate"
        assert server.calls[-1].headers[WORKLOAD_TOKEN_HEADER] == "keycloak-access-token"

    def test_workload_identity_allows_first_call_handoff(self):
        server = WorkloadServer()
        client = make_client(server)

        client.emit_handoff(AGENT_ID)

        assert server.calls[-1].url.path == "/api/v3/handoffs"


class WorkloadTransitionServer:
    def __init__(self):
        self.calls: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        if request.url.path == WORKLOAD_TRANSITION_BOOTSTRAP_PATH_V3:
            return httpx.Response(
                200,
                json={
                    "bootstrap_version": 3,
                    "contract_version": 3,
                    "transition_id": TRANSITION_ID,
                    "token_endpoint": TOKEN_ENDPOINT,
                    "client_id": CLIENT_ID,
                    "kid": KID,
                    "identity_source": "okta",
                    "expires_at": "2026-08-16T12:00:00Z",
                },
            )
        if request.url.path == WORKLOAD_TRANSITION_PROOF_PATH_V3:
            return httpx.Response(200, json={"proof_verified": True})
        return httpx.Response(404)


class TestWorkloadTransitionProof:
    def test_proves_candidate_without_activating_or_exchanging_token(self):
        server = WorkloadTransitionServer()
        transport = httpx.MockTransport(server)
        client = EvaluationClient(
            API_URL,
            API_KEY,
            transport=transport,
            async_transport=transport,
        )

        result = client.prove_workload_identity_transition(
            TRANSITION_ID, candidate_private_key=PRIVATE_KEY
        )

        assert result == {"proof_verified": True}
        assert [request.url.path for request in server.calls] == [
            WORKLOAD_TRANSITION_BOOTSTRAP_PATH_V3,
            WORKLOAD_TRANSITION_PROOF_PATH_V3,
        ]
        bootstrap, proof = server.calls
        assert bootstrap.headers["authorization"] == f"Bearer {API_KEY}"
        assert bootstrap.url.params["transition_id"] == TRANSITION_ID
        assert proof.headers["authorization"] == f"Bearer {API_KEY}"
        payload = json.loads(proof.content)
        assert payload["transition_id"] == TRANSITION_ID
        assert _jwt_segment(payload["client_assertion"], 0)["kid"] == KID
        claims = _jwt_segment(payload["client_assertion"], 1)
        assert claims["iss"] == CLIENT_ID
        assert claims["sub"] == CLIENT_ID
        assert claims["aud"] == TOKEN_ENDPOINT
        assert claims["exp"] - claims["iat"] == 60
        assert not any(str(request.url) == TOKEN_ENDPOINT for request in server.calls)

    @pytest.mark.asyncio
    async def test_async_candidate_proof_uses_same_contract(self):
        server = WorkloadTransitionServer()
        transport = httpx.MockTransport(server)
        client = EvaluationClient(
            API_URL,
            API_KEY,
            transport=transport,
            async_transport=transport,
        )

        result = await client.aprove_workload_identity_transition(
            TRANSITION_ID, candidate_private_key=PRIVATE_KEY
        )

        assert result == {"proof_verified": True}
