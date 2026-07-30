"""Client-side identity bootstrap, sync and async.

Mirrors openbox-sdk-ts's test/client-bootstrap.test.ts — the two SDKs must behave
identically (addendum §8), including the pinned RFC 7638 thumbprint vector and the
operator-facing message wording.
"""

from __future__ import annotations

import asyncio
import base64
import json
import pathlib

import httpx
import pytest
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from openbox_core.bootstrap import AUTH_BOOTSTRAP_PATH_V2
from openbox_core.client import AUTH_VALIDATE_PATH_V2, EvaluationClient
from openbox_core.errors import OpenBoxAuthError, OpenBoxConfigError, OpenBoxNetworkError
from openbox_core.identity_okta import HEADER_ASSERTION

FIXTURE_DIR = pathlib.Path(__file__).parent.parent / "signing" / "identity_v2"

# Same pinned vector as tests/signing/test_jwk_thumbprint.py, openbox-core, and
# the TypeScript SDK.
FIXTURE_THUMBPRINT = "P8EMAIrSnD-kQcn47Cpq_LlDPywhP3mqfM1RhwySFdk"
OTHER_THUMBPRINT = "mvZ_gJ0t0lSgT1112pD9yjrvBBi0-20HzVE7nzfz41c"

API_URL = "https://core.test"
API_KEY = "obx_test_bootstrapkey"

AGENT_ID = "00000000-0000-4000-8000-000000000002"
ORG_ID = "00000000-0000-4000-8000-000000000001"
DEPLOYMENT_ID = "fixture-deployment"
AUDIENCE = "urn:openbox:fixture-deployment:core"
EXTERNAL_AGENT_ID = "fixture-okta-ai-agent-0001"
CREDENTIAL_KID = "fixture-okta-credential-kid-0001"


def _b64url_to_int(segment: str) -> int:
    padding = "=" * (-len(segment) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(segment + padding), "big")


def _pem_from_jwk(jwk: dict) -> str:
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


_KEYPAIR = json.loads((FIXTURE_DIR / "keypair.json").read_text())
OKTA_PEM = _pem_from_jwk(_KEYPAIR["private_jwk"])
UNDERSIZED_PEM = _pem_from_jwk(_KEYPAIR["undersized_key_for_negative_test"]["private_jwk"])


def bootstrap_body(**overrides) -> dict:
    body = {
        "bootstrap_version": 1,
        "identity_method": "okta_ai_agent",
        "openbox_agent_id": AGENT_ID,
        "organization_id": ORG_ID,
        "deployment_id": DEPLOYMENT_ID,
        "assertion_audience": AUDIENCE,
        "okta": {
            "external_agent_id": EXTERNAL_AGENT_ID,
            "credential_kid": CREDENTIAL_KID,
            "algorithm": "RS256",
            "public_jwk_thumbprint": FIXTURE_THUMBPRINT,
        },
    }
    body.update(overrides)
    return body


class FakeCore:
    """Records every request and answers bootstrap from a FIFO queue."""

    def __init__(self, bootstrap_responses):
        self.queue = list(bootstrap_responses)
        self.calls: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        if request.url.path == AUTH_BOOTSTRAP_PATH_V2:
            if not self.queue:
                raise AssertionError("unexpected extra bootstrap call")
            responder = self.queue.pop(0)
            return responder()
        if request.url.path == AUTH_VALIDATE_PATH_V2:
            return httpx.Response(200, json={"valid": True, "agent_id": AGENT_ID})
        return httpx.Response(200, json={"verdict": "allow"})

    @property
    def bootstrap_call_count(self) -> int:
        return sum(1 for c in self.calls if c.url.path == AUTH_BOOTSTRAP_PATH_V2)

    def calls_to(self, path: str) -> list[httpx.Request]:
        return [c for c in self.calls if c.url.path == path]


def make_client(core: FakeCore, private_key: str = OKTA_PEM) -> EvaluationClient:
    transport = httpx.MockTransport(core.handler)
    return EvaluationClient(
        API_URL,
        API_KEY,
        okta_bootstrap_private_key=private_key,
        transport=transport,
        async_transport=transport,
    )


def ok(body: dict):
    return lambda: httpx.Response(200, json=body)


def status(code: int, body: dict | None = None):
    return lambda: httpx.Response(code, json=body or {})


def boom(message: str = "ECONNREFUSED"):
    def _raise():
        raise httpx.ConnectError(message)

    return _raise


def decode_segment(assertion: str, index: int) -> dict:
    segment = assertion.split(".")[index]
    padding = "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment + padding))


class TestBootstrapSuccessPath:
    def test_fetches_metadata_and_signs_with_bootstrapped_values(self):
        core = FakeCore([ok(bootstrap_body())])
        client = make_client(core)

        assert client.validate_api_key() is True

        # Bootstrap happened first, then the governed request.
        assert core.calls[0].url.path == AUTH_BOOTSTRAP_PATH_V2
        assert core.calls[1].url.path == AUTH_VALIDATE_PATH_V2

        assertion = core.calls[1].headers[HEADER_ASSERTION]
        header = decode_segment(assertion, 0)
        claims = decode_segment(assertion, 1)

        assert header["kid"] == CREDENTIAL_KID
        assert header["alg"] == "RS256"
        assert claims["aud"] == AUDIENCE
        assert claims["obx_agent_id"] == AGENT_ID
        assert claims["obx_organization_id"] == ORG_ID
        assert claims["obx_deployment_id"] == DEPLOYMENT_ID
        assert claims["iss"] == EXTERNAL_AGENT_ID
        assert claims["sub"] == EXTERNAL_AGENT_ID
        # Per-request claims are still computed locally, not bootstrapped.
        assert claims["htm"] == "GET"
        assert claims["htu"] == AUTH_VALIDATE_PATH_V2
        assert claims["jti"]
        assert claims["body_sha256"]

    def test_bootstrap_request_carries_api_key_and_no_assertion(self):
        core = FakeCore([ok(bootstrap_body())])
        make_client(core).validate_api_key()

        request = core.calls[0]
        assert request.headers["authorization"] == f"Bearer {API_KEY}"
        # Requiring an assertion here would be circular — this response is what
        # makes constructing one possible.
        assert HEADER_ASSERTION.lower() not in {k.lower() for k in request.headers}
        assert request.headers["accept"] == "application/json"

    def test_caches_per_client_instance(self):
        core = FakeCore([ok(bootstrap_body())])
        client = make_client(core)

        client.validate_api_key()
        client.evaluate({"event_type": "WorkflowStarted"})
        client.validate_api_key()

        assert core.bootstrap_call_count == 1

    def test_exposes_validated_metadata(self):
        core = FakeCore([ok(bootstrap_body())])
        client = make_client(core)

        assert client.identity_metadata() is None
        client.validate_api_key()

        metadata = client.identity_metadata()
        assert metadata.openbox_agent_id == AGENT_ID
        assert metadata.okta.credential_kid == CREDENTIAL_KID
        # Non-secret only — no key material is retained.
        assert "PRIVATE KEY" not in repr(metadata)

    def test_routes_to_v2_never_v1(self):
        core = FakeCore([ok(bootstrap_body())])
        make_client(core).evaluate({"event_type": "WorkflowStarted"})

        assert any(c.url.path.startswith("/api/v2/") for c in core.calls)
        assert not any(c.url.path.startswith("/api/v1/") for c in core.calls)

    async def test_async_path_bootstraps_identically(self):
        core = FakeCore([ok(bootstrap_body())])
        client = make_client(core)

        assert await client.avalidate_api_key() is True

        assert core.calls[0].url.path == AUTH_BOOTSTRAP_PATH_V2
        header = decode_segment(core.calls[1].headers[HEADER_ASSERTION], 0)
        assert header["kid"] == CREDENTIAL_KID
        await client.aclose()

    async def test_async_caches_per_client_instance(self):
        core = FakeCore([ok(bootstrap_body())])
        client = make_client(core)

        await client.avalidate_api_key()
        await client.aevaluate({"event_type": "WorkflowStarted"})

        assert core.bootstrap_call_count == 1
        await client.aclose()


class TestLocalKeyValidation:
    """Every case must fail WITHOUT contacting Core."""

    def test_rejects_malformed_key(self):
        core = FakeCore([])
        client = make_client(
            core, "-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----"
        )

        with pytest.raises(OpenBoxConfigError):
            client.validate_api_key()
        assert core.bootstrap_call_count == 0

    def test_rejects_undersized_rsa_key(self):
        core = FakeCore([])
        with pytest.raises(OpenBoxConfigError, match="2048"):
            make_client(core, UNDERSIZED_PEM).validate_api_key()
        assert core.bootstrap_call_count == 0

    def test_never_echoes_key_bytes(self):
        core = FakeCore([])
        with pytest.raises(OpenBoxConfigError) as excinfo:
            make_client(core, UNDERSIZED_PEM).validate_api_key()

        assert "key bytes not shown" in str(excinfo.value)
        assert "BEGIN PRIVATE KEY" not in str(excinfo.value)


class TestThumbprintMismatch:
    def test_fails_before_sending_any_governed_request(self):
        body = bootstrap_body()
        body["okta"]["public_jwk_thumbprint"] = OTHER_THUMBPRINT
        core = FakeCore([ok(body)])
        client = make_client(core)

        with pytest.raises(OpenBoxConfigError, match="does not match the selected Okta credential"):
            client.validate_api_key()

        # The bootstrap call happened; the governed request did NOT.
        assert core.bootstrap_call_count == 1
        assert core.calls_to(AUTH_VALIDATE_PATH_V2) == []

    def test_gives_actionable_remediation(self):
        body = bootstrap_body()
        body["okta"]["public_jwk_thumbprint"] = OTHER_THUMBPRINT
        core = FakeCore([ok(body)])

        with pytest.raises(OpenBoxConfigError) as excinfo:
            make_client(core).validate_api_key()

        message = str(excinfo.value)
        assert "Export the private key associated with the selected credential" in message
        assert "rotate the agent credential" in message

    async def test_async_mismatch_also_fails_closed(self):
        body = bootstrap_body()
        body["okta"]["public_jwk_thumbprint"] = OTHER_THUMBPRINT
        core = FakeCore([ok(body)])
        client = make_client(core)

        with pytest.raises(OpenBoxConfigError, match="does not match"):
            await client.avalidate_api_key()
        assert core.calls_to(AUTH_VALIDATE_PATH_V2) == []
        await client.aclose()


class TestFailureHandling:
    def test_surfaces_upgrade_guidance_on_404(self):
        core = FakeCore([status(404)])
        with pytest.raises(OpenBoxConfigError, match="does not support Okta identity bootstrap"):
            make_client(core).validate_api_key()

    @pytest.mark.parametrize(
        "responder",
        [
            status(404),
            status(401, {"reason_code": "invalid_api_key"}),
            status(409, {"reason_code": "identity_method_mismatch"}),
            status(503, {"reason_code": "provider_metadata_stale"}),
            boom(),
        ],
        ids=["404", "401", "409", "503", "network-error"],
    )
    def test_never_downgrades_on_any_failure(self, responder):
        core = FakeCore([responder])
        client = make_client(core)

        # OpenBoxConfigError is the common ancestor of every bootstrap failure
        # (including OpenBoxNetworkError) — what matters here is that SOMETHING
        # raised and no request was downgraded.
        with pytest.raises(OpenBoxConfigError):
            client.validate_api_key()

        # No v1 route, and no v2 route without an assertion.
        assert not any(c.url.path.startswith("/api/v1/") for c in core.calls)
        assert core.calls_to(AUTH_VALIDATE_PATH_V2) == []

    def test_reports_unreachable_core_as_network_error(self):
        core = FakeCore([boom()])
        with pytest.raises(OpenBoxNetworkError):
            make_client(core).validate_api_key()

    def test_surfaces_core_reason_code_guidance(self):
        core = FakeCore([status(409, {"reason_code": "selected_credential_missing"})])
        with pytest.raises(OpenBoxConfigError, match="select or register an Okta credential"):
            make_client(core).validate_api_key()

    def test_rejects_unknown_bootstrap_version(self):
        core = FakeCore([ok(bootstrap_body(bootstrap_version=2))])
        with pytest.raises(OpenBoxConfigError, match="Upgrade the OpenBox SDK"):
            make_client(core).validate_api_key()

    def test_rejects_non_okta_identity_method(self):
        core = FakeCore([ok(bootstrap_body(identity_method="openbox_did"))])
        with pytest.raises(OpenBoxConfigError, match="not 'okta_ai_agent'"):
            make_client(core).validate_api_key()

    def test_rejects_unsupported_algorithm(self):
        body = bootstrap_body()
        body["okta"]["algorithm"] = "RS512"
        core = FakeCore([ok(body)])
        with pytest.raises(OpenBoxConfigError, match="only 'RS256'"):
            make_client(core).validate_api_key()

    @pytest.mark.parametrize(
        "field",
        ["openbox_agent_id", "organization_id", "deployment_id", "assertion_audience"],
    )
    def test_rejects_response_missing_required_field(self, field):
        body = bootstrap_body()
        del body[field]
        core = FakeCore([ok(body)])
        with pytest.raises(OpenBoxConfigError, match=field):
            make_client(core).validate_api_key()

    @pytest.mark.parametrize(
        "field", ["external_agent_id", "credential_kid", "public_jwk_thumbprint"]
    )
    def test_rejects_response_missing_required_okta_field(self, field):
        body = bootstrap_body()
        del body["okta"][field]
        core = FakeCore([ok(body)])
        with pytest.raises(OpenBoxConfigError, match=field):
            make_client(core).validate_api_key()

    def test_rejects_invalid_json_body(self):
        core = FakeCore([lambda: httpx.Response(200, content=b"not json")])
        with pytest.raises(OpenBoxConfigError, match="not valid JSON"):
            make_client(core).validate_api_key()

    def test_allows_retry_after_transient_failure(self):
        # A failure leaves the identity unresolved, so a later request may retry
        # an outage rather than being permanently poisoned.
        core = FakeCore([boom(), ok(bootstrap_body())])
        client = make_client(core)

        with pytest.raises(OpenBoxNetworkError):
            client.validate_api_key()
        assert client.validate_api_key() is True
        assert core.bootstrap_call_count == 2


class TestRefreshIdentityMetadata:
    def test_replaces_metadata_after_reverifying_thumbprint(self):
        rotated = bootstrap_body()
        rotated["okta"]["credential_kid"] = "rotated-credential-kid-0002"
        core = FakeCore([ok(bootstrap_body()), ok(rotated)])
        client = make_client(core)

        client.validate_api_key()
        assert client.identity_metadata().okta.credential_kid == CREDENTIAL_KID

        refreshed = client.refresh_identity_metadata()
        assert refreshed.okta.credential_kid == "rotated-credential-kid-0002"

        # Subsequent requests sign with the refreshed kid.
        client.validate_api_key()
        last = core.calls_to(AUTH_VALIDATE_PATH_V2)[-1]
        assert decode_segment(last.headers[HEADER_ASSERTION], 0)["kid"] == (
            "rotated-credential-kid-0002"
        )

    def test_keeps_previous_identity_when_refreshed_credential_mismatches(self):
        # Credential rotated to a key this runtime does not hold: the refresh must
        # fail rather than adopt metadata it cannot sign for.
        rotated = bootstrap_body()
        rotated["okta"]["credential_kid"] = "rotated-away-kid"
        rotated["okta"]["public_jwk_thumbprint"] = OTHER_THUMBPRINT
        core = FakeCore([ok(bootstrap_body()), ok(rotated)])
        client = make_client(core)

        client.validate_api_key()
        with pytest.raises(OpenBoxConfigError, match="does not match the selected Okta credential"):
            client.refresh_identity_metadata()

        # Cached metadata is unchanged — not replaced by the unusable document.
        assert client.identity_metadata().okta.credential_kid == CREDENTIAL_KID

    def test_rejected_for_client_not_in_bootstrap_mode(self):
        transport = httpx.MockTransport(FakeCore([]).handler)
        client = EvaluationClient(API_URL, API_KEY, transport=transport)

        with pytest.raises(OpenBoxConfigError, match="requires identity bootstrap mode"):
            client.refresh_identity_metadata()

    def test_does_not_refresh_automatically_after_auth_failure(self):
        # A 401 must surface, not trigger a hidden re-bootstrap-and-replay:
        # rotation may have selected a key this process does not hold, which a
        # retry cannot fix.
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request.url.path)
            if request.url.path == AUTH_BOOTSTRAP_PATH_V2:
                return httpx.Response(200, json=bootstrap_body())
            return httpx.Response(401, json={"reason_code": "assertion_signature_invalid"})

        transport = httpx.MockTransport(handler)
        client = EvaluationClient(
            API_URL, API_KEY, okta_bootstrap_private_key=OKTA_PEM, transport=transport
        )

        with pytest.raises(OpenBoxAuthError):
            client.validate_api_key()
        assert calls.count(AUTH_BOOTSTRAP_PATH_V2) == 1

    async def test_async_refresh_mirrors_sync(self):
        rotated = bootstrap_body()
        rotated["okta"]["credential_kid"] = "rotated-credential-kid-0003"
        core = FakeCore([ok(bootstrap_body()), ok(rotated)])
        client = make_client(core)

        await client.avalidate_api_key()
        refreshed = await client.arefresh_identity_metadata()
        assert refreshed.okta.credential_kid == "rotated-credential-kid-0003"
        await client.aclose()

    async def test_async_refresh_rejected_outside_bootstrap_mode(self):
        transport = httpx.MockTransport(FakeCore([]).handler)
        client = EvaluationClient(API_URL, API_KEY, async_transport=transport)

        with pytest.raises(OpenBoxConfigError, match="requires identity bootstrap mode"):
            await client.arefresh_identity_metadata()


class TestConstructorGuards:
    def test_rejects_bootstrap_mode_with_resolved_identity(self):
        from openbox_core.identity import AgentIdentity

        identity = AgentIdentity.from_private_key(
            "did:aip:12345678-1234-5678-1234-567812345678",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        )
        with pytest.raises(OpenBoxConfigError, match="exactly one"):
            EvaluationClient(
                API_URL, API_KEY, identity=identity, okta_bootstrap_private_key=OKTA_PEM
            )


class TestHandoffOnBootstrapModeClient:
    """Handoff must not depend on bootstrap having already happened.

    The guard in `_handoff_payload` runs BEFORE `_prepared`, so if it tested only
    the resolved identity it would reject a correctly configured okta_ai_agent
    client whose first call is a handoff — and would never even attempt the
    bootstrap that would have populated it.
    """

    def test_handoff_as_the_very_first_call_bootstraps_and_succeeds(self):
        core = FakeCore([ok(bootstrap_body())])
        client = make_client(core)

        client.emit_handoff("00000000-0000-4000-8000-00000000000f", "escalation")

        assert core.bootstrap_call_count == 1
        assert [c.url.path for c in core.calls] == [
            AUTH_BOOTSTRAP_PATH_V2,
            "/api/v2/handoffs",
        ]
        # And it is signed, not API-key-only.
        assert HEADER_ASSERTION in core.calls[1].headers

    async def test_async_handoff_as_the_very_first_call(self):
        core = FakeCore([ok(bootstrap_body())])
        client = make_client(core)

        await client.aemit_handoff("00000000-0000-4000-8000-00000000000f")

        assert core.bootstrap_call_count == 1
        assert core.calls[-1].url.path == "/api/v2/handoffs"
        await client.aclose()

    def test_unsigned_client_still_refuses_handoff(self):
        # The guard must keep working for a genuinely unsigned client.
        transport = httpx.MockTransport(FakeCore([]).handler)
        client = EvaluationClient(API_URL, API_KEY, transport=transport)

        with pytest.raises(OpenBoxConfigError, match="source-authenticated handoff"):
            client.emit_handoff("00000000-0000-4000-8000-00000000000f")


class TestSingleFlight:
    """Concurrent first requests must perform exactly ONE bootstrap fetch."""

    def test_concurrent_threads_bootstrap_once(self):
        import threading

        core = FakeCore([ok(bootstrap_body())])
        client = make_client(core)

        barrier = threading.Barrier(8)
        errors: list[BaseException] = []

        def worker():
            try:
                barrier.wait()
                client.validate_api_key()
            except BaseException as exc:  # noqa: BLE001 - recorded and re-raised below
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert core.bootstrap_call_count == 1

    async def test_concurrent_coroutines_bootstrap_once(self):
        core = FakeCore([ok(bootstrap_body())])
        client = make_client(core)

        await asyncio.gather(*(client.avalidate_api_key() for _ in range(8)))

        assert core.bootstrap_call_count == 1
        await client.aclose()

    def test_concurrent_refreshes_do_not_tear_state(self):
        # Two EXPLICIT refreshes each fetch — that is what "explicit" means, and
        # the lock serializes them rather than deduping them. What the lock buys is
        # that the cached document and the signing identity are always replaced
        # together, so no observer ever sees one credential's metadata alongside
        # another credential's signing key.
        import threading

        rotated = bootstrap_body()
        rotated["okta"]["credential_kid"] = "rotated-kid"
        core = FakeCore([ok(bootstrap_body()), ok(rotated), ok(rotated)])
        client = make_client(core)

        client.validate_api_key()
        observed: list[tuple[str, str]] = []
        barrier = threading.Barrier(2)

        def refresh():
            barrier.wait()
            document = client.refresh_identity_metadata()
            # Read both without holding the lock: they must still agree.
            observed.append(
                (document.okta.credential_kid, client.identity_metadata().okta.credential_kid)
            )

        threads = [threading.Thread(target=refresh) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(observed) == 2
        for returned, cached in observed:
            assert returned == "rotated-kid"
            assert cached == "rotated-kid"


class TestNoSecretsInLogs:
    def test_bootstrap_log_carries_metadata_but_never_secrets(self, caplog):
        import logging

        core = FakeCore([ok(bootstrap_body())])
        client = make_client(core)

        with caplog.at_level(logging.INFO, logger="openbox_core.client"):
            client.validate_api_key()

        logged = " ".join(record.getMessage() for record in caplog.records)
        assert AGENT_ID in logged
        assert CREDENTIAL_KID in logged
        assert "thumbprint matched" in logged

        # Never the API key, the private key, or an assertion.
        assert API_KEY not in logged
        assert "BEGIN PRIVATE KEY" not in logged
        assert "eyJ" not in logged


class TestLocalKeyValidationNoNetwork:
    def test_non_rsa_key_fails_without_contacting_core(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        pem = (
            ed25519.Ed25519PrivateKey.generate()
            .private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            .decode("ascii")
        )
        core = FakeCore([])

        with pytest.raises(OpenBoxConfigError):
            make_client(core, pem).validate_api_key()
        assert core.bootstrap_call_count == 0
