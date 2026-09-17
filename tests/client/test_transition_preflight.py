"""Transition-preflight helpers (proposal §13.5, §17.28; contract §4.1).

The preflight helpers must sign with an EXPLICIT candidate identity and must
NEVER fall back to the client's currently active identity signer — even when
the client's active identity is the same kind (Okta or DID) as the candidate.
"""

from __future__ import annotations

import base64
import json

import httpx
import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from identity_fixtures import (
    OTHER_DID,
    make_did_identity,
    make_did_identity_config,
    make_okta_identity,
    make_okta_identity_config,
    make_other_did_identity,
)

from openbox_core.client import TRANSITION_PROOF_PATH, TRANSITION_PROOF_PATH_V2, EvaluationClient
from openbox_core.errors import OpenBoxConfigError, OpenBoxSigningError
from openbox_core.identity import build_canonical_string
from openbox_core.identity_okta import HEADER_ASSERTION, OktaAgentIdentity


def _client(handler, *, identity=None) -> EvaluationClient:
    transport = httpx.MockTransport(handler)
    return EvaluationClient(
        "https://core.test",
        "obx_test_abc",
        identity=identity,
        transport=transport,
        async_transport=transport,
    )


def _decode_jwt_segment(segment: str) -> dict:
    padding_chars = "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment + padding_chars))


class TestOmittingCandidateRaisesLocally:
    def test_okta_candidate_required(self):
        def handler(request):
            raise AssertionError("must not send a request without a candidate identity")

        client = _client(handler, identity=make_okta_identity())
        with pytest.raises(OpenBoxConfigError, match="candidate_identity"):
            client.validate_okta_identity_transition("transition-1", "challenge-1")

    def test_did_candidate_required(self):
        def handler(request):
            raise AssertionError("must not send a request without a candidate identity")

        client = _client(handler, identity=make_did_identity())
        with pytest.raises(OpenBoxConfigError, match="candidate_identity"):
            client.validate_openbox_did_identity_transition("transition-1", "challenge-1")

    async def test_async_okta_candidate_required(self):
        def handler(request):
            raise AssertionError("must not send a request without a candidate identity")

        client = _client(handler)
        with pytest.raises(OpenBoxConfigError, match="candidate_identity"):
            await client.avalidate_okta_identity_transition("transition-1", "challenge-1")

    async def test_async_did_candidate_required(self):
        def handler(request):
            raise AssertionError("must not send a request without a candidate identity")

        client = _client(handler)
        with pytest.raises(OpenBoxConfigError, match="candidate_identity"):
            await client.avalidate_openbox_did_identity_transition("transition-1", "challenge-1")


class TestPreflightSignsWithCandidateNotActiveIdentity:
    def test_okta_preflight_uses_candidate_kid_not_active_identitys(self):
        active = make_okta_identity(key_id="active-kid")
        candidate_config = make_okta_identity_config(key_id="candidate-kid")

        captured = {}

        def handler(request):
            captured["path"] = request.url.path
            captured["assertion"] = request.headers[HEADER_ASSERTION]
            return httpx.Response(200, json={"status": "proof_verified"})

        client = _client(handler, identity=active)
        client.validate_okta_identity_transition(
            "transition-1", "challenge-1", candidate_identity=candidate_config
        )

        assert captured["path"] == TRANSITION_PROOF_PATH_V2
        header = _decode_jwt_segment(captured["assertion"].split(".")[0])
        # Signed with the CANDIDATE's kid, never the active identity's.
        assert header["kid"] == "candidate-kid"
        assert header["kid"] != active.key_id

    def test_okta_preflight_signature_verifies_only_against_candidate_public_key(self):
        active = make_okta_identity()  # a different generated key than the candidate
        candidate_config = make_okta_identity_config()
        candidate = OktaAgentIdentity.from_config(candidate_config)

        captured = {}

        def handler(request):
            captured["assertion"] = request.headers[HEADER_ASSERTION]
            return httpx.Response(200, json={})

        _client(handler, identity=active).validate_okta_identity_transition(
            "transition-1", "challenge-1", candidate_identity=candidate_config
        )

        header_b64, payload_b64, sig_b64 = captured["assertion"].split(".")
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        padding_chars = "=" * (-len(sig_b64) % 4)
        signature = base64.urlsafe_b64decode(sig_b64 + padding_chars)

        # Verifies against the CANDIDATE's public key...
        candidate.signer.public_key().verify(
            signature, signing_input, padding.PKCS1v15(), hashes.SHA256()
        )
        # ...but NOT against the ACTIVE identity's public key.
        with pytest.raises(InvalidSignature):
            active.signer.public_key().verify(
                signature, signing_input, padding.PKCS1v15(), hashes.SHA256()
            )

    def test_did_preflight_uses_candidate_key_not_active_identity(self):
        active = make_did_identity()
        candidate_identity = make_other_did_identity()
        candidate_config = make_did_identity_config()

        captured = {}

        def handler(request):
            captured["path"] = request.url.path
            captured["headers"] = {k.lower(): v for k, v in request.headers.items()}
            return httpx.Response(200, json={})

        _client(handler, identity=active).validate_openbox_did_identity_transition(
            "transition-1", "challenge-1", candidate_identity=candidate_config
        )

        headers = captured["headers"]
        assert captured["path"] == TRANSITION_PROOF_PATH
        assert headers["x-openbox-agent-did"] == OTHER_DID
        assert headers["x-openbox-agent-did"] != active.agent_did

        canonical = build_canonical_string(
            "POST",
            TRANSITION_PROOF_PATH,
            headers["x-openbox-agent-timestamp"],
            headers["x-openbox-agent-nonce"],
            headers["x-openbox-body-sha256"],
        )
        signature = base64.b64decode(headers["x-openbox-agent-signature"])

        # Verifies against the CANDIDATE's public key...
        candidate_identity.signer.public_key().verify(signature, canonical.encode("utf-8"))
        # ...but NOT against the ACTIVE identity's public key.
        with pytest.raises(InvalidSignature):
            active.signer.public_key().verify(signature, canonical.encode("utf-8"))

    def test_did_transition_body_carries_transition_id_and_challenge(self):
        candidate_config = make_did_identity_config()
        captured = {}

        def handler(request):
            captured["body"] = request.content
            return httpx.Response(200, json={})

        _client(handler).validate_openbox_did_identity_transition(
            "transition-xyz", "challenge-xyz", candidate_identity=candidate_config
        )
        assert captured["body"] == b'{"transition_id":"transition-xyz","challenge":"challenge-xyz"}'


class TestOktaTransitionClaims:
    def test_transition_claims_present_and_purpose_is_okta_ai_agent(self):
        candidate_config = make_okta_identity_config()
        captured = {}

        def handler(request):
            captured["assertion"] = request.headers[HEADER_ASSERTION]
            return httpx.Response(200, json={})

        _client(handler).validate_okta_identity_transition(
            "transition-xyz", "challenge-xyz", candidate_identity=candidate_config
        )

        claims = _decode_jwt_segment(captured["assertion"].split(".")[1])
        assert claims["obx_transition_purpose"] == "okta_ai_agent"
        assert claims["obx_transition_id"] == "transition-xyz"
        assert claims["obx_transition_challenge"] == "challenge-xyz"

    def test_transition_body_carries_only_transition_id(self):
        candidate_config = make_okta_identity_config()
        captured = {}

        def handler(request):
            captured["body"] = request.content
            return httpx.Response(200, json={})

        _client(handler).validate_okta_identity_transition(
            "transition-xyz", "challenge-xyz", candidate_identity=candidate_config
        )
        assert captured["body"] == b'{"transition_id":"transition-xyz"}'


class TestPreflightAuthFailureClassification:
    def test_401_raises_signing_error_with_reason_code(self):
        candidate_config = make_okta_identity_config()

        def handler(request):
            return httpx.Response(401, json={"reason_code": "transition_proof_invalid"})

        with pytest.raises(OpenBoxSigningError, match="transition_proof_invalid"):
            _client(handler).validate_okta_identity_transition(
                "transition-1", "challenge-1", candidate_identity=candidate_config
            )

    async def test_async_401_raises_signing_error(self):
        candidate_config = make_did_identity_config()

        def handler(request):
            return httpx.Response(403, json={"reason_code": "proof_expired"})

        with pytest.raises(OpenBoxSigningError, match="proof_expired"):
            await _client(handler).avalidate_openbox_did_identity_transition(
                "transition-1", "challenge-1", candidate_identity=candidate_config
            )
