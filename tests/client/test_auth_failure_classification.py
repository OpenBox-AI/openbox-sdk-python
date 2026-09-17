"""401/403 fail closed for evaluate/approval/validate, regardless of
on_api_error (proposal §13.6). A revoked/invalid credential must never
produce a fallback ALLOW or be laundered into "still pending".
"""

from __future__ import annotations

import httpx
import pytest
from identity_fixtures import make_okta_identity

from openbox_core.approvals import ApprovalPoller
from openbox_core.client import EvaluationClient
from openbox_core.contracts.results import Verdict
from openbox_core.errors import GovernanceAPIError, OpenBoxAuthError, OpenBoxSigningError


def _client(handler, *, on_api_error="fail_open", identity=None) -> EvaluationClient:
    transport = httpx.MockTransport(handler)
    return EvaluationClient(
        "https://core.test",
        "obx_test_abc",
        on_api_error=on_api_error,
        identity=identity,
        transport=transport,
        async_transport=transport,
    )


@pytest.mark.parametrize("status", [401, 403])
@pytest.mark.parametrize("on_api_error", ["fail_open", "fail_closed"])
class TestEvaluateNeverFallsOpenOnAuthFailure:
    def test_plain_api_key_raises(self, status, on_api_error):
        def handler(request):
            return httpx.Response(status, json={"error": "revoked"})

        with pytest.raises(OpenBoxAuthError):
            _client(handler, on_api_error=on_api_error).evaluate({"x": 1})

    def test_signed_request_raises_with_reason_code(self, status, on_api_error):
        def handler(request):
            return httpx.Response(status, json={"reason_code": "assertion_signature_invalid"})

        identity = make_okta_identity()
        with pytest.raises(OpenBoxSigningError, match="assertion_signature_invalid") as exc_info:
            _client(handler, on_api_error=on_api_error, identity=identity).evaluate({"x": 1})
        assert exc_info.value.reason_code == "assertion_signature_invalid"

    async def test_async_raises(self, status, on_api_error):
        def handler(request):
            return httpx.Response(status)

        with pytest.raises(OpenBoxAuthError):
            await _client(handler, on_api_error=on_api_error).aevaluate({"x": 1})


class TestEvaluateStillRespectsOnApiErrorForNonAuthFailures:
    """Regression: only AUTH failures fail closed unconditionally — a 5xx or
    network error still respects on_api_error exactly as before this phase."""

    def test_500_still_fallback_allows_under_fail_open(self):
        def handler(request):
            return httpx.Response(500)

        result = _client(handler).evaluate({"x": 1})
        assert result.verdict is Verdict.ALLOW
        assert result.fallback_used is True

    def test_500_still_raises_governance_api_error_under_fail_closed(self):
        def handler(request):
            return httpx.Response(500)

        with pytest.raises(GovernanceAPIError):
            _client(handler, on_api_error="fail_closed").evaluate({"x": 1})

    def test_network_error_still_fallback_allows_under_fail_open(self):
        def handler(request):
            raise httpx.ConnectError("boom")

        result = _client(handler).evaluate({"x": 1})
        assert result.fallback_used is True


@pytest.mark.parametrize("status", [401, 403])
class TestApprovalNeverLaundersAuthFailureIntoPending:
    def test_plain_api_key_raises_not_none(self, status):
        def handler(request):
            return httpx.Response(status, json={"error": "revoked"})

        with pytest.raises(OpenBoxAuthError):
            _client(handler).poll_approval("wf", "run", "act")

    def test_signed_request_raises_with_reason_code(self, status):
        def handler(request):
            return httpx.Response(status, json={"reason_code": "proof_replayed"})

        identity = make_okta_identity()
        with pytest.raises(OpenBoxSigningError, match="proof_replayed"):
            _client(handler, identity=identity).poll_approval("wf", "run", "act")

    async def test_async_raises(self, status):
        def handler(request):
            return httpx.Response(status)

        with pytest.raises(OpenBoxAuthError):
            await _client(handler).apoll_approval("wf", "run", "act")


class TestApprovalStillPollsThroughNetworkFailures:
    """Regression: a genuine network error or non-auth non-200 still returns
    None (poller keeps polling); only AUTH failures are exempted from that
    leniency."""

    def test_network_error_returns_none(self):
        def handler(request):
            raise httpx.ConnectError("down")

        assert _client(handler).poll_approval("wf", "run", "act") is None

    def test_500_returns_none(self):
        def handler(request):
            return httpx.Response(500)

        assert _client(handler).poll_approval("wf", "run", "act") is None


class TestApprovalPollerPropagatesAuthFailures:
    """The poller must not swallow a hard auth failure as a retryable poll
    failure — it should propagate straight out of wait_for_decision."""

    def test_wait_for_decision_propagates_401(self):
        def handler(request):
            return httpx.Response(401, json={"error": "revoked"})

        poller = ApprovalPoller(_client(handler), poll_interval_seconds=0.0)
        with pytest.raises(OpenBoxAuthError):
            poller.wait_for_decision("wf", "run", "act")

    async def test_await_decision_propagates_401(self):
        def handler(request):
            return httpx.Response(401, json={"error": "revoked"})

        poller = ApprovalPoller(_client(handler), poll_interval_seconds=0.0)
        with pytest.raises(OpenBoxAuthError):
            await poller.await_decision("wf", "run", "act")


class TestValidateApiKeyAuthFailureClassification:
    """Regression + v2 extension of the existing validate_api_key behavior."""

    def test_v2_signed_request_surfaces_reason_code(self):
        def handler(request):
            return httpx.Response(403, json={"reason_code": "identity_ineligible"})

        identity = make_okta_identity()
        with pytest.raises(OpenBoxSigningError, match="identity_ineligible") as exc_info:
            _client(handler, identity=identity).validate_api_key()
        assert exc_info.value.reason_code == "identity_ineligible"
