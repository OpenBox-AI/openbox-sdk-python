"""Approval polling tests — client parsing + ApprovalPoller loop semantics."""

import httpx
import pytest

from openbox_core.approvals import ApprovalPoller
from openbox_core.client import APPROVAL_PATH, EvaluationClient
from openbox_core.contracts.results import Verdict
from openbox_core.errors import ApprovalTimeoutError

ARGS = ("wf-1", "run-1", "act-1")


def make_client(handler) -> EvaluationClient:
    transport = httpx.MockTransport(handler)
    return EvaluationClient(
        "https://core.test", "obx_test_abc", transport=transport, async_transport=transport
    )


class TestClientPollApproval:
    def test_parses_approval_result(self):
        def handler(request):
            assert request.url.path == APPROVAL_PATH
            return httpx.Response(200, json={"action": "allow", "id": "app-1"})

        result = make_client(handler).poll_approval(*ARGS)
        assert result.verdict is Verdict.ALLOW
        assert result.approval_id == "app-1"

    def test_poll_failure_returns_none(self):
        def handler(request):
            return httpx.Response(500)

        assert make_client(handler).poll_approval(*ARGS) is None

    def test_network_error_returns_none(self):
        def handler(request):
            raise httpx.ConnectError("down")

        assert make_client(handler).poll_approval(*ARGS) is None

    def test_past_expiration_sets_expired(self):
        def handler(request):
            return httpx.Response(
                200, json={"approval_expiration_time": "2020-01-01T00:00:00Z"}
            )

        result = make_client(handler).poll_approval(*ARGS)
        assert result.expired is True
        assert result.is_blocking()

    async def test_async_poll(self):
        def handler(request):
            return httpx.Response(200, json={"verdict": "block", "reason": "denied"})

        result = await make_client(handler).apoll_approval(*ARGS)
        assert result.is_blocking()


class TestApprovalPollerLoop:
    def _sequenced_client(self, responses):
        calls = {"n": 0}

        def handler(request):
            index = min(calls["n"], len(responses) - 1)
            calls["n"] += 1
            value = responses[index]
            if isinstance(value, Exception):
                raise value
            return httpx.Response(200, json=value)

        return make_client(handler), calls

    def test_polls_until_allow(self):
        client, calls = self._sequenced_client(
            [{"verdict": "require_approval"}, {"verdict": "require_approval"}, {"action": "allow"}]
        )
        poller = ApprovalPoller(client, poll_interval_seconds=0.0)
        result = poller.wait_for_decision(*ARGS)
        assert result.allow_shaped
        assert calls["n"] == 3

    def test_poll_failures_keep_polling(self):
        client, calls = self._sequenced_client(
            [httpx.ConnectError("down"), {"action": "allow"}]
        )
        poller = ApprovalPoller(client, poll_interval_seconds=0.0)
        assert poller.wait_for_decision(*ARGS).allow_shaped
        assert calls["n"] == 2

    def test_blocking_decision_returned_not_raised(self):
        client, _ = self._sequenced_client([{"action": "block", "reason": "denied"}])
        result = ApprovalPoller(client, poll_interval_seconds=0.0).wait_for_decision(*ARGS)
        assert result.is_blocking()
        assert result.reason == "denied"

    def test_expired_returned_as_terminal(self):
        client, _ = self._sequenced_client([{"expired": True}])
        result = ApprovalPoller(client, poll_interval_seconds=0.0).wait_for_decision(*ARGS)
        assert result.expired

    def test_timeout_budget_raises(self):
        client, _ = self._sequenced_client([{"verdict": "require_approval"}])
        poller = ApprovalPoller(client, poll_interval_seconds=0.0, max_wait_seconds=0.0)
        with pytest.raises(ApprovalTimeoutError):
            poller.wait_for_decision(*ARGS)

    async def test_async_polls_until_allow(self):
        client, calls = self._sequenced_client(
            [{"verdict": "require_approval"}, {"action": "allow"}]
        )
        poller = ApprovalPoller(client, poll_interval_seconds=0.0)
        result = await poller.await_decision(*ARGS)
        assert result.allow_shaped
        assert calls["n"] == 2

    def test_backoff_growth_capped(self):
        client, _ = self._sequenced_client([{"action": "allow"}])
        poller = ApprovalPoller(
            client, poll_interval_seconds=1.0, backoff_multiplier=10.0, max_interval_seconds=5.0
        )
        assert poller._next_interval(0) == 1.0
        assert poller._next_interval(1) == 5.0  # capped


class TestConsecutiveFailureBudget:
    """Unreachable Core must not hang the governed thread forever (fail-safe)."""

    def test_persistent_poll_failures_raise_timeout(self):
        def handler(request):
            raise httpx.ConnectError("core is down")

        client = make_client(handler)
        poller = ApprovalPoller(
            client, poll_interval_seconds=0.0, max_consecutive_failures=3
        )
        with pytest.raises(ApprovalTimeoutError):
            poller.wait_for_decision(*ARGS)

    def test_intermittent_failures_reset_the_counter(self):
        calls = {"n": 0}
        sequence = [
            httpx.ConnectError("down"),
            httpx.ConnectError("down"),
            {"verdict": "require_approval"},  # success resets the failure count
            httpx.ConnectError("down"),
            httpx.ConnectError("down"),
            {"action": "allow"},
        ]

        def handler(request):
            value = sequence[min(calls["n"], len(sequence) - 1)]
            calls["n"] += 1
            if isinstance(value, Exception):
                raise value
            return httpx.Response(200, json=value)

        poller = ApprovalPoller(
            make_client(handler), poll_interval_seconds=0.0, max_consecutive_failures=3
        )
        assert poller.wait_for_decision(*ARGS).allow_shaped

    async def test_async_failure_budget(self):
        def handler(request):
            raise httpx.ConnectError("core is down")

        poller = ApprovalPoller(
            make_client(handler), poll_interval_seconds=0.0, max_consecutive_failures=2
        )
        with pytest.raises(ApprovalTimeoutError):
            await poller.await_decision(*ARGS)
