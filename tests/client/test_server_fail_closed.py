"""PROD-1098: a governed agent's SDK fails closed because the server says so.

Core pushes ``settings.on_api_error = "fail_closed"`` on validate and on every
verdict when the agent's organisation has an exposure-barrier rule set. From
then on an API error raises instead of returning an allow.
"""

import asyncio

import httpx
import pytest

from openbox_core.client import EvaluationClient
from openbox_core.errors import GovernanceAPIError

GOVERNED = {"verdict": "allow", "settings": {"on_api_error": "fail_closed"}}


def client_for(replies: list) -> EvaluationClient:
    def handler(request: httpx.Request) -> httpx.Response:
        reply = replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        status, body = reply
        return httpx.Response(status, json=body)

    transport = httpx.MockTransport(handler)
    return EvaluationClient(
        "https://core.test", "obx_test_abc", transport=transport, async_transport=transport
    )


def test_a_governed_verdict_makes_later_errors_fail_closed():
    client = client_for([(200, GOVERNED), (500, {"message": "boom"})])
    assert client.evaluate({"event_type": "ActivityStarted"}).verdict.value == "allow"
    assert client.server_on_api_error == "fail_closed"
    assert client.on_api_error == "fail_closed"
    with pytest.raises(GovernanceAPIError):
        client.evaluate({"event_type": "ActivityStarted"})


def test_without_the_setting_errors_still_fail_open():
    client = client_for([(200, {"verdict": "allow"}), (500, {"message": "boom"})])
    client.evaluate({"event_type": "ActivityStarted"})
    assert client.server_on_api_error is None
    result = client.evaluate({"event_type": "ActivityStarted"})
    assert result.verdict.value == "allow" and result.fallback_used


def test_validate_at_startup_sets_it_before_the_first_action():
    client = client_for([(200, {"valid": True, **GOVERNED}), httpx.ConnectError("down")])
    assert client.validate_api_key()
    with pytest.raises(GovernanceAPIError):
        client.evaluate({"event_type": "ActivityStarted"})


def test_async_paths_record_and_apply_it():
    client = client_for([(200, GOVERNED), httpx.ConnectError("down")])

    async def run():
        await client.aevaluate({"event_type": "ActivityStarted"})
        await client.aevaluate({"event_type": "ActivityStarted"})

    with pytest.raises(GovernanceAPIError):
        asyncio.run(run())


def test_a_local_fail_closed_is_never_loosened():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={})

    transport = httpx.MockTransport(handler)
    client = EvaluationClient(
        "https://core.test", "obx_test_abc", on_api_error="fail_closed", transport=transport
    )
    assert client.on_api_error == "fail_closed"
    with pytest.raises(GovernanceAPIError):
        client.evaluate({"event_type": "ActivityStarted"})
