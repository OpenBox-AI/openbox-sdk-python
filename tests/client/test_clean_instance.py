"""The clean-instance remedy from the SDK side (exposure barriers, T12)."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from openbox_core import exposure_scope
from openbox_core.client import ROTATE_PATH, ROTATE_STATUS_PATH, EvaluationClient
from openbox_core.errors import OpenBoxConfigError
from openbox_core.exposure import apply_exposure


def make_client(replies: list[tuple[int, dict]], sent: list) -> EvaluationClient:
    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        status, body = replies.pop(0)
        return httpx.Response(status, json=body)

    transport = httpx.MockTransport(handler)
    return EvaluationClient(
        api_url="https://core.example",
        api_key="obx_test_" + "a" * 48,
        transport=transport,
        async_transport=transport,
    )


def test_request_then_poll_until_issued():
    sent: list[httpx.Request] = []
    client = make_client(
        [
            (202, {"rotation_id": "rot_1", "status": "pending"}),
            (200, {"rotation_id": "rot_1", "status": "activated", "instance_id": "inst_9"}),
        ],
        sent,
    )
    r = client.request_clean_instance("matter:0417", "pepsi task", instance_id="inst_1")
    assert (r.rotation_id, r.status, r.instance_id, r.ready) == ("rot_1", "pending", None, False)
    assert sent[0].url.path == ROTATE_PATH
    assert json.loads(sent[0].content) == {
        "scope": "matter:0417", "reason": "pepsi task", "retire_old": True, "instance_id": "inst_1"
    }
    r = client.clean_instance_status("rot_1")
    assert r.ready and r.instance_id == "inst_9"
    assert sent[1].url.path == ROTATE_STATUS_PATH


def test_the_issued_instance_rides_on_every_event():
    with exposure_scope("matter:0417", instance_id="inst_9"):
        assert apply_exposure({"event_type": "ActivityStarted"})["instance_id"] == "inst_9"


def test_async_request():
    sent: list[httpx.Request] = []
    client = make_client([(202, {"rotation_id": "rot_2", "status": "pending"})], sent)
    r = asyncio.run(client.arequest_clean_instance("matter:0417", "x"))
    assert r.rotation_id == "rot_2"


def test_failure_raises():
    sent: list[httpx.Request] = []
    client = make_client([(503, {"message": "clean instances are not enabled"})], sent)
    with pytest.raises(OpenBoxConfigError):
        client.request_clean_instance("matter:0417", "x")
