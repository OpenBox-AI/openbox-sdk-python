"""PROD-1099: the visibility query, from the SDK side."""

import asyncio
import json

import httpx
import pytest

from openbox_core import exposure_scope, on_behalf_of
from openbox_core.client import VISIBLE_PATH, EvaluationClient
from openbox_core.errors import OpenBoxNetworkError

ANSWER = {"visible": ["client:coke"], "hidden": ["client:pepsi"], "rule_set_hash": "rs-1"}


def make_client(sent: list, status: int = 200, body: dict | None = None) -> EvaluationClient:
    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(status, json=ANSWER if body is None else body)

    transport = httpx.MockTransport(handler)
    return EvaluationClient(
        "https://core.test", "obx_test_abc", transport=transport, async_transport=transport
    )


def test_asks_for_the_current_session_and_parses_the_answer():
    sent: list = []
    client = make_client(sent)
    with (
        on_behalf_of("amy@firm.example"),
        exposure_scope("matter:0417", purpose="pricing_review", instance_id="inst_1"),
    ):
        out = client.visible_labels(["client:coke", "client:pepsi"])
    assert sent[0].url.path == VISIBLE_PATH
    body = json.loads(sent[0].content)
    assert body["scope"] == "matter:0417"
    assert body["purpose"] == "pricing_review"
    assert body["instance_id"] == "inst_1"
    assert body["labels"] == ["client:coke", "client:pepsi"]
    assert body["on_behalf_of"]["user"] == "amy@firm.example"
    assert (out.visible, out.hidden, out.rule_set_hash) == (
        ["client:coke"],
        ["client:pepsi"],
        "rs-1",
    )
    assert out.allows(["client:coke"]) and not out.allows(["client:coke", "client:pepsi"])


def test_outside_a_scope_sends_labels_only():
    sent: list = []
    make_client(sent).visible_labels(["client:coke"])
    assert json.loads(sent[0].content) == {"labels": ["client:coke"]}


def test_async_and_errors():
    sent: list = []
    out = asyncio.run(make_client(sent).avisible_labels(["client:coke"]))
    assert out.visible == ["client:coke"]
    with pytest.raises(OpenBoxNetworkError):
        make_client([], status=503, body={}).visible_labels(["client:coke"])
