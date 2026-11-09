"""The SDK side of a verdict-bound Executor call."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from openbox_core import (
    ExecutorRefused,
    Participant,
    arelay_via_executor,
    hash_payload,
    relay_via_executor,
)

DEST = Participant("destination", "dms:main")
BODY = json.dumps({"q": "merger"}).encode()


def _executor(status: int, payload: dict, seen: list) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(status, json=payload, headers={"X-OpenBox-Relay-Id": "rl_1"})
    return httpx.MockTransport(handler)


def test_relays_the_hashed_bytes_with_token_and_participants():
    seen: list[httpx.Request] = []
    resp = relay_via_executor("http://exec/", "dms:main", BODY, [DEST], "vt.sig",
                              transport=_executor(200, {"results": []}, seen))
    assert resp.json() == {"results": []}
    req = seen[0]
    assert str(req.url) == "http://exec/v1/relay/dms:main"
    assert req.headers["X-OpenBox-Verdict-Token"] == "vt.sig"
    assert json.loads(req.headers["X-OpenBox-Participants"]) == [{"kind": "destination", "id": "dms:main"}]
    # The Executor hashes exactly what it receives; it must be what the agent hashed.
    assert hash_payload(req.content) == hash_payload(BODY)


def test_dropped_results_are_refused_as_policy():
    """PROD-1104: results governance refused read as a policy refusal."""
    seen: list[httpx.Request] = []
    refusal = {"refused": True, "reason_class": "policy", "relay_id": "rl_1"}
    with pytest.raises(ExecutorRefused) as e:
        relay_via_executor("http://exec", "dms:main", BODY, [DEST], "vt.sig",
                           transport=_executor(403, refusal, seen))
    assert e.value.reason_class == "policy"
    assert not hasattr(e.value, "remedy")
    assert e.value.relay_id == "rl_1"


def test_missing_token_is_refused_by_the_executor():
    seen: list[httpx.Request] = []
    refusal = {"refused": True, "reason_class": "verdict_token", "reason": "missing_token", "relay_id": "rl_1"}
    with pytest.raises(ExecutorRefused) as e:
        relay_via_executor("http://exec", "dms:main", BODY, [DEST], None,
                           transport=_executor(403, refusal, seen))
    assert "X-OpenBox-Verdict-Token" not in seen[0].headers
    assert (e.value.reason_class, e.value.reason) == ("verdict_token", "missing_token")


def test_async_relay():
    seen: list[httpx.Request] = []
    resp = asyncio.run(arelay_via_executor("http://exec", "dms:main", BODY, [DEST], "vt.sig",
                                           transport=_executor(200, {"ok": True}, seen)))
    assert resp.json() == {"ok": True}


def test_destination_must_be_an_id():
    with pytest.raises(ValueError):
        relay_via_executor("http://exec", "../admin", BODY, [DEST], "vt")
