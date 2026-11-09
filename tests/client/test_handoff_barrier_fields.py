"""Source-authenticated handoffs carry what Core's barrier check needs (PROD-1117).

The multi-agent session links the child's return to this handoff, the scope
names the matter both sessions share, and the directing person comes from
context as on evaluate. Core answers with a verdict.
"""

from __future__ import annotations

import json

import httpx
from identity_fixtures import make_did_identity

from openbox_core import exposure
from openbox_core.client import EvaluationClient
from openbox_core.on_behalf_of import on_behalf_of


def _client(sent: list[dict], reply: dict | None = None) -> EvaluationClient:
    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(json.loads(request.content))
        return httpx.Response(200, json=reply or {"verdict": "allow"})

    transport = httpx.MockTransport(handler)
    return EvaluationClient(
        "https://core.test",
        "obx_test_abc",
        identity=make_did_identity(),
        transport=transport,
        async_transport=transport,
    )


def test_handoff_carries_session_and_the_current_scope() -> None:
    sent: list[dict] = []
    with exposure.exposure_scope("matter:0417"):
        _client(sent).emit_handoff("agent-child", multi_agent_session_id=" mas-1 ")
    assert sent == [
        {
            "target_agent_id": "agent-child",
            "multi_agent_session_id": "mas-1",
            "scope": "matter:0417",
        }
    ]


def test_an_explicit_scope_wins_and_the_directing_person_is_sent() -> None:
    sent: list[dict] = []
    with exposure.exposure_scope("matter:ignored"), on_behalf_of("amy@firm.example"):
        _client(sent).emit_handoff(
            "agent-child", multi_agent_session_id="mas-1", scope="matter:0999"
        )
    assert sent[0]["scope"] == "matter:0999"
    assert sent[0]["on_behalf_of"]["user"] == "amy@firm.example"


def test_without_barrier_fields_the_body_is_unchanged() -> None:
    sent: list[dict] = []
    _client(sent).emit_handoff("agent-child")
    assert sent == [{"target_agent_id": "agent-child"}]


async def test_async_handoff_returns_cores_verdict() -> None:
    sent: list[dict] = []
    reply = {"handoff_id": "h1", "verdict": "block", "reason": "Action blocked by policy"}
    with exposure.exposure_scope("matter:0417"):
        result = await _client(sent, reply).aemit_handoff(
            "agent-child", multi_agent_session_id="mas-1"
        )
    assert result["verdict"] == "block"
    assert sent[0]["scope"] == "matter:0417"
