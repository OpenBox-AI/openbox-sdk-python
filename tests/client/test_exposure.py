"""Exposure fields: scope, action class, resources and participants, carried
on every evaluate call inside the block.

Uses httpx.MockTransport — requests never leave the process.
"""

import asyncio
import json

import httpx
import pytest

from openbox_core import (
    Participant,
    Resource,
    current_exposure_fields,
    exposure_scope,
    governed_action,
    on_behalf_of,
)
from openbox_core.client import EvaluationClient
from openbox_core.exposure import apply_exposure


def make_client(sent: list) -> EvaluationClient:
    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(json.loads(request.content))
        return httpx.Response(200, json={"verdict": "allow"})

    transport = httpx.MockTransport(handler)
    return EvaluationClient(
        "https://core.test",
        "obx_test_abc",
        transport=transport,
        async_transport=transport,
    )


COKE_DOC = Resource("dms://doc/17", ["client:coke", "matter:2026-0417"], "source_system")
R1 = Participant("destination", "mailbox:r1@firm.example")


class TestContext:
    def test_absent_by_default(self):
        assert current_exposure_fields() == {}
        assert apply_exposure({"a": 1}) == {"a": 1}

    def test_scope_and_action_combine(self):
        with exposure_scope("matter:2026-0417", purpose="advice"):
            with governed_action("send", resources=[COKE_DOC], participants=[R1]):
                assert current_exposure_fields() == {
                    "scope": "matter:2026-0417",
                    "purpose": "advice",
                    "action_class": "send",
                    "resources": [
                        {
                            "uri": "dms://doc/17",
                            "labels": ["client:coke", "matter:2026-0417"],
                            "label_source": "source_system",
                        }
                    ],
                    "participants": [{"kind": "destination", "id": "mailbox:r1@firm.example"}],
                }
            assert current_exposure_fields() == {"scope": "matter:2026-0417", "purpose": "advice"}
        assert current_exposure_fields() == {}

    def test_unlabelled_resource_sends_no_labels(self):
        # Core reads a resource without labels as Unknown.
        with governed_action("retrieve", resources=[Resource("dms://doc/9")]):
            assert current_exposure_fields()["resources"] == [
                {"uri": "dms://doc/9", "label_source": "sdk_declared"}
            ]

    def test_labels_are_trimmed_and_deduplicated(self):
        r = Resource("dms://doc/1", [" client:coke ", "client:coke", ""])
        assert r.labels == ("client:coke",)

    def test_payload_fields_win_one_by_one(self):
        with exposure_scope("matter:a"), governed_action("read", resources=[COKE_DOC]):
            out = apply_exposure({"scope": "matter:b"})
        assert out["scope"] == "matter:b"
        assert out["action_class"] == "read"

    def test_rejects_unknown_action_class(self):
        with pytest.raises(ValueError):
            with governed_action("teleport"):
                pass

    def test_rejects_unknown_participant_kind(self):
        with pytest.raises(ValueError):
            Participant("wizard", "x")

    def test_rejects_unknown_label_source(self):
        with pytest.raises(ValueError):
            Resource("dms://doc/1", ["client:coke"], "guess")

    def test_rejects_empty_ids(self):
        with pytest.raises(ValueError):
            Resource("  ")
        with pytest.raises(ValueError):
            Participant("destination", " ")


class TestOnBehalfOfIdpSubject:
    def test_iss_and_sub(self):
        sent: list = []
        client = make_client(sent)
        with on_behalf_of(None, iss="https://firm.okta.com", sub="user_8842"):
            client.evaluate({"event_type": "ActivityStarted"})
        assert sent[0]["on_behalf_of"] == {
            "iss": "https://firm.okta.com",
            "sub": "user_8842",
            "source": "sdk",
        }

    def test_iss_without_sub_is_rejected(self):
        with pytest.raises(ValueError):
            with on_behalf_of("amy@firm.example", iss="https://firm.okta.com"):
                pass


class TestDelivery:
    def test_sync_evaluate_carries_fields(self):
        sent: list = []
        client = make_client(sent)
        with on_behalf_of("amy@firm.example"), exposure_scope("matter:2026-0417"):
            with governed_action("send", resources=[COKE_DOC], participants=[R1]):
                client.evaluate({"event_type": "ActivityStarted"})
            client.evaluate({"event_type": "ActivityCompleted"})
        first, second = sent
        assert first["on_behalf_of"]["user"] == "amy@firm.example"
        assert first["action_class"] == "send"
        assert first["resources"][0]["labels"] == ["client:coke", "matter:2026-0417"]
        assert first["participants"] == [{"kind": "destination", "id": "mailbox:r1@firm.example"}]
        assert second["scope"] == "matter:2026-0417"
        assert "action_class" not in second

    def test_async_evaluate_carries_fields(self):
        sent: list = []
        client = make_client(sent)

        async def run():
            with governed_action("retrieve", resources=[COKE_DOC]):
                await client.aevaluate({"event_type": "ActivityStarted"})

        asyncio.run(run())
        assert sent[0]["action_class"] == "retrieve"

    def test_outside_a_block_nothing_is_added(self):
        sent: list = []
        client = make_client(sent)
        client.evaluate({"event_type": "ActivityStarted"})
        for key in ("scope", "action_class", "resources", "participants"):
            assert key not in sent[0]


class TestModelCallsGenerate:
    """PROD-1089: a model call is ``generate`` unless something declared otherwise,
    so an enforced barrier does not refuse it as an action of unknown class."""

    def test_a_model_call_is_generate_in_a_scope(self):
        sent: list = []
        client = make_client(sent)
        with exposure_scope("matter:2026-0417"):
            client.evaluate({"event_type": "ActivityStarted", "activity_type": "llm_call"})
        assert sent[0]["action_class"] == "generate"
        assert sent[0]["scope"] == "matter:2026-0417"

    def test_a_model_call_is_generate_without_a_scope(self):
        # Core checks every started activity in an organisation with a rule set,
        # scoped or not, so the class goes out either way.
        sent: list = []
        client = make_client(sent)
        client.evaluate({"event_type": "ActivityStarted", "activity_type": "llm_call"})
        assert sent[0]["action_class"] == "generate"
        assert "scope" not in sent[0]

    def test_a_declared_class_wins(self):
        with governed_action("retrieve", resources=[COKE_DOC]):
            assert apply_exposure({"activity_type": "llm_call"})["action_class"] == "retrieve"
        declared = apply_exposure({"activity_type": "llm_call", "action_class": "send"})
        assert declared["action_class"] == "send"

    def test_other_activities_get_no_class(self):
        with exposure_scope("matter:2026-0417"):
            assert "action_class" not in apply_exposure({"activity_type": "tool_call"})
            assert "action_class" not in apply_exposure({"event_type": "SignalReceived"})


class TestVerdictBinding:
    def test_payload_hash_is_sent_and_token_read_back(self):
        from openbox_core import hash_payload

        sent: list = []

        def handler(request: httpx.Request) -> httpx.Response:
            sent.append(json.loads(request.content))
            return httpx.Response(200, json={"verdict": "allow", "verdict_token": "vt.sig"})

        transport = httpx.MockTransport(handler)
        client = EvaluationClient("https://core.test", "obx_test_abc", transport=transport)
        body = b'{"to":"r1@firm.example"}'
        with governed_action("send", resources=[COKE_DOC], participants=[R1], payload_hash=hash_payload(body)):
            result = client.evaluate({"event_type": "ActivityStarted"})
        assert sent[0]["payload_hash"].startswith("sha256:")
        assert sent[0]["payload_hash"] == hash_payload(body.decode())
        assert result.verdict_token == "vt.sig"

    def test_a_refusal_exposes_nothing_barrier_specific(self):
        """PROD-1104: a block reads the same whatever decided it."""
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"verdict": "block", "reason": "Action blocked by policy"})

        transport = httpx.MockTransport(handler)
        client = EvaluationClient("https://core.test", "obx_test_abc", transport=transport)
        result = client.evaluate({"event_type": "ActivityStarted"})
        assert result.reason == "Action blocked by policy"
        assert not hasattr(result, "barrier")
        assert result.verdict_token is None
