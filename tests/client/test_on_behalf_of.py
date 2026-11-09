"""on_behalf_of: the end user an agent acts for, carried on every evaluate call.

Uses httpx.MockTransport — requests never leave the process.
"""

import asyncio
import json

import httpx

from openbox_core import (
    current_on_behalf_of,
    on_behalf_of,
    reset_on_behalf_of,
    set_on_behalf_of,
)
from openbox_core.client import EvaluationClient
from openbox_core.on_behalf_of import apply_on_behalf_of


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


class TestContext:
    def test_absent_by_default(self):
        assert current_on_behalf_of() is None
        assert apply_on_behalf_of({"a": 1}) == {"a": 1}

    def test_scoped_to_the_block(self):
        with on_behalf_of("amy@firm.example"):
            assert current_on_behalf_of() == {"user": "amy@firm.example", "source": "sdk"}
        assert current_on_behalf_of() is None

    def test_nested_blocks_restore_the_outer_user(self):
        with on_behalf_of("amy@firm.example"):
            with on_behalf_of("barry@firm.example", source="session"):
                assert current_on_behalf_of() == {"user": "barry@firm.example", "source": "session"}
            assert current_on_behalf_of()["user"] == "amy@firm.example"

    def test_blank_user_clears_it(self):
        with on_behalf_of("amy@firm.example"):
            with on_behalf_of("   "):
                assert current_on_behalf_of() is None

    def test_user_is_trimmed(self):
        token = set_on_behalf_of("  amy@firm.example ")
        try:
            assert current_on_behalf_of()["user"] == "amy@firm.example"
        finally:
            reset_on_behalf_of(token)

    def test_returned_value_is_a_copy(self):
        with on_behalf_of("amy@firm.example"):
            current_on_behalf_of()["user"] = "mallory@firm.example"
            assert current_on_behalf_of()["user"] == "amy@firm.example"


class TestApply:
    def test_value_on_the_payload_wins(self):
        explicit = {"user": "colin@firm.example", "source": "caller"}
        with on_behalf_of("amy@firm.example"):
            assert apply_on_behalf_of({"on_behalf_of": explicit})["on_behalf_of"] == explicit

    def test_does_not_mutate_the_caller_payload(self):
        payload = {"a": 1}
        with on_behalf_of("amy@firm.example"):
            out = apply_on_behalf_of(payload)
        assert "on_behalf_of" not in payload
        assert out["on_behalf_of"]["user"] == "amy@firm.example"


class TestEvaluateCarriesIt:
    def test_sync_evaluate(self):
        sent: list = []
        client = make_client(sent)
        with on_behalf_of("amy@firm.example"):
            client.evaluate({"event_type": "ActivityStarted"})
        client.evaluate({"event_type": "ActivityStarted"})
        assert sent[0]["on_behalf_of"] == {"user": "amy@firm.example", "source": "sdk"}
        assert "on_behalf_of" not in sent[1]

    async def test_async_evaluate(self):
        sent: list = []
        with on_behalf_of("amy@firm.example"):
            await make_client(sent).aevaluate({"event_type": "ActivityStarted"})
        assert sent[0]["on_behalf_of"]["user"] == "amy@firm.example"

    async def test_tasks_started_inside_the_block_inherit_it(self):
        sent: list = []
        client = make_client(sent)
        with on_behalf_of("amy@firm.example"):
            task = asyncio.create_task(client.aevaluate({"event_type": "ActivityStarted"}))
        await task
        assert sent[0]["on_behalf_of"]["user"] == "amy@firm.example"

    async def test_concurrent_requests_keep_their_own_user(self):
        sent: list = []
        client = make_client(sent)

        async def run(user: str) -> None:
            with on_behalf_of(user):
                await asyncio.sleep(0)
                await client.aevaluate({"event_type": "ActivityStarted", "who": user})

        await asyncio.gather(run("amy@firm.example"), run("barry@firm.example"))
        assert {(p["who"], p["on_behalf_of"]["user"]) for p in sent} == {
            ("amy@firm.example", "amy@firm.example"),
            ("barry@firm.example", "barry@firm.example"),
        }
