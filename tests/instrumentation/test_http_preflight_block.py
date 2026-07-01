"""HTTP wrapper conformance — started BLOCK/HALT prevents the real request."""

import httpx
import pytest
import requests
from conftest import FakeCore, RaisingHookAdapter
from instrumented_env import CountingHTTPServer, bound_activity, installed_runtime

from openbox_core.context import ContextStore
from openbox_core.errors import GovernanceBlockedError, GovernanceHaltError


@pytest.fixture(scope="module")
def server():
    server = CountingHTTPServer()
    yield server
    server.stop()


class TestRequestsLibrary:
    def test_started_block_request_not_sent(self, server):
        fake_core = FakeCore({"verdict": "block", "reason": "no egress"})
        adapter, store = RaisingHookAdapter(), ContextStore()
        with installed_runtime(fake_core, adapter, store), bound_activity(store):
            before = server.hits
            with pytest.raises(GovernanceBlockedError):
                requests.get(server.url, timeout=5)
            assert server.hits == before  # request NEVER reached the server
        assert len(fake_core.started_payloads) == 1
        started_span = fake_core.started_payloads[0]["spans"][0]
        assert started_span["hook_type"] == "http_request"
        assert started_span["http_url"] == server.url
        assert started_span["end_time"] is None  # explicit started null

    def test_started_halt_request_not_sent_halt_error(self, server):
        fake_core = FakeCore({"verdict": "halt", "reason": "kill switch"})
        adapter, store = RaisingHookAdapter(), ContextStore()
        with installed_runtime(fake_core, adapter, store), bound_activity(store):
            before = server.hits
            with pytest.raises(GovernanceHaltError):
                requests.get(server.url, timeout=5)
            assert server.hits == before
            assert store.halt_requested

    def test_allow_sends_and_emits_completed(self, server):
        fake_core = FakeCore({"verdict": "allow"}, {"verdict": "allow"})
        adapter, store = RaisingHookAdapter(), ContextStore()
        with installed_runtime(fake_core, adapter, store), bound_activity(store):
            before = server.hits
            response = requests.get(server.url, timeout=5)
            assert response.status_code == 200
            assert server.hits == before + 1
        completed = fake_core.completed_payloads
        assert len(completed) == 1
        span = completed[0]["spans"][0]
        assert span["http_status_code"] == 200
        assert span["stage"] == "completed"

    def test_no_bound_context_not_governed(self, server):
        fake_core = FakeCore()
        adapter, store = RaisingHookAdapter(), ContextStore()
        with installed_runtime(fake_core, adapter, store):
            response = requests.get(server.url, timeout=5)  # NO bound context
            assert response.status_code == 200
        assert fake_core.payloads == []  # skipped, not an error


class TestHttpxLibrary:
    def test_sync_block_request_not_sent(self, server):
        fake_core = FakeCore({"verdict": "block", "reason": "no"})
        adapter, store = RaisingHookAdapter(), ContextStore()
        with installed_runtime(fake_core, adapter, store), bound_activity(store):
            before = server.hits
            with pytest.raises(GovernanceBlockedError), httpx.Client() as client:
                client.get(server.url)
            assert server.hits == before

    async def test_async_block_request_not_sent(self, server):
        fake_core = FakeCore({"verdict": "block", "reason": "no"})
        adapter, store = RaisingHookAdapter(), ContextStore()
        with installed_runtime(fake_core, adapter, store), bound_activity(store):
            before = server.hits
            async with httpx.AsyncClient() as client:
                with pytest.raises(GovernanceBlockedError):
                    await client.get(server.url)
            assert server.hits == before

    async def test_async_allow_sends(self, server):
        fake_core = FakeCore({"verdict": "allow"}, {"verdict": "allow"})
        adapter, store = RaisingHookAdapter(), ContextStore()
        with installed_runtime(fake_core, adapter, store), bound_activity(store):
            async with httpx.AsyncClient() as client:
                response = await client.get(server.url)
            assert response.status_code == 200
        assert len(fake_core.completed_payloads) == 1
