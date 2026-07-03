"""urllib3 + urllib wrapper conformance — started BLOCK prevents the request,
allow sends and emits completed. Uses a real loopback server (no live network).

Also guards the requests→urllib3 double-instrumentation case: OTel suppresses the
nested urllib3 span while a RequestsInstrumentor call is active, so a requests
call must NOT double-govern through the urllib3 hooks.
"""

import urllib.request

import pytest
import requests
import urllib3
from conftest import FakeCore, RaisingHookAdapter
from instrumented_env import CountingHTTPServer, bound_activity, installed_runtime

from openbox_core.context import ContextStore
from openbox_core.errors import GovernanceBlockedError


@pytest.fixture(scope="module")
def server():
    server = CountingHTTPServer()
    yield server
    server.stop()


class TestUrllib3:
    def test_started_block_request_not_sent(self, server):
        fake_core = FakeCore({"verdict": "block", "reason": "no egress"})
        adapter, store = RaisingHookAdapter(), ContextStore()
        with installed_runtime(fake_core, adapter, store), bound_activity(store):
            before = server.hits
            http = urllib3.PoolManager()
            with pytest.raises(GovernanceBlockedError):
                http.request("GET", server.url)
            assert server.hits == before  # never reached the server
        started = fake_core.started_payloads[-1]["spans"][0]
        assert started["hook_type"] == "http_request"
        assert started["http_url"] == server.url
        assert started["end_time"] is None

    def test_allow_sends_and_emits_completed(self, server):
        fake_core = FakeCore({"verdict": "allow"}, {"verdict": "allow"})
        adapter, store = RaisingHookAdapter(), ContextStore()
        with installed_runtime(fake_core, adapter, store), bound_activity(store):
            before = server.hits
            http = urllib3.PoolManager()
            response = http.request("GET", server.url)
            assert response.status == 200
            assert server.hits == before + 1
        completed = fake_core.completed_payloads
        assert len(completed) == 1
        span = completed[0]["spans"][0]
        assert span["hook_type"] == "http_request"
        assert span["http_status_code"] == 200
        assert span["stage"] == "completed"

    def test_no_bound_context_not_governed(self, server):
        fake_core = FakeCore()
        adapter, store = RaisingHookAdapter(), ContextStore()
        with installed_runtime(fake_core, adapter, store):
            http = urllib3.PoolManager()
            assert http.request("GET", server.url).status == 200
        assert fake_core.payloads == []


class TestUrllib:
    def test_started_block_request_not_sent(self, server):
        fake_core = FakeCore({"verdict": "block", "reason": "no egress"})
        adapter, store = RaisingHookAdapter(), ContextStore()
        with installed_runtime(fake_core, adapter, store), bound_activity(store):
            before = server.hits
            with pytest.raises(Exception) as excinfo:
                urllib.request.urlopen(server.url, timeout=5)
            # urllib may wrap the block in URLError; the governance error is the
            # cause. Either way the request must not have been sent.
            assert isinstance(excinfo.value, GovernanceBlockedError) or isinstance(
                getattr(excinfo.value, "reason", None), GovernanceBlockedError
            )
            assert server.hits == before
        started = fake_core.started_payloads[-1]["spans"][0]
        assert started["hook_type"] == "http_request"

    def test_allow_sends(self, server):
        fake_core = FakeCore({"verdict": "allow"}, {"verdict": "allow"})
        adapter, store = RaisingHookAdapter(), ContextStore()
        with installed_runtime(fake_core, adapter, store), bound_activity(store):
            before = server.hits
            resp = urllib.request.urlopen(server.url, timeout=5)
            assert resp.status == 200
            assert server.hits == before + 1
        started = fake_core.started_payloads[-1]["spans"][0]
        assert started["http_url"].endswith("/echo")


class TestRequestsDoesNotDoubleGovernViaUrllib3:
    def test_requests_allow_emits_single_flow(self, server):
        """A requests call runs on urllib3; OTel suppression must keep it a
        SINGLE governance flow (one started, one completed) — not two."""
        fake_core = FakeCore({"verdict": "allow"}, {"verdict": "allow"})
        adapter, store = RaisingHookAdapter(), ContextStore()
        with installed_runtime(fake_core, adapter, store), bound_activity(store):
            assert requests.get(server.url, timeout=5).status_code == 200
        assert len(fake_core.started_payloads) == 1
        assert len(fake_core.completed_payloads) == 1
