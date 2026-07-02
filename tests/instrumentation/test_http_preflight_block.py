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


class TestHeaderRedaction:
    """Credential headers must never reach governance payloads."""

    def test_sanitize_headers_redacts_credentials(self):
        from openbox_core.instrumentation.http import sanitize_headers

        headers = sanitize_headers(
            {
                "Authorization": "Bearer sk-proj-SECRET",
                "Cookie": "session=SECRET",
                "Set-Cookie": "sid=SECRET",
                b"x-api-key": b"SECRET-BYTES",
                "content-type": "application/json",
            }
        )
        assert headers["Authorization"] == "[REDACTED]"
        assert headers["Cookie"] == "[REDACTED]"
        assert headers["Set-Cookie"] == "[REDACTED]"
        assert headers["x-api-key"] == "[REDACTED]"
        assert headers["content-type"] == "application/json"
        assert "SECRET" not in str(headers)
        assert sanitize_headers(None) is None

    def test_httpx_started_fields_redact_authorization(self):
        from openbox_core.instrumentation.http import _httpx_started_fields

        class _RequestInfo:
            method = b"POST"
            url = "https://api.openai.com/v1/chat/completions"
            headers = {"authorization": "Bearer sk-proj-SECRET", "accept": "application/json"}

        fields = _httpx_started_fields(_RequestInfo())
        assert fields["http_method"] == "POST"  # bytes decoded, not "b'POST'"
        assert fields["request_headers"]["authorization"] == "[REDACTED]"
        assert fields["request_headers"]["accept"] == "application/json"
