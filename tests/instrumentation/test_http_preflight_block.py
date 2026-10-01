"""HTTP wrapper conformance — started BLOCK/HALT prevents the real request."""

import httpx
import httpx2
import pytest
import requests
from conftest import FakeCore, RaisingHookAdapter
from instrumented_env import CountingHTTPServer, bound_activity, installed_runtime

from openbox_core.conformance.fake_core import assert_hook_wire_shape
from openbox_core.context import ContextStore
from openbox_core.errors import GovernanceBlockedError, GovernanceHaltError
from openbox_core.instrumentation.http import suppress_http_instrumentation


@pytest.fixture(params=[httpx, httpx2], ids=["httpx", "httpx2"])
def httpx_library(request):
    return request.param


@pytest.fixture(scope="module")
def server():
    server = CountingHTTPServer()
    yield server
    server.stop()


class TestRequestsLibrary:
    def test_started_block_request_not_sent(self, server):
        fake_core = FakeCore({"verdict": "block", "reason": "no egress"})
        adapter, store = RaisingHookAdapter(), ContextStore()
        with installed_runtime(fake_core, adapter, store, file_enabled=False), bound_activity(store):
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
        with installed_runtime(fake_core, adapter, store, file_enabled=False), bound_activity(store):
            before = server.hits
            with pytest.raises(GovernanceHaltError):
                requests.get(server.url, timeout=5)
            assert server.hits == before
            assert store.halt_requested

    def test_allow_sends_and_emits_completed(self, server):
        fake_core = FakeCore({"verdict": "allow"}, {"verdict": "allow"})
        adapter, store = RaisingHookAdapter(), ContextStore()
        with installed_runtime(fake_core, adapter, store, file_enabled=False), bound_activity(store):
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
        with installed_runtime(fake_core, adapter, store, file_enabled=False):
            response = requests.get(server.url, timeout=5)  # NO bound context
            assert response.status_code == 200
        assert fake_core.payloads == []  # skipped, not an error


class TestHttpxLibrary:
    # Isolate HTTP governance: lazy TLS setup can read system trust-store files.
    @pytest.mark.parametrize(
        ("verdict", "error"), [("block", GovernanceBlockedError), ("halt", GovernanceHaltError)]
    )
    def test_sync_block_request_not_sent(self, server, httpx_library, verdict, error):
        fake_core = FakeCore({"verdict": verdict, "reason": "no"})
        adapter, store = RaisingHookAdapter(), ContextStore()
        with installed_runtime(fake_core, adapter, store, file_enabled=False), bound_activity(store):
            before = server.hits
            with pytest.raises(error), httpx_library.Client() as client:
                client.get(server.url)
            assert server.hits == before
        assert len(fake_core.started_payloads) == 1
        assert fake_core.started_payloads[0]["spans"][0]["hook_type"] == "http_request"
        assert fake_core.completed_payloads == []

    @pytest.mark.parametrize(
        ("verdict", "error"), [("block", GovernanceBlockedError), ("halt", GovernanceHaltError)]
    )
    async def test_async_block_request_not_sent(self, server, httpx_library, verdict, error):
        fake_core = FakeCore({"verdict": verdict, "reason": "no"})
        adapter, store = RaisingHookAdapter(), ContextStore()
        with installed_runtime(fake_core, adapter, store, file_enabled=False), bound_activity(store):
            before = server.hits
            async with httpx_library.AsyncClient() as client:
                with pytest.raises(error):
                    await client.get(server.url)
            assert server.hits == before
        assert len(fake_core.started_payloads) == 1
        assert fake_core.started_payloads[0]["spans"][0]["hook_type"] == "http_request"
        assert fake_core.completed_payloads == []

    async def test_async_allow_sends(self, server, httpx_library):
        fake_core = FakeCore({"verdict": "allow"}, {"verdict": "allow"})
        adapter, store = RaisingHookAdapter(), ContextStore()
        with installed_runtime(fake_core, adapter, store, file_enabled=False), bound_activity(store):
            async with httpx_library.AsyncClient() as client:
                response = await client.get(server.url)
            assert response.status_code == 200
        assert len(fake_core.completed_payloads) == 1

    async def test_prebuilt_async_client_emits_started_and_completed(self, httpx_library):
        async def handler(request):
            return httpx_library.Response(200, json={"ok": True})

        client = httpx_library.AsyncClient(transport=httpx_library.MockTransport(handler))
        fake_core = FakeCore({"verdict": "allow"}, {"verdict": "allow"})
        adapter, store = RaisingHookAdapter(), ContextStore()
        try:
            with installed_runtime(fake_core, adapter, store, file_enabled=False), bound_activity(store):
                response = await client.post(
                    "https://api.openai.com/v1/chat/completions", json={"x": 1}
                )
            assert response.status_code == 200
        finally:
            await client.aclose()

        assert len(fake_core.started_payloads) == 1
        assert len(fake_core.completed_payloads) == 1
        started = fake_core.started_payloads[0]["spans"][0]
        completed = fake_core.completed_payloads[0]["spans"][0]
        assert started["stage"] == "started"
        assert completed["stage"] == "completed"
        assert started["http_url"] == completed["http_url"]
        assert started["span_id"] == completed["span_id"]
        assert started["trace_id"] == completed["trace_id"]
        for payload in fake_core.payloads:
            assert_hook_wire_shape(payload)

    @pytest.mark.parametrize("async_client", [False, True], ids=["sync", "async"])
    async def test_both_libraries_keep_the_same_wire_contract(self, async_client):
        fake_core, store = FakeCore(), ContextStore()
        headers = {"User-Agent": "compat-test", "Accept-Encoding": "identity"}
        # Both libraries are installed at the same time; custom transports
        # must still produce exactly two evaluations each.
        with installed_runtime(fake_core, store=store, file_enabled=False), bound_activity(store):
            for library in (httpx, httpx2):
                transport = library.MockTransport(
                    lambda request, lib=library: lib.Response(503, json={"error": "busy"})
                )
                if async_client:
                    async with library.AsyncClient(transport=transport, headers=headers) as client:
                        response = await client.post("https://service.test/echo", json={"x": 1})
                else:
                    with library.Client(transport=transport, headers=headers) as client:
                        response = client.post("https://service.test/echo", json={"x": 1})
                assert response.status_code == 503

        assert len(fake_core.payloads) == 4
        for payload in fake_core.payloads:
            assert_hook_wire_shape(payload)
        variable_fields = {"span_id", "trace_id", "start_time", "end_time", "duration_ns"}
        for first, second in zip(fake_core.payloads[:2], fake_core.payloads[2:], strict=True):
            assert first.keys() == second.keys()
            first_span, second_span = first["spans"][0], second["spans"][0]
            assert first_span.keys() == second_span.keys()
            assert {k: v for k, v in first_span.items() if k not in variable_fields} == {
                k: v for k, v in second_span.items() if k not in variable_fields
            }
        for completed in fake_core.completed_payloads:
            assert completed["spans"][0]["error"] == "HTTP 503"

    async def test_ignored_and_suppressed_requests_emit_no_hooks(self, httpx_library):
        fake_core, store = FakeCore(), ContextStore()
        transport = httpx_library.MockTransport(
            lambda request: httpx_library.Response(200, json={"ok": True})
        )
        with installed_runtime(fake_core, store=store, file_enabled=False), bound_activity(store):
            with httpx_library.Client(transport=transport) as client:
                assert client.get("https://core.test/ignored").status_code == 200
                with suppress_http_instrumentation():
                    assert client.get("https://service.test/suppressed").status_code == 200
            async with httpx_library.AsyncClient(transport=transport) as client:
                assert (await client.get("https://core.test/ignored")).status_code == 200
                with suppress_http_instrumentation():
                    assert (await client.get("https://service.test/suppressed")).status_code == 200
        assert fake_core.payloads == []

    def test_streaming_response_is_not_consumed(self, httpx_library):
        consumed = []

        def chunks():
            consumed.append(True)
            yield b"streamed response"

        transport = httpx_library.MockTransport(
            lambda request: httpx_library.Response(200, content=chunks())
        )
        fake_core, store = FakeCore(), ContextStore()
        with installed_runtime(fake_core, store=store, file_enabled=False), bound_activity(store):
            with httpx_library.Client(transport=transport) as client:
                with client.stream("GET", "https://service.test/stream") as response:
                    assert consumed == []
                    assert response.read() == b"streamed response"
        assert len(fake_core.completed_payloads) == 1
        assert fake_core.completed_payloads[0]["spans"][0]["response_body"] is None

    async def test_async_streaming_response_is_not_consumed(self, httpx_library):
        consumed = []

        async def chunks():
            consumed.append(True)
            yield b"streamed response"

        transport = httpx_library.MockTransport(
            lambda request: httpx_library.Response(200, content=chunks())
        )
        fake_core, store = FakeCore(), ContextStore()
        with installed_runtime(fake_core, store=store, file_enabled=False), bound_activity(store):
            async with httpx_library.AsyncClient(transport=transport) as client:
                async with client.stream("GET", "https://service.test/stream") as response:
                    assert consumed == []
                    assert await response.aread() == b"streamed response"
        assert len(fake_core.completed_payloads) == 1
        assert fake_core.completed_payloads[0]["spans"][0]["response_body"] is None


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


def _lower_keys(headers: dict | None) -> dict:
    """Header keys lowercased — httpx/requests differ on case preservation."""
    return {str(k).lower(): v for k, v in (headers or {}).items()}


class TestHttpBodyCapture:
    """End-to-end: request/response bodies captured and credential headers
    redacted in the ACTUAL governance payloads (real instrumentation path)."""

    def test_requests_started_captures_body_and_redacts_auth(self, server):
        fake_core = FakeCore({"verdict": "allow"}, {"verdict": "allow"})
        adapter, store = RaisingHookAdapter(), ContextStore()
        with installed_runtime(fake_core, adapter, store, file_enabled=False), bound_activity(store):
            requests.post(
                server.url,
                json={"secret_field": 1},
                headers={"Authorization": "Bearer sk-SECRET"},
                timeout=5,
            )
        started = fake_core.started_payloads[0]["spans"][0]
        assert _lower_keys(started["request_headers"])["authorization"] == "[REDACTED]"
        assert started["request_body"] and '"secret_field"' in started["request_body"]
        completed = fake_core.completed_payloads[0]["spans"][0]
        assert completed["http_status_code"] == 200
        assert completed["response_body"] is not None  # server echoes {"ok": true}
        assert "SECRET" not in str(completed["request_headers"])

    def test_httpx_sync_completed_captures_bodies_and_redacts_auth(self, server, httpx_library):
        fake_core = FakeCore({"verdict": "allow"}, {"verdict": "allow"})
        adapter, store = RaisingHookAdapter(), ContextStore()
        with installed_runtime(fake_core, adapter, store, file_enabled=False), bound_activity(store):
            with httpx_library.Client() as client:
                client.post(
                    server.url,
                    json={"secret_field": 1},
                    headers={"Authorization": "Bearer sk-SECRET"},
                )
        started = fake_core.started_payloads[0]["spans"][0]
        assert _lower_keys(started["request_headers"])["authorization"] == "[REDACTED]"
        completed = fake_core.completed_payloads[0]["spans"][0]
        assert completed["http_status_code"] == 200
        # Request body reliably available in the Client.send patch.
        assert completed["request_body"] and '"secret_field"' in completed["request_body"]
        assert completed["response_body"] is not None
        assert "SECRET" not in str(completed["request_headers"])

    async def test_httpx_async_completed_captures_bodies(self, server, httpx_library):
        fake_core = FakeCore({"verdict": "allow"}, {"verdict": "allow"})
        adapter, store = RaisingHookAdapter(), ContextStore()
        with installed_runtime(fake_core, adapter, store, file_enabled=False), bound_activity(store):
            async with httpx_library.AsyncClient() as client:
                await client.post(
                    server.url,
                    json={"secret_field": 1},
                    headers={"Authorization": "Bearer sk-SECRET"},
                )
        completed = fake_core.completed_payloads[0]["spans"][0]
        assert completed["request_body"] and '"secret_field"' in completed["request_body"]
        assert completed["response_body"] is not None
        assert _lower_keys(completed["request_headers"])["authorization"] == "[REDACTED]"
