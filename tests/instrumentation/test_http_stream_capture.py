"""Real HTTPX wrappers with lazy streams: preserve delivery and capture evidence."""

import asyncio
import gzip
from dataclasses import replace

import httpx
import httpx2
import pytest

from openbox_core.conformance.fake_core import FakeCore, assert_hook_wire_shape
from openbox_core.conformance.hook_preflight import CONFORMANCE_CONTEXT
from openbox_core.conformance.instrumentation import installed_conformance_runtime
from openbox_core.context import ContextStore, activity_scope

URL = "https://api.openai.com/v1/chat/completions"


@pytest.fixture(params=[httpx, httpx2], ids=["httpx", "httpx2"])
def library(request):
    return request.param


@pytest.fixture(params=[False, True], ids=["sync", "async"])
def asynchronous(request):
    return request.param


def lazy_response(library, asynchronous, chunks, *, failure=None, headers=None):
    state = {"chunks": 0, "closes": 0}

    class SyncStream(library.SyncByteStream):
        def __iter__(self):
            for chunk in chunks:
                state["chunks"] += 1
                yield chunk
            if failure is not None:
                raise failure

        def close(self):
            state["closes"] += 1

    class AsyncStream(library.AsyncByteStream):
        async def __aiter__(self):
            for chunk in chunks:
                state["chunks"] += 1
                yield chunk
            if failure is not None:
                raise failure

        async def aclose(self):
            state["closes"] += 1

    response = library.Response(
        200,
        headers=headers or {"content-type": "text/event-stream", "set-cookie": "secret"},
        stream=AsyncStream() if asynchronous else SyncStream(),
    )
    return response, state


def client_for(library, asynchronous, response):
    transport = library.MockTransport(lambda request: response)
    return (library.AsyncClient if asynchronous else library.Client)(transport=transport)


async def close(client, response, asynchronous):
    if asynchronous:
        await response.aclose()
        await client.aclose()
    else:
        response.close()
        client.close()


@pytest.mark.parametrize("compressed", [False, True], ids=["sse", "gzip"])
async def test_capture_waits_for_stream_and_preserves_bytes(library, asynchronous, compressed):
    body = 'data: {"text":"hello 🌍"}\n\ndata: [DONE]\n\n'.encode()
    raw = gzip.compress(body) if compressed else body
    # One-byte input chunks exercise split Unicode and decompressor buffering.
    headers = {"content-type": "text/event-stream", "set-cookie": "secret"}
    if compressed:
        headers["content-encoding"] = "gzip"
    response, state = lazy_response(
        library, asynchronous, [raw[i : i + 1] for i in range(len(raw))], headers=headers
    )
    core, store = FakeCore(), ContextStore()
    with installed_conformance_runtime(core, store=store, file_enabled=False):
        with activity_scope(CONFORMANCE_CONTEXT, store=store):
            client = client_for(library, asynchronous, response)
            request = client.build_request("POST", URL, json={"stream": True})
            if asynchronous:
                await client.send(request, stream=True)
            else:
                client.send(request, stream=True)
            assert state["chunks"] == 0
            assert core.completed_payloads == []
            if asynchronous:
                # A large chunk_size forces the decoded iterator to flush
                # AFTER HTTPX has already closed its underlying raw stream.
                received = b"".join([chunk async for chunk in response.aiter_bytes(1024)])
            else:
                received = b"".join(response.iter_bytes(1024))
            assert received == body
            await close(client, response, asynchronous)
    assert state["closes"] == 1
    assert len(core.started_payloads) == len(core.completed_payloads) == 1
    started, completed = core.started_payloads[0], core.completed_payloads[0]
    first, last = started["spans"][0], completed["spans"][0]
    assert last["response_body"] == body.decode()
    assert last["response_headers"]["set-cookie"] == "[REDACTED]"
    assert last["attributes"]["openbox.http.response_body.partial"] is False
    assert last["end_time"] > last["start_time"]
    assert first["span_id"] == last["span_id"]
    assert first["trace_id"] == last["trace_id"]
    assert started["activity_id"] == completed["activity_id"]
    assert_hook_wire_shape(completed)


@pytest.mark.parametrize("read_one", [False, True], ids=["unread", "partial"])
async def test_early_close_completes_once_with_read_prefix(library, asynchronous, read_one):
    response, state = lazy_response(library, asynchronous, [b"first", b"unread"])
    core, store = FakeCore(), ContextStore()
    with installed_conformance_runtime(core, store=store, file_enabled=False):
        with activity_scope(CONFORMANCE_CONTEXT, store=store):
            client = client_for(library, asynchronous, response)
            request = client.build_request("GET", URL)
            if asynchronous:
                await client.send(request, stream=True)
                iterator = response.aiter_bytes()
                if read_one:
                    assert await anext(iterator) == b"first"
                await response.aclose()
                await response.aclose()
                await iterator.aclose()
            else:
                client.send(request, stream=True)
                iterator = response.iter_bytes()
                if read_one:
                    assert next(iterator) == b"first"
                response.close()
                response.close()
                iterator.close()
            await close(client, response, asynchronous)
    assert state == {"chunks": int(read_one), "closes": 1}
    assert len(core.completed_payloads) == 1
    span = core.completed_payloads[0]["spans"][0]
    assert span["response_body"] == ("first" if read_one else "")
    assert span["attributes"]["openbox.http.response_body.partial"] is True


async def test_stream_error_preserves_original_exception_and_prefix(library, asynchronous):
    failure = library.ReadError("stream interrupted")
    response, state = lazy_response(library, asynchronous, [b"partial"], failure=failure)
    core, store = FakeCore(), ContextStore()
    with installed_conformance_runtime(core, store=store, file_enabled=False):
        with activity_scope(CONFORMANCE_CONTEXT, store=store):
            client = client_for(library, asynchronous, response)
            request = client.build_request("GET", URL)
            with pytest.raises(library.ReadError) as error:
                if asynchronous:
                    await client.send(request, stream=True)
                    await response.aread()
                else:
                    client.send(request, stream=True)
                    response.read()
            assert error.value is failure
            await close(client, response, asynchronous)
    assert state["closes"] == 1
    assert len(core.completed_payloads) == 1
    span = core.completed_payloads[0]["spans"][0]
    assert span["response_body"] == "partial"
    assert span["error"] == "ReadError: stream interrupted"
    assert span["attributes"]["openbox.http.response_body.partial"] is True


@pytest.mark.parametrize("limit", [5, 0], ids=["configured-cap", "disabled-truncation"])
async def test_capture_is_bounded_without_truncating_delivery(library, asynchronous, limit):
    text = "é" * 100_000
    response, _ = lazy_response(library, asynchronous, [text.encode()])
    core, store = FakeCore(), ContextStore()
    with installed_conformance_runtime(core, store=store, file_enabled=False) as runtime:
        runtime.config.privacy.max_body_size = limit
        with activity_scope(CONFORMANCE_CONTEXT, store=store):
            client = client_for(library, asynchronous, response)
            request = client.build_request("GET", URL)
            if asynchronous:
                await client.send(request, stream=True)
                received = await response.aread()
            else:
                client.send(request, stream=True)
                received = response.read()
            await close(client, response, asynchronous)
    assert received.decode() == text
    assert core.completed_payloads[0]["spans"][0]["response_body"] == text[: limit or 65536]


async def test_completed_span_keeps_request_activity(library, asynchronous):
    response, _ = lazy_response(library, asynchronous, [b"answer"])
    core, store = FakeCore(), ContextStore()
    with installed_conformance_runtime(core, store=store, file_enabled=False):
        client = client_for(library, asynchronous, response)
        with activity_scope(CONFORMANCE_CONTEXT, store=store):
            request = client.build_request("GET", URL)
            if asynchronous:
                await client.send(request, stream=True)
            else:
                client.send(request, stream=True)
        other = replace(CONFORMANCE_CONTEXT, activity_id="different-activity")
        with activity_scope(other, store=store):
            if asynchronous:
                await response.aread()
            else:
                response.read()
            await close(client, response, asynchronous)
            assert store.current_activity_context() == other
    assert len(core.completed_payloads) == 1
    assert core.completed_payloads[0]["activity_id"] == CONFORMANCE_CONTEXT.activity_id


async def test_async_cancellation_is_preserved(library):
    waiting = asyncio.Event()

    class WaitingStream(library.AsyncByteStream):
        async def __aiter__(self):
            yield b"partial"
            waiting.set()
            await asyncio.Event().wait()

    response = library.Response(200, stream=WaitingStream(), headers={"content-type": "text/plain"})
    core, store = FakeCore(), ContextStore()
    with installed_conformance_runtime(core, store=store, file_enabled=False):
        with activity_scope(CONFORMANCE_CONTEXT, store=store):
            client = client_for(library, True, response)
            await client.send(client.build_request("GET", URL), stream=True)
            reader = asyncio.create_task(response.aread())
            await asyncio.wait_for(waiting.wait(), timeout=1)
            reader.cancel()
            with pytest.raises(asyncio.CancelledError):
                await reader
            await close(client, response, True)
    assert len(core.completed_payloads) == 1
    span = core.completed_payloads[0]["spans"][0]
    assert span["response_body"] == "partial"
    assert span["error"].startswith("CancelledError:")
