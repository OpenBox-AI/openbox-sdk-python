"""Programmable fake OpenBox Core — verdict/approval queues + payload capture.

No live network: requests terminate in an ``httpx.MockTransport``. Serves both
sync and async clients. Importable from any framework SDK repo.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ..client import EvaluationClient

__all__ = ["FakeCore", "fake_client", "assert_hook_wire_shape"]

_SPAN_ID_RE = re.compile(r"^[0-9a-f]{16}$")
_TRACE_ID_RE = re.compile(r"^[0-9a-f]{32}$")


class FakeCore:
    """Queue verdict/approval responses; capture every outgoing payload.

    Responses pop FIFO from ``queue``; an empty queue answers ALLOW. Approval
    polls share the same queue (enqueue in call order).
    """

    def __init__(self, *responses: dict[str, Any]):
        self.queue: list[dict[str, Any]] = list(responses)
        self.payloads: list[dict[str, Any]] = []
        self.approval_requests: list[dict[str, Any]] = []

    # ── transport ─────────────────────────────────────────────────────────

    def handler(self, request: Any) -> Any:
        import httpx

        if request.url.path.endswith("/governance/evaluate"):
            self.payloads.append(json.loads(request.content))
            return httpx.Response(200, json=self._next({"verdict": "allow"}))
        if request.url.path.endswith("/governance/approval"):
            self.approval_requests.append(json.loads(request.content))
            return httpx.Response(200, json=self._next({"action": "allow"}))
        return httpx.Response(200, json={})

    def _next(self, default: dict[str, Any]) -> dict[str, Any]:
        return self.queue.pop(0) if self.queue else default

    # ── capture views ─────────────────────────────────────────────────────

    @property
    def started_payloads(self) -> list[dict[str, Any]]:
        return [
            p for p in self.payloads
            if p.get("spans") and p["spans"][0].get("stage") == "started"
        ]

    @property
    def completed_payloads(self) -> list[dict[str, Any]]:
        return [
            p for p in self.payloads
            if p.get("spans") and p["spans"][0].get("stage") == "completed"
        ]

    @property
    def lifecycle_payloads(self) -> list[dict[str, Any]]:
        return [p for p in self.payloads if not p.get("hook_trigger")]


def fake_client(fake_core: FakeCore, **kwargs: Any) -> EvaluationClient:
    """EvaluationClient wired to the fake Core (sync + async transports)."""
    import httpx

    transport = httpx.MockTransport(fake_core.handler)
    return EvaluationClient(
        kwargs.pop("api_url", "https://core.test"),
        kwargs.pop("api_key", "obx_test_conformance"),
        transport=transport,
        async_transport=transport,
        **kwargs,
    )


def assert_hook_wire_shape(payload: dict[str, Any]) -> None:
    """Assert one captured hook payload matches the Core wire contract:

    - ``event_type=ActivityStarted`` + ``hook_trigger=true`` + non-empty spans
    - hex-string ids (regex, not truthiness)
    - flat ``SpanData`` dicts — the nested ``otel``/``openbox`` envelope must
      never reach the wire
    - ``stage`` and ``hook_type`` present at the span root
    """
    assert payload.get("event_type") == "ActivityStarted", payload.get("event_type")
    assert payload.get("hook_trigger") is True
    spans = payload.get("spans")
    assert spans, "hook payload must carry non-empty spans"
    assert payload.get("span_count") == len(spans)
    for span in spans:
        assert "otel" not in span and "openbox" not in span, (
            "nested internal envelope leaked to the wire"
        )
        assert _SPAN_ID_RE.fullmatch(span.get("span_id", "")), span.get("span_id")
        assert _TRACE_ID_RE.fullmatch(span.get("trace_id", "")), span.get("trace_id")
        parent = span.get("parent_span_id")
        if parent is not None:
            assert _SPAN_ID_RE.fullmatch(parent), parent
        assert span.get("stage") in ("started", "completed")
        assert span.get("hook_type"), "hook spans must carry hook_type at the root"
        if span.get("stage") == "started":
            assert "end_time" in span and span["end_time"] is None
            assert "duration_ns" in span and span["duration_ns"] is None
