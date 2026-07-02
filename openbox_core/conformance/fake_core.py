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

# Common root fields every flat hook span must carry (present even when null).
_COMMON_ROOT_FIELDS = (
    "span_id",
    "trace_id",
    "parent_span_id",
    "name",
    "kind",
    "stage",
    "start_time",
    "end_time",
    "duration_ns",
    "attributes",
    "status",
    "events",
    "hook_type",
    "error",
)

# Family-specific root fields that must exist (present even when null) per type.
_FAMILY_ROOT_FIELDS = {
    "http_request": (
        "http_method",
        "http_url",
        "http_status_code",
        "request_headers",
        "response_headers",
        "request_body",
        "response_body",
    ),
    "db_query": (
        "db_system",
        "db_name",
        "db_operation",
        "db_statement",
        "server_address",
        "server_port",
        "rowcount",
    ),
    "file_operation": (
        "file_path",
        "file_mode",
        "file_operation",
        "bytes_read",
        "bytes_written",
    ),
    "function_call": ("function", "module", "args", "result"),
}


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
    """Assert one captured hook payload matches the flat Core wire contract:

    - ``event_type=ActivityStarted`` + ``hook_trigger=true`` + non-empty spans
    - hex-string ids (regex, not truthiness)
    - flat ``SpanData`` dicts — the nested ``otel``/``openbox`` envelope AND the
      opt-in ``data`` blob must never reach the wire (Temporal parity)
    - every common root field present (``stage``/``hook_type``/``error``/…)
    - every family-specific root field present for the span's ``hook_type``
    - ``semantic_type`` never set by the SDK (Core computes it)
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
        assert "data" not in span, "flat hook spans must not carry a data blob"
        assert "semantic_type" not in span, "semantic_type is computed by Core, not the SDK"
        for field_name in _COMMON_ROOT_FIELDS:
            assert field_name in span, f"missing common root field: {field_name}"
        assert _SPAN_ID_RE.fullmatch(span.get("span_id", "")), span.get("span_id")
        assert _TRACE_ID_RE.fullmatch(span.get("trace_id", "")), span.get("trace_id")
        parent = span.get("parent_span_id")
        if parent is not None:
            assert _SPAN_ID_RE.fullmatch(parent), parent
        assert span.get("stage") in ("started", "completed")
        assert span.get("hook_type"), "hook spans must carry hook_type at the root"
        for field_name in _FAMILY_ROOT_FIELDS.get(span.get("hook_type", ""), ()):
            assert field_name in span, (
                f"missing {span.get('hook_type')} root field: {field_name}"
            )
        if span.get("stage") == "started":
            assert span["end_time"] is None
            assert span["duration_ns"] is None
