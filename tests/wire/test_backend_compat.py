"""Backend compatibility fixture — the REAL Go SpanData unmarshal parses our
emitted hook spans (struct copied verbatim from openbox-core
internal/content/governance.go; DisallowUnknownFields keeps us honest).

Skips when no Go toolchain is available (CI installs one).
"""

import json
import pathlib
import shutil
import subprocess

import pytest
from span_fixtures import SPAN_ID, TRACE_ID, FakeSpan

from openbox_core.contracts.otel_spans import HookType, Stage, from_otel_span
from openbox_core.wire.core_span import to_core_span_data

GO = shutil.which("go")
HARNESS_DIR = pathlib.Path(__file__).parent / "go_spandata_compat"

pytestmark = pytest.mark.skipif(GO is None, reason="Go toolchain not available")


def go_unmarshal(spans: list[dict]) -> list[dict]:
    result = subprocess.run(
        [GO, "run", "main.go"],
        cwd=HARNESS_DIR,
        input=json.dumps(spans),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"Go SpanData unmarshal rejected payload:\n{result.stderr}"
    return json.loads(result.stdout)


def build(stage, hook_type, attributes, fields=None):
    span = FakeSpan(attributes=attributes)
    envelope = from_otel_span(span, stage=stage, hook_type=hook_type, fields=fields)
    wire, _ = to_core_span_data(envelope)
    return wire


class TestGoSpanDataCompat:
    def test_started_http_span_parses_with_null_end_time(self):
        wire = build(
            Stage.STARTED,
            HookType.HTTP_REQUEST,
            {"http.method": "GET", "http.url": "https://api.example/x"},
            fields={"request_body": '{"q":1}'},
        )
        assert wire["end_time"] is None and wire["duration_ns"] is None
        parsed = go_unmarshal([wire])[0]
        # Core's non-pointer EndTime int64 unmarshals explicit null -> 0.
        assert parsed["end_time"] == 0
        assert parsed["has_duration_ns"] is False
        assert parsed["stage"] == "started"
        assert parsed["hook_type"] == "http_request"
        assert parsed["span_id"] == format(SPAN_ID, "016x")
        assert parsed["trace_id"] == format(TRACE_ID, "032x")
        assert parsed["http_url"] == "https://api.example/x"
        assert parsed["http_method"] == "GET"
        assert parsed["has_data"] is True

    def test_completed_spans_all_hook_types_parse(self):
        spans = [
            build(
                Stage.COMPLETED,
                HookType.HTTP_REQUEST,
                {"http.method": "POST", "http.url": "https://api.example"},
                fields={"http_status_code": 201, "response_body": "ok"},
            ),
            build(
                Stage.COMPLETED,
                HookType.DB_QUERY,
                {"db.system": "postgresql", "db.statement": "SELECT 1"},
                fields={"rowcount": 3},
            ),
            build(
                Stage.COMPLETED,
                HookType.FILE_OPERATION,
                {"file.path": "/tmp/x.txt", "file.operation": "write"},
                fields={"bytes_written": 42},
            ),
            build(
                Stage.COMPLETED,
                HookType.FUNCTION_CALL,
                {"code.function": "charge", "code.namespace": "billing"},
                fields={"args": {"amount": 5}, "result": "ok"},
            ),
        ]
        parsed = go_unmarshal(spans)
        assert parsed[0]["http_status_code"] == 201
        assert parsed[0]["end_time"] > 0
        assert parsed[1]["db_statement"] == "SELECT 1"
        assert parsed[2]["file_path"] == "/tmp/x.txt"
        assert parsed[3]["function"] == "charge"
        for report in parsed:
            assert report["span_id"] == format(SPAN_ID, "016x")
            assert report["has_data"] is True

    def test_parent_span_id_parses_as_pointer_string(self):
        wire = build(Stage.STARTED, HookType.HTTP_REQUEST, {"http.method": "GET", "http.url": "https://x"})
        parsed = go_unmarshal([wire])[0]
        assert parsed["parent_span_id"] == wire["parent_span_id"]
