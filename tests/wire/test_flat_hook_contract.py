"""Flat hook wire contract — every hook family emits flat Core ``SpanData``.

Exercises the REAL send-path owner (``build_evaluate_payload``) for all four
hook families × both stages and proves, per family, the Temporal flat contract:

- no top-level ``otel`` / ``openbox`` internal envelope
- no top-level ``data`` blob (data.otel is opt-in debug, never on the wire)
- ``semantic_type`` never set by the SDK (Core computes it)
- every common root field present (null-valued when absent)
- every family-specific root field present (null-valued when absent)
- body fields captured + truncated (HTTP)
- started stage carries explicit ``end_time``/``duration_ns`` nulls
"""

import pytest
from span_fixtures import FakeSpan

from openbox_core.config import PrivacyConfig
from openbox_core.conformance.fake_core import assert_hook_wire_shape
from openbox_core.contracts.events import hook
from openbox_core.contracts.otel_spans import HookType, Stage, from_otel_span
from openbox_core.wire.evaluate_payload import build_evaluate_payload

_ACTIVITY_CONTEXT = {
    "workflow_id": "wf-flat",
    "run_id": "run-flat",
    "workflow_type": "FlatContractWorkflow",
    "task_queue": "flat-queue",
}

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

_FAMILY_ROOT_FIELDS = {
    HookType.HTTP_REQUEST: (
        "http_method",
        "http_url",
        "http_status_code",
        "request_headers",
        "response_headers",
        "request_body",
        "response_body",
    ),
    HookType.DB_QUERY: (
        "db_system",
        "db_name",
        "db_operation",
        "db_statement",
        "server_address",
        "server_port",
        "rowcount",
    ),
    HookType.FILE_OPERATION: (
        "file_path",
        "file_mode",
        "file_operation",
        "bytes_read",
        "bytes_written",
    ),
    HookType.FUNCTION_CALL: ("function", "module", "args", "result"),
}

_ALL_HOOK_TYPES = list(_FAMILY_ROOT_FIELDS)
_ALL_STAGES = [Stage.STARTED, Stage.COMPLETED]


def emit(hook_type, stage, *, attributes=None, fields=None, privacy=None):
    """Project a hook span through the real evaluate-body assembler.

    Returns ``(payload, span)`` where ``span`` is the single flat wire span.
    """
    span = FakeSpan(attributes=attributes or {})
    envelope = from_otel_span(span, stage=stage, hook_type=hook_type, fields=fields)
    event = hook(
        activity_context=_ACTIVITY_CONTEXT,
        activity_id="act-flat",
        activity_type="flat_activity",
        spans=[envelope],
    )
    payload, _ = build_evaluate_payload(event, privacy=privacy)
    return payload, payload["spans"][0]


@pytest.mark.parametrize("hook_type", _ALL_HOOK_TYPES)
@pytest.mark.parametrize("stage", _ALL_STAGES)
class TestFlatContractMatrix:
    def test_no_internal_envelope_and_no_data(self, hook_type, stage):
        _, span = emit(hook_type, stage)
        assert "otel" not in span, "internal otel envelope leaked to the wire"
        assert "openbox" not in span, "internal openbox envelope leaked to the wire"
        assert "data" not in span, "flat hook spans must not carry a data blob"

    def test_no_sdk_semantic_type(self, hook_type, stage):
        _, span = emit(hook_type, stage)
        assert "semantic_type" not in span  # Core computes it

    def test_common_root_fields_present(self, hook_type, stage):
        _, span = emit(hook_type, stage)
        for field_name in _COMMON_ROOT_FIELDS:
            assert field_name in span, f"missing common root field: {field_name}"
        assert span["hook_type"] == hook_type.value

    def test_family_root_fields_present(self, hook_type, stage):
        _, span = emit(hook_type, stage)
        for field_name in _FAMILY_ROOT_FIELDS[hook_type]:
            assert field_name in span, f"missing {hook_type.value} field: {field_name}"

    def test_conformance_assertion_passes(self, hook_type, stage):
        payload, _ = emit(hook_type, stage)
        assert_hook_wire_shape(payload)  # the shared framework-SDK contract


@pytest.mark.parametrize("hook_type", _ALL_HOOK_TYPES)
def test_started_stage_emits_explicit_nulls(hook_type):
    _, span = emit(hook_type, Stage.STARTED)
    assert span["stage"] == "started"
    assert span["end_time"] is None
    assert span["duration_ns"] is None


class TestHttpBodyAndHeaders:
    def test_started_retains_request_body_and_redacted_headers(self):
        # Headers arrive already sanitized from the instrumentation layer; the
        # projection preserves them verbatim (redaction proven end-to-end in the
        # instrumentation tests + sanitize_headers unit test).
        _, span = emit(
            HookType.HTTP_REQUEST,
            Stage.STARTED,
            fields={
                "http_method": "POST",
                "http_url": "https://api.example/x",
                "request_body": '{"q":1}',
                "request_headers": {"authorization": "[REDACTED]", "accept": "application/json"},
            },
        )
        assert span["request_body"] == '{"q":1}'
        assert span["request_headers"]["authorization"] == "[REDACTED]"
        assert span["response_body"] is None  # present but null at started

    def test_completed_carries_request_and_response_bodies(self):
        _, span = emit(
            HookType.HTTP_REQUEST,
            Stage.COMPLETED,
            fields={
                "http_method": "POST",
                "http_url": "https://api.example/x",
                "http_status_code": 201,
                "request_body": '{"q":1}',
                "response_body": '{"ok":true}',
                "response_headers": {"content-type": "application/json"},
                "duration_ns": 5_000_000,
            },
        )
        assert span["request_body"] == '{"q":1}'
        assert span["response_body"] == '{"ok":true}'
        assert span["http_status_code"] == 201

    def test_body_truncation_applies_to_request_and_response(self):
        privacy = PrivacyConfig(max_body_size=8)
        _, span = emit(
            HookType.HTTP_REQUEST,
            Stage.COMPLETED,
            fields={"request_body": "x" * 100, "response_body": "y" * 100, "duration_ns": 1},
            privacy=privacy,
        )
        assert span["request_body"] == "x" * 8
        assert span["response_body"] == "y" * 8

    def test_error_populated_for_4xx(self):
        _, span = emit(
            HookType.HTTP_REQUEST,
            Stage.COMPLETED,
            fields={"http_status_code": 500, "error": "HTTP 500", "duration_ns": 1},
        )
        assert span["error"] == "HTTP 500"


class TestDbMetadata:
    def test_connection_metadata_present(self):
        _, span = emit(
            HookType.DB_QUERY,
            Stage.COMPLETED,
            fields={
                "db_system": "postgresql",
                "db_statement": "SELECT 1",
                "db_operation": "SELECT",
                "db_name": "app",
                "server_address": "db.internal",
                "server_port": 5432,
                "rowcount": 3,
            },
        )
        assert span["db_name"] == "app"
        assert span["server_address"] == "db.internal"
        assert span["server_port"] == 5432
        assert span["rowcount"] == 3

    def test_metadata_null_when_driver_omits_it(self):
        _, span = emit(
            HookType.DB_QUERY,
            Stage.STARTED,
            fields={"db_system": "sqlite", "db_statement": "SELECT 1"},
        )
        assert span["db_name"] is None
        assert span["server_address"] is None
        assert span["server_port"] is None
        assert span["rowcount"] is None


class TestFileFields:
    def test_write_fields_present(self):
        _, span = emit(
            HookType.FILE_OPERATION,
            Stage.COMPLETED,
            fields={
                "file_path": "/tmp/x.txt",
                "file_mode": "w",
                "file_operation": "write",
                "bytes_written": 42,
            },
        )
        assert span["file_path"] == "/tmp/x.txt"
        assert span["bytes_written"] == 42
        assert span["bytes_read"] is None  # present but null


class TestFunctionFields:
    def test_captured_args_and_result(self):
        _, span = emit(
            HookType.FUNCTION_CALL,
            Stage.COMPLETED,
            fields={"function": "charge", "module": "billing", "args": {"args": [5]}, "result": "ok"},
        )
        assert span["function"] == "charge"
        assert span["module"] == "billing"
        assert span["result"] == "ok"

    def test_args_and_result_null_when_not_captured(self):
        _, span = emit(
            HookType.FUNCTION_CALL,
            Stage.COMPLETED,
            fields={"function": "charge", "module": "billing"},
        )
        assert span["args"] is None
        assert span["result"] is None
