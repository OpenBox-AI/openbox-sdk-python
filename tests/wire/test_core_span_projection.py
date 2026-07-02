"""Wire projection tests — internal envelope -> flat Core SpanData dict."""

from span_fixtures import PARENT_ID, SPAN_ID, TRACE_ID, FakeSpan

from openbox_core.config import PrivacyConfig
from openbox_core.contracts.otel_spans import (
    HookType,
    Stage,
    from_otel_span,
    serialize_readable_span,
)
from openbox_core.validation.diagnostics import (
    ATTR_REDACTED,
    ATTR_TRUNCATED,
    SPAN_ATTR_MISSING,
)
from openbox_core.wire.core_span import to_core_span_data


def project(
    span=None,
    *,
    stage=Stage.STARTED,
    hook_type=HookType.HTTP_REQUEST,
    fields=None,
    privacy=None,
    include_otel_data=False,
):
    envelope = from_otel_span(
        span or FakeSpan(), stage=stage, hook_type=hook_type, fields=fields
    )
    return to_core_span_data(envelope, privacy=privacy, include_otel_data=include_otel_data)


class TestInternalEnvelope:
    def test_envelope_preserves_otel_and_wrapper(self):
        span = FakeSpan(attributes={"http.method": "GET", "custom.key": "kept"})
        envelope = from_otel_span(span, stage=Stage.STARTED, hook_type=HookType.HTTP_REQUEST)
        assert envelope["otel"]["context"]["span_id"] == SPAN_ID  # raw int internally
        assert envelope["otel"]["attributes"]["custom.key"] == "kept"
        assert envelope["openbox"]["stage"] == "started"
        assert envelope["openbox"]["hook_type"] == "http_request"

    def test_serialize_readable_span_survives_junk(self):
        result = serialize_readable_span(object())
        assert result["name"] is None
        assert result["attributes"] == {}


class TestWireShape:
    def test_started_span_emits_explicit_nulls(self):
        wire, _ = project(stage=Stage.STARTED)
        # Explicit structural nulls — present keys, None values.
        assert "end_time" in wire and wire["end_time"] is None
        assert "duration_ns" in wire and wire["duration_ns"] is None
        assert wire["stage"] == "started"
        assert wire["start_time"] == FakeSpan().start_time

    def test_completed_span_sets_end_and_duration(self):
        wire, _ = project(stage=Stage.COMPLETED)
        span = FakeSpan()
        assert wire["end_time"] == span.end_time
        assert wire["duration_ns"] == span.end_time - span.start_time

    def test_nested_envelope_never_reaches_wire(self):
        wire, _ = project()
        assert "otel" not in wire
        assert "openbox" not in wire

    def test_data_absent_by_default(self):
        # Flat is the wire contract: no ``data`` blob unless explicitly opted in.
        wire, _ = project(FakeSpan(attributes={"exotic.attr": "yes"}))
        assert "data" not in wire
        assert "metadata" not in wire  # no span-level metadata field exists

    def test_otel_preserved_under_data_when_opted_in(self):
        span = FakeSpan(attributes={"exotic.attr": "yes"})
        wire, _ = project(span, include_otel_data=True)
        assert wire["data"]["otel"]["attributes"]["exotic.attr"] == "yes"
        assert "metadata" not in wire  # no span-level metadata field exists

    def test_data_blob_ids_are_hex_not_int(self):
        wire, _ = project(include_otel_data=True)
        context = wire["data"]["otel"]["context"]
        assert context["span_id"] == format(SPAN_ID, "016x")
        assert context["trace_id"] == format(TRACE_ID, "032x")
        assert wire["data"]["otel"]["parent"]["span_id"] == format(PARENT_ID, "016x")

    def test_common_root_fields_always_present(self):
        # Every common field present even with an attribute-less span.
        wire, _ = project(FakeSpan(attributes={}), stage=Stage.STARTED)
        for field_name in (
            "span_id", "trace_id", "parent_span_id", "name", "kind", "stage",
            "start_time", "end_time", "duration_ns", "attributes", "status",
            "events", "hook_type", "error",
        ):
            assert field_name in wire, field_name
        assert wire["error"] is None
        assert wire["attributes"] == {}  # present even when empty

    def test_hook_type_and_kind_at_root(self):
        wire, _ = project()
        assert wire["hook_type"] == "http_request"
        assert wire["kind"] == "CLIENT"


class TestSemanticMapping:
    def test_new_convention_wins_over_legacy(self):
        span = FakeSpan(
            attributes={
                "url.full": "https://new.example",
                "http.url": "https://legacy.example",
                "http.request.method": "PUT",
                "http.method": "GET",
            }
        )
        wire, _ = project(span)
        assert wire["http_url"] == "https://new.example"
        assert wire["http_method"] == "PUT"

    def test_legacy_fallback(self):
        span = FakeSpan(attributes={"http.url": "https://legacy.example", "http.method": "GET"})
        wire, _ = project(span)
        assert wire["http_url"] == "https://legacy.example"
        assert wire["http_method"] == "GET"

    def test_db_mapping(self):
        span = FakeSpan(
            attributes={
                "db.system": "postgresql",
                "db.statement": "SELECT 1",
                "net.peer.name": "db.internal",
            }
        )
        wire, _ = project(span, hook_type=HookType.DB_QUERY)
        assert wire["db_system"] == "postgresql"
        assert wire["db_statement"] == "SELECT 1"
        assert wire["server_address"] == "db.internal"

    def test_missing_semantics_diagnose_never_reject(self):
        wire, diagnostics = project(FakeSpan(attributes={}))
        assert wire["span_id"]  # span still produced
        codes = {(d.code, d.detail["field"]) for d in diagnostics}
        assert (SPAN_ATTR_MISSING, "http_url") in codes
        assert (SPAN_ATTR_MISSING, "http_method") in codes


class TestWrapperFields:
    def test_wrapper_fields_merge_at_root_and_override(self):
        span = FakeSpan(attributes={"http.method": "GET", "http.url": "https://x"})
        wire, _ = project(
            span,
            fields={
                "request_body": '{"q":1}',
                "http_status_code": 200,
                "rowcount": None,  # None values skipped
            },
        )
        assert wire["request_body"] == '{"q":1}'
        assert wire["http_status_code"] == 200
        assert "rowcount" not in wire

    def test_body_truncation_diagnosed(self):
        privacy = PrivacyConfig(max_body_size=8)
        wire, diagnostics = project(fields={"request_body": "x" * 100}, privacy=privacy)
        assert wire["request_body"] == "x" * 8
        assert any(d.code == ATTR_TRUNCATED for d in diagnostics)

    def test_attribute_redaction_diagnosed(self):
        privacy = PrivacyConfig(redact_keys={"authorization"})
        span = FakeSpan(attributes={"authorization": "Bearer secret", "http.method": "GET"})
        wire, diagnostics = project(span, privacy=privacy)
        assert wire["attributes"]["authorization"] == "[REDACTED]"
        assert any(d.code == ATTR_REDACTED for d in diagnostics)
