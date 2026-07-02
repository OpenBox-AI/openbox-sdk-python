# Base SDK hook-span flat-contract parity — implementation report

Date: 2026-07-03. Scope: make `openbox_core` emit Temporal-compatible **flat**
Core `SpanData` for every hook family (HTTP/DB/file/function). Base SDK is the
shared source of truth; no LangGraph-only shaping.

## 1. Contract matrix — Temporal legacy flat hooks vs base SDK

### Common fields (all families)

| field | Temporal | base BEFORE | base AFTER |
|---|---|---|---|
| span_id / trace_id | hex16 / hex32 | ✅ | ✅ |
| name / stage / start_time | always | ✅ | ✅ |
| status / events | always | ✅ | ✅ |
| hook_type | always | ✅ | ✅ |
| parent_span_id | always (null if none) | omitted unless int | **always (null)** |
| kind | always (CLIENT/INTERNAL) | omitted if no OTel kind | **always (OTel kind, else family default)** |
| attributes | always (dict, may be `{}`) | omitted when empty | **always (even `{}`)** |
| end_time | null started / int completed | null started; **null on OTel-owned completed** | **null started; synthesized start+dur on completed** |
| duration_ns | null started / int completed | fields override | ✅ (unchanged; parity block backfills end_time) |
| error | always (null if none) | omitted when None | **always (null)** |
| `data.otel` | **absent** | **present every span** | **absent on wire (opt-in debug only)** |
| semantic_type | absent (Core computes) | absent | absent ✅ |

### HTTP (`http_method, http_url, http_status_code, request_headers, response_headers, request_body, response_body`)

| stage/lib | Temporal | base BEFORE | base AFTER |
|---|---|---|---|
| requests started | method/url/req_body/req_headers | ✅ | ✅ |
| requests completed | + resp_body/headers/status, retains req_body/headers | resp only | **+ req_body/req_headers retained** |
| httpx started | + best-effort req_body | method/url/headers only | **+ best-effort req_body** |
| httpx completed | req_body+resp_body+resp_headers+status via `Client.send` patch | **status only, no bodies** | **full bodies+headers via ported send patch** |
| all | family keys always present | present only when non-null | **always present (null if absent)** |

### DB (`db_system, db_name, db_operation, db_statement, server_address, server_port, rowcount`)

| field | Temporal | base BEFORE | base AFTER |
|---|---|---|---|
| db_system / db_statement / db_operation / rowcount | populated | ✅ | ✅ |
| db_name / server_address / server_port | populated (host/port/db extracted) | **never populated, keys absent** | **extracted: SQLAlchemy url, dbapi connection_props, asyncpg _addr/_params** |

### File (`file_path, file_mode, file_operation, bytes_read, bytes_written`)
Parity already good (base matches `io.open`+`builtins.open` patch). AFTER: keys always present (null if absent).

### Function (`function, module, args, result`)
`function/module/args` populated BEFORE; `result` on capture. AFTER: `args`/`result` always present (null when `capture_args`/`capture_result` false) — matches Temporal.

## 2. Changes

- **`wire/core_span.py`** (core): `include_otel_data` default → `False` (flat is the wire contract); common root fields always present (parent_span_id/kind/attributes/error null-safe); per-family root-field templates via `setdefault(None)`; kind fallback per hook type; completed-stage `end_time = start_time + duration_ns` when OTel span not ended.
- **`wire/evaluate_payload.py`**: emit path passes `include_otel_data=False` explicitly (documented flat contract).
- **`instrumentation/http.py`**: ported Temporal httpx body capture — best-effort req_body at started + span stash (ContextVar); `install/uninstall_httpx_body_capture()` patches `Client.send`/`AsyncClient.send` for the SINGLE completed event (stream-safe `try/.text`, never consumes streams); httpx OTel response hook removed (no double completed); requests completed retains req_body/req_headers; shared `_is_text_content_type`.
- **`instrumentation/db.py`**: `_db_fields` gained db_name/server_address/server_port; per-driver metadata extractors (`_sqlalchemy_conn_meta`/`_dbapi_conn_meta`/`_asyncpg_conn_meta`); error path upgraded from hardcoded `"sql"` to real dialect+url.
- **`instrumentation/manager.py`**: install httpx body capture after OTel httpx; uninstall in reverse order.
- **`conformance/fake_core.py`**: `assert_hook_wire_shape` now asserts no `data`, no `semantic_type`, all common + family root fields present. Shared contract every framework SDK inherits.

## 3. Tests
- New `tests/wire/test_flat_hook_contract.py`: 4 families × 2 stages via real `build_evaluate_payload` — no otel/openbox/data, common+family roots present, truncation, started nulls, DB metadata, function null args.
- New `TestHttpBodyCapture` in `tests/instrumentation/test_http_preflight_block.py`: end-to-end requests + httpx (sync/async) — bodies captured, `Authorization` redacted in real payloads.
- Updated for new contract: `test_core_span_projection.py` (data opt-in + flat-by-default + common-fields), `test_backend_compat.py` (`has_data` → False), `test_file_function_block.py` (`args` null not absent when `capture_args=False`).

## 4. Verification
- Base SDK: **350 passed** (`uv run pytest`), ruff clean, import-safety intact.
- Go backend-compat (real Core `SpanData` + `DisallowUnknownFields`): **3 passed** — flat spans with always-present nulls parse against actual Core struct.
- LangGraph (openbox_core editable/live in its venv): conformance suite **9 passed**; full suite **206 passed × 6 consecutive runs**.

## 5. Non-goals honored
Core semantic-type computation untouched; no LangGraph-only shaping; `LangGraphHookRuntime` unchanged (pins context, delegates payload to base); no legacy LangGraph hook revival; Temporal not switched to base instrumentation.

## Unresolved questions
1. `LangGraph test_concurrent_turns_do_not_cross_contaminate` is flaky (1 fail in ~7 full-suite runs; passes in isolation and 6/6 with changes) — pre-existing `asyncio.gather` timing race in LangGraph's turn-id channel, NOT span-shape related. Left as-is (out of scope); flag to LangGraph owners.
2. httpx completed fires only on a returned response (matches Temporal); connection-error httpx calls emit no completed telemetry. Confirm acceptable.
3. Temporal SDK still emits `operations` (file close) + `lines_count`; base emits `lines_count` only (both in Core struct). `operations` intentionally not added (absent from the Go `SpanData` copy). Confirm Core tolerates/needs neither.
