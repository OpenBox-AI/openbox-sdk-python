---
type: decision
date: 2026-07-03
tags: [wire, spans, governance, temporal-parity]
status: active
---

# Decision: hook spans are flat Core SpanData (no `data.otel`)

Every hook span emitted by `openbox_core` (HTTP/DB/file/function) is a **flat**
Core `SpanData` dict, matching the Temporal legacy hook contract. The base SDK
is the shared source of truth — framework SDKs (LangGraph, Temporal migration)
inherit this shape; none reshape spans themselves.

## What "flat" means (enforced in `contracts/otel_spans.py`, `wire/core_span.py`, and `conformance/fake_core.assert_hook_wire_shape`)

- **No `data.otel` blob** anywhere in hook spans. `to_core_span_data(include_otel_data=...)`
  keeps the parameter for compatibility, but it is a no-op.
- **No nested `{"otel","openbox"}` envelope**. `contracts/otel_spans.from_otel_span`
  returns flat Core `SpanData` directly, so `EventEnvelope.spans` is flat in
  memory and on the wire.
- **Common root fields always present** (null when absent): parent_span_id, kind,
  attributes (even `{}`), error — plus span_id/trace_id/name/stage/start_time/
  end_time/duration_ns/status/events/hook_type.
- **Family root fields always present** (null when absent) via
  `_ROOT_FIELDS_BY_HOOK_TYPE` `setdefault(None)`.
- **`semantic_type` never set by the SDK** — Core computes it.
- IDs hex strings; started stage → explicit `end_time: null`/`duration_ns: null`.

## Why

Temporal's still-correct payloads come from legacy flat hooks that emit no
`data` blob and always carry the full key set. The base SDK previously appended
`data.otel` to every hook span, omitted null-valued keys, and kept the
OTel/OpenBox split as an internal interface — a real divergence. Parity target =
Temporal's flat shape, so we drop `data`, flatten at span creation, and always
emit the keys.

## Verified

Go backend-compat harness (real Core struct + `DisallowUnknownFields`,
`tests/wire/test_backend_compat.py`) parses the flat spans; base suite 350 pass;
LangGraph conformance + full suite green (openbox_core is editable in its venv).

See [[arch-httpx-body-capture-send-patch]] for the httpx body-capture mechanism.
