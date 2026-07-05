---
type: decision
date: 2026-07-03
tags: [instrumentation, coverage, redis, mongo, urllib, dbapi]
status: active
---

# Redis / MongoDB / urllib3 / urllib coverage (v0.2.0)

Added to reach parity with the legacy Temporal hook stack BEFORE Temporal flipped
to base-only instrumentation ("scope into base first" — no coverage loss).

## What landed (all under existing `db_enabled`/`http_enabled`, best-effort)

- **Redis** — OTel `RedisInstrumentor` request/response hooks → `DB_QUERY`.
- **pymongo** — dual mechanism (copied from legacy):
  - `monitoring.CommandListener` = TELEMETRY only (observe-only; a raised BLOCK is
    swallowed by pymongo, so it cannot enforce).
  - `wrapt` wrapper on 10 `Collection` methods = the BLOCKING path (raise propagates).
  - A thread-local depth counter suppresses the listener while a wrapt-governed method
    is on the stack so one op isn't governed twice.
- **urllib3 / urllib** — OTel instrumentor hooks. `requests` runs on urllib3 but OTel
  suppresses the nested urllib3 span, so a requests call does NOT double-fire.

## Key gotchas

- **pymongo address resolution triggers a connection.** `instance.database.client.address`
  runs server selection → do NOT call it before preflight (breaks block-before-connect
  and hangs with no server). Resolve the address only in the COMPLETED stage.
- **urllib3 `RequestInfo.url` is the FULL url** (the instrumentor resolves it) — use it
  directly; don't reconstruct from pool+path (double-prepends the netloc).
- **urllib3 completed body:** read only the already-buffered `response._body`
  (preload_content=True); never `.data`/`.text` (consumes a live stream).

## Rejected: raw dbapi driver instrumentors (psycopg2/mysql/pymysql/sqlite3)

Activating these makes SQLAlchemy's own dialect-init queries (version/PRAGMA on
connect) route through the CursorTracer and get governed → breaks the SQLAlchemy path
(the base's dominant DB coverage). A per-execute suppress flag doesn't cover the
dialect-init queries that run outside `before/after_cursor_execute`. So the base
governs SQLAlchemy (all backends) + asyncpg + redis + mongo; **direct raw-driver
queries used WITHOUT SQLAlchemy are not governed** — deferred follow-up.

`semantic_type` (e.g. `llm_completion`) stays Core-computed — see
[[decision-flat-hook-span-contract]].
