"""DB wrappers — SQLAlchemy, DB-API (via OTel dbapi CursorTracer), asyncpg.

v1 targets (per the roadmap): SQLAlchemy + DB-API + asyncpg.
Redis / Mongo / aiohttp are DEFERRED to a later scoped release.

Blocking semantics: the started preflight runs BEFORE the driver executes the
statement; a BLOCK/HALT raises out of the listener/patch so the query never
reaches the database.
"""

from __future__ import annotations

import logging
from typing import Any

from ..contracts.otel_spans import HookType
from ..otel.provider import get_tracer
from .shared import get_hook_runtime

logger = logging.getLogger(__name__)

__all__ = [
    "install_sqlalchemy",
    "uninstall_sqlalchemy",
    "install_dbapi",
    "uninstall_dbapi",
    "install_asyncpg",
    "uninstall_asyncpg",
]

_SPAN_KEY = "_openbox_db_span"


def _db_fields(statement: str | None, system: str, operation: str | None = None) -> dict:
    op = operation
    if op is None and statement:
        op = statement.strip().split(" ", 1)[0].upper() if statement.strip() else None
    return {"db_system": system, "db_statement": statement, "db_operation": op}


# ── SQLAlchemy (event listeners — no monkeypatching) ────────────────────────

_sqlalchemy_installed = False


def _before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    runtime = get_hook_runtime()
    if runtime is None:
        return
    span = get_tracer().start_span(f"db {statement.strip().split(' ', 1)[0].lower()}")
    if context is not None:
        setattr(context, _SPAN_KEY, span)
    dialect = getattr(getattr(conn, "dialect", None), "name", "sql")
    # Raising here (BLOCK/HALT via adapter) aborts execution — the statement
    # never reaches cursor.execute.
    runtime.preflight(
        span,
        hook_type=HookType.DB_QUERY,
        identifier=statement or "",
        fields=_db_fields(statement, dialect),
    )


def _after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    runtime = get_hook_runtime()
    if runtime is None:
        return
    span = getattr(context, _SPAN_KEY, None) if context is not None else None
    if span is None:
        return
    try:
        rowcount = getattr(cursor, "rowcount", None)
        dialect = getattr(getattr(conn, "dialect", None), "name", "sql")
        span.end()
        runtime.completed(
            span,
            hook_type=HookType.DB_QUERY,
            fields={**_db_fields(statement, dialect), "rowcount": rowcount},
        )
    finally:
        if context is not None and hasattr(context, _SPAN_KEY):
            delattr(context, _SPAN_KEY)


def _handle_error(exception_context) -> None:
    runtime = get_hook_runtime()
    if runtime is None:
        return
    context = getattr(exception_context, "execution_context", None)
    span = getattr(context, _SPAN_KEY, None) if context is not None else None
    if span is None:
        return
    try:
        span.end()
        statement = getattr(exception_context, "statement", None)
        runtime.completed(
            span,
            hook_type=HookType.DB_QUERY,
            fields={
                **_db_fields(statement, "sql"),
                "error": str(getattr(exception_context, "original_exception", "error")),
            },
        )
    finally:
        if context is not None and hasattr(context, _SPAN_KEY):
            delattr(context, _SPAN_KEY)


def install_sqlalchemy() -> bool:
    global _sqlalchemy_installed
    if _sqlalchemy_installed:
        return True
    try:
        from sqlalchemy import event
        from sqlalchemy.engine import Engine
    except ImportError:
        logger.info("sqlalchemy not available (install extra [db]) — deferred")
        return False
    event.listen(Engine, "before_cursor_execute", _before_cursor_execute)
    event.listen(Engine, "after_cursor_execute", _after_cursor_execute)
    event.listen(Engine, "handle_error", _handle_error)
    _sqlalchemy_installed = True
    return True


def uninstall_sqlalchemy() -> None:
    global _sqlalchemy_installed
    if not _sqlalchemy_installed:
        return
    try:
        from sqlalchemy import event
        from sqlalchemy.engine import Engine

        event.remove(Engine, "before_cursor_execute", _before_cursor_execute)
        event.remove(Engine, "after_cursor_execute", _after_cursor_execute)
        event.remove(Engine, "handle_error", _handle_error)
    except Exception:
        logger.debug("sqlalchemy listener removal skipped", exc_info=True)
    _sqlalchemy_installed = False


# ── DB-API (OTel dbapi CursorTracer — governs psycopg2/mysql/sqlite3) ───────

_original_traced_execution: Any = None


def install_dbapi() -> bool:
    """Patch CursorTracer.traced_execution so OTel-instrumented DB-API drivers
    run through governance. Patch ordering: apply AFTER the OTel dbapi
    instrumentors are set up (the manager guarantees this)."""
    global _original_traced_execution
    if _original_traced_execution is not None:
        return True
    try:
        from opentelemetry.instrumentation import dbapi
    except ImportError:
        logger.info("opentelemetry dbapi instrumentation not available — deferred")
        return False

    _original_traced_execution = dbapi.CursorTracer.traced_execution

    def governed_traced_execution(tracer_self, cursor, query_method, *args, **kwargs):
        runtime = get_hook_runtime()
        if runtime is None:
            return _original_traced_execution(tracer_self, cursor, query_method, *args, **kwargs)
        statement = tracer_self.get_statement(cursor, args) if args else ""
        system = getattr(tracer_self, "_db_api_integration", None)
        system_name = getattr(system, "database_system", "sql") if system else "sql"
        span = get_tracer().start_span("db query")
        runtime.preflight(
            span,
            hook_type=HookType.DB_QUERY,
            identifier=str(statement),
            fields=_db_fields(str(statement), system_name),
        )
        try:
            result = _original_traced_execution(tracer_self, cursor, query_method, *args, **kwargs)
        except Exception as exc:
            span.end()
            runtime.completed(
                span,
                hook_type=HookType.DB_QUERY,
                fields={**_db_fields(str(statement), system_name), "error": str(exc)},
            )
            raise
        span.end()
        runtime.completed(
            span,
            hook_type=HookType.DB_QUERY,
            fields={
                **_db_fields(str(statement), system_name),
                "rowcount": getattr(cursor, "rowcount", None),
            },
        )
        return result

    dbapi.CursorTracer.traced_execution = governed_traced_execution
    return True


def uninstall_dbapi() -> None:
    global _original_traced_execution
    if _original_traced_execution is None:
        return
    try:
        from opentelemetry.instrumentation import dbapi

        dbapi.CursorTracer.traced_execution = _original_traced_execution
    except Exception:
        logger.debug("dbapi restore skipped", exc_info=True)
    _original_traced_execution = None


# ── asyncpg ──────────────────────────────────────────────────────────────────

_original_asyncpg_execute: Any = None


def install_asyncpg() -> bool:
    """Patch asyncpg.Connection._execute — the funnel every fetch/execute
    variant goes through."""
    global _original_asyncpg_execute
    if _original_asyncpg_execute is not None:
        return True
    try:
        from asyncpg import Connection
    except ImportError:
        logger.info("asyncpg not available (install extra [db]) — deferred")
        return False

    _original_asyncpg_execute = Connection._execute

    async def governed_execute(conn_self, query, *args, **kwargs):
        runtime = get_hook_runtime()
        if runtime is None:
            return await _original_asyncpg_execute(conn_self, query, *args, **kwargs)
        span = get_tracer().start_span("db query")
        await runtime.apreflight(
            span,
            hook_type=HookType.DB_QUERY,
            identifier=str(query),
            fields=_db_fields(str(query), "postgresql"),
        )
        try:
            result = await _original_asyncpg_execute(conn_self, query, *args, **kwargs)
        except Exception as exc:
            span.end()
            await runtime.acompleted(
                span,
                hook_type=HookType.DB_QUERY,
                fields={**_db_fields(str(query), "postgresql"), "error": str(exc)},
            )
            raise
        span.end()
        await runtime.acompleted(
            span,
            hook_type=HookType.DB_QUERY,
            fields=_db_fields(str(query), "postgresql"),
        )
        return result

    Connection._execute = governed_execute
    return True


def uninstall_asyncpg() -> None:
    global _original_asyncpg_execute
    if _original_asyncpg_execute is None:
        return
    try:
        from asyncpg import Connection

        Connection._execute = _original_asyncpg_execute
    except Exception:
        logger.debug("asyncpg restore skipped", exc_info=True)
    _original_asyncpg_execute = None
