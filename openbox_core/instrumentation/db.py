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


def _db_fields(
    statement: str | None,
    system: str,
    operation: str | None = None,
    *,
    db_name: str | None = None,
    server_address: str | None = None,
    server_port: int | None = None,
) -> dict:
    """Assemble DB wire root fields. ``db_name``/``server_address``/
    ``server_port`` are populated per driver so the flat SpanData carries the
    same connection metadata the Temporal legacy hooks emit (null when a driver
    does not expose them; the projection keeps the keys present regardless)."""
    op = operation
    if op is None and statement:
        op = statement.strip().split(" ", 1)[0].upper() if statement.strip() else None
    port = server_port
    if port is not None:
        try:
            port = int(port)
        except (TypeError, ValueError):
            port = None
    return {
        "db_system": system,
        "db_name": str(db_name) if db_name else None,
        "db_operation": op,
        "db_statement": statement,
        "server_address": server_address,
        "server_port": port,
    }


def _sqlalchemy_conn_meta(conn: Any) -> tuple[str, str | None, str | None, int | None]:
    """(dialect, db_name, host, port) from a SQLAlchemy Connection."""
    engine = getattr(conn, "engine", None)
    url = getattr(engine, "url", None)
    dialect = getattr(getattr(conn, "dialect", None), "name", "sql") or "sql"
    return (
        dialect,
        getattr(url, "database", None),
        getattr(url, "host", None),
        getattr(url, "port", None),
    )


def _dbapi_conn_meta(tracer_self: Any) -> tuple[str, str | None, str | None, int | None]:
    """(db_system, db_name, host, port) from an OTel dbapi CursorTracer."""
    integ = getattr(tracer_self, "_db_api_integration", None)
    system = getattr(integ, "database_system", "sql") if integ else "sql"
    db_name = getattr(integ, "database", None) if integ else None
    props = getattr(integ, "connection_props", None) if integ else None
    host = props.get("host") if isinstance(props, dict) else None
    port = props.get("port") if isinstance(props, dict) else None
    return system or "sql", db_name, host, port


def _asyncpg_conn_meta(conn_self: Any) -> tuple[str | None, str | None, int | None]:
    """(db_name, host, port) from an asyncpg Connection."""
    addr = getattr(conn_self, "_addr", None)
    host = addr[0] if isinstance(addr, (tuple, list)) and len(addr) >= 1 else None
    port = addr[1] if isinstance(addr, (tuple, list)) and len(addr) >= 2 else None
    params = getattr(conn_self, "_params", None)
    db_name = getattr(params, "database", None) if params is not None else None
    return db_name, host, port


# ── SQLAlchemy (event listeners — no monkeypatching) ────────────────────────

_sqlalchemy_installed = False


def _before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    runtime = get_hook_runtime()
    if runtime is None:
        return
    span = get_tracer().start_span(f"db {statement.strip().split(' ', 1)[0].lower()}")
    if context is not None:
        setattr(context, _SPAN_KEY, span)
    dialect, db_name, host, port = _sqlalchemy_conn_meta(conn)
    # Raising here (BLOCK/HALT via adapter) aborts execution — the statement
    # never reaches cursor.execute.
    runtime.preflight(
        span,
        hook_type=HookType.DB_QUERY,
        identifier=statement or "",
        fields=_db_fields(
            statement, dialect, db_name=db_name, server_address=host, server_port=port
        ),
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
        dialect, db_name, host, port = _sqlalchemy_conn_meta(conn)
        span.end()
        runtime.completed(
            span,
            hook_type=HookType.DB_QUERY,
            fields={
                **_db_fields(
                    statement, dialect, db_name=db_name, server_address=host, server_port=port
                ),
                "rowcount": rowcount,
            },
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
        engine = getattr(exception_context, "engine", None)
        url = getattr(engine, "url", None)
        dialect = getattr(getattr(engine, "dialect", None), "name", "sql") or "sql"
        runtime.completed(
            span,
            hook_type=HookType.DB_QUERY,
            fields={
                **_db_fields(
                    statement,
                    dialect,
                    db_name=getattr(url, "database", None),
                    server_address=getattr(url, "host", None),
                    server_port=getattr(url, "port", None),
                ),
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
        system_name, db_name, host, port = _dbapi_conn_meta(tracer_self)
        span = get_tracer().start_span("db query")

        def _fields() -> dict:
            return _db_fields(
                str(statement),
                system_name,
                db_name=db_name,
                server_address=host,
                server_port=port,
            )

        runtime.preflight(
            span,
            hook_type=HookType.DB_QUERY,
            identifier=str(statement),
            fields=_fields(),
        )
        try:
            result = _original_traced_execution(tracer_self, cursor, query_method, *args, **kwargs)
        except Exception as exc:
            span.end()
            runtime.completed(
                span,
                hook_type=HookType.DB_QUERY,
                fields={**_fields(), "error": str(exc)},
            )
            raise
        span.end()
        runtime.completed(
            span,
            hook_type=HookType.DB_QUERY,
            fields={**_fields(), "rowcount": getattr(cursor, "rowcount", None)},
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
        db_name, host, port = _asyncpg_conn_meta(conn_self)
        span = get_tracer().start_span("db query")

        def _fields() -> dict:
            return _db_fields(
                str(query),
                "postgresql",
                db_name=db_name,
                server_address=host,
                server_port=port,
            )

        await runtime.apreflight(
            span,
            hook_type=HookType.DB_QUERY,
            identifier=str(query),
            fields=_fields(),
        )
        try:
            result = await _original_asyncpg_execute(conn_self, query, *args, **kwargs)
        except Exception as exc:
            span.end()
            await runtime.acompleted(
                span,
                hook_type=HookType.DB_QUERY,
                fields={**_fields(), "error": str(exc)},
            )
            raise
        span.end()
        await runtime.acompleted(
            span,
            hook_type=HookType.DB_QUERY,
            fields=_fields(),
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
