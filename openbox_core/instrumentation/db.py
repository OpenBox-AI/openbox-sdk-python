"""DB wrappers — SQLAlchemy, DB-API (via OTel dbapi CursorTracer), asyncpg.

v1 targets (per the roadmap): SQLAlchemy + DB-API + asyncpg.
Redis / Mongo / aiohttp are DEFERRED to a later scoped release.

Blocking semantics: the started preflight runs BEFORE the driver executes the
statement; a BLOCK/HALT raises out of the listener/patch so the query never
reaches the database.
"""

from __future__ import annotations

import logging
import threading
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
    "install_redis",
    "uninstall_redis",
    "install_pymongo",
    "uninstall_pymongo",
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


# ── redis (OTel RedisInstrumentor request/response hooks) ────────────────────

_redis_installed = False
# span_id -> (command, statement) stashed at request so the response hook (which
# receives only span+response) can carry the same operation into completed.
_redis_pending: dict[int, tuple[str, str]] = {}
_REDIS_PENDING_MAX = 4096


def _span_id_of(span: Any) -> int | None:
    try:
        return span.get_span_context().span_id
    except Exception:
        return None


def _redis_conn_meta(instance: Any) -> tuple[str | None, int | None, str | None]:
    """(host, port, db_name) from a redis client's connection pool."""
    try:
        kwargs = instance.connection_pool.connection_kwargs
        return kwargs.get("host", "localhost"), kwargs.get("port", 6379), str(kwargs.get("db", 0))
    except AttributeError:
        return "localhost", 6379, "0"


def _redis_request_hook(span: Any, instance: Any, args: Any, kwargs: Any) -> None:
    runtime = get_hook_runtime()
    if runtime is None:
        return
    command = str(args[0]) if args else "UNKNOWN"
    statement = " ".join(str(a) for a in args) if args else ""
    host, port, db_name = _redis_conn_meta(instance)
    span_id = _span_id_of(span)
    if span_id is not None:
        if len(_redis_pending) >= _REDIS_PENDING_MAX:
            _redis_pending.clear()
        _redis_pending[span_id] = (command, statement)
    # Raising (BLOCK/HALT via adapter) aborts before the command reaches redis.
    runtime.preflight(
        span,
        hook_type=HookType.DB_QUERY,
        identifier=statement or command,
        fields=_db_fields(
            statement, "redis", operation=command,
            db_name=db_name, server_address=host, server_port=port,
        ),
    )


def _redis_response_hook(span: Any, instance: Any, response: Any) -> None:
    runtime = get_hook_runtime()
    if runtime is None:
        return
    host, port, db_name = _redis_conn_meta(instance)
    span_id = _span_id_of(span)
    command, statement = (
        _redis_pending.pop(span_id, ("UNKNOWN", "")) if span_id is not None else ("UNKNOWN", "")
    )
    runtime.completed(
        span,
        hook_type=HookType.DB_QUERY,
        fields=_db_fields(
            statement, "redis", operation=command,
            db_name=db_name, server_address=host, server_port=port,
        ),
    )


def install_redis() -> bool:
    global _redis_installed
    if _redis_installed:
        return True
    try:
        from opentelemetry.instrumentation.redis import RedisInstrumentor
    except ImportError:
        logger.info("redis instrumentation not available (install extra [db]) — deferred")
        return False
    RedisInstrumentor().instrument(
        request_hook=_redis_request_hook, response_hook=_redis_response_hook
    )
    _redis_installed = True
    return True


def uninstall_redis() -> None:
    global _redis_installed
    if not _redis_installed:
        return
    try:
        from opentelemetry.instrumentation.redis import RedisInstrumentor

        RedisInstrumentor().uninstrument()
    except Exception:
        logger.debug("redis uninstrument skipped", exc_info=True)
    _redis_pending.clear()
    _redis_installed = False


# ── pymongo (CommandListener telemetry + wrapt Collection blocking) ──────────
#
# pymongo monitoring listeners are OBSERVE-ONLY — raising from them cannot stop
# a command. Blocking therefore rides on a wrapt wrapper around Collection CRUD
# methods (a Python-level wrapper whose raise propagates to the caller), while
# the CommandListener supplies telemetry for every OTHER command. A thread-local
# depth counter suppresses the listener while a wrapt-governed method is on the
# stack so one logical operation is never evaluated twice. The listener cannot
# be unregistered (pymongo has no public API); after uninstall it goes dormant
# because ``get_hook_runtime()`` returns None.

_pymongo_listener: Any = None
_pymongo_wrapt_installed = False
_pymongo_wrapt_depth = threading.local()
# request_id -> (span, command string) correlating started with succeeded/failed.
_pymongo_pending: dict[int, tuple[Any, str]] = {}
_PYMONGO_PENDING_MAX = 4096
_pymongo_patched: list[tuple[str, str]] = []

_PYMONGO_METHODS = (
    "find", "find_one", "insert_one", "insert_many",
    "update_one", "update_many", "delete_one", "delete_many",
    "aggregate", "count_documents",
)


def _pymongo_address(event: Any) -> tuple[str | None, int | None]:
    try:
        addr = event.connection_id
        if addr and len(addr) >= 2:
            return str(addr[0]), int(addr[1])
    except (AttributeError, TypeError, IndexError):
        pass
    return None, 27017


def _pymongo_collection_address(instance: Any) -> tuple[str | None, int | None]:
    # ``client.address`` triggers pymongo server selection (a live connection).
    # Catch broadly (incl. ServerSelectionTimeoutError) so metadata resolution
    # never blocks or crashes governance — call only AFTER an op has run, when
    # the address is already cached.
    try:
        address = instance.database.client.address
        if address:
            return address[0], int(address[1])
    except Exception:
        pass
    return None, 27017


def install_pymongo() -> bool:
    global _pymongo_listener
    installed = False
    if _pymongo_listener is None:
        try:
            import pymongo.monitoring

            class _GovernanceCommandListener(pymongo.monitoring.CommandListener):
                def started(self, event: Any) -> None:
                    if getattr(_pymongo_wrapt_depth, "value", 0) > 0:
                        return
                    runtime = get_hook_runtime()
                    if runtime is None:
                        return
                    try:
                        span = get_tracer().start_span(f"mongodb {event.command_name}")
                        host, port = _pymongo_address(event)
                        cmd_str = str(event.command)[:2000]
                        if len(_pymongo_pending) >= _PYMONGO_PENDING_MAX:
                            _pymongo_pending.clear()
                        _pymongo_pending[event.request_id] = (span, cmd_str)
                        # A BLOCK sets the abort flag (future ops) before raising;
                        # the listener cannot stop THIS command, so swallow so the
                        # pymongo monitoring loop is never crashed.
                        runtime.preflight(
                            span,
                            hook_type=HookType.DB_QUERY,
                            identifier=cmd_str,
                            fields=_db_fields(
                                cmd_str, "mongodb", operation=event.command_name,
                                db_name=event.database_name, server_address=host, server_port=port,
                            ),
                        )
                    except Exception:
                        logger.debug("pymongo started governance error", exc_info=True)

                def succeeded(self, event: Any) -> None:
                    self._completed(event)

                def failed(self, event: Any) -> None:
                    self._completed(event, error=str(getattr(event, "failure", "error")))

                def _completed(self, event: Any, error: str | None = None) -> None:
                    if getattr(_pymongo_wrapt_depth, "value", 0) > 0:
                        _pymongo_pending.pop(event.request_id, None)
                        return
                    runtime = get_hook_runtime()
                    span, cmd_str = _pymongo_pending.pop(
                        event.request_id, (None, event.command_name)
                    )
                    if runtime is None:
                        return
                    if span is None:
                        span = get_tracer().start_span(f"mongodb {event.command_name}")
                    host, port = _pymongo_address(event)
                    try:
                        span.end()
                    except Exception:
                        pass
                    fields = _db_fields(
                        cmd_str, "mongodb", operation=event.command_name,
                        db_name=event.database_name, server_address=host, server_port=port,
                    )
                    if error:
                        fields["error"] = error
                    runtime.completed(span, hook_type=HookType.DB_QUERY, fields=fields)

            _pymongo_listener = _GovernanceCommandListener()
            pymongo.monitoring.register(_pymongo_listener)
            installed = True
        except ImportError:
            logger.info("pymongo not available (install extra [db]) — deferred")
    else:
        installed = True

    if _install_pymongo_wrapt():
        installed = True
    return installed


def _install_pymongo_wrapt() -> bool:
    global _pymongo_wrapt_installed
    if _pymongo_wrapt_installed:
        return True
    try:
        import wrapt
    except ImportError:
        logger.debug("wrapt not available — pymongo blocking disabled")
        return False

    def _collection_wrapper(wrapped, instance, args, kwargs):
        depth = getattr(_pymongo_wrapt_depth, "value", 0)
        _pymongo_wrapt_depth.value = depth + 1
        try:
            if depth > 0:
                return wrapped(*args, **kwargs)
            runtime = get_hook_runtime()
            if runtime is None:
                return wrapped(*args, **kwargs)
            db_name = getattr(getattr(instance, "database", None), "name", None)
            operation = getattr(wrapped, "__name__", "query")
            statement = f"{getattr(instance, 'name', '?')}.{operation}"
            span = get_tracer().start_span(f"mongodb {operation}")

            def _fields(host: Any = None, port: Any = None) -> dict:
                return _db_fields(
                    statement, "mongodb", operation=operation,
                    db_name=db_name, server_address=host, server_port=port,
                )

            # Preflight WITHOUT resolving the server address — doing so would
            # trigger a connection and defeat block-before-connect. A BLOCK here
            # raises before the driver runs (and connects).
            runtime.preflight(
                span, hook_type=HookType.DB_QUERY, identifier=statement, fields=_fields()
            )
            try:
                result = wrapped(*args, **kwargs)
            except Exception as exc:
                span.end()
                runtime.completed(
                    span, hook_type=HookType.DB_QUERY, fields={**_fields(), "error": str(exc)}
                )
                raise
            span.end()
            # Address is cached now the op has run — safe to resolve for telemetry.
            host, port = _pymongo_collection_address(instance)
            runtime.completed(span, hook_type=HookType.DB_QUERY, fields=_fields(host, port))
            return result
        finally:
            _pymongo_wrapt_depth.value = getattr(_pymongo_wrapt_depth, "value", 1) - 1

    patched = 0
    for method in _PYMONGO_METHODS:
        try:
            wrapt.wrap_function_wrapper(
                "pymongo.collection", f"Collection.{method}", _collection_wrapper
            )
            _pymongo_patched.append(("pymongo.collection", f"Collection.{method}"))
            patched += 1
        except (AttributeError, TypeError, ImportError):
            pass
    _pymongo_wrapt_installed = patched > 0
    return _pymongo_wrapt_installed


def uninstall_pymongo() -> None:
    """Remove wrapt Collection patches and clear pending state. The monitoring
    listener stays registered (no pymongo deregister API) but goes dormant once
    the hook runtime is cleared."""
    global _pymongo_wrapt_installed
    import importlib

    for module, name in _pymongo_patched:
        try:
            mod = importlib.import_module(module)
            cls_name, meth = name.split(".")
            cls = getattr(mod, cls_name)
            bound = getattr(cls, meth)
            original = getattr(bound, "__wrapped__", None)
            if original is not None:
                setattr(cls, meth, original)
        except Exception:
            logger.debug("pymongo wrapt removal skipped", exc_info=True)
    _pymongo_patched.clear()
    _pymongo_pending.clear()
    _pymongo_wrapt_installed = False
