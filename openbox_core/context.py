"""ContextStore — contextvars bind/reset plus canonical trace-key correlation.

Two complementary lookup paths (both required):

1. ``ContextVar`` — the bound context for the current async task/thread flow.
2. trace→context map — hook code running where ContextVars don't propagate
   (e.g. ``run_in_executor`` worker threads on Python 3.11) resolves the
   context by OTel trace id instead.

Trace-key invariant: registration and lookup BOTH go through
``canonical_trace_key()`` — the raw OTel ``SpanContext.trace_id`` integer.
The 32-hex ``trace_id`` string is a WIRE-ONLY representation; accepting one
here converts it to the canonical integer so both sides always agree.

Leak safety: callers MUST wrap bind/reset in try/finally (use
``activity_scope``); ``unregister_trace`` runs on activity completion and
``clear()`` on runtime close so long-lived workers never grow the map
unbounded or serve stale correlations.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token

from .contracts.context import ActivityContext

__all__ = [
    "canonical_trace_key",
    "ContextStore",
    "default_context_store",
    "bind_activity_context",
    "reset_activity_context",
    "current_activity_context",
    "register_trace",
    "context_for_trace",
    "unregister_trace",
    "activity_scope",
]


def canonical_trace_key(trace_id: int | str) -> int:
    """Normalize any accepted trace-id representation to the canonical key.

    The canonical key is the raw OTel ``SpanContext.trace_id`` INTEGER. Hex
    strings convert through here so the wire representation can never end up
    on only one side of a lookup.
    """
    if isinstance(trace_id, bool):  # bool is an int subclass — reject explicitly
        raise TypeError("trace_id must be an int or hex string, got bool")
    if isinstance(trace_id, int):
        return trace_id
    if isinstance(trace_id, str):
        try:
            return int(trace_id, 16)
        except ValueError:
            raise ValueError(f"trace_id string is not hex: {trace_id!r}") from None
    raise TypeError(f"trace_id must be an int or hex string, got {type(trace_id).__name__}")


class ContextStore:
    """Thread-safe context binding + trace correlation + governance flags."""

    def __init__(self) -> None:
        self._current: ContextVar[ActivityContext | None] = ContextVar(
            "openbox_activity_context", default=None
        )
        self._lock = threading.Lock()
        self._trace_to_context: dict[int, ActivityContext] = {}
        # Governance flags read by the hook runtime (set via adapter/runtime):
        self._aborted_activities: set[str] = set()
        self._halt_requested = False

    # ── ContextVar binding ────────────────────────────────────────────────

    def bind(self, ctx: ActivityContext) -> Token:
        """Bind ``ctx`` to the current flow. Pair with :meth:`reset` in a
        try/finally — or use :func:`activity_scope`."""
        return self._current.set(ctx)

    def reset(self, token: Token) -> None:
        """Restore the previous binding (call in ``finally``)."""
        self._current.reset(token)

    def current_activity_context(self) -> ActivityContext | None:
        return self._current.get()

    # ── Trace correlation map ─────────────────────────────────────────────

    def register_trace(self, trace_id: int | str, ctx: ActivityContext) -> None:
        key = canonical_trace_key(trace_id)
        with self._lock:
            self._trace_to_context[key] = ctx

    def context_for_trace(self, trace_id: int | str) -> ActivityContext | None:
        key = canonical_trace_key(trace_id)
        with self._lock:
            return self._trace_to_context.get(key)

    def unregister_trace(self, trace_id: int | str) -> None:
        """Mandatory cleanup on activity completion/session end."""
        key = canonical_trace_key(trace_id)
        with self._lock:
            self._trace_to_context.pop(key, None)

    def trace_map_size(self) -> int:
        """Observability/leak-test helper."""
        with self._lock:
            return len(self._trace_to_context)

    # ── Governance flags (abort short-circuit, halt) ──────────────────────

    @staticmethod
    def activity_key(workflow_id: str | None, activity_id: str | None) -> str:
        return f"{workflow_id}:{activity_id}"

    def mark_activity_aborted(self, workflow_id: str | None, activity_id: str | None) -> None:
        with self._lock:
            self._aborted_activities.add(self.activity_key(workflow_id, activity_id))

    def is_activity_aborted(self, workflow_id: str | None, activity_id: str | None) -> bool:
        with self._lock:
            return self.activity_key(workflow_id, activity_id) in self._aborted_activities

    def clear_activity_aborted(self, workflow_id: str | None, activity_id: str | None) -> None:
        with self._lock:
            self._aborted_activities.discard(self.activity_key(workflow_id, activity_id))

    def request_halt(self) -> None:
        with self._lock:
            self._halt_requested = True

    @property
    def halt_requested(self) -> bool:
        with self._lock:
            return self._halt_requested

    # ── Shutdown ──────────────────────────────────────────────────────────

    def clear(self) -> None:
        """Drop ALL correlation state and flags (runtime close)."""
        with self._lock:
            self._trace_to_context.clear()
            self._aborted_activities.clear()
            self._halt_requested = False


# Default process-wide store: instrumentation resolves context here unless a
# runtime injects its own store.
_default_store = ContextStore()


def default_context_store() -> ContextStore:
    return _default_store


def bind_activity_context(ctx: ActivityContext) -> Token:
    return _default_store.bind(ctx)


def reset_activity_context(token: Token) -> None:
    _default_store.reset(token)


def current_activity_context() -> ActivityContext | None:
    return _default_store.current_activity_context()


def register_trace(trace_id: int | str, ctx: ActivityContext) -> None:
    _default_store.register_trace(trace_id, ctx)


def context_for_trace(trace_id: int | str) -> ActivityContext | None:
    return _default_store.context_for_trace(trace_id)


def unregister_trace(trace_id: int | str) -> None:
    _default_store.unregister_trace(trace_id)


@contextmanager
def activity_scope(
    ctx: ActivityContext,
    *,
    trace_id: int | str | None = None,
    store: ContextStore | None = None,
) -> Iterator[ActivityContext]:
    """Bind a context (and optional trace registration) with GUARANTEED reset.

    Reset and trace cleanup run even when the framework operation raises.
    """
    target = store if store is not None else _default_store
    token = target.bind(ctx)
    try:
        # Inside the try: a bad trace_id (e.g. non-hex string) must not leak
        # the ContextVar binding this helper promises to reset.
        if trace_id is not None:
            target.register_trace(trace_id, ctx)
        yield ctx
    finally:
        target.reset(token)
        if trace_id is not None:
            target.unregister_trace(trace_id)
