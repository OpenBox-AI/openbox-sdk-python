"""Hook event assembly from the bound ActivityContext + serialized OTel span."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from ..context import ContextStore
from ..contracts.context import ActivityContext
from ..contracts.events import EventEnvelope, hook
from ..contracts.otel_spans import HookType, Stage, from_otel_span
from ..otel.trace_context import raw_trace_id

logger = logging.getLogger(__name__)

__all__ = ["resolve_context", "build_hook_event"]


def resolve_context(store: ContextStore, span: Any) -> ActivityContext | None:
    """Bound context via ContextVar first, trace-map fallback second.

    The trace-map path serves code running where ContextVars don't propagate
    (executor threads); both sides key by the canonical integer trace id.
    """
    ctx = store.current_activity_context()
    if ctx is not None:
        return ctx
    trace_id = raw_trace_id(span)
    if trace_id is not None and trace_id != 0:
        return store.context_for_trace(trace_id)
    return None


def build_hook_event(
    store: ContextStore,
    span: Any,
    *,
    stage: Stage,
    hook_type: HookType,
    fields: Mapping[str, Any] | None = None,
) -> EventEnvelope | None:
    """Build a hook EventEnvelope, or None when the hook must be SKIPPED.

    No bound ActivityContext (or a context without an activity binding) means
    this operation is not inside a governed activity — skipping is the
    CORRECT behavior, not an error.
    """
    ctx = resolve_context(store, span)
    if ctx is None:
        logger.debug("hook skipped: no bound ActivityContext for span")
        return None
    if not ctx.activity_id or not ctx.activity_type:
        logger.debug("hook skipped: bound context has no activity binding")
        return None
    envelope = from_otel_span(
        span, stage=stage, hook_type=hook_type, activity_context=None, fields=fields
    )
    return hook(
        activity_context=ctx.to_payload_fields(),
        activity_id=ctx.activity_id,
        activity_type=ctx.activity_type,
        spans=[envelope],
    )
