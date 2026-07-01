"""Shared around-operation driver: preflight -> real op -> completed.

Wrappers never interpret verdicts — a blocked preflight raises out of the
hook runtime/adapter before the real operation is invoked. Completed
telemetry always fires (success AND failure paths) with duration + error.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from typing import Any

from ..contracts.otel_spans import HookType
from .preflight import HookRuntime

__all__ = ["run_governed_sync", "run_governed_async"]


def _completed_fields(
    base: Mapping[str, Any] | None,
    extra: Mapping[str, Any] | None,
    duration_ms: float,
    error: str | None,
) -> dict[str, Any]:
    fields = dict(base or {})
    fields.update(extra or {})
    fields.setdefault("duration_ns", int(duration_ms * 1_000_000))
    if error is not None:
        fields["error"] = error
    return fields


def run_governed_sync(
    hook_runtime: HookRuntime,
    operation: Callable[..., Any],
    args: tuple,
    kwargs: dict,
    *,
    span: Any,
    hook_type: HookType,
    identifier: str = "",
    started_fields: Mapping[str, Any] | None = None,
    completed_fields: Callable[[Any], Mapping[str, Any] | None] | None = None,
) -> Any:
    """preflight -> operation -> completed (sync)."""
    hook_runtime.preflight(
        span, hook_type=hook_type, identifier=identifier, fields=started_fields
    )
    start = time.perf_counter()
    try:
        result = operation(*args, **kwargs)
    except Exception as exc:
        duration_ms = (time.perf_counter() - start) * 1000
        hook_runtime.completed(
            span,
            hook_type=hook_type,
            fields=_completed_fields(started_fields, None, duration_ms, str(exc)),
        )
        raise
    duration_ms = (time.perf_counter() - start) * 1000
    extra = completed_fields(result) if completed_fields else None
    hook_runtime.completed(
        span,
        hook_type=hook_type,
        fields=_completed_fields(started_fields, extra, duration_ms, None),
    )
    return result


async def run_governed_async(
    hook_runtime: HookRuntime,
    operation: Callable[..., Any],
    args: tuple,
    kwargs: dict,
    *,
    span: Any,
    hook_type: HookType,
    identifier: str = "",
    started_fields: Mapping[str, Any] | None = None,
    completed_fields: Callable[[Any], Mapping[str, Any] | None] | None = None,
) -> Any:
    """preflight -> operation -> completed (async)."""
    await hook_runtime.apreflight(
        span, hook_type=hook_type, identifier=identifier, fields=started_fields
    )
    start = time.perf_counter()
    try:
        result = await operation(*args, **kwargs)
    except Exception as exc:
        duration_ms = (time.perf_counter() - start) * 1000
        await hook_runtime.acompleted(
            span,
            hook_type=hook_type,
            fields=_completed_fields(started_fields, None, duration_ms, str(exc)),
        )
        raise
    duration_ms = (time.perf_counter() - start) * 1000
    extra = completed_fields(result) if completed_fields else None
    await hook_runtime.acompleted(
        span,
        hook_type=hook_type,
        fields=_completed_fields(started_fields, extra, duration_ms, None),
    )
    return result
