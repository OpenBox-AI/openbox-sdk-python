"""Function decorator instrumentation — @governed for sync and async callables.

Preflight runs before the wrapped function; a BLOCK/HALT means the function
body never executes. Fast path: no active hook runtime or no bound context ⇒
zero-governance passthrough.
"""

from __future__ import annotations

import functools
import inspect
import logging
from collections.abc import Callable
from typing import Any

from ..contracts.otel_spans import HookType
from ..hooks.wrappers import run_governed_async, run_governed_sync
from ..otel.provider import get_tracer
from ..serialization import to_json_safe
from .shared import get_hook_runtime

logger = logging.getLogger(__name__)

__all__ = ["governed"]


def _function_fields(func: Callable, args: tuple, kwargs: dict, capture_args: bool) -> dict:
    fields: dict[str, Any] = {
        "function": getattr(func, "__qualname__", getattr(func, "__name__", "function")),
        "module": getattr(func, "__module__", None),
    }
    if capture_args:
        try:
            fields["args"] = to_json_safe({"args": list(args), "kwargs": kwargs})
        except Exception:
            fields["args"] = None
    return fields


def governed(
    func: Callable | None = None,
    *,
    name: str | None = None,
    capture_args: bool = True,
    capture_result: bool = True,
):
    """Decorate a function with started/completed hook governance.

    Usage::

        @governed
        def charge(amount): ...

        @governed(name="billing.charge", capture_args=False)
        async def acharge(amount): ...
    """

    def decorate(target: Callable) -> Callable:
        span_name = name or getattr(target, "__qualname__", "function")

        if inspect.iscoroutinefunction(target):

            @functools.wraps(target)
            async def async_wrapper(*args, **kwargs):
                runtime = get_hook_runtime()
                if runtime is None:
                    return await target(*args, **kwargs)
                span = get_tracer().start_span(f"function {span_name}")
                started = _function_fields(target, args, kwargs, capture_args)
                try:
                    return await run_governed_async(
                        runtime,
                        target,
                        args,
                        kwargs,
                        span=span,
                        hook_type=HookType.FUNCTION_CALL,
                        identifier=span_name,
                        started_fields=started,
                        completed_fields=(
                            (lambda result: {"result": to_json_safe(result)})
                            if capture_result
                            else None
                        ),
                    )
                finally:
                    span.end()

            return async_wrapper

        @functools.wraps(target)
        def sync_wrapper(*args, **kwargs):
            runtime = get_hook_runtime()
            if runtime is None:
                return target(*args, **kwargs)
            span = get_tracer().start_span(f"function {span_name}")
            started = _function_fields(target, args, kwargs, capture_args)
            try:
                return run_governed_sync(
                    runtime,
                    target,
                    args,
                    kwargs,
                    span=span,
                    hook_type=HookType.FUNCTION_CALL,
                    identifier=span_name,
                    started_fields=started,
                    completed_fields=(
                        (lambda result: {"result": to_json_safe(result)})
                        if capture_result
                        else None
                    ),
                )
            finally:
                span.end()

        return sync_wrapper

    if func is not None:
        return decorate(func)
    return decorate
