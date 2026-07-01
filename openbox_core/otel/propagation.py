"""Cross-thread ContextVar propagation for run_in_executor threads.

Python < 3.12 does NOT copy ContextVars into default-executor threads: the
HTTP/DB instrumentors then create spans with trace_id=0 in the worker thread
and the hook runtime can't find the bound ActivityContext. Installing a
context-propagating executor fixes both. (Ported from the Temporal SDK's
context_propagation.py; live issue on Python 3.11, the pinned floor.)
"""

from __future__ import annotations

import concurrent.futures
import contextvars
import functools
import logging

logger = logging.getLogger(__name__)

__all__ = ["ContextPropagatingExecutor", "install_context_propagating_executor"]


class ContextPropagatingExecutor(concurrent.futures.ThreadPoolExecutor):
    """ThreadPoolExecutor that copies ContextVars into spawned threads."""

    def submit(self, fn, /, *args, **kwargs):
        ctx = contextvars.copy_context()
        return super().submit(ctx.run, functools.partial(fn, *args, **kwargs))


def install_context_propagating_executor(max_workers: int = 32) -> bool:
    """Install a ContextVar-propagating default executor on the running loop.

    Only the DEFAULT executor (``run_in_executor(None, ...)``) is patched;
    explicit user executors are untouched. Returns True when installed,
    False when no loop is running (callers may retry from async context).
    """
    import asyncio

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        logger.debug("No running event loop — executor patch skipped")
        return False
    loop.set_default_executor(ContextPropagatingExecutor(max_workers=max_workers))
    logger.info("Installed context-propagating default executor")
    return True
