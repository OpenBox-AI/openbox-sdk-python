"""OpenBoxSpanProcessor — a PASSIVE SpanProcessor.

It registers trace -> ActivityContext correlations so hook code can resolve
the bound context from any child span, and nothing else. It MUST NOT perform
preflight blocking: ``on_end`` fires after the operation already ran, so hard
blocking lives exclusively in the wrapper call path (hooks/wrappers.py).
Abort/halt registries live in the ContextStore/runtime — not here.
"""

from __future__ import annotations

import logging
from typing import Any

from opentelemetry.sdk.trace import SpanProcessor

from ..context import ContextStore

logger = logging.getLogger(__name__)

__all__ = ["OpenBoxSpanProcessor"]


class OpenBoxSpanProcessor(SpanProcessor):
    """Passive correlation processor bound to a ContextStore."""

    def __init__(self, context_store: ContextStore):
        self._store = context_store

    def on_start(self, span: Any, parent_context: Any = None) -> None:
        """Register the span's trace to the CURRENTLY BOUND context (if any).

        Frameworks register the activity root trace explicitly via
        ``activity_scope``; this passive hook additionally catches spans whose
        traces were minted after binding. No bound context ⇒ no-op.
        """
        try:
            ctx = self._store.current_activity_context()
            if ctx is None:
                return
            span_context = span.get_span_context()
            trace_id = getattr(span_context, "trace_id", None)
            if isinstance(trace_id, int) and trace_id != 0:
                if self._store.context_for_trace(trace_id) is None:
                    self._store.register_trace(trace_id, ctx)
        except Exception:  # correlation must never break user spans
            logger.debug("OpenBoxSpanProcessor.on_start correlation failed", exc_info=True)

    def on_end(self, span: Any) -> None:
        """PASSIVE by contract — never evaluates, never blocks, never raises.

        ``on_end`` fires after the operation completed; a verdict here could
        not stop anything. Hard preflight blocking happens in the wrapper
        call path before the real operation.
        """
        return None

    def shutdown(self) -> None:
        return None

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True
