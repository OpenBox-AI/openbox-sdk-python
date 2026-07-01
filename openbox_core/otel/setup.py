"""install_opentelemetry()/shutdown_opentelemetry() — OTel lifecycle."""

from __future__ import annotations

import logging
from typing import Any

from ..context import ContextStore
from .provider import get_or_create_tracer_provider
from .span_processor import OpenBoxSpanProcessor

logger = logging.getLogger(__name__)

__all__ = ["install_opentelemetry", "shutdown_opentelemetry"]


def install_opentelemetry(context_store: ContextStore) -> tuple[Any, OpenBoxSpanProcessor]:
    """Attach the passive OpenBox span processor to the process provider.

    Reuses an existing user provider; returns (provider, processor) so the
    caller can flush/detach on shutdown.
    """
    provider = get_or_create_tracer_provider()
    processor = OpenBoxSpanProcessor(context_store)
    provider.add_span_processor(processor)
    logger.info("Registered OpenBoxSpanProcessor with the TracerProvider")
    return provider, processor


def shutdown_opentelemetry(provider: Any) -> None:
    """Flush pending spans. The provider itself is left running — it may be
    user-owned; the SDK only ever ADDS a processor, so it only flushes."""
    try:
        provider.force_flush(timeout_millis=5000)
    except Exception:
        logger.debug("TracerProvider force_flush failed", exc_info=True)
