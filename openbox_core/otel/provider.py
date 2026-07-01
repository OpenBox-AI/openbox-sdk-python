"""Create-or-reuse TracerProvider — never clobber a user-installed provider."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

__all__ = ["get_or_create_tracer_provider", "get_tracer"]


def get_or_create_tracer_provider() -> Any:
    """Return the process TracerProvider, creating one only if none exists.

    Attaches to an existing SDK provider (user-installed providers are
    reused, never replaced); only the no-op default is upgraded to a real
    ``opentelemetry.sdk.trace.TracerProvider``.
    """
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider

    provider = trace.get_tracer_provider()
    if not isinstance(provider, TracerProvider):
        provider = TracerProvider()
        trace.set_tracer_provider(provider)
        logger.info("Created OpenBox TracerProvider (no SDK provider was set)")
    return provider


def get_tracer(name: str = "openbox_core") -> Any:
    """Tracer for spans the SDK creates itself (db/file/function wrappers)."""
    from opentelemetry import trace

    return trace.get_tracer(name)
