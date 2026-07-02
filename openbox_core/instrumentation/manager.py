"""InstrumentationManager — idempotent install/uninstall of all wrappers.

Owned by OpenBoxRuntime. Install order matters:

1. OTel provider + passive span processor (``install_opentelemetry`` toggle)
2. cross-thread ContextVar executor patch (best-effort; needs a running loop)
3. publish the HookRuntime to the shared instrumentation state
4. HTTP / DB / file wrappers per config toggles (each deferral is LOGGED)

The evaluate call must never instrument itself: the ignored-URL set always
contains the configured ``api_url``.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from ..otel.propagation import install_context_propagating_executor
from ..otel.setup import install_opentelemetry, shutdown_opentelemetry
from . import db as db_instrumentation
from . import file as file_instrumentation
from . import http as http_instrumentation
from .shared import get_hook_runtime, set_hook_runtime

if TYPE_CHECKING:
    from ..runtime import OpenBoxRuntime

logger = logging.getLogger(__name__)

__all__ = ["InstrumentationManager"]


class InstrumentationManager:
    """Install/uninstall lifecycle with per-target guard flags."""

    def __init__(self, runtime: OpenBoxRuntime, *, extra_ignored_urls: set[str] | None = None):
        self._runtime = runtime
        self._installed = False
        self._provider: Any = None
        self._installed_targets: list[str] = []
        self._extra_ignored_urls = set(extra_ignored_urls or ())

    @property
    def installed_targets(self) -> list[str]:
        return list(self._installed_targets)

    def install(self) -> None:
        """Idempotent — a second install() is a no-op."""
        if self._installed:
            return
        config = self._runtime.config
        instrumentation = config.instrumentation

        if instrumentation.install_opentelemetry:
            self._provider, _ = install_opentelemetry(self._runtime.context_store)

        # ContextVars → executor threads (no running loop ⇒ skipped, logged).
        if not install_context_propagating_executor():
            logger.info("executor ContextVar patch deferred (no running event loop)")

        # Self-instrumentation guard: never govern our own evaluate calls.
        http_instrumentation.set_ignored_url_prefixes(
            {config.api_url, *self._extra_ignored_urls}
        )

        from ..hooks.preflight import HookRuntime

        set_hook_runtime(HookRuntime(self._runtime))

        if instrumentation.http_enabled:
            if http_instrumentation.install_requests():
                self._installed_targets.append("requests")
            if http_instrumentation.install_httpx():
                self._installed_targets.append("httpx")
                # Body capture patches Client.send AFTER OTel instrumentation so
                # the captured original send already carries the request hook.
                if http_instrumentation.install_httpx_body_capture():
                    self._installed_targets.append("httpx_body_capture")
        else:
            logger.info("HTTP instrumentation disabled by config")

        if instrumentation.db_enabled:
            if db_instrumentation.install_sqlalchemy():
                self._installed_targets.append("sqlalchemy")
            if db_instrumentation.install_dbapi():
                self._installed_targets.append("dbapi")
            if db_instrumentation.install_asyncpg():
                self._installed_targets.append("asyncpg")
        else:
            logger.info("DB instrumentation disabled by config")

        if instrumentation.file_enabled:
            if file_instrumentation.install_file_io():
                self._installed_targets.append("file")
        else:
            logger.info("file instrumentation disabled by config (opt-in)")

        # Function instrumentation is decorator-based (@governed) — nothing to
        # patch; it activates through the published hook runtime.
        logger.info(f"OpenBox instrumentation installed: {self._installed_targets}")
        self._installed = True

    def uninstall(self) -> None:
        """Restore every original and flush OTel (idempotent, safe shutdown)."""
        if not self._installed:
            return
        file_instrumentation.uninstall_file_io()
        db_instrumentation.uninstall_asyncpg()
        db_instrumentation.uninstall_dbapi()
        db_instrumentation.uninstall_sqlalchemy()
        # Reverse install order: unwind the send patch before OTel httpx.
        http_instrumentation.uninstall_httpx_body_capture()
        http_instrumentation.uninstall_httpx()
        http_instrumentation.uninstall_requests()
        if get_hook_runtime() is not None:
            set_hook_runtime(None)
        if self._provider is not None:
            shutdown_opentelemetry(self._provider)
            self._provider = None
        self._installed_targets.clear()
        self._installed = False
        logger.info("OpenBox instrumentation uninstalled")
