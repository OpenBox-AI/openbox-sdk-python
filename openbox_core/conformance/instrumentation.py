"""Instrumentation conformance environment — real wrappers, fake Core.

Framework SDKs import this to prove their integration keeps every behavioral
guarantee: the checks assert the REAL operation ran / did not run, not merely
payload shape. No live network (governance terminates in the fake Core; HTTP
cases hit a local counting server).
"""

from __future__ import annotations

import contextlib
import http.server
import threading
from collections.abc import Iterator
from typing import Any

from ..context import ContextStore, activity_scope
from ..instrumentation.manager import InstrumentationManager
from ..runtime import OpenBoxRuntime
from .fake_core import FakeCore
from .hook_preflight import (
    CONFORMANCE_CONTEXT,
    RecordingHookAdapter,
    build_conformance_runtime,
)

__all__ = [
    "LocalCountingServer",
    "installed_conformance_runtime",
    "bound_conformance_activity",
]


class LocalCountingServer:
    """Loopback HTTP server counting hits — proves a request was/wasn't sent."""

    def __init__(self) -> None:
        self.hits = 0
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def _respond(self) -> None:
                outer.hits += 1
                body = b'{"ok": true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = _respond
            do_POST = _respond

            def log_message(self, *args: Any) -> None:  # keep test output clean
                pass

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self.url = f"http://127.0.0.1:{self._server.server_port}/echo"

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()


@contextlib.contextmanager
def installed_conformance_runtime(
    fake_core: FakeCore,
    adapter: Any | None = None,
    store: ContextStore | None = None,
    **instrumentation_overrides: Any,
) -> Iterator[OpenBoxRuntime]:
    """Runtime with REAL instrumentation installed; guaranteed uninstall."""
    adapter = adapter if adapter is not None else RecordingHookAdapter()
    store = store if store is not None else ContextStore()
    runtime = build_conformance_runtime(fake_core, adapter, store, **instrumentation_overrides)
    manager = InstrumentationManager(runtime)
    runtime._instrumentation_manager = manager
    manager.install()
    try:
        yield runtime
    finally:
        manager.uninstall()


@contextlib.contextmanager
def bound_conformance_activity(store: ContextStore) -> Iterator[None]:
    """Bind the reference ActivityContext with guaranteed reset."""
    with activity_scope(CONFORMANCE_CONTEXT, store=store):
        yield
