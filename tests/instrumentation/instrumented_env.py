"""Installed-instrumentation environment helpers for wrapper behavior tests."""

import contextlib
import http.server
import threading

from conftest import ACTIVITY_CTX, build_runtime

from openbox_core.context import activity_scope
from openbox_core.instrumentation.manager import InstrumentationManager


class CountingHTTPServer:
    """Real local HTTP server counting hits — proves requests were/weren't sent."""

    def __init__(self):
        self.hits = 0
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def _respond(self):
                outer.hits += 1
                body = b'{"ok": true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = _respond
            do_POST = _respond

            def log_message(self, *args):
                pass

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self.url = f"http://127.0.0.1:{self._server.server_port}/echo"

    def stop(self):
        self._server.shutdown()
        self._server.server_close()


@contextlib.contextmanager
def installed_runtime(fake_core, adapter, store, **overrides):
    """Runtime with instrumentation installed; guaranteed uninstall."""
    runtime = build_runtime(fake_core, adapter, store, **overrides)
    manager = InstrumentationManager(runtime)
    runtime._instrumentation_manager = manager
    manager.install()
    try:
        yield runtime
    finally:
        manager.uninstall()


@contextlib.contextmanager
def bound_activity(store):
    with activity_scope(ACTIVITY_CTX, store=store):
        yield
