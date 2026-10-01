"""Manager idempotency, ignored-URL self-guard, passive processor, executor threads."""

import asyncio
import builtins
import sys

import httpx
import httpx2
import requests
from conftest import ACTIVITY_CTX, FakeCore, RaisingHookAdapter, build_runtime
from instrumented_env import CountingHTTPServer, bound_activity, installed_runtime

from openbox_core.context import ContextStore, activity_scope
from openbox_core.instrumentation import http as http_instrumentation
from openbox_core.instrumentation.http import should_ignore_url
from openbox_core.instrumentation.manager import InstrumentationManager
from openbox_core.otel.span_processor import OpenBoxSpanProcessor


class TestIdempotentInstall:
    def test_double_install_double_uninstall(self):
        fake_core = FakeCore()
        runtime = build_runtime(fake_core, RaisingHookAdapter(), ContextStore())
        manager = InstrumentationManager(runtime)
        original_open = builtins.open
        original_sends = {
            library: (library.Client.send, library.AsyncClient.send) for library in (httpx, httpx2)
        }
        manager.install()
        try:
            first_targets = manager.installed_targets
            assert "httpx_body_capture" in first_targets
            assert "httpx2_body_capture" in first_targets
            for library, (sync_send, async_send) in original_sends.items():
                assert library.Client.send is not sync_send
                assert library.AsyncClient.send is not async_send
            manager.install()  # idempotent — no double patch
            assert manager.installed_targets == first_targets
        finally:
            manager.uninstall()
        manager.uninstall()  # idempotent
        assert builtins.open is original_open
        for library, sends in original_sends.items():
            assert (library.Client.send, library.AsyncClient.send) == sends

    def test_uninstall_restores_open_when_file_enabled(self):
        fake_core = FakeCore()
        runtime = build_runtime(fake_core, RaisingHookAdapter(), ContextStore(), file_enabled=True)
        manager = InstrumentationManager(runtime)
        original_open = builtins.open
        manager.install()
        assert builtins.open is not original_open
        manager.uninstall()
        assert builtins.open is original_open

    def test_toggles_respected(self):
        fake_core = FakeCore()
        original_sends = (httpx2.Client.send, httpx2.AsyncClient.send)
        runtime = build_runtime(
            fake_core, RaisingHookAdapter(), ContextStore(),
            http_enabled=False, db_enabled=False,
        )
        manager = InstrumentationManager(runtime)
        manager.install()
        try:
            assert "requests" not in manager.installed_targets
            assert "httpx2_body_capture" not in manager.installed_targets
            assert (httpx2.Client.send, httpx2.AsyncClient.send) == original_sends
            assert "sqlalchemy" not in manager.installed_targets
        finally:
            manager.uninstall()

    def test_runtime_close_uninstalls(self):
        fake_core = FakeCore()
        runtime = build_runtime(fake_core, RaisingHookAdapter(), ContextStore(), file_enabled=True)
        original_open = builtins.open
        runtime.install_instrumentation()
        assert builtins.open is not original_open
        runtime.close()
        assert builtins.open is original_open

    def test_missing_httpx2_keeps_httpx_capture_working(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "httpx2", None)
        fake_core, store = FakeCore(), ContextStore()
        transport = httpx.MockTransport(lambda request: httpx.Response(200))
        with installed_runtime(fake_core, store=store) as runtime, bound_activity(store):
            assert "httpx2_body_capture" not in runtime._instrumentation_manager.installed_targets
            with httpx.Client(transport=transport) as client:
                assert client.get("https://service.test/echo").status_code == 200
        assert len(fake_core.started_payloads) == 1
        assert len(fake_core.completed_payloads) == 1

    def test_httpx2_does_not_require_httpx_instrumentor(self, monkeypatch):
        monkeypatch.setattr(http_instrumentation, "install_httpx", lambda: False)
        fake_core, store = FakeCore(), ContextStore()
        transport = httpx2.MockTransport(lambda request: httpx2.Response(200))
        with installed_runtime(fake_core, store=store), bound_activity(store):
            with httpx2.Client(transport=transport) as client:
                assert client.get("https://service.test/echo").status_code == 200
        assert len(fake_core.started_payloads) == 1
        assert len(fake_core.completed_payloads) == 1

    def test_httpx2_restore_and_reinstall_does_not_affect_httpx(self):
        fake_core, store = FakeCore(), ContextStore()
        original_sends = (httpx2.Client.send, httpx2.AsyncClient.send)
        with installed_runtime(fake_core, store=store), bound_activity(store):
            http_instrumentation.uninstall_httpx2_body_capture()
            http_instrumentation.uninstall_httpx2_body_capture()
            assert (httpx2.Client.send, httpx2.AsyncClient.send) == original_sends
            transport = httpx.MockTransport(lambda request: httpx.Response(200))
            with httpx.Client(transport=transport) as client:
                assert client.get("https://service.test/echo").status_code == 200
            assert http_instrumentation.install_httpx2_body_capture()
            assert http_instrumentation.install_httpx2_body_capture()
            transport = httpx2.MockTransport(lambda request: httpx2.Response(200))
            with httpx2.Client(transport=transport) as client:
                assert client.get("https://service.test/echo").status_code == 200
        assert len(fake_core.started_payloads) == 2
        assert len(fake_core.completed_payloads) == 2
        assert (httpx2.Client.send, httpx2.AsyncClient.send) == original_sends


class TestIgnoredUrls:
    def test_api_url_always_ignored(self):
        fake_core = FakeCore()
        adapter, store = RaisingHookAdapter(), ContextStore()
        with installed_runtime(fake_core, adapter, store):
            assert should_ignore_url("https://core.test/api/v1/governance/evaluate")
            assert should_ignore_url("https://core.test/anything")
            assert not should_ignore_url("https://elsewhere.example/x")

    def test_evaluate_call_not_self_instrumented(self):
        """The governance evaluate triggered by a governed request must not
        recurse into another evaluation."""
        server = CountingHTTPServer()
        try:
            fake_core = FakeCore({"verdict": "allow"}, {"verdict": "allow"})
            adapter, store = RaisingHookAdapter(), ContextStore()
            with installed_runtime(fake_core, adapter, store), bound_activity(store):
                requests.get(server.url, timeout=5)
            # Exactly one started + one completed — no recursive evaluations.
            assert len(fake_core.payloads) == 2
        finally:
            server.stop()


class TestPassiveSpanProcessor:
    def test_on_end_never_evaluates_or_blocks(self):
        """The processor is PASSIVE by contract: on_end performs no network,
        no verdict handling, and never raises."""
        import ast
        import inspect
        import textwrap

        store = ContextStore()
        processor = OpenBoxSpanProcessor(store)
        assert processor.on_end(object()) is None  # junk span: still silent
        # AST-level: on_end contains NO calls at all (docstrings may talk
        # about evaluation; the body may not perform any).
        source = textwrap.dedent(inspect.getsource(OpenBoxSpanProcessor.on_end))
        calls = [n for n in ast.walk(ast.parse(source)) if isinstance(n, ast.Call)]
        assert calls == [], "on_end must stay passive — it may not call anything"

    def test_on_start_registers_trace_for_bound_context(self):
        import sys
        from pathlib import Path

        sys.path.insert(0, str(Path(__file__).parent.parent / "wire"))
        from span_fixtures import TRACE_ID, FakeSpan

        store = ContextStore()
        processor = OpenBoxSpanProcessor(store)
        with activity_scope(ACTIVITY_CTX, store=store):
            processor.on_start(FakeSpan())
            assert store.context_for_trace(TRACE_ID) is ACTIVITY_CTX

    def test_on_start_noop_without_bound_context(self):
        import sys
        from pathlib import Path

        sys.path.insert(0, str(Path(__file__).parent.parent / "wire"))
        from span_fixtures import TRACE_ID, FakeSpan

        store = ContextStore()
        OpenBoxSpanProcessor(store).on_start(FakeSpan())
        assert store.context_for_trace(TRACE_ID) is None


class TestExecutorThreadPropagation:
    async def test_hook_in_executor_thread_finds_context(self):
        """run_in_executor work resolves the bound ActivityContext after the
        propagation patch — guards the trace_id=0 Python 3.11 failure mode."""
        from openbox_core.otel.propagation import install_context_propagating_executor

        assert install_context_propagating_executor() is True
        store = ContextStore()

        def executor_work():
            # ContextVar propagated -> current context visible in the thread.
            return store.current_activity_context()

        with activity_scope(ACTIVITY_CTX, store=store):
            loop = asyncio.get_running_loop()
            seen = await loop.run_in_executor(None, executor_work)
        assert seen is ACTIVITY_CTX

    async def test_trace_map_fallback_without_contextvar(self):
        """Even WITHOUT ContextVar propagation, the trace-map path resolves
        context from the span's trace id (the second lookup path)."""
        import sys
        from pathlib import Path

        sys.path.insert(0, str(Path(__file__).parent.parent / "wire"))
        from span_fixtures import TRACE_ID, FakeSpan

        from openbox_core.hooks.events import resolve_context

        store = ContextStore()
        store.register_trace(TRACE_ID, ACTIVITY_CTX)

        def raw_thread_work():
            # Simulates a thread with NO ContextVars: current() is None there,
            # but the span's trace id still resolves.
            return resolve_context(store, FakeSpan())

        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            resolved = pool.submit(raw_thread_work).result(timeout=10)
        assert resolved is ACTIVITY_CTX


class TestIgnoredUrlNormalization:
    """Recursion guard survives host-case/default-port representation drift."""

    def test_case_and_default_port_normalized(self):
        from openbox_core.instrumentation.http import (
            set_ignored_url_prefixes,
            should_ignore_url,
        )

        set_ignored_url_prefixes({"https://Core.Example.com"})
        try:
            # httpx normalizes request URLs: lowercase host, default port dropped.
            assert should_ignore_url("https://core.example.com/api/v1/governance/evaluate")
            assert should_ignore_url("https://core.example.com:443/anything")
            assert not should_ignore_url("http://core.example.com/x")  # scheme differs
            assert not should_ignore_url("https://other.example.com/x")
        finally:
            set_ignored_url_prefixes(set())

    def test_explicit_nonstandard_port_respected(self):
        from openbox_core.instrumentation.http import (
            set_ignored_url_prefixes,
            should_ignore_url,
        )

        set_ignored_url_prefixes({"http://localhost:8080"})
        try:
            assert should_ignore_url("http://localhost:8080/api/v1/governance/evaluate")
            assert not should_ignore_url("http://localhost:9090/api")
        finally:
            set_ignored_url_prefixes(set())
