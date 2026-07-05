"""File + function wrapper conformance — started BLOCK prevents the operation."""

import builtins
import pathlib

import pytest
from conftest import FakeCore, RaisingHookAdapter
from instrumented_env import bound_activity, installed_runtime

from openbox_core.context import ContextStore
from openbox_core.errors import GovernanceBlockedError
from openbox_core.instrumentation.function import governed


class TestFileOpen:
    def test_started_block_file_not_opened(self, tmp_path):
        fake_core = FakeCore({"verdict": "block", "reason": "no writes"})
        adapter, store = RaisingHookAdapter(), ContextStore()
        victim = tmp_path / "blocked.txt"
        with installed_runtime(fake_core, adapter, store, file_enabled=True), bound_activity(store):
            with pytest.raises(GovernanceBlockedError):
                open(victim, "w")
        assert not victim.exists()  # the handle was never created
        span = fake_core.started_payloads[0]["spans"][0]
        assert span["hook_type"] == "file_operation"
        assert span["name"] == "file.write"
        assert span["file_path"] == str(victim)
        assert span["file_operation"] == "write"
        assert span["attributes"]["file.path"] == str(victim)
        assert span["attributes"]["file.mode"] == "w"
        assert span["attributes"]["file.operation"] == "write"

    def test_allow_opens_counts_and_reports_on_close(self, tmp_path):
        fake_core = FakeCore({"verdict": "allow"}, {"verdict": "allow"})
        adapter, store = RaisingHookAdapter(), ContextStore()
        target_file = tmp_path / "allowed.txt"
        with installed_runtime(fake_core, adapter, store, file_enabled=True), bound_activity(store):
            with open(target_file, "w") as handle:
                handle.write("hello")
                handle.writelines(["a\n", "bb\n"])
        assert target_file.read_text() == "helloa\nbb\n"
        span = fake_core.completed_payloads[0]["spans"][0]
        assert span["name"] == "file.write"
        assert span["bytes_written"] == 10
        assert span["lines_count"] == 2
        assert span["file_operation"] == "write"
        assert span["attributes"]["file.operation"] == "write"

    def test_read_counting(self, tmp_path):
        fake_core = FakeCore(
            {"verdict": "allow"},
            {"verdict": "allow"},
            {"verdict": "allow"},
            {"verdict": "allow"},
        )
        adapter, store = RaisingHookAdapter(), ContextStore()
        source = tmp_path / "data.txt"
        with installed_runtime(fake_core, adapter, store, file_enabled=True), bound_activity(store):
            with open(source, "w") as handle:
                handle.write("payload")
            with open(source) as handle:
                assert handle.read() == "payload"
        read_span = fake_core.completed_payloads[-1]["spans"][0]
        assert read_span["name"] == "file.read"
        assert read_span["bytes_read"] == 7
        assert read_span["file_operation"] == "read"
        assert read_span["attributes"]["file.operation"] == "read"

    def test_stdlib_paths_bypass_governance(self):
        import sysconfig

        fake_core = FakeCore()
        adapter, store = RaisingHookAdapter(), ContextStore()
        stdlib_file = pathlib.Path(sysconfig.get_paths()["stdlib"]) / "os.py"
        with installed_runtime(fake_core, adapter, store, file_enabled=True), bound_activity(store):
            with open(stdlib_file) as handle:
                handle.read(10)
        assert fake_core.payloads == []

    def test_no_context_open_ungoverned(self, tmp_path):
        fake_core = FakeCore()
        adapter, store = RaisingHookAdapter(), ContextStore()
        with installed_runtime(fake_core, adapter, store, file_enabled=True):
            with open(tmp_path / "free.txt", "w") as handle:
                handle.write("x")
        assert fake_core.payloads == []

    def test_file_enabled_by_default(self, tmp_path):
        # All instrumentation defaults ON (safe since the re-entrancy guard
        # + interpreter-prefix bypass); file opens under a bound activity
        # are governed without any toggle.
        fake_core = FakeCore()
        adapter, store = RaisingHookAdapter(), ContextStore()
        with installed_runtime(fake_core, adapter, store), bound_activity(store):
            with open(tmp_path / "tracked.txt", "w") as handle:
                handle.write("x")
        assert fake_core.started_payloads, "default-on file hook sent no events"

    def test_file_opt_out_still_works(self, tmp_path):
        fake_core = FakeCore()
        adapter, store = RaisingHookAdapter(), ContextStore()
        with (
            installed_runtime(fake_core, adapter, store, file_enabled=False),
            bound_activity(store),
        ):
            with open(tmp_path / "untracked.txt", "w") as handle:
                handle.write("x")
        assert fake_core.payloads == []


class TestFunctionDecorator:
    def test_started_block_function_not_called(self):
        fake_core = FakeCore({"verdict": "block", "reason": "not allowed"})
        adapter, store = RaisingHookAdapter(), ContextStore()
        calls = []

        @governed
        def sensitive(amount):
            calls.append(amount)
            return amount * 2

        with installed_runtime(fake_core, adapter, store), bound_activity(store):
            with pytest.raises(GovernanceBlockedError):
                sensitive(5)
        assert calls == []  # wrapped function never ran
        span = fake_core.started_payloads[0]["spans"][0]
        assert span["hook_type"] == "function_call"
        assert "sensitive" in span["function"]

    def test_allow_runs_and_captures_result(self):
        fake_core = FakeCore({"verdict": "allow"}, {"verdict": "allow"})
        adapter, store = RaisingHookAdapter(), ContextStore()

        @governed
        def double(amount):
            return amount * 2

        with installed_runtime(fake_core, adapter, store), bound_activity(store):
            assert double(5) == 10
        completed_span = fake_core.completed_payloads[0]["spans"][0]
        assert completed_span["result"] == 10
        assert completed_span["args"]["args"] == [5]

    async def test_async_block_function_not_called(self):
        fake_core = FakeCore({"verdict": "block", "reason": "no"})
        adapter, store = RaisingHookAdapter(), ContextStore()
        calls = []

        @governed
        async def acharge(amount):
            calls.append(amount)
            return amount

        with installed_runtime(fake_core, adapter, store), bound_activity(store):
            with pytest.raises(GovernanceBlockedError):
                await acharge(1)
        assert calls == []

    async def test_async_allow_runs(self):
        fake_core = FakeCore({"verdict": "allow"}, {"verdict": "allow"})
        adapter, store = RaisingHookAdapter(), ContextStore()

        @governed(name="billing.acharge", capture_args=False)
        async def acharge(amount):
            return amount + 1

        with installed_runtime(fake_core, adapter, store), bound_activity(store):
            assert await acharge(1) == 2
        span = fake_core.completed_payloads[0]["spans"][0]
        # capture_args=False ⇒ args present but null (flat contract always
        # carries the family key set; the value is simply not captured).
        assert "args" in span and span["args"] is None

    def test_exception_still_reports_completed_with_error(self):
        fake_core = FakeCore({"verdict": "allow"}, {"verdict": "allow"})
        adapter, store = RaisingHookAdapter(), ContextStore()

        @governed
        def broken():
            raise RuntimeError("kaboom")

        with installed_runtime(fake_core, adapter, store), bound_activity(store):
            with pytest.raises(RuntimeError, match="kaboom"):
                broken()
        span = fake_core.completed_payloads[0]["spans"][0]
        assert span["error"] == "kaboom"

    def test_no_runtime_passthrough(self):
        @governed
        def plain(value):
            return value

        assert plain(7) == 7  # no installed instrumentation — zero governance


class TestFileSelfGovernanceReentrancy:
    def test_nested_open_during_preflight_passes_through(self, tmp_path):
        """Evaluation-time file opens (ssl, metadata scans) are never governed."""
        from openbox_core.conformance.fake_core import FakeCore
        from openbox_core.conformance.hook_preflight import (
            CONFORMANCE_CONTEXT,
            RecordingHookAdapter,
        )
        from openbox_core.conformance.instrumentation import (
            installed_conformance_runtime,
        )
        from openbox_core.context import ContextStore, activity_scope

        nested = tmp_path / "metadata-blob.txt"
        nested.write_text("blob")
        outer = tmp_path / "app-data.txt"
        outer.write_text("app")
        seen = []

        class OpeningFakeCore(FakeCore):
            def handler(self, request):
                # Simulates httpx/importlib_metadata opening files mid-evaluate.
                with open(nested) as fh:
                    seen.append(fh.read())
                return super().handler(request)

        store = ContextStore()
        with installed_conformance_runtime(
            OpeningFakeCore(), RecordingHookAdapter(), store, file_enabled=True
        ):
            with activity_scope(CONFORMANCE_CONTEXT, store=store):
                with open(outer) as fh:
                    assert fh.read() == "app"

        assert seen and seen[0] == "blob"  # nested open worked, ungoverned


class TestPathlibAndIoOpenGovernance:
    """pathlib helpers (Path.open/read_text/write_text) call io.open directly,
    bypassing builtins.open — governance must patch both names, with exactly
    one started + one completed hook per logical open (no double wrapping)."""

    def test_direct_builtins_open_one_started_one_completed(self, tmp_path):
        fake_core = FakeCore()
        adapter, store = RaisingHookAdapter(), ContextStore()
        target = tmp_path / "direct.txt"
        with installed_runtime(fake_core, adapter, store, file_enabled=True), bound_activity(store):
            with open(target, "w") as handle:
                handle.write("hi")
        assert len(fake_core.started_payloads) == 1
        assert len(fake_core.completed_payloads) == 1
        assert fake_core.completed_payloads[0]["spans"][0]["bytes_written"] == 2

    def test_io_open_one_started_one_completed(self, tmp_path):
        import io

        fake_core = FakeCore()
        adapter, store = RaisingHookAdapter(), ContextStore()
        target = tmp_path / "via_io.txt"
        with installed_runtime(fake_core, adapter, store, file_enabled=True), bound_activity(store):
            # io.open (NOT builtin open) on purpose — this is the exact name
            # pathlib routes through; the test proves that name is governed.
            with io.open(target, "w") as handle:  # noqa: UP020
                handle.write("io-write")
        assert len(fake_core.started_payloads) == 1
        assert len(fake_core.completed_payloads) == 1
        completed = fake_core.completed_payloads[0]["spans"][0]
        assert completed["file_operation"] == "write"
        assert completed["bytes_written"] == 8

    def test_pathlib_path_open_one_started_one_completed(self, tmp_path):
        fake_core = FakeCore()
        adapter, store = RaisingHookAdapter(), ContextStore()
        target = tmp_path / "via_path_open.txt"
        with installed_runtime(fake_core, adapter, store, file_enabled=True), bound_activity(store):
            with target.open("w") as handle:
                handle.write("path-open")
        assert len(fake_core.started_payloads) == 1
        assert len(fake_core.completed_payloads) == 1
        assert fake_core.completed_payloads[0]["spans"][0]["bytes_written"] == 9

    def test_pathlib_write_text_emits_write_span_with_bytes_written(self, tmp_path):
        fake_core = FakeCore()
        adapter, store = RaisingHookAdapter(), ContextStore()
        target = tmp_path / "written.txt"
        with installed_runtime(fake_core, adapter, store, file_enabled=True), bound_activity(store):
            target.write_text("pathlib-payload")
        assert len(fake_core.started_payloads) == 1
        assert len(fake_core.completed_payloads) == 1
        started = fake_core.started_payloads[0]["spans"][0]
        completed = fake_core.completed_payloads[0]["spans"][0]
        assert started["hook_type"] == "file_operation"
        assert started["file_path"] == str(target)
        assert started["file_operation"] == "write"
        assert completed["file_operation"] == "write"
        assert completed["bytes_written"] == len("pathlib-payload")
        # verify OUTSIDE the governed block (instrumentation now uninstalled)
        assert target.read_text() == "pathlib-payload"

    def test_pathlib_read_text_emits_read_span_with_bytes_read(self, tmp_path):
        target = tmp_path / "to_read.txt"
        target.write_text("read-me-please")  # seeded before instrumentation
        fake_core = FakeCore()
        adapter, store = RaisingHookAdapter(), ContextStore()
        with installed_runtime(fake_core, adapter, store, file_enabled=True), bound_activity(store):
            assert target.read_text() == "read-me-please"
        assert len(fake_core.started_payloads) == 1
        assert len(fake_core.completed_payloads) == 1
        completed = fake_core.completed_payloads[0]["spans"][0]
        assert completed["file_operation"] == "read"
        assert completed["bytes_read"] == len("read-me-please")

    def test_uninstall_restores_both_builtins_and_io_open(self):
        import io

        from openbox_core.instrumentation import file as file_mod

        orig_builtins, orig_io = builtins.open, io.open
        assert file_mod.install_file_io() is True
        assert builtins.open is not orig_builtins  # patched
        assert io.open is not orig_io  # patched
        file_mod.uninstall_file_io()
        assert builtins.open is orig_builtins  # restored exactly
        assert io.open is orig_io  # restored exactly

    def test_pathlib_no_context_skips_governance(self, tmp_path):
        fake_core = FakeCore()
        adapter, store = RaisingHookAdapter(), ContextStore()
        target = tmp_path / "no_ctx.txt"
        with installed_runtime(fake_core, adapter, store, file_enabled=True):
            target.write_text("ungoverned")  # no bound_activity
        assert fake_core.payloads == []
        assert target.read_text() == "ungoverned"

    def test_pathlib_interpreter_path_bypasses_governance(self):
        import sysconfig

        fake_core = FakeCore()
        adapter, store = RaisingHookAdapter(), ContextStore()
        stdlib_file = pathlib.Path(sysconfig.get_paths()["stdlib"]) / "os.py"
        with installed_runtime(fake_core, adapter, store, file_enabled=True), bound_activity(store):
            stdlib_file.read_text()  # via io.open, under stdlib prefix -> skipped
        assert fake_core.payloads == []
