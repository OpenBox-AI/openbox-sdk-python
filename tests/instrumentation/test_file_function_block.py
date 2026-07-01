"""File + function wrapper conformance — started BLOCK prevents the operation."""

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
        assert span["file_path"] == str(victim)
        assert span["file_operation"] == "write"

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
        assert span["bytes_written"] == 10
        assert span["lines_count"] == 2
        assert span["file_operation"] == "write"

    def test_read_counting(self, tmp_path):
        fake_core = FakeCore(
            {"verdict": "allow"}, {"verdict": "allow"},
            {"verdict": "allow"}, {"verdict": "allow"},
        )
        adapter, store = RaisingHookAdapter(), ContextStore()
        source = tmp_path / "data.txt"
        with installed_runtime(fake_core, adapter, store, file_enabled=True), bound_activity(store):
            with open(source, "w") as handle:
                handle.write("payload")
            with open(source) as handle:
                assert handle.read() == "payload"
        read_span = fake_core.completed_payloads[-1]["spans"][0]
        assert read_span["bytes_read"] == 7
        assert read_span["file_operation"] == "read"

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

    def test_file_disabled_by_default(self, tmp_path):
        # file_enabled defaults False (Temporal parity: opt-in)
        fake_core = FakeCore()
        adapter, store = RaisingHookAdapter(), ContextStore()
        with installed_runtime(fake_core, adapter, store), bound_activity(store):
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
        assert "args" not in span

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
