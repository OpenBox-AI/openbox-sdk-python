"""DB wrapper conformance — started BLOCK prevents the query."""

import pytest
import sqlalchemy
from conftest import FakeCore, RaisingHookAdapter
from instrumented_env import bound_activity, installed_runtime
from sqlalchemy import text

from openbox_core.context import ContextStore
from openbox_core.errors import GovernanceBlockedError


@pytest.fixture
def engine():
    engine = sqlalchemy.create_engine("sqlite:///:memory:")
    yield engine
    engine.dispose()


class TestSQLAlchemy:
    def test_started_block_query_not_called(self, engine):
        fake_core = FakeCore({"verdict": "allow"}, {"verdict": "allow"})
        adapter, store = RaisingHookAdapter(), ContextStore()
        with installed_runtime(fake_core, adapter, store), bound_activity(store):
            with engine.connect() as conn:
                conn.execute(text("CREATE TABLE t (x INTEGER)"))
                conn.execute(text("INSERT INTO t VALUES (1)"))
                conn.commit()
            # Now BLOCK the sensitive query — the row must remain unreadable.
            fake_core.queue = [{"verdict": "block", "reason": "no reads"}]
            with engine.connect() as conn:
                with pytest.raises(GovernanceBlockedError):
                    conn.execute(text("SELECT * FROM t"))
        blocked_started = fake_core.started_payloads[-1]["spans"][0]
        assert blocked_started["hook_type"] == "db_query"
        assert blocked_started["db_statement"].startswith("SELECT")

    def test_allow_executes_with_completed_telemetry(self, engine):
        fake_core = FakeCore(
            {"verdict": "allow"}, {"verdict": "allow"},  # CREATE started/completed
            {"verdict": "allow"}, {"verdict": "allow"},  # SELECT started/completed
        )
        adapter, store = RaisingHookAdapter(), ContextStore()
        with installed_runtime(fake_core, adapter, store), bound_activity(store):
            with engine.connect() as conn:
                conn.execute(text("CREATE TABLE u (x INTEGER)"))
                rows = conn.execute(text("SELECT * FROM u")).fetchall()
                assert rows == []
        completed_spans = [p["spans"][0] for p in fake_core.completed_payloads]
        assert any(s["db_statement"].startswith("SELECT") for s in completed_spans)
        assert all(s["hook_type"] == "db_query" for s in completed_spans)

    def test_no_context_query_ungoverned(self, engine):
        fake_core = FakeCore()
        adapter, store = RaisingHookAdapter(), ContextStore()
        with installed_runtime(fake_core, adapter, store):
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
        assert fake_core.payloads == []


class TestAsyncpgPatch:
    async def test_patched_execute_blocks_before_query(self):
        """Unit-level: the asyncpg Connection._execute patch preflights first
        (a live PostgreSQL server is out of unit scope)."""
        import asyncpg

        from openbox_core.instrumentation import db as db_instrumentation

        fake_core = FakeCore({"verdict": "block", "reason": "no db"})
        adapter, store = RaisingHookAdapter(), ContextStore()
        with installed_runtime(fake_core, adapter, store), bound_activity(store):
            assert asyncpg.Connection._execute is not db_instrumentation._original_asyncpg_execute

            executed = []

            class FakeConnection:
                # Bypass __init__; call the patched unbound method directly.
                _execute = asyncpg.Connection._execute

                async def _original(self, *a, **k):
                    executed.append(a)

            connection = FakeConnection.__new__(FakeConnection)
            original = db_instrumentation._original_asyncpg_execute
            try:
                # Route the "original" through our recorder to observe calls.
                db_instrumentation._original_asyncpg_execute = FakeConnection._original
                with pytest.raises(GovernanceBlockedError):
                    await connection._execute("SELECT secret FROM vault", (), 0, None)
            finally:
                db_instrumentation._original_asyncpg_execute = original
            assert executed == []  # the real execute never ran

    def test_uninstall_restores_original(self):
        import asyncpg

        from openbox_core.instrumentation import db as db_instrumentation

        original = asyncpg.Connection._execute
        assert db_instrumentation.install_asyncpg() is True
        assert asyncpg.Connection._execute is not original
        db_instrumentation.uninstall_asyncpg()
        assert asyncpg.Connection._execute is original


class TestDbapiPatch:
    def test_cursor_tracer_patched_and_restored(self):
        from opentelemetry.instrumentation import dbapi

        from openbox_core.instrumentation import db as db_instrumentation

        original = dbapi.CursorTracer.traced_execution
        assert db_instrumentation.install_dbapi() is True
        assert dbapi.CursorTracer.traced_execution is not original
        db_instrumentation.uninstall_dbapi()
        assert dbapi.CursorTracer.traced_execution is original
