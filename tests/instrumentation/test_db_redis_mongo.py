"""redis + pymongo wrapper conformance.

redis is exercised at the hook level (no live server) — the RedisInstrumentor
request/response hooks are the integration surface. pymongo blocking is proven
end-to-end through the wrapt Collection wrapper: a BLOCK must raise before the
driver connects, so no server is required.
"""

import pytest
from conftest import FakeCore, RaisingHookAdapter
from instrumented_env import bound_activity, installed_runtime

from openbox_core.context import ContextStore
from openbox_core.errors import GovernanceBlockedError
from openbox_core.instrumentation import db as db_instrumentation
from openbox_core.otel.provider import get_tracer


class _FakePool:
    connection_kwargs = {"host": "cache.internal", "port": 6380, "db": 3}


class _FakeRedis:
    connection_pool = _FakePool()


class TestRedis:
    def test_started_block_raises_flat_db_query(self):
        fake_core = FakeCore({"verdict": "block", "reason": "no redis"})
        adapter, store = RaisingHookAdapter(), ContextStore()
        with installed_runtime(fake_core, adapter, store), bound_activity(store):
            span = get_tracer().start_span("redis GET")
            with pytest.raises(GovernanceBlockedError):
                db_instrumentation._redis_request_hook(
                    span, _FakeRedis(), ("GET", "secret-key"), {}
                )
        started = fake_core.started_payloads[-1]["spans"][0]
        assert started["hook_type"] == "db_query"
        assert started["db_system"] == "redis"
        assert started["db_operation"] == "GET"
        assert started["db_statement"] == "GET secret-key"
        assert started["server_address"] == "cache.internal"
        assert started["server_port"] == 6380

    def test_allow_started_and_completed(self):
        fake_core = FakeCore({"verdict": "allow"}, {"verdict": "allow"})
        adapter, store = RaisingHookAdapter(), ContextStore()
        with installed_runtime(fake_core, adapter, store), bound_activity(store):
            span = get_tracer().start_span("redis SET")
            db_instrumentation._redis_request_hook(span, _FakeRedis(), ("SET", "k", "v"), {})
            span.end()
            db_instrumentation._redis_response_hook(span, _FakeRedis(), "OK")
        started = fake_core.started_payloads[-1]["spans"][0]
        assert started["db_operation"] == "SET"
        completed = fake_core.completed_payloads[-1]["spans"][0]
        assert completed["db_system"] == "redis"
        assert completed["db_operation"] == "SET"
        assert completed["stage"] == "completed"

    def test_uninstall_is_idempotent(self):
        assert db_instrumentation.install_redis() is True
        db_instrumentation.uninstall_redis()
        db_instrumentation.uninstall_redis()  # second call must be a no-op


class TestPymongoBlocking:
    def test_find_one_blocked_before_connect(self):
        import pymongo

        fake_core = FakeCore({"verdict": "block", "reason": "no mongo"})
        adapter, store = RaisingHookAdapter(), ContextStore()
        with installed_runtime(fake_core, adapter, store), bound_activity(store):
            client = pymongo.MongoClient(
                "mongodb://localhost:27017",
                connect=False,
                serverSelectionTimeoutMS=200,
            )
            coll = client["appdb"]["users"]
            with pytest.raises(GovernanceBlockedError):
                coll.find_one({"x": 1})
        started = fake_core.started_payloads[-1]["spans"][0]
        assert started["hook_type"] == "db_query"
        assert started["db_system"] == "mongodb"
        assert started["db_operation"] == "find_one"
        assert started["db_name"] == "appdb"

    def test_uninstall_restores_collection_method(self):
        import pymongo.collection

        # Install fresh so a wrapt wrapper is present, then confirm removal.
        db_instrumentation.install_pymongo()
        db_instrumentation.uninstall_pymongo()
        # After uninstall the method is the original (no __wrapped__ shim).
        assert not hasattr(pymongo.collection.Collection.find_one, "__wrapped__")


class TestNoContextUngoverned:
    def test_redis_hook_without_context_skips(self):
        fake_core = FakeCore()
        adapter, store = RaisingHookAdapter(), ContextStore()
        with installed_runtime(fake_core, adapter, store):  # no bound activity
            span = get_tracer().start_span("redis GET")
            db_instrumentation._redis_request_hook(span, _FakeRedis(), ("GET", "k"), {})
        assert fake_core.payloads == []
