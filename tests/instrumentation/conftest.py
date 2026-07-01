"""Shared fixtures — thin aliases over the packaged conformance kit.

The kit (openbox_core.conformance) is the canonical home for the fake Core,
the recording adapter, and the runtime builder; these tests dogfood it.
"""

import pytest

from openbox_core.conformance.fake_core import FakeCore  # noqa: F401 (re-export)
from openbox_core.conformance.hook_preflight import (
    CONFORMANCE_CONTEXT as ACTIVITY_CTX,  # noqa: F401 (re-export)
)
from openbox_core.conformance.hook_preflight import (
    RecordingHookAdapter as RaisingHookAdapter,  # noqa: F401 (re-export)
)
from openbox_core.conformance.hook_preflight import (
    build_conformance_runtime as build_runtime,  # noqa: F401 (re-export)
)
from openbox_core.context import ContextStore
from openbox_core.hooks.preflight import HookRuntime


@pytest.fixture
def fake_core():
    return FakeCore()


@pytest.fixture
def adapter():
    return RaisingHookAdapter()


@pytest.fixture
def store():
    return ContextStore()


@pytest.fixture
def runtime(fake_core, adapter, store):
    return build_runtime(fake_core, adapter, store)


@pytest.fixture
def hook_runtime(runtime):
    return HookRuntime(runtime)
