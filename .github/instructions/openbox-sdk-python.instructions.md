---
applyTo: "**/*.py,pyproject.toml,uv.lock,README.md,tests/**/*.py"
description: "How to build a Python framework SDK that integrates with openbox-sdk-python."
name: "OpenBox Python Framework SDK Integration"
---

# Build A Framework SDK With OpenBox Python Base SDK

Use this guide when creating a new Python framework SDK on top of
`openbox-sdk-python`. The base package is imported as `openbox_core`; it already
owns governance contracts, configuration, identity/signing, the HTTP client,
strict gate validation, context correlation, generic instrumentation, hook wire
payloads, approval parsing, and reusable conformance fixtures.

A framework SDK should be a thin adapter. It should bind framework lifecycle
events into `openbox_core`, translate governance results into native framework
behavior, and avoid reimplementing base SDK responsibilities.

## Mental Model

The integration path is:

```text
framework lifecycle
  -> ActivityContext
  -> EventEnvelope factories
  -> OpenBoxRuntime
  -> GovernanceGate
  -> EvaluationClient
  -> OpenBox Core
  -> EvaluationResult
  -> FrameworkAdapter native behavior
```

Generic operation hooks follow this path:

```text
HTTP/DB/file/function wrapper
  -> HookRuntime
  -> GovernanceGate.preflight/completed
  -> FrameworkAdapter
```

## Build Checklist

- Add `openbox-sdk-python` as a dependency.
- Import explicit base modules such as `openbox_core.config`,
  `openbox_core.runtime`, `openbox_core.adapters.base`,
  `openbox_core.contracts.context`, and `openbox_core.contracts.events`.
- Do not import heavy runtime modules from `openbox_core.__init__`; that package
  root is intentionally side-effect light.
- Create a framework-specific config wrapper that calls
  `OpenBoxConfig.resolve(env_prefix="OPENBOX_<FRAMEWORK>", ...)`.
- Implement `FrameworkAdapter` for native block, halt, and approval behavior.
- Build a runtime factory that creates `OpenBoxRuntime(config, adapter=...)`.
- Bind framework execution metadata into `ActivityContext`.
- Emit lifecycle events using `openbox_core.contracts.events` factories.
- Install generic instrumentation only in safe worker/runtime paths, never in
  deterministic or constrained framework import paths.
- Close the runtime on worker/application shutdown.
- Add conformance tests using the base SDK fixtures.

## Dependency And Imports

In the new framework SDK, depend on the base SDK instead of copying its code:

```toml
[project]
dependencies = [
    "openbox-sdk-python>=0.2.0",
]
```

Use explicit imports:

```python
from openbox_core.adapters.base import FrameworkAdapter
from openbox_core.config import OpenBoxConfig
from openbox_core.context import activity_scope
from openbox_core.contracts.context import ActivityContext
from openbox_core.contracts import events
from openbox_core.contracts.results import EvaluationResult, Verdict
from openbox_core.runtime import OpenBoxRuntime
```

Avoid broad package-root imports for runtime pieces. Keep import-time behavior
safe for framework loaders, workflow sandboxes, plugin discovery, and test
collection.

## Configuration

Expose framework-friendly config, but resolve into `OpenBoxConfig`:

```python
def resolve_openbox_config(**overrides) -> OpenBoxConfig:
    return OpenBoxConfig.resolve(
        env_prefix="OPENBOX_MYFRAMEWORK",
        **overrides,
    )
```

Resolution order is explicit arguments, framework-specific environment
variables, global `OPENBOX_*` variables, defaults, then validation. Do not build
your own API key, URL, signing, or fail-mode resolution.

Identity fields must be passed through together:

- `agent_did`
- `agent_private_key`

If only one is present, let `OpenBoxConfig` raise the configuration error.

## Adapter

The adapter is the only place where governance decisions become native
framework effects.

```python
class MyFrameworkAdapter:
    name = "myframework"

    async def handle_approval(self, result: EvaluationResult) -> None:
        # Drive the framework's native async approval behavior.
        # Return normally only when approved.
        raise MyFrameworkApprovalPending(result.approval_id)

    def raise_lifecycle_blocked(self, result: EvaluationResult):
        if result.verdict is Verdict.HALT:
            raise MyFrameworkHalt(result.reason or "Halted by governance")
        raise MyFrameworkBlocked(result.reason or "Blocked by governance")

    def raise_hook_blocked(self, result: EvaluationResult):
        if result.verdict is Verdict.HALT:
            raise MyFrameworkHalt(result.reason or "Halted by governance")
        raise MyFrameworkBlocked(result.reason or "Blocked by governance")

    def on_completed_hook_result(
        self,
        result: EvaluationResult,
        context: ActivityContext | None = None,
    ) -> None:
        # Completed hooks run after the operation. Never pretend to undo work.
        # Record state only for future framework execution.
        if result.verdict.should_stop() and context is not None:
            mark_future_work_blocked(context, result)
```

For sync frameworks that own HITL natively, optionally implement
`handle_approval_sync(result, context=None)`. Returning means approved. Raising
a native pending/rejected/expired error prevents the operation from running.

Do not interpret BLOCK/HALT inside wrappers. Wrappers should call the base hook
runtime and let the adapter produce the native effect.

## Runtime Factory

Create the runtime once per framework worker/application scope:

```python
def create_openbox_runtime(**config_overrides) -> OpenBoxRuntime:
    config = resolve_openbox_config(**config_overrides)
    runtime = OpenBoxRuntime(config, adapter=MyFrameworkAdapter())
    runtime.install_instrumentation()
    return runtime
```

Shutdown must uninstall instrumentation and close transports:

```python
runtime.close()
# or
await runtime.aclose()
```

Install instrumentation only where monkeypatching is safe. Do not install it
inside deterministic workflow code, import-time module globals, or framework
paths that forbid network or wall-clock behavior.

## Activity Context Mapping

Map framework execution state into `ActivityContext`. Keep framework-specific
extras in `metadata`.

```python
ctx = ActivityContext(
    workflow_id=framework_run.workflow_id,
    run_id=framework_run.run_id,
    workflow_type=framework_run.workflow_type,
    task_queue=framework_run.queue,
    activity_id=task.id,
    activity_type=task.name,
    activity_input=task.input,
    agent_name=agent.name,
    agent_role=agent.role,
    session_id=session.id,
    multi_agent_session_id=session.multi_agent_session_id,
    metadata={
        "attempt": task.attempt,
    },
)
```

Bind context around the real framework operation:

```python
with activity_scope(ctx, trace_id=current_trace_id, store=runtime.context_store):
    result = run_real_framework_operation()
```

Use `try/finally` or `activity_scope` so context and trace correlation always
reset, including when the framework operation raises.

## Lifecycle Events

Use event factories from `openbox_core.contracts.events`. Do not hand-build
wire dicts unless a test is intentionally covering malformed input.

```python
event = events.workflow_started(
    workflow_id=ctx.workflow_id or "",
    run_id=ctx.run_id or "",
    workflow_type=ctx.workflow_type or "",
    task_queue=ctx.task_queue,
    multi_agent_session_id=ctx.multi_agent_session_id,
)
runtime.evaluate_lifecycle(event)
```

Activity start/completion should use `activity_started(...)` and
`activity_completed(...)`. Signals should use `signal_received(...)`. Multi-agent
handoff should use `handoff(...)`.

For async framework paths, use `await runtime.aevaluate_lifecycle(event)` so
approval flow can be driven through the adapter.

## Generic Instrumentation

The base SDK already provides generic HTTP, DB, file, and function hooks. A
framework SDK usually only needs to:

- create the runtime,
- bind `ActivityContext`,
- call `runtime.install_instrumentation()` in safe worker/runtime setup,
- call `runtime.close()` or `await runtime.aclose()` during shutdown.

The base instrumentation handles started/completed hook emission, self-guarding
OpenBox Core API calls, flat span projection, body redaction/truncation, and
adapter delegation.

If a framework has native tool/task hooks that the generic wrappers cannot see,
build those hooks by producing `ActivityContext` and lifecycle events. Do not
duplicate `HookRuntime`, `GovernanceGate`, or wire payload assembly.

## Do Not Reimplement

Do not reimplement these base SDK responsibilities in a framework SDK:

- signed request canonicalization,
- API key validation calls,
- `EvaluationClient`,
- fail-open/fail-closed network policy,
- strict event validation,
- `EvaluationResult` or `ApprovalResult` parsing,
- flat hook `SpanData` projection,
- evaluate payload assembly,
- redaction/truncation behavior,
- generic HTTP/DB/file/function wrappers,
- conformance fake Core utilities.

When a framework needs different native behavior, adapt at `FrameworkAdapter` or
at lifecycle/context binding boundaries.

## Wire Contract Requirements

- Lifecycle event payloads are flat top-level fields.
- Hook evaluations serialize as `ActivityStarted` with `hook_trigger=true` and
  non-empty `spans`.
- Hook spans are flat Core `SpanData` dicts. Never emit nested `otel`,
  `openbox`, `data`, or debug envelope shapes.
- Wire IDs are lowercase hex strings: `span_id` has 16 chars, `trace_id` has 32
  chars, and `parent_span_id` has 16 chars when present.
- Started-stage spans must carry explicit `end_time: null` and
  `duration_ns: null`.
- Completed hooks never undo the operation that already ran; they only mark
  future execution state through the adapter/runtime.

## Signing Rules

Framework SDKs should not sign requests directly. If you touch the client path,
preserve these invariants:

- serialize once with `serialization.serialize_body`,
- hash the exact bytes sent,
- send via `content=body_bytes`,
- never use `json=` for signed requests,
- keep `httpx` and `cryptography` lazy-imported,
- never log private keys, raw Ed25519 seeds, signatures, or nonce material.

## Conformance Tests For New SDKs

Use the base conformance utilities instead of inventing a fake backend.

Useful imports:

```python
from openbox_core.conformance.fake_core import (
    FakeCore,
    assert_hook_wire_shape,
    fake_client,
)
from openbox_core.conformance.hook_preflight import (
    RecordingHookAdapter,
    build_conformance_runtime,
)
from openbox_core.conformance.instrumentation import (
    installed_conformance_runtime,
)
```

Recommended test coverage:

- config resolution with framework-specific `env_prefix`,
- pure import safety for framework package roots,
- lifecycle event emission and adapter enforcement,
- BLOCK/HALT mapping to native framework errors,
- REQUIRE_APPROVAL behavior for sync and async paths,
- fail-open and fail-closed network behavior,
- context binding and reset on success and exception,
- generic instrumentation install/uninstall lifecycle,
- HTTP/DB/file/function preflight blocking where applicable,
- flat hook wire shape with `assert_hook_wire_shape`,
- completed-hook stop verdict affects future work only.

Run the base SDK tests that match any changed contract or dependency surface:

- import safety: `tests/test_import_safety.py`
- signing/client behavior: `tests/signing/` and `tests/client/`
- contracts/gate behavior: `tests/contracts/` and `tests/gate/`
- wire payloads: `tests/wire/`
- instrumentation: `tests/instrumentation/`
- conformance matrix: `tests/conformance/test_required_cases.py`

## Framework SDK Shape

A minimal framework SDK usually has files like:

```text
openbox_myframework/
  __init__.py              # light exports only
  config.py                # framework config -> OpenBoxConfig
  adapter.py               # FrameworkAdapter implementation
  runtime.py               # create/close runtime helpers
  context.py               # framework object -> ActivityContext mapping
  lifecycle.py             # lifecycle event emission helpers
  instrumentation.py       # framework-specific install hooks, if needed
tests/
  test_import_safety.py
  test_config.py
  test_lifecycle.py
  test_adapter.py
  test_conformance.py
```

Keep package roots import-safe. Heavy setup belongs in runtime factories or
explicit install functions, not in module import side effects.

## Style

- Prefer adapter-first integration over base-SDK edits.
- Add a base-SDK change only when the framework exposes a shared gap that other
  SDKs will also need.
- Keep comments focused on active invariants and non-obvious safety constraints.
  Avoid migration history, roadmap notes, project comparisons, or personal
  decision records in code comments.
- Preserve unrelated local changes.
