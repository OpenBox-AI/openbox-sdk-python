"""ActivityContext dataclass and ActivityContextProvider protocol.

Pure, import-safe module. The base SDK owns THE context shape; framework SDKs
populate it (they do not define competing context types). Core instrumentation
reads the bound context without knowing the framework.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

__all__ = ["ActivityContext", "ActivityContextProvider"]


@dataclass(frozen=True)
class ActivityContext:
    """The framework-agnostic activity/task execution context.

    Immutable — per-operation deltas go in ``metadata`` or a freshly bound
    context, never mutation. Framework-specific extras that have no first-class
    field here belong in ``metadata``.
    """

    workflow_id: str | None = None
    run_id: str | None = None
    workflow_type: str | None = None
    task_queue: str | None = None
    activity_id: str | None = None
    activity_type: str | None = None
    activity_input: Any = None
    agent_name: str | None = None
    agent_role: str | None = None
    session_id: str | None = None
    multi_agent_session_id: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_payload_fields(self) -> dict[str, Any]:
        """Flat wire fields for hook payload assembly (omit-when-absent).

        ``metadata`` entries merge at the top level last, but never overwrite
        first-class fields.
        """
        fields_map = {
            "workflow_id": self.workflow_id,
            "run_id": self.run_id,
            "workflow_type": self.workflow_type,
            "task_queue": self.task_queue,
            "activity_id": self.activity_id,
            "activity_type": self.activity_type,
            "activity_input": self.activity_input,
            "agent_name": self.agent_name,
            "agent_role": self.agent_role,
            "session_id": self.session_id,
            "multi_agent_session_id": self.multi_agent_session_id,
        }
        payload = {k: v for k, v in fields_map.items() if v is not None}
        for key, value in self.metadata.items():
            payload.setdefault(str(key), value)
        return payload


@runtime_checkable
class ActivityContextProvider(Protocol):
    """How core instrumentation resolves the bound context.

    Implemented by ``openbox_core.context.ContextStore``; frameworks may plug
    a custom provider as long as registration and lookup share the SAME
    canonical trace key.
    """

    def current_activity_context(self) -> ActivityContext | None:
        """The context bound to the current execution flow (or None)."""
        ...

    def context_for_trace(self, trace_id: int) -> ActivityContext | None:
        """The context registered for an OTel trace id (or None)."""
        ...
