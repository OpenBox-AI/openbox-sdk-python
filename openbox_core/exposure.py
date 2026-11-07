"""What an action touches and who it reaches, for exposure barriers.

Core's barrier check needs four facts about every governed action: which
matter or tenant the agent is working for (``scope``), what the action does
(``action_class``), which labelled objects it touches (``resources``) and who
it reaches (``participants``). Set the scope once per session and describe
each action as it happens::

    from openbox_core import Participant, Resource, exposure_scope, governed_action

    with exposure_scope("matter:2026-0417"):
        with governed_action(
            "send",
            resources=[Resource("dms://doc/17", ["client:coke"], "source_system")],
            participants=[Participant("destination", "mailbox:r1@firm.example")],
        ):
            send_email(...)

Every governance event sent inside the block carries the fields. Values the
caller already put on a payload win. Labels are opaque ``namespace:value``
strings from the source system; Core treats a resource with no labels as
Unknown. The agent is never told which label caused a refusal.

Stdlib only, so ``import openbox_core`` stays side-effect free.
"""

from __future__ import annotations

import contextvars
import hashlib
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

#: Action classes Core understands (spec §7.2). Anything else is refused.
ACTION_CLASSES = frozenset(
    {
        "retrieve",
        "read",
        "generate",
        "send",
        "file",
        "write",
        "external_call",
        "memory_write",
        "memory_read",
        "handoff",
        "handoff_return",
    }
)

#: Principal kinds a participant may claim. Core trusts a claimed kind only
#: where the organisation's registry agrees; an unregistered destination is
#: public.
PARTICIPANT_KINDS = frozenset(
    {
        "person",
        "agent_session",
        "memory_store",
        "store",
        "hub",
        "destination",
        "stateless_processor",
        "trusted_sink",
    }
)

#: Where a resource's labels came from (spec §6, ``ObjectRef.label_source``).
LABEL_SOURCES = frozenset({"source_system", "executor_metadata", "sdk_declared", "cast"})


@dataclass(frozen=True, init=False)
class Resource:
    """One object the action touches, with the labels its source declared."""

    uri: str
    labels: tuple[str, ...] = field(default_factory=tuple)
    label_source: str = "sdk_declared"

    def __init__(self, uri: str, labels: Iterable[str] = (), label_source: str = "sdk_declared"):
        uri = (uri or "").strip()
        if not uri:
            raise ValueError("resource uri is required")
        if label_source not in LABEL_SOURCES:
            raise ValueError(f"unknown label_source {label_source!r}")
        cleaned = []
        for label in labels:
            label = (label or "").strip()
            if label and label not in cleaned:
                cleaned.append(label)
        object.__setattr__(self, "uri", uri)
        object.__setattr__(self, "labels", tuple(cleaned))
        object.__setattr__(self, "label_source", label_source)

    def to_wire(self) -> dict[str, Any]:
        out: dict[str, Any] = {"uri": self.uri, "label_source": self.label_source}
        if self.labels:
            out["labels"] = list(self.labels)
        return out


@dataclass(frozen=True)
class Participant:
    """A principal the action reaches: a recipient, a store, a sub-agent."""

    kind: str
    id: str

    def __post_init__(self) -> None:
        if self.kind not in PARTICIPANT_KINDS:
            raise ValueError(f"unknown participant kind {self.kind!r}")
        if not (self.id or "").strip():
            raise ValueError("participant id is required")
        object.__setattr__(self, "id", self.id.strip())

    def to_wire(self) -> dict[str, str]:
        return {"kind": self.kind, "id": self.id}


_scope: contextvars.ContextVar[dict[str, str] | None] = contextvars.ContextVar(
    "openbox_exposure_scope", default=None
)
_action: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar(
    "openbox_governed_action", default=None
)


@contextmanager
def exposure_scope(
    scope: str | None, purpose: str | None = None, instance_id: str | None = None
) -> Iterator[None]:
    """Scope governance events in this block to one matter or tenant.

    Core keeps one exposure history per agent and scope, so an agent working
    two matters in two scopes is two principals. ``purpose`` is checked
    against the purposes registered for the agent, never trusted as declared.
    ``instance_id`` runs the block as a clean instance core issued
    (:meth:`EvaluationClient.request_clean_instance`); an id core did not
    issue is refused.
    """
    value: dict[str, str] = {}
    if (scope or "").strip():
        value["scope"] = scope.strip()
    if (purpose or "").strip():
        value["purpose"] = purpose.strip()
    if (instance_id or "").strip():
        value["instance_id"] = instance_id.strip()
    token = _scope.set(value or None)
    try:
        yield
    finally:
        _scope.reset(token)


def hash_payload(data: bytes | str) -> str:
    """The ``payload_hash`` of an outbound call body: ``sha256:<hex>``. A
    verdict-bound Executor computes the same hash from the call it relays."""
    raw = data.encode() if isinstance(data, str) else bytes(data)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


@contextmanager
def governed_action(
    action_class: str,
    resources: Iterable[Resource] = (),
    participants: Iterable[Participant] = (),
    payload_hash: str | None = None,
) -> Iterator[None]:
    """Describe the action the governance events in this block gate.

    ``payload_hash`` (see :func:`hash_payload`) binds the call: an allowed
    action then returns ``EvaluationResult.verdict_token`` for a
    verdict-bound Executor."""
    if action_class not in ACTION_CLASSES:
        raise ValueError(f"unknown action_class {action_class!r}")
    value = {
        "action_class": action_class,
        "resources": [r.to_wire() for r in resources],
        "participants": [p.to_wire() for p in participants],
    }
    if (payload_hash or "").strip():
        value["payload_hash"] = payload_hash.strip()
    token = _action.set(value)
    try:
        yield
    finally:
        _action.reset(token)


def current_exposure_fields() -> dict[str, Any]:
    """The exposure fields for the current context (possibly empty)."""
    out: dict[str, Any] = {}
    scope = _scope.get()
    if scope:
        out.update(scope)
    action = _action.get()
    if action:
        out["action_class"] = action["action_class"]
        if action["resources"]:
            out["resources"] = [dict(r) for r in action["resources"]]
        if action["participants"]:
            out["participants"] = [dict(p) for p in action["participants"]]
        if action.get("payload_hash"):
            out["payload_hash"] = action["payload_hash"]
    return out


def apply_exposure(payload: dict[str, Any]) -> dict[str, Any]:
    """Add the context's exposure fields to an evaluate payload. Fields the
    caller already set win, one by one."""
    fields = current_exposure_fields()
    missing = {k: v for k, v in fields.items() if not payload.get(k)}
    if not missing:
        return payload
    return {**payload, **missing}
