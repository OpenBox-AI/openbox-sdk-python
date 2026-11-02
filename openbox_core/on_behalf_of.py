"""The end user an agent is acting for.

OpenBox information barriers check every principal behind an action: the
agent and the person it acts on behalf of. Set that person once per request
or session and every governance event sent inside the context carries it::

    from openbox_core import on_behalf_of

    with on_behalf_of("amy@firm.example"):
        graph.invoke(...)

The value must be the user's directory identity (email or IdP subject) as it
appears in the organisation's barrier memberships. It can only narrow what an
agent may touch: Core requires every principal present to pass every wall.

Stdlib only, so ``import openbox_core`` stays side-effect free.
"""

from __future__ import annotations

import contextvars
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

DEFAULT_SOURCE = "sdk"

_current: contextvars.ContextVar[dict[str, str] | None] = contextvars.ContextVar(
    "openbox_on_behalf_of", default=None
)


def set_on_behalf_of(user: str | None, source: str = DEFAULT_SOURCE) -> contextvars.Token:
    """Set the on-behalf-of user for the current context. ``None`` or an empty
    string clears it. Returns a token for :func:`reset_on_behalf_of`."""
    value = (user or "").strip()
    return _current.set({"user": value, "source": source} if value else None)


def reset_on_behalf_of(token: contextvars.Token) -> None:
    _current.reset(token)


def current_on_behalf_of() -> dict[str, str] | None:
    """The ``on_behalf_of`` object for the current context, or ``None``."""
    value = _current.get()
    return dict(value) if value else None


@contextmanager
def on_behalf_of(user: str | None, source: str = DEFAULT_SOURCE) -> Iterator[None]:
    """Scope governance events in this block to ``user``."""
    token = set_on_behalf_of(user, source)
    try:
        yield
    finally:
        reset_on_behalf_of(token)


def apply_on_behalf_of(payload: dict[str, Any]) -> dict[str, Any]:
    """Add the context's ``on_behalf_of`` to an evaluate payload. A value the
    caller already put on the payload wins."""
    if payload.get("on_behalf_of"):
        return payload
    value = current_on_behalf_of()
    if value is None:
        return payload
    return {**payload, "on_behalf_of": value}
