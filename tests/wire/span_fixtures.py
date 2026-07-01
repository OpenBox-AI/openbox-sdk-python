"""Shared fake-OTel-span fixtures (duck-typed — no opentelemetry import)."""

from dataclasses import dataclass, field
from typing import Any

SPAN_ID = 0x00F067AA0BA902B7
TRACE_ID = 0x4BF92F3577B34DA6A3CE929D0E0E4736
PARENT_ID = 0x00F067AA0BA90200


@dataclass
class FakeSpanContext:
    span_id: int = SPAN_ID
    trace_id: int = TRACE_ID


@dataclass
class FakeParent:
    span_id: int = PARENT_ID


@dataclass
class FakeStatus:
    status_code: str = "UNSET"
    description: str | None = None


class FakeKind:
    name = "CLIENT"


@dataclass
class FakeSpan:
    """Duck-typed stand-in for an OTel ReadableSpan."""

    name: str = "HTTP GET"
    kind: Any = field(default_factory=FakeKind)
    start_time: int = 1_760_000_000_000_000_000
    end_time: int | None = 1_760_000_000_500_000_000
    attributes: dict = field(default_factory=dict)
    parent: Any = field(default_factory=FakeParent)
    status: Any = field(default_factory=FakeStatus)
    events: tuple = ()
    links: tuple = ()
    resource: Any = None
    instrumentation_scope: Any = None
    _context: Any = field(default_factory=FakeSpanContext)

    def get_span_context(self):
        return self._context
