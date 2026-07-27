from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from openbox_core.contracts.context import ActivityContext

from .errors import SandboxValidationError


def _identifier(value: object) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 512:
        raise SandboxValidationError()
    return value


@dataclass(frozen=True, slots=True, repr=False, init=False)
class SandboxCommand:
    """One profile-derived command bound to the canonical ActivityContext."""

    context: ActivityContext
    argv: tuple[str, ...]
    profile_id: str
    timeout_seconds: int

    def __init__(
        self,
        *,
        context: ActivityContext,
        argv: Sequence[str],
        profile_id: str,
        timeout_seconds: int = 30,
    ) -> None:
        if not isinstance(context, ActivityContext):
            raise SandboxValidationError()
        for value in (context.workflow_id, context.run_id, context.activity_id):
            _identifier(value)
        if isinstance(argv, (str, bytes, bytearray, Mapping)):
            raise SandboxValidationError()
        try:
            snapshot = tuple(argv)
        except TypeError as error:
            raise SandboxValidationError() from error
        attempt = context.metadata.get("attempt", 1)
        if (
            not snapshot
            or not all(isinstance(value, str) and "\x00" not in value for value in snapshot)
            or sum(len(value.encode("utf-8")) for value in snapshot) > 1024 * 1024
            or type(attempt) is not int
            or attempt != 1
            or isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, int)
            or not 1 <= timeout_seconds <= 300
        ):
            raise SandboxValidationError()
        object.__setattr__(self, "context", context)
        object.__setattr__(self, "argv", snapshot)
        object.__setattr__(self, "profile_id", _identifier(profile_id))
        object.__setattr__(self, "timeout_seconds", timeout_seconds)

    @property
    def workflow_id(self) -> str:
        assert self.context.workflow_id is not None
        return self.context.workflow_id

    @property
    def run_id(self) -> str:
        assert self.context.run_id is not None
        return self.context.run_id

    @property
    def activity_id(self) -> str:
        assert self.context.activity_id is not None
        return self.context.activity_id

    @property
    def workflow_type(self) -> str:
        return self.context.workflow_type or "generic"

    @property
    def task_queue(self) -> str:
        return self.context.task_queue or "generic"

    @property
    def attempt(self) -> int:
        return 1

    def __repr__(self) -> str:
        return (
            "SandboxCommand("
            f"workflow_id={self.workflow_id!r}, run_id={self.run_id!r}, "
            f"activity_id={self.activity_id!r}, profile_id={self.profile_id!r}, "
            f"argv=<redacted>, argv_count={len(self.argv)}, "
            f"timeout_seconds={self.timeout_seconds})"
        )
