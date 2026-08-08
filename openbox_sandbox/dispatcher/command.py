from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .errors import DispatcherValidationError


def _identifier(value: object) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 512:
        raise DispatcherValidationError()
    return value


@dataclass(frozen=True, slots=True, repr=False, init=False)
class GovernedCommand:
    workflow_id: str
    run_id: str
    activity_id: str
    argv: tuple[str, ...]
    profile_id: str
    timeout_seconds: int
    workflow_type: str
    task_queue: str
    attempt: int
    arguments: Mapping[str, Any]

    def __init__(
        self,
        *,
        workflow_id: str,
        run_id: str,
        activity_id: str,
        argv: Sequence[str],
        profile_id: str,
        timeout_seconds: int = 30,
        workflow_type: str = "generic",
        task_queue: str = "generic",
        attempt: int = 1,
        arguments: Mapping[str, Any] | None = None,
    ) -> None:
        if isinstance(argv, (str, bytes, bytearray, Mapping)):
            raise DispatcherValidationError()
        try:
            snapshot = tuple(argv)
        except TypeError as error:
            raise DispatcherValidationError() from error
        if (
            not snapshot
            or not all(isinstance(value, str) for value in snapshot)
            or sum(len(value.encode("utf-8")) for value in snapshot) > 1024 * 1024
            or isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, int)
            or not 1 <= timeout_seconds <= 300
            or type(attempt) is not int
            or attempt != 1
        ):
            raise DispatcherValidationError()
        object.__setattr__(self, "workflow_id", _identifier(workflow_id))
        object.__setattr__(self, "run_id", _identifier(run_id))
        object.__setattr__(self, "activity_id", _identifier(activity_id))
        object.__setattr__(self, "argv", snapshot)
        object.__setattr__(self, "profile_id", _identifier(profile_id))
        object.__setattr__(self, "timeout_seconds", timeout_seconds)
        object.__setattr__(self, "workflow_type", _identifier(workflow_type))
        object.__setattr__(self, "task_queue", _identifier(task_queue))
        object.__setattr__(self, "attempt", 1)
        object.__setattr__(self, "arguments", dict(arguments or {}))

    def __repr__(self) -> str:
        return (
            "GovernedCommand("
            f"workflow_id={self.workflow_id!r}, run_id={self.run_id!r}, "
            f"activity_id={self.activity_id!r}, profile_id={self.profile_id!r}, "
            f"argv=<redacted>, argv_count={len(self.argv)}, "
            f"timeout_seconds={self.timeout_seconds})"
        )
