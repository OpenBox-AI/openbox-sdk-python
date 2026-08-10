from __future__ import annotations

import base64
import copy
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from .errors import NormalizedDispatchError


class Disposition(str, Enum):
    EXECUTED_ON_HOST = "executed_on_host"
    EXECUTED_IN_SANDBOX = "executed_in_sandbox"
    NOT_EXECUTED = "not_executed"
    EXECUTION_INDETERMINATE = "execution_indeterminate"


class Directive(str, Enum):
    CONTINUE = "continue"
    HALT = "halt"


class TimeoutStatus(str, Enum):
    NOT_OBSERVED = "not_observed"
    CONFIRMED_TIMEOUT = "confirmed_timeout"
    POSSIBLE_TIMEOUT = "possible_timeout"
    UNKNOWN = "unknown"


class CleanupStatus(str, Enum):
    NOT_NEEDED = "not_needed"
    DELETED = "deleted"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class CleanupReconciliationResult:
    attempted: int
    deleted: int
    remaining: int


@dataclass(frozen=True, slots=True, repr=False)
class ExecutionMetadata:
    sandbox_id: str | None
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    timeout_status: TimeoutStatus
    cleanup_status: CleanupStatus

    def __post_init__(self) -> None:
        if not isinstance(self.stdout, bytes) or not isinstance(self.stderr, bytes):
            raise TypeError("execution output must be bytes")

    def __repr__(self) -> str:
        return (
            "ExecutionMetadata("
            f"sandbox_id={self.sandbox_id!r}, exit_code={self.exit_code!r}, "
            f"stdout_bytes={len(self.stdout)}, stderr_bytes={len(self.stderr)}, "
            f"timeout_status={self.timeout_status.value!r}, "
            f"cleanup_status={self.cleanup_status.value!r}, output=<redacted>)"
        )

    def to_wire(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "exit_code": self.exit_code,
            "stdout_base64": base64.b64encode(self.stdout).decode("ascii"),
            "stderr_base64": base64.b64encode(self.stderr).decode("ascii"),
            "timeout_status": self.timeout_status.value,
            "cleanup_status": self.cleanup_status.value,
        }
        if self.sandbox_id is not None:
            value["sandbox_id"] = self.sandbox_id
            value["sandbox_name"] = self.sandbox_id
        return value


@dataclass(frozen=True, slots=True, repr=False)
class DispatchResult:
    disposition: Disposition
    directive: Directive
    execution: ExecutionMetadata | None
    error: NormalizedDispatchError | None
    _governance: Mapping[str, Any] | None

    @property
    def governance(self) -> dict[str, Any] | None:
        return None if self._governance is None else copy.deepcopy(dict(self._governance))

    def __repr__(self) -> str:
        return (
            f"DispatchResult(disposition={self.disposition.value!r}, "
            f"directive={self.directive.value!r}, execution={self.execution!r}, "
            f"error={self.error!r}, governance=<preserved>)"
        )

    def to_wire(self) -> dict[str, Any]:
        return {
            "governance": self.governance,
            "disposition": self.disposition.value,
            "directive": self.directive.value,
            "execution": None if self.execution is None else self.execution.to_wire(),
            "error": None if self.error is None else self.error.to_wire(),
        }
