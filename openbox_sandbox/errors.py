from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class SandboxErrorCode(str, Enum):
    PROFILE_REJECTED = "profile_rejected"
    SANDBOX_DISABLED = "sandbox_disabled"
    SANDBOX_CREATE = "sandbox_create_failed"
    SANDBOX_READINESS = "sandbox_readiness_failed"
    SANDBOX_EXEC_NOT_DISPATCHED = "sandbox_exec_not_dispatched"
    SANDBOX_EXEC_INDETERMINATE = "sandbox_exec_indeterminate"
    SANDBOX_PROTOCOL = "sandbox_protocol_failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class NormalizedSandboxError:
    code: SandboxErrorCode

    def to_wire(self) -> dict[str, str]:
        return {"code": self.code.value}


class SandboxValidationError(ValueError):
    def __init__(self) -> None:
        super().__init__("sandbox command rejected")


class ProfileValidationError(ValueError):
    def __init__(self) -> None:
        super().__init__("command profile bundle rejected")


class GovernedCommandDeploymentError(ValueError):
    def __init__(self) -> None:
        super().__init__("governed-command deployment rejected")
