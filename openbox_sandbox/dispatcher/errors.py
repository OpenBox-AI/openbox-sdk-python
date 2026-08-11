from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class DispatchErrorCode(str, Enum):
    INVALID_COMMAND = "invalid_command"
    PROFILE_REJECTED = "profile_rejected"
    GOVERNANCE_TRANSPORT = "governance_transport"
    GOVERNANCE_PROTOCOL = "governance_protocol"
    GOVERNANCE_FALLBACK = "governance_fallback"
    UNSUPPORTED_CONSTRAINT = "unsupported_constraint"
    REMEDIATION_UNSUPPORTED = "remediation_unsupported"
    APPROVAL_REQUIRED = "approval_required"
    BLOCKED = "blocked"
    HALTED = "halted"
    SANDBOX_DISABLED = "sandbox_disabled"
    SANDBOX_CREATE = "sandbox_create_failed"
    SANDBOX_READINESS = "sandbox_readiness_failed"
    SANDBOX_EXEC_NOT_DISPATCHED = "sandbox_exec_not_dispatched"
    SANDBOX_EXEC_INDETERMINATE = "sandbox_exec_indeterminate"
    SANDBOX_PROTOCOL = "sandbox_protocol_failed"
    HOST_EXEC_INDETERMINATE = "host_exec_indeterminate"
    HOST_OUTPUT_LIMIT = "host_output_limit"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class NormalizedDispatchError:
    code: DispatchErrorCode
    detail: str | None = None

    def to_wire(self) -> dict[str, str]:
        wire: dict[str, str] = {"code": self.code.value}
        if self.detail:
            wire["detail"] = self.detail
        return wire


class DispatcherValidationError(ValueError):
    def __init__(self) -> None:
        super().__init__("governed command rejected")


class ProfileValidationError(ValueError):
    def __init__(self) -> None:
        super().__init__("command profile bundle rejected")


class GovernanceProtocolError(ValueError):
    def __init__(self) -> None:
        super().__init__("governance protocol rejected")


class GovernanceTransportError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("governance transport failed")
