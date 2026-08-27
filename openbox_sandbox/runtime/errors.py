from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class SubmissionState(str, Enum):
    NOT_SUBMITTED = "not_submitted"
    POSSIBLY_SUBMITTED = "possibly_submitted"


class TransportFailureCode(str, Enum):
    AUTHENTICATION = "authentication"
    CANCELLED = "cancelled"
    DEADLINE = "deadline"
    PROTOCOL = "protocol"
    TRANSPORT = "transport"


@dataclass(frozen=True, slots=True)
class SandboxServiceTransportError(Exception):
    submission_state: SubmissionState
    code: TransportFailureCode

    def __str__(self) -> str:
        return "sandbox service transport failed"


class ProtocolValidationError(ValueError):
    def __init__(self) -> None:
        super().__init__("sandbox service protocol value rejected")
