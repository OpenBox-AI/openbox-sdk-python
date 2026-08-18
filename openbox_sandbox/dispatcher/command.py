from __future__ import annotations

import hashlib
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .errors import DispatcherValidationError


def _identifier(value: object) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 512:
        raise DispatcherValidationError()
    return value


def _dispatch_id(
    value: object | None,
    *,
    workflow_id: str,
    run_id: str,
    activity_id: str,
    attempt: int,
    profile_id: str,
) -> str:
    if value is None:
        identity = "\0".join(
            (
                "openbox.sandbox.dispatch.v1",
                workflow_id,
                run_id,
                activity_id,
                str(attempt),
                profile_id,
            )
        ).encode("utf-8")
        digest = hashlib.sha256(identity).digest()
        # The durable PROD-250 boundary admits canonical RFC 4122 UUIDv4 IDs.
        # Set the version/variant bits on deterministic digest bytes so retries
        # can reconstruct the same identity without weakening that contract.
        return str(uuid.UUID(bytes=digest[:16], version=4))
    try:
        parsed = uuid.UUID(value) if isinstance(value, str) else None
    except ValueError as error:
        raise DispatcherValidationError() from error
    if (
        parsed is None
        or parsed.version != 4
        or parsed.variant != uuid.RFC_4122
        or str(parsed) != value
    ):
        raise DispatcherValidationError()
    return value


def _parent_span_id(value: object) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or len(value) != 16
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise DispatcherValidationError()
    return value


@dataclass(frozen=True, slots=True, repr=False, init=False)
class GovernedCommand:
    workflow_id: str
    run_id: str
    activity_id: str
    dispatch_id: str
    argv: tuple[str, ...]
    profile_id: str
    timeout_seconds: int
    workflow_type: str
    task_queue: str
    attempt: int
    arguments: Mapping[str, Any]
    parent_span_id: str | None

    def __init__(
        self,
        *,
        workflow_id: str,
        run_id: str,
        activity_id: str,
        argv: Sequence[str],
        profile_id: str,
        dispatch_id: str | None = None,
        timeout_seconds: int = 30,
        workflow_type: str = "generic",
        task_queue: str = "generic",
        attempt: int = 1,
        arguments: Mapping[str, Any] | None = None,
        parent_span_id: str | None = None,
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
            or attempt < 1
        ):
            raise DispatcherValidationError()
        validated_workflow_id = _identifier(workflow_id)
        validated_run_id = _identifier(run_id)
        validated_activity_id = _identifier(activity_id)
        validated_profile_id = _identifier(profile_id)
        object.__setattr__(self, "workflow_id", validated_workflow_id)
        object.__setattr__(self, "run_id", validated_run_id)
        object.__setattr__(self, "activity_id", validated_activity_id)
        object.__setattr__(
            self,
            "dispatch_id",
            _dispatch_id(
                dispatch_id,
                workflow_id=validated_workflow_id,
                run_id=validated_run_id,
                activity_id=validated_activity_id,
                attempt=attempt,
                profile_id=validated_profile_id,
            ),
        )
        object.__setattr__(self, "argv", snapshot)
        object.__setattr__(self, "profile_id", validated_profile_id)
        object.__setattr__(self, "timeout_seconds", timeout_seconds)
        object.__setattr__(self, "workflow_type", _identifier(workflow_type))
        object.__setattr__(self, "task_queue", _identifier(task_queue))
        object.__setattr__(self, "attempt", attempt)
        object.__setattr__(self, "arguments", dict(arguments or {}))
        object.__setattr__(self, "parent_span_id", _parent_span_id(parent_span_id))

    def __repr__(self) -> str:
        return (
            "GovernedCommand("
            f"workflow_id={self.workflow_id!r}, run_id={self.run_id!r}, "
            f"activity_id={self.activity_id!r}, dispatch_id={self.dispatch_id!r}, "
            f"profile_id={self.profile_id!r}, "
            f"argv=<redacted>, argv_count={len(self.argv)}, "
            f"timeout_seconds={self.timeout_seconds})"
        )
