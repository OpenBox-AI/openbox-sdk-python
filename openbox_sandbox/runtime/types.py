from __future__ import annotations

import base64
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from .errors import ProtocolValidationError

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_COMPATIBILITY = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_MEDIA_TYPE = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,63}/"
    r"[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,63}\Z"
)
_MAX_POLICY_DOCUMENT_BYTES = 1024 * 1024
_MAX_STDOUT_BYTES = 1024 * 1024
_MAX_STDERR_BYTES = 1024 * 1024
_MAX_COMBINED_BYTES = 2 * 1024 * 1024
_MAX_CHUNK_BYTES = 4 * 1024 * 1024
_MAX_ARGV_BYTES = 1024 * 1024


def _sha256(value: object) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ProtocolValidationError()
    return value


def _uuid4(value: object) -> str:
    if not isinstance(value, str):
        raise ProtocolValidationError()
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as error:
        raise ProtocolValidationError() from error
    if parsed.version != 4 or parsed.variant != uuid.RFC_4122 or str(parsed) != value:
        raise ProtocolValidationError()
    return value


def request_owned_id(value: str) -> str:
    if not isinstance(value, str) or not value.startswith("sbx-") or len(value) != 40:
        raise ProtocolValidationError()
    _uuid4(value[4:])
    return value


def operation_id() -> str:
    return str(uuid.uuid4())


def capability_token(value: str) -> str:
    return _uuid4(value)


@dataclass(frozen=True, slots=True)
class PolicyIdentity:
    id: str
    version: int
    sha256: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.id, str)
            or _COMPATIBILITY.fullmatch(self.id) is None
            or type(self.version) is not int
            or not 1 <= self.version <= 2**32 - 1
        ):
            raise ProtocolValidationError()
        _sha256(self.sha256)

    def to_wire(self) -> dict[str, Any]:
        return {"id": self.id, "version": self.version, "sha256": self.sha256}


@dataclass(frozen=True, slots=True)
class AssetBundleIdentity:
    runtime_contract_version: int
    adapter_build_sha256: str
    template: str
    policy: PolicyIdentity
    compatibility_id: str

    def __post_init__(self) -> None:
        if (
            type(self.runtime_contract_version) is not int
            or not 1 <= self.runtime_contract_version <= 2**32 - 1
            or not isinstance(self.template, str)
            or not self.template
            or len(self.template.encode("utf-8")) > 4096
            or "\x00" in self.template
            or not isinstance(self.policy, PolicyIdentity)
        ):
            raise ProtocolValidationError()
        _sha256(self.adapter_build_sha256)
        if not isinstance(self.compatibility_id, str) or not _COMPATIBILITY.fullmatch(
            self.compatibility_id
        ):
            raise ProtocolValidationError()

    def to_wire(self) -> dict[str, Any]:
        return {
            "runtime_contract_version": self.runtime_contract_version,
            "adapter_build_sha256": self.adapter_build_sha256,
            "template": self.template,
            "policy": self.policy.to_wire(),
            "compatibility_id": self.compatibility_id,
        }


@dataclass(frozen=True, slots=True)
class PolicyDocument:
    media_type: str
    document: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.media_type, str)
            or _MEDIA_TYPE.fullmatch(self.media_type) is None
            or type(self.document) is not bytes
            or not self.document
            or len(self.document) > _MAX_POLICY_DOCUMENT_BYTES
        ):
            raise ProtocolValidationError()

    def to_wire(self) -> dict[str, Any]:
        return {
            "media_type": self.media_type,
            "document_base64": base64.b64encode(self.document).decode("ascii"),
        }


@dataclass(frozen=True, slots=True)
class CreateRequest:
    request_id: str
    template: str
    policy_document: PolicyDocument
    expected_policy: PolicyIdentity

    def __post_init__(self) -> None:
        request_owned_id(self.request_id)
        if (
            not isinstance(self.template, str)
            or not self.template
            or len(self.template.encode("utf-8")) > 4096
            or "\x00" in self.template
            or not isinstance(self.policy_document, PolicyDocument)
            or not isinstance(self.expected_policy, PolicyIdentity)
        ):
            raise ProtocolValidationError()

    def to_wire(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "template": self.template,
            "policy_document": self.policy_document.to_wire(),
            "expected_policy": self.expected_policy.to_wire(),
        }


@dataclass(frozen=True, slots=True)
class OutputLimits:
    stdout_bytes: int
    stderr_bytes: int
    combined_bytes: int
    chunk_bytes: int

    def __post_init__(self) -> None:
        values = (
            self.stdout_bytes,
            self.stderr_bytes,
            self.combined_bytes,
            self.chunk_bytes,
        )
        maxima = (
            _MAX_STDOUT_BYTES,
            _MAX_STDERR_BYTES,
            _MAX_COMBINED_BYTES,
            _MAX_CHUNK_BYTES,
        )
        if any(type(value) is not int for value in values) or any(
            not 1 <= value <= maximum for value, maximum in zip(values, maxima)
        ):
            raise ProtocolValidationError()

    def to_wire(self) -> dict[str, int]:
        return {
            "stdout_bytes": self.stdout_bytes,
            "stderr_bytes": self.stderr_bytes,
            "combined_bytes": self.combined_bytes,
            "chunk_bytes": self.chunk_bytes,
        }


@dataclass(frozen=True, slots=True, repr=False)
class ExecRequest:
    argv: tuple[str, ...]
    timeout: int
    output_limits: OutputLimits

    def __init__(
        self,
        argv: Sequence[str],
        timeout: int,
        output_limits: OutputLimits,
    ) -> None:
        values = tuple(argv)
        if (
            not values
            or type(timeout) is not int
            or not 1 <= timeout <= 300
            or not isinstance(output_limits, OutputLimits)
            or not all(isinstance(value, str) and "\x00" not in value for value in values)
            or sum(len(value.encode("utf-8")) for value in values) > _MAX_ARGV_BYTES
        ):
            raise ProtocolValidationError()
        object.__setattr__(self, "argv", values)
        object.__setattr__(self, "timeout", timeout)
        object.__setattr__(self, "output_limits", output_limits)

    def __repr__(self) -> str:
        return (
            "ExecRequest(argv=<redacted>, "
            f"argv_count={len(self.argv)}, timeout={self.timeout}, "
            f"output_limits={self.output_limits!r})"
        )

    def to_wire(self) -> dict[str, Any]:
        return {
            "argv": list(self.argv),
            "timeout": self.timeout,
            "output_limits": self.output_limits.to_wire(),
        }


@dataclass(frozen=True, slots=True, repr=False)
class ExecCompleted:
    exit_code: int
    stdout: bytes
    stderr: bytes
    timeout: str

    def __repr__(self) -> str:
        return (
            f"ExecCompleted(exit_code={self.exit_code}, "
            f"stdout_bytes={len(self.stdout)}, stderr_bytes={len(self.stderr)}, "
            f"timeout={self.timeout!r})"
        )

    @classmethod
    def from_wire(cls, value: Mapping[str, Any]) -> ExecCompleted:
        if set(value) != {"exit_code", "stdout_base64", "stderr_base64", "timeout"}:
            raise ProtocolValidationError()
        exit_code = value["exit_code"]
        timeout = value["timeout"]
        if type(exit_code) is not int or not 0 <= exit_code <= 2**31 - 1:
            raise ProtocolValidationError()
        if timeout not in {"not_observed", "confirmed", "possible"}:
            raise ProtocolValidationError()
        try:
            stdout = base64.b64decode(value["stdout_base64"], validate=True)
            stderr = base64.b64decode(value["stderr_base64"], validate=True)
        except (ValueError, TypeError) as error:
            raise ProtocolValidationError() from error
        return cls(exit_code=exit_code, stdout=stdout, stderr=stderr, timeout=timeout)


@dataclass(frozen=True, slots=True)
class ServiceResponse:
    response: str
    fields: Mapping[str, Any]

    def __post_init__(self) -> None:
        if not isinstance(self.response, str) or not isinstance(self.fields, Mapping):
            raise ProtocolValidationError()
