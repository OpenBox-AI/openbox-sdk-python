"""Typed Unix-domain-socket client for the local OpenBox sandbox agent.

The local agent is an authenticated executor adapter only. This client speaks
a strict typed handshake (Hello/HelloAck) and then exactly one existing typed
service request per connection; the agent reconstructs the unchanged TCP mTLS
``RequestEnvelope`` and forwards it to sandbox-service. The agent never calls
Core, never derives argv, never chooses a policy or profile, and never retries
execution.

Discovery is internal and deterministic (standard per-user OS runtime
directories); there is no OpenBox environment selector. The trust boundary is
the operating-system user: socket ownership, file modes, and peer credentials
are all validated against the current UID, and a hostile same-UID process is
inside that boundary by design.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import socket
import stat
import struct
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

from .client import MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, PROTOCOL_VERSION
from .errors import (
    ProtocolValidationError,
    SandboxServiceTransportError,
    SubmissionState,
    TransportFailureCode,
)
from .types import (
    AssetBundleIdentity,
    CreateRequest,
    ExecRequest,
    PolicyIdentity,
    ServiceResponse,
    capability_token,
    operation_id,
    request_owned_id,
)

AGENT_PROTOCOL_VERSION = 1
MAX_HELLO_BYTES = 256 * 1024
_HELLO_DEADLINE_SECONDS = 5.0
_REQUIRED_CAPABILITY = "cancel_on_disconnect"


class AgentProtocolError(ValueError):
    """Constant public error for any invalid local-agent interaction."""

    def __init__(self) -> None:
        super().__init__("sandbox agent endpoint rejected")


def default_agent_socket_path() -> Path:
    """Return the deterministic per-user agent socket path for this platform."""
    uid = os.getuid()
    if sys.platform == "linux":
        runtime_root = os.environ.get("XDG_RUNTIME_DIR")
        if runtime_root and Path(runtime_root).is_absolute():
            return Path(runtime_root) / "openbox" / "agent.sock"
        return Path(f"/run/user/{uid}") / "openbox" / "agent.sock"
    temporary_root = os.environ.get("TMPDIR")
    if temporary_root and Path(temporary_root).is_absolute():
        return Path(os.path.realpath(temporary_root)) / f"openbox-{uid}" / "agent.sock"
    return Path(f"/tmp/openbox-{uid}") / "agent.sock"


def _reject_symlink_components(path: Path) -> None:
    if not path.is_absolute():
        raise AgentProtocolError()
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            if stat.S_ISLNK(os.lstat(current).st_mode):
                raise AgentProtocolError()
        except FileNotFoundError:
            raise
        except OSError:
            raise AgentProtocolError() from None


def agent_socket_present(path: Path) -> bool:
    """Return whether a socket exists at the path; validate when present."""
    try:
        _reject_symlink_components(path)
        metadata = os.lstat(path)
    except FileNotFoundError:
        return False
    if not stat.S_ISSOCK(metadata.st_mode):
        raise AgentProtocolError()
    _validate_socket_metadata(path, metadata)
    return True


def _validate_socket_metadata(path: Path, metadata: os.stat_result) -> None:
    parent = os.lstat(path.parent)
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.getuid()
        or stat.S_IMODE(parent.st_mode) & 0o077
    ):
        raise AgentProtocolError()


def _peer_uid(raw_socket: socket.socket) -> int:
    if sys.platform == "linux":
        credentials = raw_socket.getsockopt(
            socket.SOL_SOCKET,
            socket.SO_PEERCRED,  # type: ignore[attr-defined]
            struct.calcsize("3i"),
        )
        _, uid, _ = struct.unpack("3i", credentials)
        return int(uid)
    if sys.platform == "darwin":
        # struct xucred { u_int cr_version; uid_t cr_uid; short cr_ngroups;
        #                 gid_t cr_groups[16]; }
        raw = raw_socket.getsockopt(0, socket.LOCAL_PEERCRED, 4 + 4 + 4 + 16 * 4)
        version, uid = struct.unpack_from("Ii", raw, 0)
        if version != 0:
            raise AgentProtocolError()
        return int(uid)
    raise AgentProtocolError()


@dataclass(frozen=True, slots=True, repr=False)
class UnixAgentRuntimeClientConfig:
    socket_path: Path
    asset_bundle: AssetBundleIdentity
    registry_fingerprint: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.socket_path, Path)
            or not self.socket_path.is_absolute()
            or not isinstance(self.registry_fingerprint, str)
            or len(self.registry_fingerprint) != 64
            or any(character not in "0123456789abcdef" for character in self.registry_fingerprint)
        ):
            raise ProtocolValidationError()

    def __repr__(self) -> str:
        return (
            "UnixAgentRuntimeClientConfig(socket_path=<local>, "
            f"asset_bundle={self.asset_bundle!r}, "
            f"registry_fingerprint={self.registry_fingerprint!r})"
        )


class UnixAgentRuntimeClient:
    """Drop-in runtime surface matching :class:`SandboxRuntimeClient`."""

    def __init__(self, config: UnixAgentRuntimeClientConfig) -> None:
        self._config = config

    async def _connect(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        path = self._config.socket_path
        try:
            _reject_symlink_components(path)
            metadata = os.lstat(path)
            _validate_socket_metadata(path, metadata)
        except FileNotFoundError:
            raise AgentProtocolError() from None
        reader, writer = await asyncio.open_unix_connection(str(path))
        try:
            raw_socket = writer.get_extra_info("socket")
            if raw_socket is None or _peer_uid(raw_socket) != os.getuid():
                raise AgentProtocolError()
        except AgentProtocolError:
            writer.close()
            raise
        except OSError:
            writer.close()
            raise AgentProtocolError() from None
        return reader, writer

    async def _write_frame(
        self,
        writer: asyncio.StreamWriter,
        value: object,
        maximum: int,
    ) -> None:
        body = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
        if not body or len(body) > maximum:
            raise ProtocolValidationError()
        writer.write(struct.pack(">I", len(body)) + body)
        await writer.drain()

    async def _read_frame(self, reader: asyncio.StreamReader, maximum: int) -> dict[str, Any]:
        size = struct.unpack(">I", await reader.readexactly(4))[0]
        if not 1 <= size <= maximum:
            raise ProtocolValidationError()
        body = await reader.readexactly(size)
        value = json.loads(
            body,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
        if not isinstance(value, dict):
            raise ProtocolValidationError()
        return value

    async def _handshake(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> str:
        nonce = secrets.token_urlsafe(32)
        await self._write_frame(
            writer,
            {
                "agent_protocol_version": AGENT_PROTOCOL_VERSION,
                "client_nonce": nonce,
                "asset_bundle": self._config.asset_bundle.to_wire(),
                "registry_fingerprint": self._config.registry_fingerprint,
                "max_request_bytes": MAX_REQUEST_BYTES,
                "max_response_bytes": MAX_RESPONSE_BYTES,
            },
            MAX_HELLO_BYTES,
        )
        acknowledged = await self._read_frame(reader, MAX_HELLO_BYTES)
        if set(acknowledged) != {
            "agent_protocol_version",
            "client_nonce",
            "operation_capability",
            "capabilities",
            "max_request_bytes",
            "max_response_bytes",
        }:
            raise ProtocolValidationError()
        capabilities = acknowledged["capabilities"]
        if (
            acknowledged["agent_protocol_version"] != AGENT_PROTOCOL_VERSION
            or acknowledged["client_nonce"] != nonce
            or not isinstance(capabilities, list)
            or len(capabilities) > 16
            or not all(isinstance(item, str) and 0 < len(item) <= 64 for item in capabilities)
            or _REQUIRED_CAPABILITY not in capabilities
            or acknowledged["max_request_bytes"] != MAX_REQUEST_BYTES
            or acknowledged["max_response_bytes"] != MAX_RESPONSE_BYTES
        ):
            raise ProtocolValidationError()
        capability = acknowledged["operation_capability"]
        if not isinstance(capability, str):
            raise ProtocolValidationError()
        return capability_token(capability)

    async def call(
        self,
        operation: str,
        fields: Mapping[str, Any],
        deadline_ms: int,
        *,
        request_operation_id: str | None = None,
    ) -> ServiceResponse:
        if not 1 <= deadline_ms <= 120_000 or not operation:
            raise ProtocolValidationError()
        request_id = request_operation_id or operation_id()
        capability_token(request_id)
        writer: asyncio.StreamWriter | None = None
        submission = SubmissionState.NOT_SUBMITTED
        try:
            async with asyncio.timeout(_HELLO_DEADLINE_SECONDS + deadline_ms / 1000):
                reader, writer = await self._connect()
                capability = await self._handshake(reader, writer)
                envelope = {
                    "agent_protocol_version": AGENT_PROTOCOL_VERSION,
                    "operation_capability": capability,
                    "envelope": {
                        "protocol_version": PROTOCOL_VERSION,
                        "operation_id": request_id,
                        "asset_bundle": self._config.asset_bundle.to_wire(),
                        "request": {"operation": operation, **dict(fields)},
                    },
                }
                submission = SubmissionState.POSSIBLY_SUBMITTED
                await self._write_frame(writer, envelope, MAX_REQUEST_BYTES)
                response = await self._read_frame(reader, MAX_RESPONSE_BYTES)
        except asyncio.CancelledError as error:
            raise SandboxServiceTransportError(
                submission,
                TransportFailureCode.CANCELLED,
            ) from error
        except TimeoutError as error:
            raise SandboxServiceTransportError(
                submission,
                TransportFailureCode.DEADLINE,
            ) from error
        except AgentProtocolError as error:
            raise SandboxServiceTransportError(
                submission,
                TransportFailureCode.AUTHENTICATION,
            ) from error
        except (ConnectionError, OSError, asyncio.IncompleteReadError) as error:
            raise SandboxServiceTransportError(
                submission,
                TransportFailureCode.TRANSPORT,
            ) from error
        except (
            ProtocolValidationError,
            json.JSONDecodeError,
            UnicodeDecodeError,
        ) as error:
            raise SandboxServiceTransportError(
                submission,
                TransportFailureCode.PROTOCOL,
            ) from error
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except (ConnectionError, OSError):
                    pass
        return _decode_agent_response(response, request_id)

    async def health(self, deadline_ms: int = 5_000) -> ServiceResponse:
        return await self.call("health", {}, deadline_ms)

    async def create(
        self,
        request: CreateRequest,
        deadline_ms: int = 60_000,
    ) -> ServiceResponse:
        if (
            request.template != self._config.asset_bundle.template
            or request.expected_policy != self._config.asset_bundle.policy
        ):
            raise ProtocolValidationError()
        return await self.call(
            "create",
            {"request": request.to_wire(), "deadline_ms": deadline_ms},
            deadline_ms,
        )

    async def wait_ready(
        self,
        sandbox_id: str,
        lifecycle_token: str,
        expected_policy: PolicyIdentity,
        deadline_ms: int = 120_000,
    ) -> ServiceResponse:
        return await self.call(
            "wait_ready",
            {
                "request_id": request_owned_id(sandbox_id),
                "lifecycle_token": capability_token(lifecycle_token),
                "expected_policy": expected_policy.to_wire(),
                "deadline_ms": deadline_ms,
            },
            deadline_ms,
        )

    async def exec(
        self,
        sandbox_id: str,
        lifecycle_token: str,
        request: ExecRequest,
        deadline_ms: int = 45_000,
    ) -> ServiceResponse:
        started = asyncio.get_running_loop().time()

        def remaining() -> int:
            elapsed = int((asyncio.get_running_loop().time() - started) * 1000)
            value = deadline_ms - elapsed
            if value <= 0:
                raise SandboxServiceTransportError(
                    SubmissionState.NOT_SUBMITTED,
                    TransportFailureCode.DEADLINE,
                )
            return value

        prepare_deadline = remaining()
        prepared = await self.call(
            "prepare_exec",
            {
                "request_id": request_owned_id(sandbox_id),
                "lifecycle_token": capability_token(lifecycle_token),
                "request": request.to_wire(),
                "deadline_ms": prepare_deadline,
            },
            prepare_deadline,
        )
        if prepared.response != "exec_prepared":
            return prepared
        token = prepared.fields.get("prepare_token")
        if not isinstance(token, str):
            raise ProtocolValidationError()
        commit_deadline = remaining()
        return await self.call(
            "commit_exec",
            {
                "request_id": sandbox_id,
                "prepare_token": capability_token(token),
                "deadline_ms": commit_deadline,
            },
            commit_deadline,
        )

    async def delete(
        self,
        sandbox_id: str,
        deadline_ms: int = 60_000,
    ) -> ServiceResponse:
        return await self.call(
            "delete",
            {
                "target": {"request_id": request_owned_id(sandbox_id)},
                "deadline_ms": deadline_ms,
            },
            deadline_ms,
        )

    async def wait_deleted(
        self,
        sandbox_id: str,
        deadline_ms: int = 60_000,
    ) -> ServiceResponse:
        return await self.call(
            "wait_deleted",
            {
                "target": {"request_id": request_owned_id(sandbox_id)},
                "deadline_ms": deadline_ms,
            },
            deadline_ms,
        )

    async def cancel(
        self,
        target_operation_id: str,
        deadline_ms: int = 5_000,
    ) -> ServiceResponse:
        return await self.call(
            "cancel",
            {"target_operation_id": capability_token(target_operation_id)},
            deadline_ms,
        )


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolValidationError()
        result[key] = value
    return result


def _reject_constant(_: str) -> NoReturn:
    raise ProtocolValidationError()


def _decode_agent_response(value: dict[str, Any], expected_operation_id: str) -> ServiceResponse:
    try:
        if set(value) != {"agent_protocol_version", "envelope"}:
            raise ProtocolValidationError()
        if value["agent_protocol_version"] != AGENT_PROTOCOL_VERSION:
            raise ProtocolValidationError()
        envelope = value["envelope"]
        if not isinstance(envelope, dict) or set(envelope) != {
            "protocol_version",
            "operation_id",
            "response",
        }:
            raise ProtocolValidationError()
        if (
            envelope["protocol_version"] != PROTOCOL_VERSION
            or envelope["operation_id"] != expected_operation_id
            or not isinstance(envelope["response"], dict)
        ):
            raise ProtocolValidationError()
        response = envelope["response"]
        response_type = response.get("response")
        if not isinstance(response_type, str):
            raise ProtocolValidationError()
        return ServiceResponse(
            response=response_type,
            fields={key: item for key, item in response.items() if key != "response"},
        )
    except ProtocolValidationError as error:
        raise SandboxServiceTransportError(
            SubmissionState.POSSIBLY_SUBMITTED,
            TransportFailureCode.PROTOCOL,
        ) from error
