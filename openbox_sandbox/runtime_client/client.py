from __future__ import annotations

import asyncio
import ipaddress
import json
import ssl
import struct
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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

PROTOCOL_VERSION = 1
MAX_REQUEST_BYTES = 2 * 1024 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True, slots=True, repr=False)
class SandboxRuntimeClientConfig:
    host: str
    port: int
    server_name: str
    ca_path: Path
    certificate_path: Path
    private_key_path: Path
    asset_bundle: AssetBundleIdentity

    def __post_init__(self) -> None:
        try:
            address = ipaddress.ip_address(self.host)
        except ValueError as error:
            raise ProtocolValidationError() from error
        if not address.is_loopback or not 1 <= self.port <= 65535 or not self.server_name:
            raise ProtocolValidationError()

    def __repr__(self) -> str:
        return (
            f"SandboxRuntimeClientConfig(host={self.host!r}, port={self.port}, "
            f"server_name={self.server_name!r}, credentials=<redacted>, "
            f"asset_bundle={self.asset_bundle!r})"
        )


class SandboxRuntimeClient:
    def __init__(self, config: SandboxRuntimeClientConfig) -> None:
        self._config = config
        context = ssl.create_default_context(
            ssl.Purpose.SERVER_AUTH,
            cafile=str(config.ca_path),
        )
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(
            certfile=str(config.certificate_path),
            keyfile=str(config.private_key_path),
        )
        context.check_hostname = True
        self._ssl = context

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
        request = {
            "protocol_version": PROTOCOL_VERSION,
            "operation_id": request_id,
            "asset_bundle": self._config.asset_bundle.to_wire(),
            "request": {"operation": operation, **dict(fields)},
        }
        body = json.dumps(
            request,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
        if not body or len(body) > MAX_REQUEST_BYTES:
            raise SandboxServiceTransportError(
                SubmissionState.NOT_SUBMITTED,
                TransportFailureCode.PROTOCOL,
            )
        writer: asyncio.StreamWriter | None = None
        submission = SubmissionState.NOT_SUBMITTED
        try:
            async with asyncio.timeout(deadline_ms / 1000):
                reader, writer = await asyncio.open_connection(
                    self._config.host,
                    self._config.port,
                    ssl=self._ssl,
                    server_hostname=self._config.server_name,
                )
                submission = SubmissionState.POSSIBLY_SUBMITTED
                writer.write(struct.pack(">I", len(body)) + body)
                await writer.drain()
                size = struct.unpack(">I", await reader.readexactly(4))[0]
                if not 1 <= size <= MAX_RESPONSE_BYTES:
                    raise ProtocolValidationError()
                response_body = await reader.readexactly(size)
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
        except (ssl.SSLError, ConnectionError, OSError, asyncio.IncompleteReadError) as error:
            code = (
                TransportFailureCode.AUTHENTICATION
                if submission is SubmissionState.NOT_SUBMITTED and isinstance(error, ssl.SSLError)
                else TransportFailureCode.TRANSPORT
            )
            raise SandboxServiceTransportError(submission, code) from error
        except ProtocolValidationError as error:
            raise SandboxServiceTransportError(
                submission,
                TransportFailureCode.PROTOCOL,
            ) from error
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except (ssl.SSLError, ConnectionError, OSError):
                    pass
        return _decode_response(response_body, request_id)

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


def _decode_response(body: bytes, expected_operation_id: str) -> ServiceResponse:
    try:
        value = json.loads(body, object_pairs_hook=_strict_object)
        if not isinstance(value, dict) or set(value) != {
            "protocol_version",
            "operation_id",
            "response",
        }:
            raise ProtocolValidationError()
        if (
            value["protocol_version"] != PROTOCOL_VERSION
            or value["operation_id"] != expected_operation_id
            or not isinstance(value["response"], dict)
        ):
            raise ProtocolValidationError()
        response = value["response"]
        response_type = response.get("response")
        if not isinstance(response_type, str):
            raise ProtocolValidationError()
        return ServiceResponse(
            response=response_type,
            fields={key: item for key, item in response.items() if key != "response"},
        )
    except (json.JSONDecodeError, UnicodeDecodeError, ProtocolValidationError) as error:
        raise SandboxServiceTransportError(
            SubmissionState.POSSIBLY_SUBMITTED,
            TransportFailureCode.PROTOCOL,
        ) from error
