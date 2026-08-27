"""Minimal authenticated Unix-socket adapter for the sandbox service.

This process is deliberately an executor transport only. It authenticates a
same-UID SDK client, negotiates one fixed asset/registry identity, accepts one
existing typed sandbox-service operation per connection, and forwards that
operation over the existing TLS 1.3/mTLS client. Governance, command-profile
selection, lifecycle ordering, retries, and cleanup decisions remain in the
SDK dispatcher.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import stat
import struct
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

from .._trusted_files import load_strict_json, validate_trusted_file
from ..errors import GovernedCommandDeploymentError
from .agent_client import (
    AGENT_PROTOCOL_VERSION,
    MAX_HELLO_BYTES,
    _peer_uid,
    _strict_object,
)
from .client import (
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    PROTOCOL_VERSION,
    SandboxRuntimeClient,
    SandboxRuntimeClientConfig,
)
from .errors import ProtocolValidationError
from .types import (
    AssetBundleIdentity,
    PolicyIdentity,
    capability_token,
)

_REQUIRED_CAPABILITY = "cancel_on_disconnect"
_ALLOWED_REQUEST_FIELDS: Mapping[str, frozenset[str]] = {
    "health": frozenset({"operation"}),
    "create": frozenset({"operation", "request", "deadline_ms"}),
    "wait_ready": frozenset(
        {
            "operation",
            "request_id",
            "lifecycle_token",
            "expected_policy",
            "deadline_ms",
        }
    ),
    "prepare_exec": frozenset(
        {
            "operation",
            "request_id",
            "lifecycle_token",
            "request",
            "deadline_ms",
        }
    ),
    "commit_exec": frozenset({"operation", "request_id", "prepare_token", "deadline_ms"}),
    "delete": frozenset({"operation", "target", "deadline_ms"}),
    "wait_deleted": frozenset({"operation", "target", "deadline_ms"}),
    "cancel": frozenset({"operation", "target_operation_id"}),
}


def _reject_constant(_: str) -> NoReturn:
    raise ProtocolValidationError()


def _sha256(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ProtocolValidationError()
    return value


def _asset_bundle(value: object) -> AssetBundleIdentity:
    if not isinstance(value, dict) or set(value) != {
        "runtime_contract_version",
        "adapter_build_sha256",
        "template",
        "policy",
        "compatibility_id",
    }:
        raise ProtocolValidationError()
    policy = value["policy"]
    if not isinstance(policy, dict) or set(policy) != {"id", "version", "sha256"}:
        raise ProtocolValidationError()
    policy_id = policy["id"]
    policy_version = policy["version"]
    template = value["template"]
    compatibility_id = value["compatibility_id"]
    contract_version = value["runtime_contract_version"]
    if (
        not isinstance(policy_id, str)
        or isinstance(policy_version, bool)
        or not isinstance(policy_version, int)
        or not isinstance(template, str)
        or not isinstance(compatibility_id, str)
        or isinstance(contract_version, bool)
        or not isinstance(contract_version, int)
    ):
        raise ProtocolValidationError()
    return AssetBundleIdentity(
        runtime_contract_version=contract_version,
        adapter_build_sha256=_sha256(value["adapter_build_sha256"]),
        template=template,
        policy=PolicyIdentity(
            id=policy_id,
            version=policy_version,
            sha256=_sha256(policy["sha256"]),
        ),
        compatibility_id=compatibility_id,
    )


def load_service_client_config(
    service_config: Path,
    *,
    ca_path: Path,
    certificate_path: Path,
    private_key_path: Path,
) -> SandboxRuntimeClientConfig:
    """Load only the upstream address and immutable asset identity."""
    try:
        raw = load_strict_json(service_config)
        if not isinstance(raw, dict):
            raise ProtocolValidationError()
        bind_address = raw["bind_address"]
        if not isinstance(bind_address, str):
            raise ProtocolValidationError()
        host, port_text = bind_address.rsplit(":", 1)
        port = int(port_text)
        asset = _asset_bundle(raw["asset_bundle"])
    except (
        KeyError,
        OSError,
        UnicodeDecodeError,
        ValueError,
        GovernedCommandDeploymentError,
    ) as error:
        raise ProtocolValidationError() from error
    return SandboxRuntimeClientConfig(
        host=host,
        port=port,
        server_name="localhost",
        ca_path=ca_path,
        certificate_path=certificate_path,
        private_key_path=private_key_path,
        asset_bundle=asset,
    )


@dataclass(frozen=True, slots=True, repr=False)
class UnixAgentServerConfig:
    socket_path: Path
    registry_fingerprint: str
    upstream: SandboxRuntimeClientConfig

    def __post_init__(self) -> None:
        if not self.socket_path.is_absolute():
            raise ProtocolValidationError()
        _sha256(self.registry_fingerprint)

    def __repr__(self) -> str:
        return (
            "UnixAgentServerConfig(socket_path=<local>, "
            f"registry_fingerprint={self.registry_fingerprint!r}, "
            "upstream=<mTLS-redacted>)"
        )


class UnixAgentServer:
    """One-operation-per-connection typed local adapter."""

    def __init__(
        self,
        config: UnixAgentServerConfig,
        *,
        upstream: Any | None = None,
    ) -> None:
        self._config = config
        self._upstream = upstream or SandboxRuntimeClient(config.upstream)
        self._server: asyncio.AbstractServer | None = None
        self._socket_identity: tuple[int, int] | None = None

    async def start(self) -> None:
        if self._server is not None:
            raise RuntimeError("sandbox agent already started")
        path = self._config.socket_path
        parent = path.parent
        self._prepare_parent(parent)
        try:
            os.lstat(path)
        except FileNotFoundError:
            pass
        else:
            raise ProtocolValidationError()
        old_umask = os.umask(0o077)
        try:
            server = await asyncio.start_unix_server(self._handle, path=str(path))
        finally:
            os.umask(old_umask)
        try:
            os.chmod(path, 0o600, follow_symlinks=False)
            metadata = os.lstat(path)
            if (
                not stat.S_ISSOCK(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise ProtocolValidationError()
        except BaseException:
            server.close()
            await server.wait_closed()
            try:
                path.unlink()
            except OSError:
                pass
            raise
        self._server = server
        self._socket_identity = (metadata.st_dev, metadata.st_ino)

    def _prepare_parent(self, parent: Path) -> None:
        ancestor = parent.parent
        try:
            ancestor_metadata = os.lstat(ancestor)
            if not stat.S_ISDIR(ancestor_metadata.st_mode):
                raise ProtocolValidationError()
            parent.mkdir(mode=0o700)
        except FileExistsError:
            pass
        except OSError as error:
            raise ProtocolValidationError() from error
        metadata = os.lstat(parent)
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise ProtocolValidationError()

    async def close(self) -> None:
        server = self._server
        self._server = None
        if server is not None:
            server.close()
            await server.wait_closed()
        path = self._config.socket_path
        identity = self._socket_identity
        self._socket_identity = None
        if identity is None:
            return
        try:
            metadata = os.lstat(path)
            if (
                not stat.S_ISSOCK(metadata.st_mode)
                or (metadata.st_dev, metadata.st_ino) != identity
            ):
                raise ProtocolValidationError()
            path.unlink()
        except FileNotFoundError:
            return

    async def serve_forever(self) -> None:
        if self._server is None:
            raise RuntimeError("sandbox agent not started")
        await self._server.serve_forever()

    async def _read_frame(
        self,
        reader: asyncio.StreamReader,
        maximum: int,
    ) -> dict[str, Any]:
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

    async def _handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            raw_socket = writer.get_extra_info("socket")
            if raw_socket is None or _peer_uid(raw_socket) != os.getuid():
                raise ProtocolValidationError()
            async with asyncio.timeout(5):
                hello = await self._read_frame(reader, MAX_HELLO_BYTES)
                nonce = self._validate_hello(hello)
                operation_capability = capability_token_from_random()
                await self._write_frame(
                    writer,
                    {
                        "agent_protocol_version": AGENT_PROTOCOL_VERSION,
                        "client_nonce": nonce,
                        "operation_capability": operation_capability,
                        "capabilities": [_REQUIRED_CAPABILITY],
                        "max_request_bytes": MAX_REQUEST_BYTES,
                        "max_response_bytes": MAX_RESPONSE_BYTES,
                    },
                    MAX_HELLO_BYTES,
                )
            request = await self._read_frame(reader, MAX_REQUEST_BYTES)
            operation_id, operation, fields, deadline_ms = self._validate_request(
                request,
                operation_capability,
            )
            upstream_task = asyncio.create_task(
                self._upstream.call(
                    operation,
                    fields,
                    deadline_ms,
                    request_operation_id=operation_id,
                )
            )
            disconnect_task = asyncio.create_task(reader.read(1))
            done, _ = await asyncio.wait(
                {upstream_task, disconnect_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if disconnect_task in done:
                upstream_task.cancel()
                await asyncio.gather(upstream_task, return_exceptions=True)
                return
            disconnect_task.cancel()
            await asyncio.gather(disconnect_task, return_exceptions=True)
            response = await upstream_task
            await self._write_frame(
                writer,
                {
                    "agent_protocol_version": AGENT_PROTOCOL_VERSION,
                    "envelope": {
                        "protocol_version": PROTOCOL_VERSION,
                        "operation_id": operation_id,
                        "response": {
                            "response": response.response,
                            **dict(response.fields),
                        },
                    },
                },
                MAX_RESPONSE_BYTES,
            )
        except (
            asyncio.IncompleteReadError,
            ConnectionError,
            OSError,
            ProtocolValidationError,
            TimeoutError,
            UnicodeDecodeError,
            ValueError,
        ):
            return
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    def _validate_hello(self, value: dict[str, Any]) -> str:
        if set(value) != {
            "agent_protocol_version",
            "client_nonce",
            "asset_bundle",
            "registry_fingerprint",
            "max_request_bytes",
            "max_response_bytes",
        }:
            raise ProtocolValidationError()
        nonce = value["client_nonce"]
        if (
            value["agent_protocol_version"] != AGENT_PROTOCOL_VERSION
            or not isinstance(nonce, str)
            or not 32 <= len(nonce) <= 128
            or _asset_bundle(value["asset_bundle"]) != self._config.upstream.asset_bundle
            or value["registry_fingerprint"] != self._config.registry_fingerprint
            or value["max_request_bytes"] != MAX_REQUEST_BYTES
            or value["max_response_bytes"] != MAX_RESPONSE_BYTES
        ):
            raise ProtocolValidationError()
        return nonce

    def _validate_request(
        self,
        value: dict[str, Any],
        expected_capability: str,
    ) -> tuple[str, str, dict[str, Any], int]:
        if set(value) != {
            "agent_protocol_version",
            "operation_capability",
            "envelope",
        }:
            raise ProtocolValidationError()
        if (
            value["agent_protocol_version"] != AGENT_PROTOCOL_VERSION
            or value["operation_capability"] != expected_capability
        ):
            raise ProtocolValidationError()
        envelope = value["envelope"]
        if not isinstance(envelope, dict) or set(envelope) != {
            "protocol_version",
            "operation_id",
            "asset_bundle",
            "request",
        }:
            raise ProtocolValidationError()
        operation_id = envelope["operation_id"]
        capability_token(operation_id)
        if (
            envelope["protocol_version"] != PROTOCOL_VERSION
            or _asset_bundle(envelope["asset_bundle"]) != self._config.upstream.asset_bundle
        ):
            raise ProtocolValidationError()
        request = envelope["request"]
        if not isinstance(request, dict):
            raise ProtocolValidationError()
        operation = request.get("operation")
        if not isinstance(operation, str):
            raise ProtocolValidationError()
        expected_fields = _ALLOWED_REQUEST_FIELDS.get(operation)
        if expected_fields is None or set(request) != expected_fields:
            raise ProtocolValidationError()
        raw_deadline = request.get("deadline_ms", 5_000)
        if (
            isinstance(raw_deadline, bool)
            or not isinstance(raw_deadline, int)
            or not 1 <= raw_deadline <= 120_000
        ):
            raise ProtocolValidationError()
        fields = {key: item for key, item in request.items() if key != "operation"}
        return operation_id, operation, fields, raw_deadline


def capability_token_from_random() -> str:
    from .types import operation_id

    return operation_id()


async def _serve(args: argparse.Namespace) -> None:
    try:
        validate_trusted_file(args.ca)
        validate_trusted_file(args.certificate, private=True)
        validate_trusted_file(args.private_key, private=True)
    except GovernedCommandDeploymentError as error:
        raise ProtocolValidationError() from error
    upstream = load_service_client_config(
        args.service_config,
        ca_path=args.ca,
        certificate_path=args.certificate,
        private_key_path=args.private_key,
    )
    server = UnixAgentServer(
        UnixAgentServerConfig(
            socket_path=args.socket,
            registry_fingerprint=args.registry_fingerprint,
            upstream=upstream,
        )
    )
    await server.start()
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for current_signal in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(current_signal, stop.set)
        except NotImplementedError:
            pass
    try:
        await stop.wait()
    finally:
        await server.close()


async def _health(args: argparse.Namespace) -> None:
    from .agent_client import UnixAgentRuntimeClient, UnixAgentRuntimeClientConfig

    upstream = load_service_client_config(
        args.service_config,
        ca_path=Path("/not-used"),
        certificate_path=Path("/not-used"),
        private_key_path=Path("/not-used"),
    )
    client = UnixAgentRuntimeClient(
        UnixAgentRuntimeClientConfig(
            socket_path=args.socket,
            asset_bundle=upstream.asset_bundle,
            registry_fingerprint=args.registry_fingerprint,
        )
    )
    response = await client.health()
    status = response.fields.get("status")
    if (
        response.response != "health"
        or not isinstance(status, dict)
        or status.get("ready") is not True
    ):
        raise RuntimeError("sandbox agent health rejected")


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    serve = subparsers.add_parser("serve")
    health = subparsers.add_parser("health")
    for current in (serve, health):
        current.add_argument("--service-config", type=Path, required=True)
        current.add_argument("--socket", type=Path, required=True)
        current.add_argument("--registry-fingerprint", required=True)
    serve.add_argument("--ca", type=Path, required=True)
    serve.add_argument("--certificate", type=Path, required=True)
    serve.add_argument("--private-key", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "serve":
        asyncio.run(_serve(args))
    else:
        asyncio.run(_health(args))


if __name__ == "__main__":
    main()
