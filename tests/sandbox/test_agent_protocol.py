from __future__ import annotations

import asyncio
import os
import stat
import tempfile
import unittest
from pathlib import Path
from typing import Any, Mapping

from openbox_sandbox.runtime import (
    AssetBundleIdentity,
    SandboxServiceTransportError,
    ServiceResponse,
    TransportFailureCode,
    UnixAgentRuntimeClient,
    UnixAgentRuntimeClientConfig,
    agent_socket_present,
)
from openbox_sandbox.runtime.agent_server import (
    UnixAgentServer,
    UnixAgentServerConfig,
)
from openbox_sandbox.runtime.client import SandboxRuntimeClientConfig
from openbox_sandbox.runtime.types import PolicyIdentity


class _Upstream:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Mapping[str, Any], int, str | None]] = []

    async def call(
        self,
        operation: str,
        fields: Mapping[str, Any],
        deadline_ms: int,
        *,
        request_operation_id: str | None = None,
    ) -> ServiceResponse:
        self.calls.append((operation, fields, deadline_ms, request_operation_id))
        return ServiceResponse(
            response="health",
            fields={
                "status": {
                    "ready": True,
                    "draining": False,
                    "startup_reconciled": True,
                    "active_operations": 0,
                    "pending_cleanup_records": 0,
                }
            },
        )


class AgentProtocolTests(unittest.IsolatedAsyncioTestCase):
    def bundle(self) -> AssetBundleIdentity:
        return AssetBundleIdentity(
            runtime_contract_version=1,
            adapter_build_sha256="a" * 64,
            template="registry.invalid/sandbox@sha256:" + "b" * 64,
            policy=PolicyIdentity("deny-network", 1, "c" * 64),
            compatibility_id="poc-local-v1",
        )

    def upstream_config(self) -> SandboxRuntimeClientConfig:
        return SandboxRuntimeClientConfig(
            host="127.0.0.1",
            port=7443,
            server_name="localhost",
            ca_path=Path("/not-opened/ca"),
            certificate_path=Path("/not-opened/cert"),
            private_key_path=Path("/not-opened/key"),
            asset_bundle=self.bundle(),
        )

    async def asyncSetUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.socket_path = Path(os.path.realpath(self.temporary.name)) / "agent" / "agent.sock"
        self.fingerprint = "d" * 64
        self.upstream = _Upstream()
        self.server = UnixAgentServer(
            UnixAgentServerConfig(
                socket_path=self.socket_path,
                registry_fingerprint=self.fingerprint,
                upstream=self.upstream_config(),
            ),
            upstream=self.upstream,
        )
        await self.server.start()

    async def asyncTearDown(self) -> None:
        await self.server.close()
        self.temporary.cleanup()

    def client(self, fingerprint: str | None = None) -> UnixAgentRuntimeClient:
        return UnixAgentRuntimeClient(
            UnixAgentRuntimeClientConfig(
                socket_path=self.socket_path,
                asset_bundle=self.bundle(),
                registry_fingerprint=fingerprint or self.fingerprint,
            )
        )

    async def test_same_uid_handshake_forwards_one_typed_health_operation(self) -> None:
        response = await self.client().health()

        self.assertEqual(response.response, "health")
        self.assertTrue(response.fields["status"]["ready"])
        self.assertEqual(len(self.upstream.calls), 1)
        operation, fields, deadline, operation_id = self.upstream.calls[0]
        self.assertEqual(operation, "health")
        self.assertEqual(fields, {})
        self.assertEqual(deadline, 5_000)
        self.assertIsNotNone(operation_id)

    async def test_socket_is_owner_only_and_removed_on_close(self) -> None:
        metadata = os.lstat(self.socket_path)
        self.assertTrue(stat.S_ISSOCK(metadata.st_mode))
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
        self.assertEqual(metadata.st_uid, os.getuid())
        self.assertTrue(agent_socket_present(self.socket_path))

        await self.server.close()
        self.assertFalse(self.socket_path.exists())

    async def test_registry_mismatch_fails_closed_without_upstream_call(self) -> None:
        with self.assertRaises(SandboxServiceTransportError) as captured:
            await self.client("e" * 64).health()

        self.assertIn(
            captured.exception.code,
            {
                TransportFailureCode.AUTHENTICATION,
                TransportFailureCode.TRANSPORT,
                TransportFailureCode.PROTOCOL,
            },
        )
        self.assertEqual(self.upstream.calls, [])

    async def test_disconnect_cancels_inflight_upstream_operation(self) -> None:
        started = asyncio.Event()
        cancelled = asyncio.Event()

        class BlockingUpstream(_Upstream):
            async def call(
                inner_self,
                operation: str,
                fields: Mapping[str, Any],
                deadline_ms: int,
                *,
                request_operation_id: str | None = None,
            ) -> ServiceResponse:
                started.set()
                try:
                    await asyncio.Event().wait()
                    raise AssertionError("blocking upstream unexpectedly resumed")
                except asyncio.CancelledError:
                    cancelled.set()
                    raise

        await self.server.close()
        self.server = UnixAgentServer(
            UnixAgentServerConfig(
                socket_path=self.socket_path,
                registry_fingerprint=self.fingerprint,
                upstream=self.upstream_config(),
            ),
            upstream=BlockingUpstream(),
        )
        await self.server.start()

        task = asyncio.create_task(self.client().health())
        await asyncio.wait_for(started.wait(), timeout=2)
        task.cancel()
        with self.assertRaises(SandboxServiceTransportError):
            await task
        await asyncio.wait_for(cancelled.wait(), timeout=2)


if __name__ == "__main__":
    unittest.main()
