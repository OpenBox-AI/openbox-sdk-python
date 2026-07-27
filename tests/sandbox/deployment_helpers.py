from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from openbox_sandbox import SandboxCommandDefinition, sandbox_command_registry

POLICY_BODY = b"version: 1\ndefault: deny\n"


def registry():
    return sandbox_command_registry(SandboxCommandDefinition("proof", "/usr/local/bin/proof"))


def write_file(path: Path, body: bytes, mode: int = 0o600) -> Path:
    path.write_bytes(body)
    path.chmod(mode)
    return path


def release_value(policy_path: Path) -> dict[str, Any]:
    return {
        "runtime_contract_version": 1,
        "adapter_build_sha256": "a" * 64,
        "template": "registry.invalid/openbox@sha256:" + "c" * 64,
        "policy": {
            "id": "deny-network",
            "version": 1,
            "sha256": hashlib.sha256(POLICY_BODY).hexdigest(),
            "media_type": "application/yaml",
            "path": str(policy_path),
        },
        "compatibility_id": "linux-client-v1",
    }


def prepare_files(tmp_path: Path) -> dict[str, Path]:
    policy = write_file(tmp_path / "policy.yaml", POLICY_BODY, 0o644)
    release_path = write_file(
        tmp_path / "approved-release.json",
        json.dumps(
            {"schema_version": 1, "release": release_value(policy)},
            separators=(",", ":"),
        ).encode(),
        0o644,
    )
    cleanup = tmp_path / "cleanup"
    cleanup.mkdir(mode=0o700)
    return {
        "policy": policy,
        "release": release_path,
        "cleanup": cleanup,
        "ca": write_file(tmp_path / "ca.pem", b"test-ca", 0o644),
        "certificate": write_file(tmp_path / "client.pem", b"test-cert", 0o600),
        "private_key": write_file(tmp_path / "client.key", b"test-key", 0o600),
    }


def deployment_value(tmp_path: Path, files: dict[str, Path], *, uds: bool = False):
    commands = registry()
    transport: dict[str, Any]
    if uds:
        transport = {
            "kind": "uds_agent",
            "socket_path": str(tmp_path / "agent.sock"),
        }
    else:
        transport = {
            "kind": "direct_tls",
            "host": "127.0.0.1",
            "port": 7443,
            "server_name": "sandbox-service.internal",
            "ca_path": str(files["ca"]),
            "certificate_path": str(files["certificate"]),
            "private_key_path": str(files["private_key"]),
        }
    return commands, {
        "schema_version": 1,
        "deployment_id": "client-sandbox-v1",
        "transport": transport,
        "release": release_value(files["policy"]),
        "profiles": {
            "registry_fingerprint": commands.fingerprint,
            "bundle_version": commands.bundle_version,
            "command_ids": list(commands.command_ids),
        },
        "cleanup_backlog_directory": str(files["cleanup"]),
        "output_limits": {
            "stdout_bytes": 1024 * 1024,
            "stderr_bytes": 1024 * 1024,
            "combined_bytes": 2 * 1024 * 1024,
            "chunk_bytes": 4 * 1024 * 1024,
        },
        "deadlines": {
            "create_deadline_ms": 60_000,
            "readiness_deadline_ms": 120_000,
            "exec_deadline_ms": 45_000,
            "delete_deadline_ms": 60_000,
            "wait_deleted_deadline_ms": 60_000,
        },
        "enabled": True,
    }


def write_manifest(path: Path, value: dict[str, Any]) -> Path:
    return write_file(path, json.dumps(value, separators=(",", ":")).encode(), 0o644)
