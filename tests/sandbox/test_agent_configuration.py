from __future__ import annotations

import json
from pathlib import Path

import pytest

from openbox_sandbox.runtime.agent_server import load_service_client_config
from openbox_sandbox.runtime.errors import ProtocolValidationError


def _service_config(path: Path) -> Path:
    value = {
        "bind_address": "127.0.0.1:17443",
        "asset_bundle": {
            "runtime_contract_version": 1,
            "adapter_build_sha256": "a" * 64,
            "template": "registry.invalid/openbox@sha256:" + "b" * 64,
            "policy": {
                "id": "deny-network",
                "version": 1,
                "sha256": "c" * 64,
            },
            "compatibility_id": "openshell-v1",
        },
    }
    path.write_text(json.dumps(value))
    path.chmod(0o644)
    return path


def _load(path: Path):
    return load_service_client_config(
        path,
        ca_path=Path("/credentials/ca.pem"),
        certificate_path=Path("/credentials/client.pem"),
        private_key_path=Path("/credentials/client.key"),
    )


def test_agent_service_config_requires_owner_controlled_regular_file(tmp_path: Path) -> None:
    config = _service_config(tmp_path / "service.json")
    assert _load(config).asset_bundle.compatibility_id == "openshell-v1"

    config.chmod(0o666)
    with pytest.raises(ProtocolValidationError):
        _load(config)
    config.chmod(0o644)

    linked = tmp_path / "linked.json"
    linked.symlink_to(config)
    with pytest.raises(ProtocolValidationError):
        _load(linked)


def test_agent_service_config_rejects_duplicate_or_oversized_input(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_bytes(b'{"bind_address":"127.0.0.1:1","bind_address":"127.0.0.1:2"}')
    duplicate.chmod(0o644)
    with pytest.raises(ProtocolValidationError):
        _load(duplicate)

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"{" + b" " * (1024 * 1024))
    oversized.chmod(0o644)
    with pytest.raises(ProtocolValidationError):
        _load(oversized)
