"""Load a local sandbox runtime from the ``OPENBOX_SANDBOX_*`` environment.

The provisioning wizard ``packaging/launcher/scripts/provision-local-sandbox.sh``
emits an ``agent.env`` file containing all the credentials and parameters an
OpenBox SDK agent needs to drive a locally-running ``openbox-sandbox`` service
over mutual TLS. This module ingests that env contract and produces the typed
objects the runtime client requires:

* :class:`SandboxRuntimeClientConfig` — mTLS connection parameters.
* :class:`AssetBundleIdentity` — the pinned adapter / template / policy bundle.
* :class:`PolicyDocument` — the raw policy YAML the service attests.
* :class:`PolicyIdentity` — the policy's expected identity.

A framework agent typically does this once at startup::

    from openbox_sandbox.runtime.env import load_local_sandbox_env

    env = load_local_sandbox_env()
    client = SandboxRuntimeClient(env.client_config)
    # client.create(CreateRequest(...)) / client.exec(...) ...

All configured values are required by the service (mTLS, asset-bundle
attestation, policy sha256 match). Missing env vars raise
:class:`EnvLoadError` with a message indicating which one is missing so the
agent fail-closes loudly instead of carrying wrong defaults.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .client import SandboxRuntimeClientConfig
from .types import AssetBundleIdentity, PolicyDocument, PolicyIdentity


def _require(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise EnvLoadError(f"missing required env var: {name}")
    return value


def _require_int(name: str) -> int:
    raw = _require(name)
    try:
        return int(raw)
    except ValueError as error:  # pragma: no cover - explicit fail-closed
        raise EnvLoadError(f"{name} must be an integer, got {raw!r}") from error


def _require_path(name: str) -> Path:
    return Path(_require(name)).resolve()


def _require_file(name: str) -> Path:
    path = _require_path(name)
    if not path.is_file():
        raise EnvLoadError(f"{name} points to a missing file: {path}")
    return path


class EnvLoadError(RuntimeError):
    """Raised when the ``OPENBOX_SANDBOX_*`` env contract is incomplete."""


@dataclass(frozen=True, slots=True)
class LocalSandboxEnv:
    """Resolved local sandbox environment (env contract -> typed objects)."""

    client_config: SandboxRuntimeClientConfig
    asset_bundle: AssetBundleIdentity
    expected_policy: PolicyIdentity
    policy_document: PolicyDocument
    template: str
    adapter_sha: str
    gateway_endpoint: str

    def policy_yaml_sha256(self) -> str:
        return self.expected_policy.sha256


def load_local_sandbox_env() -> LocalSandboxEnv:
    """Parse the ``OPENBOX_SANDBOX_*`` env contract into typed objects.

    Read by both the Python SDK demo agent and any user agent that wants the
    same one-shot local-dev path. The endpoint must be loopback (the service
    refuses non-loopback binds) and the policy file SHA256 must match the
    expected identity.
    """
    endpoint = _require("OPENBOX_SANDBOX_ENDPOINT")
    if ":" not in endpoint:
        raise EnvLoadError(
            "OPENBOX_SANDBOX_ENDPOINT must be host:port, got " + repr(endpoint),
        )
    host, _, port_str = endpoint.rpartition(":")
    try:
        port = int(port_str)
    except ValueError as error:
        raise EnvLoadError(
            f"OPENBOX_SANDBOX_ENDPOINT port must be int, got {port_str!r}",
        ) from error

    server_name = os.environ.get("OPENBOX_SANDBOX_SERVER_NAME", "localhost")
    template = _require("OPENBOX_SANDBOX_TEMPLATE")
    adapter_sha = _require("OPENBOX_SANDBOX_ADAPTER_SHA")
    policy_id = _require("OPENBOX_SANDBOX_POLICY_ID")
    policy_version = _require_int("OPENBOX_SANDBOX_POLICY_VERSION")
    compat_id = os.environ.get("OPENBOX_SANDBOX_COMPAT_ID", "darwin-dev-1")
    policy_file = _require_file("OPENBOX_SANDBOX_POLICY_FILE")
    ca_path = _require_file("OPENBOX_SANDBOX_CA")
    cert_path = _require_file("OPENBOX_SANDBOX_CERT")
    key_path = _require_file("OPENBOX_SANDBOX_KEY")

    policy_bytes = policy_file.read_bytes()
    import hashlib

    actual_policy_sha = hashlib.sha256(policy_bytes).hexdigest()
    expected_policy_sha = os.environ.get(
        "OPENBOX_SANDBOX_POLICY_SHA256",
        actual_policy_sha,
    )
    if expected_policy_sha != actual_policy_sha:
        raise EnvLoadError(
            f"OPENBOX_SANDBOX_POLICY_SHA256 {expected_policy_sha!r} does not "
            f"match the file digest {actual_policy_sha!r}"
        )
    policy_identity = PolicyIdentity(
        id=policy_id,
        version=policy_version,
        sha256=actual_policy_sha,
    )
    asset_bundle = AssetBundleIdentity(
        runtime_contract_version=1,
        adapter_build_sha256=adapter_sha,
        template=template,
        policy=policy_identity,
        compatibility_id=compat_id,
    )
    policy_document = PolicyDocument(
        media_type="application/yaml",
        document=policy_bytes,
    )
    client_config = SandboxRuntimeClientConfig(
        host=host,
        port=port,
        server_name=server_name,
        ca_path=ca_path,
        certificate_path=cert_path,
        private_key_path=key_path,
        asset_bundle=asset_bundle,
    )
    return LocalSandboxEnv(
        client_config=client_config,
        asset_bundle=asset_bundle,
        expected_policy=policy_identity,
        policy_document=policy_document,
        template=template,
        adapter_sha=adapter_sha,
        gateway_endpoint=os.environ.get(
            "OPENBOX_GATEWAY_ENDPOINT",
            "https://127.0.0.1:17670",
        ),
    )


__all__ = [
    "EnvLoadError",
    "LocalSandboxEnv",
    "load_local_sandbox_env",
]