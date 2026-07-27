"""Explicit, process-wide sandbox release approval.

No release identity is embedded in this distribution. The application owner
must load one exact release declaration from an owner-controlled absolute path
before a deployment can be materialized. The declaration and policy are read
through verified descriptors and can be installed only once per process.
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ._trusted_files import load_strict_json, read_trusted_file
from .errors import GovernedCommandDeploymentError
from .runtime import AssetBundleIdentity, PolicyDocument, PolicyIdentity

_HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE = re.compile(r"[^\s]+@sha256:[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_MAX_POLICY_BYTES = 1024 * 1024


def _exact(value: object, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise GovernedCommandDeploymentError()
    return value


def _integer(value: object, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise GovernedCommandDeploymentError()
    return value


def _string(value: object, *, maximum: int = 4096) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\x00" in value
        or any(ord(character) < 32 for character in value)
        or len(value.encode("utf-8")) > maximum
    ):
        raise GovernedCommandDeploymentError()
    return value


def _absolute_path(value: object) -> Path:
    path = Path(_string(value))
    if not path.is_absolute():
        raise GovernedCommandDeploymentError()
    return path


@dataclass(frozen=True, slots=True, repr=False)
class ApprovedSandboxRelease:
    """One exact, immutable sandbox runtime and policy identity."""

    runtime_contract_version: int
    adapter_build_sha256: str
    template: str
    policy_id: str
    policy_version: int
    policy_media_type: str
    policy_body: bytes
    compatibility_id: str

    def __post_init__(self) -> None:
        if (
            type(self.runtime_contract_version) is not int
            or not 1 <= self.runtime_contract_version <= 2**32 - 1
            or not isinstance(self.adapter_build_sha256, str)
            or _HEX_SHA256.fullmatch(self.adapter_build_sha256) is None
            or not isinstance(self.template, str)
            or _IMAGE.fullmatch(self.template) is None
            or not isinstance(self.policy_id, str)
            or _IDENTIFIER.fullmatch(self.policy_id) is None
            or type(self.policy_version) is not int
            or not 1 <= self.policy_version <= 2**32 - 1
            or not isinstance(self.policy_media_type, str)
            or not 0 < len(self.policy_media_type.encode("utf-8")) <= 128
            or not isinstance(self.policy_body, bytes)
            or not 0 < len(self.policy_body) <= _MAX_POLICY_BYTES
            or not isinstance(self.compatibility_id, str)
            or _IDENTIFIER.fullmatch(self.compatibility_id) is None
        ):
            raise GovernedCommandDeploymentError()

    @property
    def policy_sha256(self) -> str:
        return hashlib.sha256(self.policy_body).hexdigest()

    def __repr__(self) -> str:
        return (
            "ApprovedSandboxRelease("
            f"runtime_contract_version={self.runtime_contract_version}, "
            f"template=<digest-pinned>, policy_id={self.policy_id!r}, "
            f"policy_version={self.policy_version}, "
            f"compatibility_id={self.compatibility_id!r}, policy_body=<redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class SandboxReleaseMaterial:
    """Runtime values derived exclusively from the installed release."""

    release: ApprovedSandboxRelease
    asset_bundle: AssetBundleIdentity
    policy_document: PolicyDocument

    def __repr__(self) -> str:
        return (
            "SandboxReleaseMaterial("
            f"release={self.release!r}, asset_bundle={self.asset_bundle!r}, "
            "policy_document=<redacted>)"
        )


@dataclass(frozen=True, slots=True)
class _ReleaseDeclaration:
    runtime_contract_version: int
    adapter_build_sha256: str
    template: str
    policy_id: str
    policy_version: int
    policy_sha256: str
    policy_media_type: str
    policy_path: Path
    compatibility_id: str


def _parse_release_declaration(value: object) -> _ReleaseDeclaration:
    root = _exact(
        value,
        {
            "runtime_contract_version",
            "adapter_build_sha256",
            "template",
            "policy",
            "compatibility_id",
        },
    )
    policy = _exact(root["policy"], {"id", "version", "sha256", "media_type", "path"})
    adapter_hash = _string(root["adapter_build_sha256"], maximum=64)
    template = _string(root["template"])
    policy_hash = _string(policy["sha256"], maximum=64)
    if (
        _HEX_SHA256.fullmatch(adapter_hash) is None
        or _IMAGE.fullmatch(template) is None
        or _HEX_SHA256.fullmatch(policy_hash) is None
    ):
        raise GovernedCommandDeploymentError()
    return _ReleaseDeclaration(
        runtime_contract_version=_integer(root["runtime_contract_version"], 1, 2**32 - 1),
        adapter_build_sha256=adapter_hash,
        template=template,
        policy_id=_string(policy["id"], maximum=128),
        policy_version=_integer(policy["version"], 1, 2**32 - 1),
        policy_sha256=policy_hash,
        policy_media_type=_string(policy["media_type"], maximum=128),
        policy_path=_absolute_path(policy["path"]),
        compatibility_id=_string(root["compatibility_id"], maximum=128),
    )


def _release_from_declaration(declaration: _ReleaseDeclaration) -> ApprovedSandboxRelease:
    policy_body = read_trusted_file(declaration.policy_path, maximum=_MAX_POLICY_BYTES)
    if hashlib.sha256(policy_body).hexdigest() != declaration.policy_sha256:
        raise GovernedCommandDeploymentError()
    release = ApprovedSandboxRelease(
        runtime_contract_version=declaration.runtime_contract_version,
        adapter_build_sha256=declaration.adapter_build_sha256,
        template=declaration.template,
        policy_id=declaration.policy_id,
        policy_version=declaration.policy_version,
        policy_media_type=declaration.policy_media_type,
        policy_body=policy_body,
        compatibility_id=declaration.compatibility_id,
    )
    _material_from_release(release)
    return release


def _declaration_matches(
    declaration: _ReleaseDeclaration,
    release: ApprovedSandboxRelease,
) -> bool:
    try:
        policy_body = read_trusted_file(declaration.policy_path, maximum=_MAX_POLICY_BYTES)
    except GovernedCommandDeploymentError:
        return False
    return (
        declaration.runtime_contract_version == release.runtime_contract_version
        and declaration.adapter_build_sha256 == release.adapter_build_sha256
        and declaration.template == release.template
        and declaration.policy_id == release.policy_id
        and declaration.policy_version == release.policy_version
        and declaration.policy_sha256 == release.policy_sha256
        and declaration.policy_media_type == release.policy_media_type
        and policy_body == release.policy_body
        and declaration.compatibility_id == release.compatibility_id
    )


def _material_from_release(release: ApprovedSandboxRelease) -> SandboxReleaseMaterial:
    try:
        policy = PolicyIdentity(
            release.policy_id,
            release.policy_version,
            release.policy_sha256,
        )
        asset_bundle = AssetBundleIdentity(
            runtime_contract_version=release.runtime_contract_version,
            adapter_build_sha256=release.adapter_build_sha256,
            template=release.template,
            policy=policy,
            compatibility_id=release.compatibility_id,
        )
        document = PolicyDocument(release.policy_media_type, release.policy_body)
    except (TypeError, ValueError):
        raise GovernedCommandDeploymentError() from None
    return SandboxReleaseMaterial(release, asset_bundle, document)


_lock = threading.Lock()
_installed: ApprovedSandboxRelease | None = None


def _install_approved_sandbox_release(release: ApprovedSandboxRelease) -> None:
    global _installed
    with _lock:
        if _installed is not None and _installed != release:
            raise GovernedCommandDeploymentError()
        _installed = release


def load_approved_sandbox_release(path: Path) -> ApprovedSandboxRelease:
    """Load and atomically install one explicit owner-approved release file."""
    try:
        if not isinstance(path, Path) or not path.is_absolute():
            raise GovernedCommandDeploymentError()
        root = _exact(load_strict_json(path), {"schema_version", "release"})
        if type(root["schema_version"]) is not int or root["schema_version"] != 1:
            raise GovernedCommandDeploymentError()
        release = _release_from_declaration(_parse_release_declaration(root["release"]))
        _install_approved_sandbox_release(release)
        return release
    except GovernedCommandDeploymentError:
        raise GovernedCommandDeploymentError() from None
    except Exception:
        raise GovernedCommandDeploymentError() from None


def approved_sandbox_release() -> ApprovedSandboxRelease:
    """Return the installed approved release, failing closed when absent."""
    with _lock:
        if _installed is None:
            raise GovernedCommandDeploymentError()
        return _installed


def materialize_approved_sandbox_release() -> SandboxReleaseMaterial:
    """Derive immutable runtime values from the installed release only."""
    return _material_from_release(approved_sandbox_release())


def _clear_approved_sandbox_release_for_testing() -> None:
    global _installed
    with _lock:
        _installed = None
