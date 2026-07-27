from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import openbox_sandbox
from openbox_sandbox import (
    GovernedCommandDeploymentError,
    approved_sandbox_release,
    load_approved_sandbox_release,
    materialize_approved_sandbox_release,
)
from openbox_sandbox.release import _clear_approved_sandbox_release_for_testing

from .deployment_helpers import POLICY_BODY, prepare_files, release_value, write_file


@pytest.fixture(autouse=True)
def clear_release() -> None:
    _clear_approved_sandbox_release_for_testing()


def test_explicit_release_load_materializes_exact_identity(tmp_path: Path) -> None:
    files = prepare_files(tmp_path)
    release = load_approved_sandbox_release(files["release"])
    material = materialize_approved_sandbox_release()

    assert approved_sandbox_release() is release
    assert material.release is release
    assert material.asset_bundle.runtime_contract_version == 1
    assert material.asset_bundle.adapter_build_sha256 == "a" * 64
    assert material.asset_bundle.template.endswith("@sha256:" + "c" * 64)
    assert material.asset_bundle.policy.sha256 == release.policy_sha256
    assert material.policy_document.document == POLICY_BODY
    assert "version: 1" not in repr(material)
    assert "policy_body=<redacted>" in repr(release)


def test_release_fails_closed_until_explicitly_loaded() -> None:
    with pytest.raises(GovernedCommandDeploymentError):
        approved_sandbox_release()
    with pytest.raises(GovernedCommandDeploymentError):
        materialize_approved_sandbox_release()


def test_public_mutable_release_installer_is_not_exported() -> None:
    assert "install_approved_sandbox_release" not in openbox_sandbox.__all__
    with pytest.raises(AttributeError):
        getattr(openbox_sandbox, "install_approved_sandbox_release")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("runtime_contract_version", 0),
        ("adapter_build_sha256", "x" * 64),
        ("template", "registry.invalid/openbox:latest"),
        ("compatibility_id", "bad value"),
    ],
)
def test_release_rejects_invalid_identity(tmp_path: Path, field: str, value: object) -> None:
    files = prepare_files(tmp_path)
    release = release_value(files["policy"])
    release[field] = value
    path = write_file(
        tmp_path / "invalid-release.json",
        json.dumps({"schema_version": 1, "release": release}).encode(),
        0o644,
    )
    with pytest.raises(GovernedCommandDeploymentError):
        load_approved_sandbox_release(path)


def test_release_rejects_policy_hash_media_type_and_body_mismatch(tmp_path: Path) -> None:
    files = prepare_files(tmp_path)
    for name, value in (
        ("sha256", "d" * 64),
        ("media_type", "not-a-media-type"),
    ):
        release = release_value(files["policy"])
        release["policy"][name] = value
        path = write_file(
            tmp_path / f"invalid-{name}.json",
            json.dumps({"schema_version": 1, "release": release}).encode(),
            0o644,
        )
        with pytest.raises(GovernedCommandDeploymentError):
            load_approved_sandbox_release(path)


@pytest.mark.parametrize(
    "body",
    [
        b'{"schema_version":1,"schema_version":1}',
        b'{"schema_version":NaN}',
        b'{"schema_version":true,"release":{}}',
        b"\xff",
    ],
)
def test_release_manifest_rejects_noncanonical_json(tmp_path: Path, body: bytes) -> None:
    path = write_file(tmp_path / "malformed-release.json", body, 0o644)
    with pytest.raises(GovernedCommandDeploymentError):
        load_approved_sandbox_release(path)


def test_release_manifest_and_policy_require_secure_files(tmp_path: Path) -> None:
    files = prepare_files(tmp_path)
    files["release"].chmod(0o666)
    with pytest.raises(GovernedCommandDeploymentError):
        load_approved_sandbox_release(files["release"])
    files["release"].chmod(0o644)

    linked = tmp_path / "linked-release.json"
    linked.symlink_to(files["release"])
    with pytest.raises(GovernedCommandDeploymentError):
        load_approved_sandbox_release(linked)

    files["policy"].chmod(0o666)
    with pytest.raises(GovernedCommandDeploymentError):
        load_approved_sandbox_release(files["release"])


def test_release_cannot_be_changed_after_installation(tmp_path: Path) -> None:
    files = prepare_files(tmp_path)
    load_approved_sandbox_release(files["release"])
    other_policy = write_file(tmp_path / "other-policy.yaml", b"other: policy\n", 0o644)
    other = release_value(other_policy)
    other["policy"]["sha256"] = hashlib.sha256(other_policy.read_bytes()).hexdigest()
    path = write_file(
        tmp_path / "other-release.json",
        json.dumps({"schema_version": 1, "release": other}).encode(),
        0o644,
    )
    with pytest.raises(GovernedCommandDeploymentError):
        load_approved_sandbox_release(path)
