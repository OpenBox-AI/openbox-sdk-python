from __future__ import annotations

import inspect
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from openbox_sandbox import (
    AuthorizedConstrain,
    SandboxCommandRequest,
    SandboxReceiptError,
    SandboxReceiptVerifier,
    issue_sandbox_receipt,
    load_approved_sandbox_release,
    materialize_approved_sandbox_release,
)
from openbox_sandbox.release import _clear_approved_sandbox_release_for_testing

from .deployment_helpers import prepare_files, registry

NOW = datetime(2026, 7, 23, 3, 0, tzinfo=timezone.utc)


class ExternalSigner:
    def __init__(self, key: Ed25519PrivateKey) -> None:
        self._key = key
        self.payloads: list[bytes] = []

    def sign(self, payload: bytes) -> bytes:
        self.payloads.append(payload)
        return self._key.sign(payload)


@pytest.fixture(autouse=True)
def clear_release() -> None:
    _clear_approved_sandbox_release_for_testing()


def test_issues_binding_aware_receipt_from_explicit_constrain(
    tmp_path: Path,
) -> None:
    files = prepare_files(tmp_path)
    load_approved_sandbox_release(files["release"])
    commands = registry()
    key = Ed25519PrivateKey.generate()
    signer = ExternalSigner(key)
    request = SandboxCommandRequest("proof", {})

    issued = issue_sandbox_receipt(
        request,
        authorization=AuthorizedConstrain("constrain", "authorization-1"),
        registry=commands,
        workflow_id="workflow-1",
        key_id="receipt-key-1",
        signer=signer,
        ttl=timedelta(minutes=5),
        now=NOW,
    )

    assert request.receipt is None
    assert issued.receipt is not None
    assert issued.receipt.receipt_id == "authorization-1"
    assert issued.receipt.verdict == "constrain"
    assert issued.receipt.expires_at == "2026-07-23T03:05:00Z"
    assert len(signer.payloads) == 1
    assert b"/usr/local/bin/proof" not in signer.payloads[0]

    public_key = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    verifier = SandboxReceiptVerifier(
        "receipt-key-1",
        public_key,
        clock=lambda: NOW + timedelta(minutes=1),
    )
    profiles = commands.structured_profile_bundle()
    assert (
        verifier.verify(
            issued,
            expected_workflow_id="workflow-1",
            command_argv=profiles.derive(request, now=NOW),
            asset_bundle=materialize_approved_sandbox_release().asset_bundle,
            profile_fingerprint=profiles.profile_fingerprint("proof", now=NOW),
        )
        == "authorization-1"
    )


@pytest.mark.parametrize(
    "authorization",
    [
        None,
        object(),
    ],
)
def test_issuance_requires_explicit_typed_authorization(
    tmp_path: Path, authorization: object
) -> None:
    files = prepare_files(tmp_path)
    load_approved_sandbox_release(files["release"])
    signer = ExternalSigner(Ed25519PrivateKey.generate())
    with pytest.raises(SandboxReceiptError):
        issue_sandbox_receipt(
            SandboxCommandRequest("proof", {}),
            authorization=authorization,  # type: ignore[arg-type]
            registry=registry(),
            workflow_id="workflow-1",
            key_id="receipt-key-1",
            signer=signer,
            now=NOW,
        )
    assert signer.payloads == []


def test_authorization_marker_rejects_non_constrain() -> None:
    with pytest.raises(SandboxReceiptError):
        AuthorizedConstrain("allow", "authorization-1")


@pytest.mark.parametrize(
    "ttl",
    [timedelta(0), timedelta(milliseconds=1), timedelta(minutes=10, seconds=1)],
)
def test_issuance_rejects_invalid_ttl(tmp_path: Path, ttl: timedelta) -> None:
    files = prepare_files(tmp_path)
    load_approved_sandbox_release(files["release"])
    with pytest.raises(SandboxReceiptError):
        issue_sandbox_receipt(
            SandboxCommandRequest("proof", {}),
            authorization=AuthorizedConstrain("constrain", "authorization-1"),
            registry=registry(),
            workflow_id="workflow-1",
            key_id="receipt-key-1",
            signer=ExternalSigner(Ed25519PrivateKey.generate()),
            ttl=ttl,
            now=NOW,
        )


def test_issuance_fails_without_installed_release(tmp_path: Path) -> None:
    del tmp_path
    with pytest.raises(SandboxReceiptError):
        issue_sandbox_receipt(
            SandboxCommandRequest("proof", {}),
            authorization=AuthorizedConstrain("constrain", "authorization-1"),
            registry=registry(),
            workflow_id="workflow-1",
            key_id="receipt-key-1",
            signer=ExternalSigner(Ed25519PrivateKey.generate()),
            now=NOW,
        )


def test_issuance_rejects_signer_output_and_existing_receipt(tmp_path: Path) -> None:
    files = prepare_files(tmp_path)
    load_approved_sandbox_release(files["release"])

    class InvalidSigner:
        def sign(self, payload: bytes) -> bytes:
            del payload
            return b"short"

    commands = registry()
    request = SandboxCommandRequest("proof", {})
    with pytest.raises(SandboxReceiptError):
        issue_sandbox_receipt(
            request,
            authorization=AuthorizedConstrain("constrain", "authorization-1"),
            registry=commands,
            workflow_id="workflow-1",
            key_id="receipt-key-1",
            signer=InvalidSigner(),
            now=NOW,
        )

    issued = issue_sandbox_receipt(
        request,
        authorization=AuthorizedConstrain("constrain", "authorization-1"),
        registry=commands,
        workflow_id="workflow-1",
        key_id="receipt-key-1",
        signer=ExternalSigner(Ed25519PrivateKey.generate()),
        now=NOW,
    )
    with pytest.raises(SandboxReceiptError):
        issue_sandbox_receipt(
            issued,
            authorization=AuthorizedConstrain("constrain", "authorization-2"),
            registry=commands,
            workflow_id="workflow-1",
            key_id="receipt-key-1",
            signer=ExternalSigner(Ed25519PrivateKey.generate()),
            now=NOW,
        )


def test_issuance_api_has_no_private_key_parameter() -> None:
    parameters = inspect.signature(issue_sandbox_receipt).parameters
    assert "private_key" not in parameters
    assert "secret" not in parameters
