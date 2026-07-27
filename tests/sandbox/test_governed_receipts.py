from __future__ import annotations

import inspect
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from openbox_sandbox import (
    SandboxCommandRequest,
    SandboxInputError,
    SandboxReceipt,
)
from openbox_sandbox.receipts import (
    InsecureLocalReceiptVerifier,
    SandboxReceiptError,
    SandboxReceiptVerifier,
    receipt_binding,
    receipt_payload,
)

NOW = datetime(2026, 7, 21, tzinfo=timezone.utc)
WORKFLOW_ID = "workflow-reconcile-1"
COMMAND_ARGV = ("/usr/bin/safe", "--job", "job-1", "--count", "7")
ASSET_BUNDLE = {
    "runtime_contract_version": 1,
    "template": "registry.example/sandbox@sha256:" + "b" * 64,
    "policy": {"id": "deny-network", "version": 1, "sha256": "c" * 64},
}
PROFILE_FINGERPRINT = "d" * 64


def _signed_request(
    *,
    expires_delta: timedelta = timedelta(minutes=5),
    receipt_overrides: dict[str, Any] | None = None,
) -> tuple[
    SandboxCommandRequest,
    SandboxReceiptVerifier,
    dict[str, Any],
]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    bare = SandboxCommandRequest("safe-profile", {"job_id": "job-1", "count": 7})
    binding = receipt_binding(
        bare,
        command_argv=COMMAND_ARGV,
        asset_bundle=ASSET_BUNDLE,
        profile_fingerprint=PROFILE_FINGERPRINT,
    )
    unsigned_values: dict[str, Any] = {
        "schema_version": 1,
        "receipt_id": "rcpt-test-1",
        "nonce": "nonce-test-1",
        "workflow_id": WORKFLOW_ID,
        "verdict": "constrain",
        "profile_id": bare.profile_id,
        **binding,
        "issued_at": NOW.isoformat().replace("+00:00", "Z"),
        "expires_at": (NOW + expires_delta).isoformat().replace("+00:00", "Z"),
        "key_id": "core-key-1",
        "signature": "",
    }
    if receipt_overrides:
        unsigned_values.update(receipt_overrides)
    unsigned = SandboxReceipt(**unsigned_values)
    canonical = json.dumps(
        receipt_payload(unsigned), sort_keys=True, separators=(",", ":")
    ).encode()
    receipt = SandboxReceipt(
        **{
            **receipt_payload(unsigned),
            "signature": private_key.sign(canonical).hex(),
        }
    )
    request = SandboxCommandRequest(bare.profile_id, bare.arguments, receipt)
    verifier = SandboxReceiptVerifier("core-key-1", public_key, lambda: NOW)
    verification = {
        "expected_workflow_id": WORKFLOW_ID,
        "command_argv": COMMAND_ARGV,
        "asset_bundle": ASSET_BUNDLE,
        "profile_fingerprint": PROFILE_FINGERPRINT,
    }
    return request, verifier, verification


def _insecure_local_request(
    *,
    expires_delta: timedelta = timedelta(minutes=5),
    receipt_overrides: dict[str, Any] | None = None,
) -> tuple[
    SandboxCommandRequest,
    InsecureLocalReceiptVerifier,
    SandboxReceiptVerifier,
    dict[str, Any],
]:
    request, signed_verifier, verification = _signed_request(expires_delta=expires_delta)
    assert request.receipt is not None
    values = {
        **asdict(request.receipt),
        "key_id": "insecure-local-testing",
        "signature": "",
    }
    if receipt_overrides:
        values.update(receipt_overrides)
    receipt = SandboxReceipt(**values)
    local_request = SandboxCommandRequest(request.profile_id, request.arguments, receipt)
    signed_verifier = SandboxReceiptVerifier(
        "insecure-local-testing", signed_verifier.public_key, lambda: NOW
    )
    return (
        local_request,
        InsecureLocalReceiptVerifier(lambda: NOW),
        signed_verifier,
        verification,
    )


def test_receipt_verifier_authenticates_all_authorization_bindings() -> None:
    request, verifier, verification = _signed_request()

    assert verifier.verify(request, **verification) == "rcpt-test-1"


@pytest.mark.parametrize(
    ("replacement", "value"),
    [
        ("expected_workflow_id", "workflow-other"),
        ("command_argv", ("/usr/bin/safe", "--job", "job-2")),
        ("asset_bundle", {"runtime_contract_version": 2}),
        ("profile_fingerprint", "e" * 64),
    ],
)
def test_receipt_verifier_rejects_workflow_command_asset_or_profile_mismatch(
    replacement: str, value: object
) -> None:
    request, verifier, verification = _signed_request()
    verification[replacement] = value

    with pytest.raises(SandboxReceiptError):
        verifier.verify(request, **verification)


def test_receipt_verifier_rejects_profile_or_typed_request_mismatch() -> None:
    request, verifier, verification = _signed_request()
    tampered = SandboxCommandRequest(
        request.profile_id, {"job_id": "job-1", "count": 8}, request.receipt
    )
    with pytest.raises(SandboxReceiptError):
        verifier.verify(tampered, **verification)

    request, verifier, verification = _signed_request()
    wrong_profile = SandboxCommandRequest("other-profile", request.arguments, request.receipt)
    with pytest.raises(SandboxReceiptError):
        verifier.verify(wrong_profile, **verification)


def test_receipt_verifier_fails_closed_for_missing_expired_or_bad_signature() -> None:
    request, verifier, verification = _signed_request(expires_delta=timedelta(seconds=-1))
    with pytest.raises(SandboxReceiptError):
        verifier.verify(request, **verification)

    _, verifier, verification = _signed_request()
    with pytest.raises(SandboxReceiptError):
        verifier.verify(SandboxCommandRequest("safe-profile", {}), **verification)

    valid, verifier, verification = _signed_request()
    assert valid.receipt is not None
    bad = SandboxReceipt(**{**asdict(valid.receipt), "signature": "00" * 64})
    with pytest.raises(SandboxReceiptError):
        verifier.verify(
            SandboxCommandRequest(valid.profile_id, valid.arguments, bad),
            **verification,
        )


def test_receipt_verifier_rejects_lifetime_over_ten_minutes() -> None:
    request, verifier, verification = _signed_request(
        expires_delta=timedelta(minutes=10, microseconds=1)
    )

    with pytest.raises(SandboxReceiptError):
        verifier.verify(request, **verification)


def test_failed_check_does_not_consume_but_success_consumes_exactly_once() -> None:
    request, verifier, verification = _signed_request()

    with pytest.raises(SandboxReceiptError):
        verifier.verify(
            request,
            **{**verification, "expected_workflow_id": "workflow-wrong"},
        )
    assert verifier.verify(request, **verification) == "rcpt-test-1"
    with pytest.raises(SandboxReceiptError, match="already consumed"):
        verifier.verify(request, **verification)


def test_receipt_consumption_is_atomic_under_concurrent_reuse() -> None:
    request, verifier, verification = _signed_request()

    def consume() -> str:
        return verifier.verify(request, **verification)

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = [executor.submit(consume) for _ in range(2)]
    successes = 0
    failures = 0
    for outcome in outcomes:
        try:
            assert outcome.result() == "rcpt-test-1"
            successes += 1
        except SandboxReceiptError:
            failures += 1
    assert (successes, failures) == (1, 1)


def test_receipt_contains_digests_but_no_argv_or_output_bodies() -> None:
    request, _, _ = _signed_request()
    assert request.receipt is not None
    encoded = json.dumps(asdict(request.receipt), sort_keys=True)

    assert "command_sha256" in encoded
    assert "asset_bundle_sha256" in encoded
    assert "profile_fingerprint" in encoded
    assert "/usr/bin/safe" not in encoded
    assert '"argv"' not in encoded
    assert '"stdout"' not in encoded
    assert '"stderr"' not in encoded


def test_receipt_value_rejects_unknown_or_missing_fields() -> None:
    request, _, _ = _signed_request()
    assert request.receipt is not None
    value = asdict(request.receipt)

    with pytest.raises(SandboxInputError):
        SandboxReceipt.from_value({**value, "unknown": "value"})
    value.pop("nonce")
    with pytest.raises(SandboxInputError):
        SandboxReceipt.from_value(value)


@pytest.mark.parametrize(
    "receipt_overrides",
    [
        {"schema_version": 2},
        {"verdict": "allow"},
        {"receipt_id": "not canonical!"},
        {"nonce": "not canonical!"},
        {"workflow_id": "workflow-other"},
        {"profile_id": "other-profile"},
        {"arguments_sha256": "0" * 64},
        {"command_sha256": "0" * 64},
        {"asset_bundle_sha256": "0" * 64},
        {"profile_fingerprint": "0" * 64},
        {"issued_at": "not-a-timestamp"},
        {"expires_at": "not-a-timestamp"},
    ],
)
def test_signed_and_insecure_modes_share_common_validation(
    receipt_overrides: dict[str, Any],
) -> None:
    signed_request, signed_verifier, signed_verification = _signed_request(
        receipt_overrides=receipt_overrides
    )
    local_request, local_verifier, _, local_verification = _insecure_local_request(
        receipt_overrides=receipt_overrides
    )

    with pytest.raises(SandboxReceiptError) as signed_error:
        signed_verifier.verify(signed_request, **signed_verification)
    with pytest.raises(SandboxReceiptError) as local_error:
        local_verifier.verify(local_request, **local_verification)

    assert str(signed_error.value) == "governed command receipt rejected"
    assert str(local_error.value) == "INSECURE LOCAL unsigned governed command receipt rejected"


def test_signed_and_insecure_modes_share_request_presence_and_clock_checks() -> None:
    signed_request, signed_verifier, verification = _signed_request()
    local_request, local_verifier, _, _ = _insecure_local_request()
    missing = SandboxCommandRequest("safe-profile", {})

    with pytest.raises(SandboxReceiptError) as signed_missing:
        signed_verifier.verify(missing, **verification)
    with pytest.raises(SandboxReceiptError) as local_missing:
        local_verifier.verify(missing, **verification)
    assert str(signed_missing.value) == "governed command receipt required"
    assert str(local_missing.value) == "INSECURE LOCAL unsigned governed command receipt required"

    with pytest.raises(SandboxReceiptError) as signed_type:
        signed_verifier.verify(object(), **verification)  # type: ignore[arg-type]
    with pytest.raises(SandboxReceiptError) as local_type:
        local_verifier.verify(object(), **verification)  # type: ignore[arg-type]
    assert str(signed_type.value) == "governed command receipt rejected"
    assert str(local_type.value) == "INSECURE LOCAL unsigned governed command receipt rejected"

    signed_verifier.clock = lambda: datetime(2026, 7, 21)
    local_verifier.clock = lambda: datetime(2026, 7, 21)
    with pytest.raises(SandboxReceiptError) as signed_clock:
        signed_verifier.verify(signed_request, **verification)
    with pytest.raises(SandboxReceiptError) as local_clock:
        local_verifier.verify(local_request, **verification)
    assert str(signed_clock.value) == "receipt verifier rejected"
    assert str(local_clock.value) == "INSECURE LOCAL receipt verifier rejected"


def test_authentication_field_shape_precedes_clock_error_as_before() -> None:
    signed_request, signed_verifier, verification = _signed_request()
    assert signed_request.receipt is not None
    signed_receipt = SandboxReceipt(**{**asdict(signed_request.receipt), "signature": ""})
    signed_request = SandboxCommandRequest(
        signed_request.profile_id, signed_request.arguments, signed_receipt
    )
    local_request, local_verifier, _, _ = _insecure_local_request(
        receipt_overrides={"signature": object()}
    )
    signed_verifier.clock = lambda: datetime(2026, 7, 21)
    local_verifier.clock = lambda: datetime(2026, 7, 21)

    with pytest.raises(SandboxReceiptError) as signed_error:
        signed_verifier.verify(signed_request, **verification)
    with pytest.raises(SandboxReceiptError) as local_error:
        local_verifier.verify(local_request, **verification)

    assert str(signed_error.value) == "governed command receipt rejected"
    assert str(local_error.value) == "INSECURE LOCAL unsigned governed command receipt rejected"


def test_receipt_verifier_public_contract_and_repr_regression() -> None:
    _, signed_verifier, _ = _signed_request()
    local_verifier = InsecureLocalReceiptVerifier(lambda: NOW)

    assert tuple(inspect.signature(SandboxReceiptVerifier).parameters) == (
        "key_id",
        "public_key",
        "clock",
    )
    assert tuple(inspect.signature(InsecureLocalReceiptVerifier).parameters) == ("clock",)
    assert repr(signed_verifier) == (
        "SandboxReceiptVerifier(key_id='core-key-1', "
        "public_key=<redacted>, replay_protection=in_process)"
    )
    assert repr(local_verifier) == (
        "InsecureLocalReceiptVerifier("
        "mode=INSECURE_LOCAL_UNSIGNED_TESTING_ONLY, "
        "signature_verification=disabled, replay_protection=in_process)"
    )


def test_insecure_local_verifier_accepts_explicitly_unsigned_receipt() -> None:
    request, verifier, _, verification = _insecure_local_request()

    assert request.receipt is not None
    assert request.receipt.signature == ""
    assert verifier.verify(request, **verification) == "rcpt-test-1"
    assert "INSECURE_LOCAL_UNSIGNED_TESTING_ONLY" in repr(verifier)
    assert "signature_verification=disabled" in repr(verifier)


@pytest.mark.parametrize(
    ("replacement", "value"),
    [
        ("expected_workflow_id", "workflow-other"),
        ("command_argv", ("/usr/bin/safe", "--job", "tampered")),
        ("asset_bundle", {"runtime_contract_version": 999}),
        ("profile_fingerprint", "e" * 64),
    ],
)
def test_insecure_local_verifier_retains_every_external_binding(
    replacement: str, value: object
) -> None:
    request, verifier, _, verification = _insecure_local_request()
    verification[replacement] = value

    with pytest.raises(SandboxReceiptError, match="INSECURE LOCAL"):
        verifier.verify(request, **verification)


def test_insecure_local_verifier_rejects_tampered_request_and_profile() -> None:
    request, verifier, _, verification = _insecure_local_request()
    tampered_arguments = SandboxCommandRequest(
        request.profile_id, {"job_id": "job-1", "count": 8}, request.receipt
    )
    with pytest.raises(SandboxReceiptError, match="INSECURE LOCAL"):
        verifier.verify(tampered_arguments, **verification)

    request, verifier, _, verification = _insecure_local_request()
    tampered_profile = SandboxCommandRequest("other-profile", request.arguments, request.receipt)
    with pytest.raises(SandboxReceiptError, match="INSECURE LOCAL"):
        verifier.verify(tampered_profile, **verification)


@pytest.mark.parametrize(
    "receipt_overrides",
    [
        {"schema_version": 2},
        {"schema_version": True},
        {"verdict": "allow"},
        {"receipt_id": "not canonical!"},
        {"key_id": "not canonical!"},
        {"signature": object()},
    ],
)
def test_insecure_local_verifier_rejects_malformed_receipts(
    receipt_overrides: dict[str, Any],
) -> None:
    request, verifier, _, verification = _insecure_local_request(
        receipt_overrides=receipt_overrides
    )

    with pytest.raises(SandboxReceiptError, match="INSECURE LOCAL"):
        verifier.verify(request, **verification)


def test_insecure_local_verifier_retains_expiry_and_lifetime_checks() -> None:
    expired, expired_verifier, _, verification = _insecure_local_request(
        expires_delta=timedelta(seconds=-1)
    )
    with pytest.raises(SandboxReceiptError, match="INSECURE LOCAL"):
        expired_verifier.verify(expired, **verification)

    overlong, overlong_verifier, _, verification = _insecure_local_request(
        expires_delta=timedelta(minutes=10, microseconds=1)
    )
    with pytest.raises(SandboxReceiptError, match="INSECURE LOCAL"):
        overlong_verifier.verify(overlong, **verification)


def test_insecure_local_verifier_ignores_forgery_but_signed_verifier_does_not() -> None:
    forged = "00" * 64
    request, insecure_verifier, signed_verifier, verification = _insecure_local_request(
        receipt_overrides={"signature": forged}
    )

    assert insecure_verifier.verify(request, **verification) == "rcpt-test-1"
    with pytest.raises(SandboxReceiptError):
        signed_verifier.verify(request, **verification)


def test_insecure_local_verifier_consumes_receipt_exactly_once() -> None:
    request, verifier, _, verification = _insecure_local_request()

    assert verifier.verify(request, **verification) == "rcpt-test-1"
    with pytest.raises(SandboxReceiptError, match="already consumed"):
        verifier.verify(request, **verification)


def test_insecure_local_consumption_is_atomic_under_concurrent_reuse() -> None:
    request, verifier, _, verification = _insecure_local_request()

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = [executor.submit(verifier.verify, request, **verification) for _ in range(2)]
    successes = 0
    failures = 0
    for outcome in outcomes:
        try:
            assert outcome.result() == "rcpt-test-1"
            successes += 1
        except SandboxReceiptError:
            failures += 1
    assert (successes, failures) == (1, 1)


def test_insecure_local_verifier_is_direct_path_only_and_never_top_level() -> None:
    import openbox_sandbox

    assert "InsecureLocalReceiptVerifier" not in openbox_sandbox.__all__
    assert not hasattr(openbox_sandbox, "InsecureLocalReceiptVerifier")
