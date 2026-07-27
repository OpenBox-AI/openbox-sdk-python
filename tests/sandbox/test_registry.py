from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from openbox_sandbox import (
    DecimalArgument,
    EnumArgument,
    IdentifierArgument,
    IdentifierResultField,
    IntegerResultField,
    LiteralArgument,
    SandboxActivityResult,
    SandboxCommandDefinition,
    SandboxCommandRegistryError,
    SandboxCommandRequest,
    SandboxInputError,
    TypedJsonResultSchema,
    sandbox_command_registry,
)
from openbox_sandbox.command_profiles import CommandResultValidationError


def registry():
    return sandbox_command_registry(
        SandboxCommandDefinition(
            "reconcile",
            "/usr/local/bin/reconcile",
            (
                LiteralArgument("--batch"),
                IdentifierArgument("batch_id", max_bytes=64),
                LiteralArgument("--mode"),
                EnumArgument("mode", ("strict", "review")),
                LiteralArgument("--threshold"),
                DecimalArgument("threshold", 0, 100),
            ),
            TypedJsonResultSchema(
                "reconciliation-v1",
                (
                    IdentifierResultField("batch_id", max_bytes=64),
                    IntegerResultField("approved", 0, 1_000_000),
                ),
            ),
        )
    )


def test_registry_derives_bound_input_and_admission_from_one_identity() -> None:
    value = registry()
    structured = value.structured_profile_bundle()
    admission = value.admission_profile_bundle()
    request = SandboxCommandRequest(
        "reconcile",
        {"batch_id": "batch-1", "mode": "strict", "threshold": 70},
    )

    argv = structured.derive(request)

    assert argv == (
        "/usr/local/bin/reconcile",
        "--batch",
        "batch-1",
        "--mode",
        "strict",
        "--threshold",
        "70",
    )
    assert admission.admits("reconcile", argv, now=datetime.now(timezone.utc))
    assert structured.fingerprint == admission.fingerprint == value.fingerprint
    assert structured.bundle_version == admission.bundle_version == value.bundle_version


def test_registry_typed_result_returns_only_schema_admitted_values() -> None:
    structured = registry().structured_profile_bundle()
    output = json.dumps(
        {"approved": 42, "batch_id": "batch-1"},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()

    result = structured.parse_result("reconcile", output)

    assert result is not None
    assert result.schema_name == "reconciliation-v1"
    assert [(item.name, item.value) for item in result.values] == [
        ("batch_id", "batch-1"),
        ("approved", 42),
    ]


@pytest.mark.parametrize(
    "output",
    [
        b'{"batch_id":"batch-1","approved":42}',  # non-canonical key order
        b'{"approved":1000001,"batch_id":"batch-1"}',
        b'{"approved":42,"batch_id":"batch-1","raw":"secret"}',
        b'{"approved":NaN,"batch_id":"batch-1"}',
    ],
)
def test_registry_typed_result_rejects_noncanonical_or_unbounded_output(
    output: bytes,
) -> None:
    with pytest.raises(CommandResultValidationError):
        registry().structured_profile_bundle().parse_result("reconcile", output)


@pytest.mark.parametrize(
    "definition",
    [
        lambda: SandboxCommandDefinition("bad", "relative"),
        lambda: SandboxCommandDefinition("bad", "/bin/echo", (IdentifierArgument("secret_value"),)),
        lambda: SandboxCommandDefinition(
            "bad",
            "/bin/echo",
            result_schema=TypedJsonResultSchema(
                "result",
                (
                    IdentifierResultField("same"),
                    IntegerResultField("same", 0, 1),
                ),
            ),
        ),
    ],
)
def test_registry_rejects_unsafe_or_ambiguous_definitions(definition) -> None:
    with pytest.raises(SandboxCommandRegistryError):
        definition()


def test_activity_result_contract_is_bounded_and_terminal() -> None:
    valid = SandboxActivityResult(
        "reconcile",
        "executed_in_sandbox",
        0,
        "not_observed",
        "deleted",
        1024,
        1024,
    )
    assert valid.typed_result is None

    invalid_values = [
        {"disposition": "not_executed"},
        {"exit_code": True},
        {"timeout_status": "unknown"},
        {"cleanup_status": "not_needed"},
        {"stdout_bytes": 1024 * 1024 + 1},
        {"stderr_bytes": -1},
    ]
    base = {
        "profile_id": "reconcile",
        "disposition": "executed_in_sandbox",
        "exit_code": 0,
        "timeout_status": "not_observed",
        "cleanup_status": "deleted",
        "stdout_bytes": 0,
        "stderr_bytes": 0,
    }
    for override in invalid_values:
        with pytest.raises(SandboxInputError):
            SandboxActivityResult(**{**base, **override})
