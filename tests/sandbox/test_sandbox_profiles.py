from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from openbox_sandbox import (
    CommandProfileBundleError,
    SandboxCommandArgument,
    SandboxCommandRequest,
    SandboxInputError,
    StructuredCommandProfileBundle,
)
from openbox_sandbox.command_profiles import CommandResultValidationError

from .sandbox_helpers import (
    KEY_ID,
    NOW,
    SECRET,
    sign,
    structured_payload,
    structured_profiles,
)


def _trusted_temporal_profile(*, typed_result: bool = False) -> dict[str, Any]:
    return deepcopy(structured_payload(typed_result=typed_result)["profiles"][0])


def _trusted_temporal_bundle(
    profiles: Any,
    *,
    issued_at: datetime = NOW - timedelta(minutes=1),
    expires_at: datetime = NOW + timedelta(minutes=30),
    now: datetime = NOW,
) -> StructuredCommandProfileBundle:
    return StructuredCommandProfileBundle.from_trusted(
        bundle_version="trusted-temporal-test-v1",
        issued_at=issued_at,
        expires_at=expires_at,
        profiles=profiles,
        now=now,
    )


def test_signed_structural_profile_derives_exact_argv_without_callable() -> None:
    profiles = structured_profiles()
    request = SandboxCommandRequest("proof", {"mode": "safe", "count": 3, "job": "job-1"})
    assert profiles.derive(request, now=NOW) == (
        "/usr/bin/proof",
        "--mode",
        "safe",
        "3",
        "job-1",
    )
    assert not callable(profiles)
    assert profiles.profile_ids == ("proof",)


@pytest.mark.parametrize(
    "arguments",
    [
        {"mode": "unsafe", "count": 3, "job": "job-1"},
        {"mode": "safe", "count": 0, "job": "job-1"},
        {"mode": "safe", "count": 3, "job": "../escape"},
        {"mode": "safe", "count": 3, "job": "job-1", "extra": "x"},
    ],
)
def test_profile_specific_input_rejection(arguments: dict[str, str | int]) -> None:
    with pytest.raises(SandboxInputError):
        structured_profiles().derive(SandboxCommandRequest("proof", arguments), now=NOW)


def test_generic_input_rejects_raw_action_and_sensitive_field_names() -> None:
    for profile_id in ("", "../proof", "p" * 129):
        with pytest.raises(SandboxInputError):
            SandboxCommandRequest(profile_id, {})
    for name in ("argv", "command", "api_token", "private_key"):
        with pytest.raises(SandboxInputError):
            SandboxCommandRequest("proof", {name: "value"})
    with pytest.raises(SandboxInputError):
        SandboxCommandRequest(
            "proof",
            [
                SandboxCommandArgument("mode", "safe"),
                SandboxCommandArgument("mode", "safe"),
            ],
        )


@pytest.mark.parametrize(
    "document,secret,key,now",
    [
        (
            sign(structured_payload()).replace(b"/usr/bin/proof", b"/usr/bin/pro0f"),
            SECRET,
            KEY_ID,
            NOW,
        ),
        (sign(structured_payload()), b"x" * 32, KEY_ID, NOW),
        (sign(structured_payload()), SECRET, "wrong-key", NOW),
        (
            sign(structured_payload()),
            SECRET,
            KEY_ID,
            datetime(2025, 1, 1, tzinfo=timezone.utc),
        ),
        (
            sign(structured_payload()),
            SECRET,
            KEY_ID,
            datetime(2028, 1, 1, tzinfo=timezone.utc),
        ),
        (sign(structured_payload(sensitive=True)), SECRET, KEY_ID, NOW),
        (sign(structured_payload(free_form=True)), SECRET, KEY_ID, NOW),
    ],
)
def test_bundle_tamper_key_time_and_unsafe_capabilities_fail_startup(
    document: bytes, secret: bytes, key: str, now: datetime
) -> None:
    with pytest.raises(CommandProfileBundleError):
        StructuredCommandProfileBundle.load(document, secret=secret, expected_key_id=key, now=now)


def test_boolean_schema_version_is_rejected() -> None:
    with pytest.raises(CommandProfileBundleError):
        StructuredCommandProfileBundle.load(
            sign(structured_payload() | {"schema_version": True}),
            secret=SECRET,
            expected_key_id=KEY_ID,
            now=NOW,
        )


def test_bundle_constructor_requires_an_explicit_validating_constructor() -> None:
    with pytest.raises(TypeError, match=r"load\(\) or from_trusted\(\)"):
        StructuredCommandProfileBundle()


def test_trusted_profiles_snapshot_mappings_schema_and_identity() -> None:
    profile = _trusted_temporal_profile(typed_result=True)
    profiles = _trusted_temporal_bundle([profile])
    request = SandboxCommandRequest("proof", {"mode": "safe", "count": 3, "job": "job-1"})
    argv = profiles.derive(request, now=NOW)
    fingerprint = profiles.profile_fingerprint("proof", now=NOW)
    typed = profiles.parse_result("proof", b'{"count":3,"job":"job-1"}', now=NOW)

    profile["executable"] = "/host/mutated"
    profile["arguments"][1]["values"].append("mutated")
    profile["arguments"][2]["minimum"] = 99
    profile["result_schema"]["fields"][1]["maximum"] = 1

    assert profiles.derive(request, now=NOW) == argv
    assert profiles.profile_fingerprint("proof", now=NOW) == fingerprint
    assert profiles.parse_result("proof", b'{"count":3,"job":"job-1"}', now=NOW) == typed


def test_trusted_profiles_reject_shapes_duplicates_and_unsafe_capabilities() -> None:
    valid = _trusted_temporal_profile()
    unknown = deepcopy(valid)
    unknown["unexpected"] = True
    missing = deepcopy(valid)
    del missing["arguments"]
    sensitive = deepcopy(valid)
    sensitive["sensitive"] = True
    free_form = deepcopy(valid)
    free_form["free_form"] = True
    invalid_values: list[Any] = [
        {},
        [],
        ["not-an-object"],
        [unknown],
        [missing],
        [deepcopy(valid), deepcopy(valid)],
        [sensitive],
        [free_form],
    ]
    for profiles in invalid_values:
        with pytest.raises(CommandProfileBundleError):
            _trusted_temporal_bundle(profiles)


def test_trusted_profiles_reject_naive_invalid_or_expired_windows() -> None:
    aware = NOW
    naive = NOW.replace(tzinfo=None)
    invalid = (
        (naive, aware + timedelta(minutes=1), aware),
        (aware - timedelta(minutes=1), naive, aware),
        (aware - timedelta(minutes=1), aware + timedelta(minutes=1), naive),
        (aware + timedelta(seconds=1), aware + timedelta(minutes=1), aware),
        (aware - timedelta(minutes=2), aware, aware),
        (aware, aware, aware),
    )
    for issued_at, expires_at, now in invalid:
        with pytest.raises(CommandProfileBundleError):
            _trusted_temporal_bundle(
                [_trusted_temporal_profile()],
                issued_at=issued_at,
                expires_at=expires_at,
                now=now,
            )


def test_trusted_profiles_reject_duplicate_dynamic_fields_and_argument_ranges() -> None:
    duplicate = _trusted_temporal_profile()
    duplicate["arguments"].append(deepcopy(duplicate["arguments"][1]))
    boolean_range = _trusted_temporal_profile()
    boolean_range["arguments"][2]["minimum"] = True
    reversed_range = _trusted_temporal_profile()
    reversed_range["arguments"][2].update(minimum=6, maximum=5)
    boolean_size = _trusted_temporal_profile()
    boolean_size["arguments"][3]["max_bytes"] = True
    for profile in (duplicate, boolean_range, reversed_range, boolean_size):
        with pytest.raises(CommandProfileBundleError):
            _trusted_temporal_bundle([profile])


def test_trusted_profiles_reject_malformed_typed_result_schemas() -> None:
    missing = _trusted_temporal_profile(typed_result=True)
    del missing["result_schema"]["fields"]
    duplicate = _trusted_temporal_profile(typed_result=True)
    duplicate["result_schema"]["fields"].append(deepcopy(duplicate["result_schema"]["fields"][0]))
    boolean_range = _trusted_temporal_profile(typed_result=True)
    boolean_range["result_schema"]["fields"][1]["minimum"] = True
    reversed_range = _trusted_temporal_profile(typed_result=True)
    reversed_range["result_schema"]["fields"][1].update(minimum=6, maximum=5)
    boolean_size = _trusted_temporal_profile(typed_result=True)
    boolean_size["result_schema"]["max_bytes"] = True
    unknown = _trusted_temporal_profile(typed_result=True)
    unknown["result_schema"]["unexpected"] = True
    for profile in (
        missing,
        duplicate,
        boolean_range,
        reversed_range,
        boolean_size,
        unknown,
    ):
        with pytest.raises(CommandProfileBundleError):
            _trusted_temporal_bundle([profile])


def test_profile_declared_typed_result_is_strict_and_ordered() -> None:
    profiles = structured_profiles(typed_result=True)

    result = profiles.parse_result("proof", b'{"count":3,"job":"job-1"}', now=NOW)

    assert result is not None
    assert result.schema_name == "openbox.proof.v1"
    assert tuple((item.name, item.value) for item in result.values) == (
        ("job", "job-1"),
        ("count", 3),
    )
    assert profiles.profile_fingerprint(
        "proof", now=NOW
    ) != structured_profiles().profile_fingerprint("proof", now=NOW)


@pytest.mark.parametrize(
    "output",
    [
        b"{",
        b'{"count":3,"count":3,"job":"job-1"}',
        b'{"count":3,"extra":1,"job":"job-1"}',
        b'{"count":NaN,"job":"job-1"}',
        b"x" * 257,
        b'{"count":"3","job":"job-1"}',
        b'{"count":true,"job":"job-1"}',
        b'{"count":6,"job":"job-1"}',
        b'{"count":3,"job":"job-1"}{}',
        b'{"count":3,"job":"job-1"}\n',
        b'{"job":"job-1"}',
        b"\xff",
    ],
)
def test_profile_declared_typed_result_rejects_untrusted_output(output: bytes) -> None:
    with pytest.raises(CommandResultValidationError):
        structured_profiles(typed_result=True).parse_result("proof", output, now=NOW)


def test_metadata_only_profile_ignores_output_body() -> None:
    assert structured_profiles().parse_result("proof", b"untrusted output", now=NOW) is None


@pytest.mark.parametrize(
    "mutate",
    [
        lambda profile: profile.update(result_mode="unknown"),
        lambda profile: profile.update(
            result_mode="typed_json_v1", result_schema={"name": "unsupported"}
        ),
        lambda profile: profile.update(result_schema={"unexpected": True}),
    ],
)
def test_unsupported_result_schema_or_mode_fails_bundle_load(mutate) -> None:
    payload = structured_payload()
    mutate(payload["profiles"][0])
    with pytest.raises(CommandProfileBundleError):
        StructuredCommandProfileBundle.load(
            sign(payload), secret=SECRET, expected_key_id=KEY_ID, now=NOW
        )
