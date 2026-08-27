from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any

from .errors import ProfileValidationError

_MAX_DOCUMENT_BYTES = 1024 * 1024
_HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ProfileValidationError()
        value[key] = item
    return value


def _reject_constant(_: str) -> None:
    raise ProfileValidationError()


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ProfileValidationError()
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise ProfileValidationError() from None
    if parsed.tzinfo is None:
        raise ProfileValidationError()
    return parsed.astimezone(UTC)


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise ProfileValidationError() from None


def _plain_object(value: object, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ProfileValidationError()
    return value


@dataclass(frozen=True, slots=True)
class ArgumentRule:
    kind: str
    literal: str | None = None
    choices: tuple[str, ...] = ()
    minimum: int | None = None
    maximum: int | None = None
    max_bytes: int | None = None

    @classmethod
    def from_wire(cls, value: object) -> ArgumentRule:
        if not isinstance(value, dict) or not isinstance(value.get("kind"), str):
            raise ProfileValidationError()
        kind = value["kind"]
        if kind == "literal":
            item = _plain_object(value, {"kind", "value"})["value"]
            if not isinstance(item, str) or "\x00" in item or len(item.encode("utf-8")) > 4096:
                raise ProfileValidationError()
            return cls(kind=kind, literal=item)
        if kind == "enum":
            items = _plain_object(value, {"kind", "values"})["values"]
            if (
                not isinstance(items, list)
                or not items
                or len(items) > 128
                or not all(isinstance(item, str) for item in items)
                or len(set(items)) != len(items)
                or any("\x00" in item or len(item.encode("utf-8")) > 4096 for item in items)
            ):
                raise ProfileValidationError()
            return cls(kind=kind, choices=tuple(items))
        if kind == "decimal":
            item = _plain_object(value, {"kind", "minimum", "maximum"})
            minimum, maximum = item["minimum"], item["maximum"]
            if (
                isinstance(minimum, bool)
                or isinstance(maximum, bool)
                or not isinstance(minimum, int)
                or not isinstance(maximum, int)
                or minimum > maximum
            ):
                raise ProfileValidationError()
            return cls(kind=kind, minimum=minimum, maximum=maximum)
        if kind == "identifier":
            item = _plain_object(value, {"kind", "max_bytes"})["max_bytes"]
            if isinstance(item, bool) or not isinstance(item, int) or not 1 <= item <= 4096:
                raise ProfileValidationError()
            return cls(kind=kind, max_bytes=item)
        raise ProfileValidationError()

    def accepts(self, value: str) -> bool:
        if self.kind == "literal":
            return value == self.literal
        if self.kind == "enum":
            return value in self.choices
        if self.kind == "decimal":
            try:
                parsed = int(value, 10)
            except ValueError:
                return False
            return str(parsed) == value and self.minimum <= parsed <= self.maximum  # type: ignore[operator]
        if self.kind == "identifier":
            return (
                len(value.encode("utf-8")) <= self.max_bytes  # type: ignore[operator]
                and _IDENTIFIER.fullmatch(value) is not None
            )
        return False


@dataclass(frozen=True, slots=True, repr=False)
class CommandProfile:
    profile_id: str
    executable: str
    arguments: tuple[ArgumentRule, ...]
    sensitive: bool
    free_form: bool

    def __repr__(self) -> str:
        return (
            f"CommandProfile(profile_id={self.profile_id!r}, "
            f"executable={self.executable!r}, arguments={len(self.arguments)}, "
            f"sensitive={self.sensitive}, free_form={self.free_form})"
        )

    def admits(self, argv: Sequence[str]) -> bool:
        return (
            not self.sensitive
            and not self.free_form
            and len(argv) == len(self.arguments) + 1
            and argv[0] == self.executable
            and all(
                rule.accepts(value)
                for rule, value in zip(self.arguments, argv[1:], strict=True)
            )
        )


@dataclass(frozen=True, slots=True, repr=False, init=False)
class CommandProfileBundle:
    schema_version: int
    bundle_version: str
    key_id: str
    issued_at: datetime
    expires_at: datetime
    fingerprint: str
    _profiles: Mapping[str, CommandProfile]

    def __init__(self) -> None:
        raise TypeError("use load() or from_trusted() to construct command profiles")

    @classmethod
    def from_trusted(
        cls,
        *,
        bundle_version: str,
        issued_at: datetime,
        expires_at: datetime,
        profiles: Sequence[Mapping[str, Any]],
        now: datetime,
    ) -> CommandProfileBundle:
        """Build an immutable bundle from profiles owned by this process."""
        return _trusted_bundle(
            cls,
            bundle_version=bundle_version,
            issued_at=issued_at,
            expires_at=expires_at,
            profiles=profiles,
            now=now,
        )

    @classmethod
    def load(
        cls,
        document: bytes | str,
        *,
        secret: bytes,
        expected_key_id: str,
        now: datetime | None = None,
    ) -> CommandProfileBundle:
        if not isinstance(secret, bytes) or len(secret) < 32 or not expected_key_id:
            raise ProfileValidationError()
        encoded = document.encode("utf-8") if isinstance(document, str) else document
        if not isinstance(encoded, bytes) or not encoded or len(encoded) > _MAX_DOCUMENT_BYTES:
            raise ProfileValidationError()
        try:
            root = json.loads(
                encoded,
                object_pairs_hook=_strict_object,
                parse_constant=_reject_constant,
            )
        except (json.JSONDecodeError, UnicodeDecodeError, ProfileValidationError):
            raise ProfileValidationError() from None
        root = _plain_object(root, {"payload", "signature"})
        payload = _plain_object(
            root["payload"],
            {
                "schema_version",
                "bundle_version",
                "key_id",
                "issued_at",
                "expires_at",
                "profiles",
            },
        )
        signature = _plain_object(root["signature"], {"algorithm", "key_id", "value"})
        if (
            signature["algorithm"] != "hmac-sha256"
            or signature["key_id"] != expected_key_id
            or payload["key_id"] != expected_key_id
            or not isinstance(signature["value"], str)
            or _HEX_SHA256.fullmatch(signature["value"]) is None
        ):
            raise ProfileValidationError()
        canonical = _canonical(payload)
        expected = hmac.new(secret, canonical, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature["value"], expected):
            raise ProfileValidationError()
        if (
            type(payload["schema_version"]) is not int
            or payload["schema_version"] != 1
            or not isinstance(payload["bundle_version"], str)
            or not payload["bundle_version"]
        ):
            raise ProfileValidationError()
        issued_at = _timestamp(payload["issued_at"])
        expires_at = _timestamp(payload["expires_at"])
        current = (now or datetime.now(UTC)).astimezone(UTC)
        if issued_at > current or expires_at <= current or issued_at >= expires_at:
            raise ProfileValidationError()
        profile_values = payload["profiles"]
        if not isinstance(profile_values, list) or not profile_values or len(profile_values) > 1024:
            raise ProfileValidationError()
        profiles: dict[str, CommandProfile] = {}
        for raw_profile in profile_values:
            profile = _parse_profile(raw_profile)
            if profile.profile_id in profiles:
                raise ProfileValidationError()
            profiles[profile.profile_id] = profile
        instance = object.__new__(cls)
        object.__setattr__(instance, "schema_version", 1)
        object.__setattr__(instance, "bundle_version", payload["bundle_version"])
        object.__setattr__(instance, "key_id", expected_key_id)
        object.__setattr__(instance, "issued_at", issued_at)
        object.__setattr__(instance, "expires_at", expires_at)
        object.__setattr__(instance, "fingerprint", hashlib.sha256(canonical).hexdigest())
        object.__setattr__(instance, "_profiles", MappingProxyType(profiles))
        return instance

    def __repr__(self) -> str:
        return (
            f"CommandProfileBundle(schema_version={self.schema_version}, "
            f"bundle_version={self.bundle_version!r}, key_id={self.key_id!r}, "
            f"profiles={len(self._profiles)}, fingerprint={self.fingerprint!r})"
        )

    @property
    def profile_ids(self) -> tuple[str, ...]:
        """Return the validated profile identifiers in stable order."""
        return tuple(sorted(self._profiles))

    def admits(self, profile_id: str, argv: Sequence[str], *, now: datetime) -> bool:
        current = now.astimezone(UTC)
        profile = self._profiles.get(profile_id)
        return (
            self.issued_at <= current < self.expires_at
            and profile is not None
            and profile.admits(argv)
        )


def _parse_profile(value: object) -> CommandProfile:
    profile = _plain_object(
        value,
        {"id", "executable", "arguments", "sensitive", "free_form"},
    )
    profile_id = profile["id"]
    executable = profile["executable"]
    arguments = profile["arguments"]
    if (
        not isinstance(profile_id, str)
        or _IDENTIFIER.fullmatch(profile_id) is None
        or not isinstance(executable, str)
        or not executable.startswith("/")
        or "\x00" in executable
        or len(executable.encode("utf-8")) > 4096
        or not isinstance(arguments, list)
        or len(arguments) > 128
        or type(profile["sensitive"]) is not bool
        or type(profile["free_form"]) is not bool
    ):
        raise ProfileValidationError()
    return CommandProfile(
        profile_id=profile_id,
        executable=executable,
        arguments=tuple(ArgumentRule.from_wire(item) for item in arguments),
        sensitive=profile["sensitive"],
        free_form=profile["free_form"],
    )


def _trusted_bundle(
    bundle_type: type[CommandProfileBundle],
    *,
    bundle_version: str,
    issued_at: datetime,
    expires_at: datetime,
    profiles: Sequence[Mapping[str, Any]],
    now: datetime,
) -> CommandProfileBundle:
    if (
        not isinstance(bundle_version, str)
        or not bundle_version
        or not isinstance(issued_at, datetime)
        or issued_at.tzinfo is None
        or not isinstance(expires_at, datetime)
        or expires_at.tzinfo is None
        or not isinstance(now, datetime)
        or now.tzinfo is None
        or isinstance(profiles, (str, bytes))
        or not isinstance(profiles, Sequence)
        or not profiles
        or len(profiles) > 1024
    ):
        raise ProfileValidationError()
    issued = issued_at.astimezone(UTC)
    expires = expires_at.astimezone(UTC)
    current = now.astimezone(UTC)
    if issued > current or expires <= current or issued >= expires:
        raise ProfileValidationError()
    parsed: dict[str, CommandProfile] = {}
    profile_values = list(profiles)
    for raw_profile in profile_values:
        profile = _parse_profile(raw_profile)
        if profile.profile_id in parsed or profile.sensitive or profile.free_form:
            raise ProfileValidationError()
        parsed[profile.profile_id] = profile
    identity = {
        "schema_version": 1,
        "bundle_version": bundle_version,
        "issued_at": issued.isoformat(),
        "expires_at": expires.isoformat(),
        "profiles": profile_values,
    }
    instance = object.__new__(bundle_type)
    object.__setattr__(instance, "schema_version", 1)
    object.__setattr__(instance, "bundle_version", bundle_version)
    object.__setattr__(instance, "key_id", "")
    object.__setattr__(instance, "issued_at", issued)
    object.__setattr__(instance, "expires_at", expires)
    object.__setattr__(instance, "fingerprint", hashlib.sha256(_canonical(identity)).hexdigest())
    object.__setattr__(instance, "_profiles", MappingProxyType(parsed))
    return instance


def _sign_for_test(payload: Mapping[str, Any], secret: bytes, key_id: str) -> bytes:
    canonical = _canonical(payload)
    root = {
        "payload": payload,
        "signature": {
            "algorithm": "hmac-sha256",
            "key_id": key_id,
            "value": hmac.new(secret, canonical, hashlib.sha256).hexdigest(),
        },
    }
    return _canonical(root)
